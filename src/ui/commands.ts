/**
 * ui/commands.ts
 *
 * Checkwash Lens Session & Command Coordinator (Rev 3 §1.1, §2, §3, §6, §8, §9).
 *
 * Responsibilities:
 * - Coordinates all user-initiated commands across CheckwashEngineRunner, RevisionProvider,
 *   FastGuard, ContextDiet, ProveSatelliteRunner, StatusBar, LiveDiagnostics, and TreeView.
 * - Enforces zero external processes on activation, save, buffer edit, configuration change,
 *   or Workspace Trust change (Rev 3 §1.1 & B01).
 * - Binds all results, diagnostics, and execution records to a single selected repository root;
 *   switching repositories resets the active session so results never bleed across folders.
 * - Offline report viewing is strictly bounded (<= 16 MiB), read-only, spawns zero processes,
 *   and never alters the active Checkwash 5-state verdict.
 */

import * as fs from "fs";
import * as path from "path";
import {
  CheckwashFindingsDocumentV2,
  MAX_REPORT_BYTES,
  validateFindingsJsonV2,
  ValidationResult,
} from "../core/checkwashSchema";
import {
  BoundedProveOptions,
  ProveEntryKind,
} from "../core/replayBuilder";
import { normalizeSourceForComparison } from "../core/sourceIdentity";
import {
  CheckwashEvaluatedState,
  createErrorState,
  createNotRunState,
  withScanScope,
} from "../core/verdictModel";
import {
  CheckwashEngineRunner,
  CompletedStaticScanSession,
  EnrichedFindingLocation,
  OpenEditorDocumentSnapshot,
  reconcileOpenDocumentsAfterScan,
} from "../engine/checkwashRunner";
import {
  authorizeClipboardCopy,
  buildContextDietDiff,
  ContextDietResult,
} from "../engine/contextDiet";
import {
  analyzeCommittedDiffWithFastGuard,
  FastGuardAnalysisResult,
} from "../engine/fastDiffGuard";
import { UncommittedSnapshotMode } from "../engine/snapshotBuilder";
import {
  areSameRepositoryPath,
  HostEnvironmentDescriptor,
  isDangerousUncOrDevicePath,
  isFullyQualifiedWindowsPath,
} from "../runtime/admission";
import {
  EnvironmentDoctorReport,
  runEnvironmentDoctor,
  WorkspaceSettingOverrideInspection,
} from "../runtime/environmentDoctor";
import { RunnerLimits, UnifiedProcessRunner } from "../runtime/processRunner";
import {
  ProveExecutionAuthorization,
  ProvePreflightResult,
  ProveSatelliteRunner,
  ProveSessionOutcome,
} from "../satellite/proveRunner";
import {
  ImmutableBlobRecord,
  parseRevisionUriString,
  RevisionProvider,
} from "../source/revisionProvider";
import {
  buildLiveDiagnosticsPlan,
  LiveDiagnosticsPlan,
} from "./diagnostics";
import {
  buildStatusBarViewModel,
  StatusBarViewModel,
} from "./statusBar";
import {
  buildCheckwashTreeModel,
  CheckwashTreeNode,
} from "./treeView";

export interface ControllerViewSnapshot {
  boundRepositoryRoot: string | null;
  evaluatedState: CheckwashEvaluatedState;
  enrichedFindings: readonly EnrichedFindingLocation[];
  statusBar: StatusBarViewModel;
  diagnosticsPlan: LiveDiagnosticsPlan;
  treeNodes: CheckwashTreeNode[];
  fastGuardResult: FastGuardAnalysisResult | null;
  contextDietResult: ContextDietResult | null;
  proveOutcome: ProveSessionOutcome;
  offlineFindingsPreview: CheckwashFindingsDocumentV2 | null;
}

export class CheckwashLensController {
  private readonly processRunner: UnifiedProcessRunner;
  private readonly revisionProvider: RevisionProvider;
  private readonly engineRunner: CheckwashEngineRunner;
  private readonly proveRunner: ProveSatelliteRunner;

  private boundRepositoryRoot: string | null = null;
  private repositoryGeneration = 0;
  private monotonicStaticScanToken = 0;
  private activeStaticScanGeneration: number | null = null;
  private activeStaticScanToken: number | null = null;
  private activeScanBaseOpenDocuments: readonly OpenEditorDocumentSnapshot[] | null = null;
  private monotonicProveCommandToken = 0;
  private activeProveGeneration: number | null = null;
  private activeProveCommandToken: number | null = null;
  private latestOpenDocumentsDuringScan: readonly OpenEditorDocumentSnapshot[] | null = null;
  private readonly viewListeners: Array<(snapshot: ControllerViewSnapshot) => void> = [];

  private evaluatedState: CheckwashEvaluatedState = createNotRunState(
    "Not Run: Trigger 'Checkwash Lens: Scan Committed Range' to analyze a commit range."
  );
  private enrichedFindings: EnrichedFindingLocation[] = [];
  private fastGuardResult: FastGuardAnalysisResult | null = null;
  private contextDietResult: ContextDietResult | null = null;
  private proveOutcome: ProveSessionOutcome = {
    status: "Not Run / Cancelled",
    errorReason: null,
    record: null,
  };
  private offlineReadOnlyFindingsPreview: CheckwashFindingsDocumentV2 | null = null;
  private worktreePreCheckBaselineByRelPath: Map<string, string> | null = null;

  constructor(runner?: UnifiedProcessRunner) {
    this.processRunner = runner ?? new UnifiedProcessRunner();
    this.revisionProvider = new RevisionProvider(this.processRunner);
    this.engineRunner = new CheckwashEngineRunner(this.processRunner, this.revisionProvider);
    this.proveRunner = new ProveSatelliteRunner(this.processRunner);

    this.processRunner.onDidChangeState((state) => {
      if (this.processRunner.hasUnconfirmedCleanup()) {
        this.evaluatedState = state;
        this.notifyViewListeners();
        return;
      }
      if (
        this.activeStaticScanToken !== null &&
        this.activeStaticScanGeneration !== null &&
        this.activeStaticScanGeneration === this.repositoryGeneration
      ) {
        this.evaluatedState = state;
        this.notifyViewListeners();
      }
    });

    this.proveRunner.onDidChangeOutcome((outcome) => {
      if (
        this.activeProveCommandToken !== null &&
        this.activeProveGeneration !== null &&
        this.activeProveGeneration === this.repositoryGeneration
      ) {
        this.proveOutcome = outcome;
        this.notifyViewListeners();
      }
    });
  }

  public onDidChangeViewSnapshot(
    listener: (snapshot: ControllerViewSnapshot) => void
  ): () => void {
    this.viewListeners.push(listener);
    return () => {
      const idx = this.viewListeners.indexOf(listener);
      if (idx >= 0) {
        this.viewListeners.splice(idx, 1);
      }
    };
  }

  private notifyViewListeners(): void {
    if (this.viewListeners.length === 0) {
      return;
    }
    const snap = this.getViewSnapshot();
    for (const listener of [...this.viewListeners]) {
      try {
        listener(snap);
      } catch {
        // Ignore listener errors
      }
    }
  }

  public getProcessRunner(): UnifiedProcessRunner {
    return this.processRunner;
  }

  public getProveRunner(): ProveSatelliteRunner {
    return this.proveRunner;
  }

  public getOfflineReadOnlyFindingsPreview(): CheckwashFindingsDocumentV2 | null {
    return this.offlineReadOnlyFindingsPreview;
  }

  /**
   * Binds the active repository for multi-folder workspaces (Rev 3 §1.1).
   * If the bound repository changes, resets all session state so results from one
   * repository never bleed into another. Zero external processes are spawned.
   */
  public selectRepository(repositoryRootPath: string): void {
    const normalized = isFullyQualifiedWindowsPath(repositoryRootPath)
      ? path.win32.resolve(repositoryRootPath)
      : path.resolve(repositoryRootPath);
    if (
      this.boundRepositoryRoot !== null &&
      areSameRepositoryPath(this.boundRepositoryRoot, normalized)
    ) {
      return;
    }
    this.repositoryGeneration++;
    this.monotonicStaticScanToken++;
    this.monotonicProveCommandToken++;
    this.boundRepositoryRoot = normalized;
    this.activeStaticScanGeneration = null;
    this.activeStaticScanToken = null;
    this.activeScanBaseOpenDocuments = null;
    this.activeProveGeneration = null;
    this.activeProveCommandToken = null;
    this.latestOpenDocumentsDuringScan = null;
    this.revisionProvider.clearCache();
    this.engineRunner.clearSession();
    this.proveRunner.clearSessionForRepositorySwitch();

    if (this.processRunner.isOperationActive()) {
      void this.processRunner.cancelActiveRunAndConfirmStop();
    }

    const unconfirmedReason = this.processRunner.getUnconfirmedCleanupReason();
    this.evaluatedState = unconfirmedReason
      ? createErrorState(
          `Process tree cleanup was not confirmed by Job Object broker: ${unconfirmedReason}`
        )
      : createNotRunState(
          `Bound to repository '${normalized}'. Trigger a scan command to analyze committed changes.`
        );
    this.enrichedFindings = [];
    this.fastGuardResult = null;
    this.contextDietResult = null;
    this.offlineReadOnlyFindingsPreview = null;
    this.worktreePreCheckBaselineByRelPath = null;
    this.proveOutcome = {
      status: "Not Run / Cancelled",
      errorReason: null,
      record: null,
    };
    this.notifyViewListeners();
  }

  /**
   * Unbinds the active repository (e.g., when the bound workspace folder is removed from VS Code)
   * and clears all repository-bound state without spawning any external process.
   */
  public clearBoundRepository(
    reason: string = "No repository selected. Select a repository folder and run a scan command."
  ): void {
    this.repositoryGeneration++;
    this.monotonicStaticScanToken++;
    this.monotonicProveCommandToken++;
    this.boundRepositoryRoot = null;
    this.activeStaticScanGeneration = null;
    this.activeStaticScanToken = null;
    this.activeScanBaseOpenDocuments = null;
    this.activeProveGeneration = null;
    this.activeProveCommandToken = null;
    this.latestOpenDocumentsDuringScan = null;
    this.revisionProvider.clearCache();
    this.engineRunner.clearSession();
    this.proveRunner.clearSessionForRepositorySwitch();

    if (this.processRunner.isOperationActive()) {
      void this.processRunner.cancelActiveRunAndConfirmStop();
    }

    const unconfirmedReason = this.processRunner.getUnconfirmedCleanupReason();
    this.evaluatedState = unconfirmedReason
      ? createErrorState(
          `Process tree cleanup was not confirmed by Job Object broker: ${unconfirmedReason}`
        )
      : createNotRunState(reason);
    this.enrichedFindings = [];
    this.fastGuardResult = null;
    this.contextDietResult = null;
    this.offlineReadOnlyFindingsPreview = null;
    this.worktreePreCheckBaselineByRelPath = null;
    this.proveOutcome = {
      status: "Not Run / Cancelled",
      errorReason: null,
      record: null,
    };
    this.notifyViewListeners();
  }

  public getViewSnapshot(): ControllerViewSnapshot {
    const statusBar = buildStatusBarViewModel(this.evaluatedState);
    const diagnosticsPlan = buildLiveDiagnosticsPlan(
      this.enrichedFindings,
      this.fastGuardResult?.hints ?? []
    );
    const treeNodes = buildCheckwashTreeModel({
      evaluatedState: this.evaluatedState,
      enrichedFindings: this.enrichedFindings,
      fastGuardResult: this.fastGuardResult,
      proveOutcome: this.proveOutcome,
      offlineFindingsPreview: this.offlineReadOnlyFindingsPreview,
    });

    return {
      boundRepositoryRoot: this.boundRepositoryRoot,
      evaluatedState: this.evaluatedState,
      enrichedFindings: this.enrichedFindings,
      statusBar,
      diagnosticsPlan,
      treeNodes,
      fastGuardResult: this.fastGuardResult,
      contextDietResult: this.contextDietResult,
      proveOutcome: this.proveOutcome,
      offlineFindingsPreview: this.offlineReadOnlyFindingsPreview,
    };
  }

  /**
   * Executes a committed-range Checkwash static scan + Fast Guard + Context Diet.
   */
  public async scanCommittedRange(
    hostDesc: HostEnvironmentDescriptor,
    rawRangeSpec: string,
    openDocuments: readonly OpenEditorDocumentSnapshot[] = [],
    limits?: RunnerLimits
  ): Promise<ControllerViewSnapshot> {
    if (!hostDesc.repositoryRootPath || hostDesc.repositoryRootPath.trim().length === 0) {
      this.evaluatedState = createNotRunState(
        "No Git repository selected. Select a local repository folder first."
      );
      this.enrichedFindings = [];
      this.fastGuardResult = null;
      this.contextDietResult = null;
      this.notifyViewListeners();
      return this.getViewSnapshot();
    }

    this.selectRepository(hostDesc.repositoryRootPath);

    const genAtStart = this.repositoryGeneration;
    const repoAtStart = this.boundRepositoryRoot;
    const scanToken = ++this.monotonicStaticScanToken;
    this.activeStaticScanGeneration = genAtStart;
    this.activeStaticScanToken = scanToken;
    const initialOpenDocs = [...openDocuments];
    this.activeScanBaseOpenDocuments = initialOpenDocs;
    this.latestOpenDocumentsDuringScan = null;

    const session: CompletedStaticScanSession = await this.engineRunner.executeStaticScan(
      hostDesc,
      rawRangeSpec,
      initialOpenDocs,
      limits
    );

    // If the user switched repositories OR another static scan superseded this one on the same repo,
    // discard stale results without clearing the active scan's tracking or evaluatedState (Round 3 Issue #2)!
    if (
      this.repositoryGeneration !== genAtStart ||
      this.boundRepositoryRoot !== repoAtStart ||
      this.activeStaticScanToken !== scanToken
    ) {
      return this.getViewSnapshot();
    }

    this.activeStaticScanGeneration = null;
    this.activeStaticScanToken = null;
    const hadMidScanDocUpdates = this.latestOpenDocumentsDuringScan !== null;
    const effectiveOpenDocs = reconcileOpenDocumentsAfterScan(
      initialOpenDocs,
      this.latestOpenDocumentsDuringScan
    );
    this.activeScanBaseOpenDocuments = null;
    this.latestOpenDocumentsDuringScan = null;
    this.worktreePreCheckBaselineByRelPath = null;

    this.evaluatedState = session.evaluatedState;
    this.enrichedFindings = hadMidScanDocUpdates
      ? this.engineRunner.refreshLiveEditorBindings(effectiveOpenDocs)
      : session.enrichedFindings;

    if (session.scanIdentity) {
      this.boundRepositoryRoot = session.scanIdentity.repositoryRoot;
    }

    if (session.diffSnapshot && session.scanIdentity) {
      this.fastGuardResult = analyzeCommittedDiffWithFastGuard({
        scanId: session.scanIdentity.scanId,
        diffSnapshot: session.diffSnapshot,
        headBlobsByPath: session.headBlobsByPath,
        openDocuments: effectiveOpenDocs,
      });
      this.contextDietResult = buildContextDietDiff(session.diffSnapshot);
    } else {
      this.fastGuardResult = null;
      this.contextDietResult = null;
    }

    this.notifyViewListeners();
    return this.getViewSnapshot();
  }

  /**
   * Executes a pre-commit uncommitted snapshot Checkwash static scan (`staged` or `worktree`),
   * plus Fast Guard and Context Diet, without mutating `.git/index`, `.git/objects`, or `HEAD`.
   */
  public async scanUncommittedSnapshot(
    hostDesc: HostEnvironmentDescriptor,
    mode: UncommittedSnapshotMode,
    openDocuments: readonly OpenEditorDocumentSnapshot[] = [],
    limits?: RunnerLimits
  ): Promise<ControllerViewSnapshot> {
    const preCheckScope = mode === "staged" ? "staged-precheck" : "worktree-precheck";
    if (!hostDesc.repositoryRootPath || hostDesc.repositoryRootPath.trim().length === 0) {
      this.evaluatedState = withScanScope(
        createNotRunState("No Git repository selected. Select a local repository folder first."),
        preCheckScope
      );
      this.enrichedFindings = [];
      this.fastGuardResult = null;
      this.contextDietResult = null;
      this.notifyViewListeners();
      return this.getViewSnapshot();
    }

    this.selectRepository(hostDesc.repositoryRootPath);

    const genAtStart = this.repositoryGeneration;
    const repoAtStart = this.boundRepositoryRoot;
    const scanToken = ++this.monotonicStaticScanToken;
    this.activeStaticScanGeneration = genAtStart;
    this.activeStaticScanToken = scanToken;
    const initialOpenDocs = [...openDocuments];
    this.activeScanBaseOpenDocuments = initialOpenDocs;
    this.latestOpenDocumentsDuringScan = null;

    const session: CompletedStaticScanSession =
      await this.engineRunner.executeUncommittedSnapshotScan(
        hostDesc,
        mode,
        initialOpenDocs,
        limits
      );

    if (
      this.repositoryGeneration !== genAtStart ||
      this.boundRepositoryRoot !== repoAtStart ||
      this.activeStaticScanToken !== scanToken
    ) {
      return this.getViewSnapshot();
    }

    this.activeStaticScanGeneration = null;
    this.activeStaticScanToken = null;
    const hadMidScanDocUpdates = this.latestOpenDocumentsDuringScan !== null;
    const effectiveOpenDocs = reconcileOpenDocumentsAfterScan(
      initialOpenDocs,
      this.latestOpenDocumentsDuringScan
    );
    this.activeScanBaseOpenDocuments = null;
    this.latestOpenDocumentsDuringScan = null;
    this.worktreePreCheckBaselineByRelPath = null;

    this.evaluatedState = session.evaluatedState;
    this.enrichedFindings = hadMidScanDocUpdates
      ? this.engineRunner.refreshLiveEditorBindings(effectiveOpenDocs)
      : session.enrichedFindings;

    if (session.scanIdentity) {
      this.boundRepositoryRoot = session.scanIdentity.repositoryRoot;
    }

    if (
      mode === "worktree" &&
      this.boundRepositoryRoot &&
      (session.evaluatedState.state === "Pass" ||
        session.evaluatedState.state === "Partial / Review" ||
        session.evaluatedState.state === "Block")
    ) {
      const baseline = new Map<string, string>();
      for (const [relPath, blob] of session.headBlobsByPath.entries()) {
        baseline.set(relPath, blob.normalizedText);
      }
      for (const doc of initialOpenDocs) {
        if (
          !doc.isClosedOrDeleted &&
          areSameRepositoryPath(doc.repositoryRoot, this.boundRepositoryRoot)
        ) {
          baseline.set(doc.relativePath, normalizeSourceForComparison(doc.text));
        }
      }
      this.worktreePreCheckBaselineByRelPath = baseline;
      if (hadMidScanDocUpdates) {
        const divergedMidScan = this.hasWorktreeDivergedFromBaseline(
          effectiveOpenDocs,
          session,
          baseline
        );
        if (divergedMidScan) {
          this.evaluatedState = {
            ...this.evaluatedState,
            lifecycle: {
              ...this.evaluatedState.lifecycle,
              stale: true,
            },
          };
        }
      }
    } else {
      this.worktreePreCheckBaselineByRelPath = null;
    }

    if (session.diffSnapshot && session.scanIdentity) {
      this.fastGuardResult = analyzeCommittedDiffWithFastGuard({
        scanId: session.scanIdentity.scanId,
        diffSnapshot: session.diffSnapshot,
        headBlobsByPath: session.headBlobsByPath,
        openDocuments: effectiveOpenDocs,
      });
      this.contextDietResult = buildContextDietDiff(session.diffSnapshot);
    } else {
      this.fastGuardResult = null;
      this.contextDietResult = null;
    }

    this.notifyViewListeners();
    return this.getViewSnapshot();
  }

  /**
   * Runs the read-only Environment Doctor diagnostic check.
   */
  public async runEnvironmentDoctor(params: {
    hostDesc: HostEnvironmentDescriptor;
    configuredProvePath?: string;
    configuredProveTestPythonPath?: string;
    settingInspections?: readonly WorkspaceSettingOverrideInspection[];
  }): Promise<EnvironmentDoctorReport> {
    return runEnvironmentDoctor({
      processRunner: this.processRunner,
      hostDesc: params.hostDesc,
      configuredProvePath: params.configuredProvePath,
      configuredProveTestPythonPath: params.configuredProveTestPythonPath,
      settingInspections: params.settingInspections,
    });
  }

  /**
   * Releases any ephemeral snapshot overlay directories owned by this controller.
   */
  public dispose(): void {
    this.revisionProvider.clearCache();
    this.engineRunner.clearSession();
  }

  private hasWorktreeDivergedFromBaseline(
    openDocuments: readonly OpenEditorDocumentSnapshot[],
    latestSession: CompletedStaticScanSession,
    baselineByRelPath: ReadonlyMap<string, string>
  ): boolean {
    if (!this.boundRepositoryRoot) {
      return false;
    }
    for (const doc of openDocuments) {
      if (
        doc.isClosedOrDeleted ||
        !areSameRepositoryPath(doc.repositoryRoot, this.boundRepositoryRoot)
      ) {
        continue;
      }
      if (doc.isDirty) {
        return true;
      }
      const normText = normalizeSourceForComparison(doc.text);
      const baseText =
        baselineByRelPath.get(doc.relativePath) ??
        latestSession.headBlobsByPath.get(doc.relativePath)?.normalizedText;
      if (baseText !== undefined && normText !== baseText) {
        return true;
      }
    }
    return false;
  }

  /**
   * Called when open editor buffers change (typing, saving, closing, switching tabs).
   * Spawns ZERO external processes; immediately invalidates live inline diagnostics for dirty
   * or content-mismatched buffers while keeping Checkwash engine verdict and TreeView intact,
   * and marks Working-Tree Pre-Checks as `Stale` when open working-tree files diverge (RT-08).
   */
  public onOpenDocumentsChanged(
    openDocuments: readonly OpenEditorDocumentSnapshot[]
  ): ControllerViewSnapshot {
    if (this.activeStaticScanToken !== null) {
      this.latestOpenDocumentsDuringScan = reconcileOpenDocumentsAfterScan(
        this.latestOpenDocumentsDuringScan ?? this.activeScanBaseOpenDocuments ?? [],
        openDocuments
      );
      this.engineRunner.refreshLiveEditorBindings(openDocuments);
    }

    const latestSession = this.engineRunner.getLatestSession();
    const sessionMatchesBoundRepo =
      Boolean(
        latestSession &&
          latestSession.scanIdentity &&
          this.boundRepositoryRoot &&
          areSameRepositoryPath(latestSession.scanIdentity.repositoryRoot, this.boundRepositoryRoot)
      );

    if (!sessionMatchesBoundRepo) {
      this.enrichedFindings = [];
      this.fastGuardResult = null;
      this.notifyViewListeners();
      return this.getViewSnapshot();
    }

    this.enrichedFindings = this.engineRunner.refreshLiveEditorBindings(openDocuments);
    if (latestSession && latestSession.diffSnapshot && latestSession.scanIdentity) {
      this.fastGuardResult = analyzeCommittedDiffWithFastGuard({
        scanId: latestSession.scanIdentity.scanId,
        diffSnapshot: latestSession.diffSnapshot,
        headBlobsByPath: latestSession.headBlobsByPath,
        openDocuments,
      });
    }

    if (
      latestSession &&
      !this.evaluatedState.lifecycle.analyzing &&
      this.evaluatedState.scanScope === "worktree-precheck" &&
      this.worktreePreCheckBaselineByRelPath !== null &&
      (this.evaluatedState.state === "Pass" ||
        this.evaluatedState.state === "Partial / Review" ||
        this.evaluatedState.state === "Block")
    ) {
      const nextStale = this.hasWorktreeDivergedFromBaseline(
        openDocuments,
        latestSession,
        this.worktreePreCheckBaselineByRelPath
      );
      if (this.evaluatedState.lifecycle.stale !== nextStale) {
        this.evaluatedState = {
          ...this.evaluatedState,
          lifecycle: {
            ...this.evaluatedState.lifecycle,
            stale: nextStale,
          },
        };
      }
    }

    this.notifyViewListeners();
    return this.getViewSnapshot();
  }

  /**
   * Authorizes and prepares the Context Diet diff payload for copying to the clipboard.
   * Enforces the sensitive-data confirmation/redaction gate.
   */
  public prepareContextDietCopy(params: {
    mode: "redacted" | "unredacted";
    userConfirmedUnredactedCopy?: boolean;
  }): ValidationResult<{ payloadToCopy: string; modeUsed: "redacted" | "unredacted" }> {
    if (!this.contextDietResult) {
      return {
        ok: false,
        error: "No Context Diet diff is available. Run 'Scan Committed Range' first.",
      };
    }
    return authorizeClipboardCopy({
      dietResult: this.contextDietResult,
      mode: params.mode,
      userConfirmedUnredactedCopy: params.userConfirmedUnredactedCopy,
    });
  }

  /**
   * Resolves a read-only `checkwash-rev:` URI to its immutable Git commit blob.
   */
  public async resolveImmutableRevisionUri(
    hostDesc: HostEnvironmentDescriptor,
    revisionUriString: string
  ): Promise<ValidationResult<ImmutableBlobRecord>> {
    const parsed = parseRevisionUriString(revisionUriString);
    if (!parsed.ok) {
      return parsed;
    }
    if (!this.boundRepositoryRoot) {
      return {
        ok: false,
        error: "No active repository is currently bound in Checkwash Lens.",
      };
    }
    const target = parsed.value;
    if (!areSameRepositoryPath(target.repositoryRoot, this.boundRepositoryRoot)) {
      return {
        ok: false,
        error: `Revision URI repository ('${target.repositoryRoot}') does not match active repository ('${this.boundRepositoryRoot}')`,
      };
    }
    return this.revisionProvider.readCommitBlob(
      hostDesc,
      target.commitOid,
      target.relativePath
    );
  }

  /**
   * Prepares an immutable Prove execution plan (`list` or `full`) before user confirmation.
   * Binds the selected repository first and records `Execution error` if preflight fails.
   */
  public async prepareProveManualCommandPlan(params: {
    hostDesc: HostEnvironmentDescriptor;
    configuredProvePath: string;
    configuredTestPythonPath?: string;
    rawRangeSpec: string;
    entryKind: "list" | "full";
    options?: Partial<BoundedProveOptions>;
    wallClockBudgetMs?: number;
    abortSignal?: AbortSignal;
  }): Promise<ProvePreflightResult> {
    if (params.hostDesc.repositoryRootPath && params.hostDesc.repositoryRootPath.trim().length > 0) {
      this.selectRepository(params.hostDesc.repositoryRootPath);
    }
    const genAtStart = this.repositoryGeneration;
    const proveToken = ++this.monotonicProveCommandToken;
    this.activeProveGeneration = genAtStart;
    this.activeProveCommandToken = proveToken;

    const res = await this.proveRunner.prepareManualProvePlan(params);
    if (
      this.repositoryGeneration === genAtStart &&
      this.activeProveCommandToken === proveToken
    ) {
      this.activeProveGeneration = null;
      this.activeProveCommandToken = null;
      if (!res.ok) {
        const isCleanCancel =
          Boolean(res.cancelled) && !this.processRunner.hasUnconfirmedCleanup();
        this.proveOutcome = isCleanCancel
          ? {
              status: "Not Run / Cancelled",
              errorReason: null,
              record: null,
            }
          : {
              status: "Execution error",
              errorReason: res.error,
              record: null,
            };
        this.notifyViewListeners();
      }
    }
    return res;
  }

  /**
   * Prepares an immutable single-mutant Replay execution plan before user confirmation.
   * Rejects imported external reports or unknown records with zero processes spawned.
   */
  public async prepareProveReplayCommandPlan(params: {
    hostDesc: HostEnvironmentDescriptor;
    configuredProvePath: string;
    configuredTestPythonPath?: string;
    recordRunId: number;
    selectedMutantId: string;
    wallClockBudgetMs?: number;
    abortSignal?: AbortSignal;
  }): Promise<ProvePreflightResult> {
    if (params.hostDesc.repositoryRootPath && params.hostDesc.repositoryRootPath.trim().length > 0) {
      this.selectRepository(params.hostDesc.repositoryRootPath);
    }
    const genAtStart = this.repositoryGeneration;
    const proveToken = ++this.monotonicProveCommandToken;
    this.activeProveGeneration = genAtStart;
    this.activeProveCommandToken = proveToken;

    const res = await this.proveRunner.prepareReplayProvePlan({
      hostDesc: params.hostDesc,
      configuredProvePath: params.configuredProvePath,
      configuredTestPythonPath: params.configuredTestPythonPath,
      recordOrRunId: params.recordRunId,
      selectedMutantId: params.selectedMutantId,
      wallClockBudgetMs: params.wallClockBudgetMs,
      abortSignal: params.abortSignal,
    });
    if (
      this.repositoryGeneration === genAtStart &&
      this.activeProveCommandToken === proveToken
    ) {
      this.activeProveGeneration = null;
      this.activeProveCommandToken = null;
      if (!res.ok) {
        const isCleanCancel =
          Boolean(res.cancelled) && !this.processRunner.hasUnconfirmedCleanup();
        this.proveOutcome = isCleanCancel
          ? {
              status: "Not Run / Cancelled",
              errorReason: null,
              record: null,
            }
          : {
              status: "Execution error",
              errorReason: res.error,
              record: null,
            };
        this.notifyViewListeners();
      }
    }
    return res;
  }

  /**
   * Executes a previously prepared and user-confirmed Prove plan (`list`, `full`, or `replay`),
   * re-verifying admission and runtime identity against current settings at execution time.
   */
  public async executeAuthorizedProveCommand(params: {
    hostDesc: HostEnvironmentDescriptor;
    configuredProvePath: string;
    configuredTestPythonPath?: string;
    authorization: ProveExecutionAuthorization | undefined | null;
    expectedEntryKind?: ProveEntryKind;
    expectedOptions?: Partial<BoundedProveOptions>;
    expectedWallClockBudgetMs?: number;
    expectedRecordRunId?: number;
    expectedSelectedMutantId?: string;
  }): Promise<ControllerViewSnapshot> {
    if (params.hostDesc.repositoryRootPath && params.hostDesc.repositoryRootPath.trim().length > 0) {
      this.selectRepository(params.hostDesc.repositoryRootPath);
    }
    const genAtStart = this.repositoryGeneration;
    const proveToken = ++this.monotonicProveCommandToken;
    this.activeProveGeneration = genAtStart;
    this.activeProveCommandToken = proveToken;
    const outcome = await this.proveRunner.executeAuthorizedProvePlan(params);
    if (
      this.repositoryGeneration === genAtStart &&
      this.activeProveCommandToken === proveToken
    ) {
      this.activeProveGeneration = null;
      this.activeProveCommandToken = null;
      this.proveOutcome = outcome;
      this.notifyViewListeners();
    }
    return this.getViewSnapshot();
  }

  /**
   * Runs Prove (`list` or `full`) with mandatory per-invocation plan-bound manual authorization.
   * Never alters the Checkwash static `evaluatedState` (unless Job Object cleanup fails).
   */
  public async runProveManualCommand(params: {
    hostDesc: HostEnvironmentDescriptor;
    configuredProvePath: string;
    configuredTestPythonPath?: string;
    rawRangeSpec: string;
    entryKind: "list" | "full";
    options?: Partial<BoundedProveOptions>;
    authorization: ProveExecutionAuthorization | undefined | null;
    wallClockBudgetMs?: number;
  }): Promise<ControllerViewSnapshot> {
    return this.executeAuthorizedProveCommand({
      hostDesc: params.hostDesc,
      configuredProvePath: params.configuredProvePath,
      configuredTestPythonPath: params.configuredTestPythonPath,
      authorization: params.authorization,
      expectedEntryKind: params.entryKind,
      expectedOptions: params.options,
      expectedWallClockBudgetMs: params.wallClockBudgetMs,
    });
  }

  /**
   * Runs a single-mutant Replay from an in-memory session TrustedProveExecutionRecord
   * with mandatory per-invocation plan-bound manual authorization.
   */
  public async runProveReplayCommand(params: {
    hostDesc: HostEnvironmentDescriptor;
    configuredProvePath: string;
    configuredTestPythonPath?: string;
    recordRunId: number;
    selectedMutantId: string;
    authorization: ProveExecutionAuthorization | undefined | null;
    wallClockBudgetMs?: number;
  }): Promise<ControllerViewSnapshot> {
    const record = this.proveRunner.getTrustedRecord(params.recordRunId);
    if (!record) {
      if (params.authorization?.planId) {
        this.proveRunner.invalidatePreparedPlan(params.authorization.planId);
      }
      this.proveOutcome = {
        status: "Execution error",
        errorReason: `No trusted session Prove execution record found for runId #${params.recordRunId} (imported external reports cannot be replayed)`,
        record: null,
      };
      this.notifyViewListeners();
      return this.getViewSnapshot();
    }

    return this.executeAuthorizedProveCommand({
      hostDesc: params.hostDesc,
      configuredProvePath: params.configuredProvePath,
      configuredTestPythonPath: params.configuredTestPythonPath,
      authorization: params.authorization,
      expectedEntryKind: "replay",
      expectedRecordRunId: params.recordRunId,
      expectedSelectedMutantId: params.selectedMutantId,
      expectedWallClockBudgetMs: params.wallClockBudgetMs,
    });
  }

  public clearOfflineReadOnlyPreview(): ControllerViewSnapshot {
    this.offlineReadOnlyFindingsPreview = null;
    if (this.proveOutcome.record?.isImportedExternalReport) {
      this.proveRunner.clearSessionForRepositorySwitch();
      this.proveOutcome = this.proveRunner.getLatestOutcome();
    }
    this.notifyViewListeners();
    return this.getViewSnapshot();
  }

  /**
   * Views an offline Checkwash JSON v2 or Prove v0.1.0 JSON report in strictly read-only mode.
   * Rejects UNC/device paths and symlinks, reads from a single file descriptor with a bounded
   * <= 16 MiB cap (eliminating stat->read TOCTOU, RT-07), spawns zero external processes,
   * and NEVER alters `this.evaluatedState`.
   */
  public viewOfflineReportFileReadOnly(
    filePath: string
  ): ValidationResult<{
    kind: "checkwash-findings-v2" | "checkwash-prove-v0.1.0";
    readOnly: true;
  }> {
    if (!filePath || isDangerousUncOrDevicePath(filePath)) {
      return {
        ok: false,
        error: `Refusing unsafe, UNC, or device offline report path: ${String(filePath)}`,
      };
    }

    let lstat: fs.Stats;
    try {
      lstat = fs.lstatSync(filePath);
    } catch (err) {
      return { ok: false, error: `Cannot access offline report file: ${String(err)}` };
    }
    if (lstat.isSymbolicLink()) {
      return {
        ok: false,
        error: `Refusing symbolic-link offline report path: ${filePath}`,
      };
    }
    if (!lstat.isFile()) {
      return { ok: false, error: `Offline report path is not a regular file: ${filePath}` };
    }
    if (lstat.size > MAX_REPORT_BYTES) {
      return {
        ok: false,
        error: `Offline report size (${lstat.size} bytes) exceeds 16 MiB limit (${MAX_REPORT_BYTES} bytes)`,
      };
    }

    let rawText: string;
    let fd: number | null = null;
    try {
      const noFollowFlag =
        typeof fs.constants.O_NOFOLLOW === "number" ? fs.constants.O_NOFOLLOW : 0;
      fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollowFlag);
      const fdStat = fs.fstatSync(fd);
      if (!fdStat.isFile()) {
        return { ok: false, error: `Opened offline report descriptor is not a regular file: ${filePath}` };
      }
      if (fdStat.size > MAX_REPORT_BYTES) {
        return {
          ok: false,
          error: `Offline report size (${fdStat.size} bytes) exceeds 16 MiB limit (${MAX_REPORT_BYTES} bytes)`,
        };
      }

      const chunks: Buffer[] = [];
      let totalRead = 0;
      const scratch = Buffer.alloc(Math.min(65_536, MAX_REPORT_BYTES + 1));
      while (true) {
        const remainingAllowed = MAX_REPORT_BYTES + 1 - totalRead;
        if (remainingAllowed <= 0) {
          break;
        }
        const n = fs.readSync(
          fd,
          scratch,
          0,
          Math.min(scratch.length, remainingAllowed),
          null
        );
        if (n <= 0) {
          break;
        }
        totalRead += n;
        if (totalRead > MAX_REPORT_BYTES) {
          return {
            ok: false,
            error: `Offline report exceeded 16 MiB limit (${MAX_REPORT_BYTES} bytes) while reading`,
          };
        }
        chunks.push(Buffer.from(scratch.subarray(0, n)));
      }
      rawText = Buffer.concat(chunks, totalRead).toString("utf8");
    } catch (err) {
      return { ok: false, error: `Failed to read offline report file: ${String(err)}` };
    } finally {
      if (fd !== null) {
        try {
          fs.closeSync(fd);
        } catch {
          // ignore close error
        }
      }
    }

    const cwRes = validateFindingsJsonV2(rawText);
    if (cwRes.ok) {
      // Store in read-only preview slot ONLY; never touch this.evaluatedState!
      this.offlineReadOnlyFindingsPreview = cwRes.value;
      this.notifyViewListeners();
      return {
        ok: true,
        value: {
          kind: "checkwash-findings-v2",
          readOnly: true,
        },
      };
    }

    const proveImport = this.proveRunner.importExternalProveReportReadOnly(
      rawText,
      this.boundRepositoryRoot ?? ""
    );
    if (proveImport.ok) {
      this.proveOutcome = proveImport.value;
      this.notifyViewListeners();
      return {
        ok: true,
        value: {
          kind: "checkwash-prove-v0.1.0",
          readOnly: true,
        },
      };
    }

    return {
      ok: false,
      error: `File is neither a valid Checkwash JSON v2 report (${cwRes.error}) nor a valid Prove v0.1.0 report (${proveImport.error})`,
    };
  }
}
