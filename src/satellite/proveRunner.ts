/**
 * satellite/proveRunner.ts
 *
 * Manual Execution Coordinator for checkwash-prove v0.1.0 (Rev 3 §2, §3, §9).
 *
 * Strict Contract Guarantees:
 * 1. Prove NEVER runs automatically. Every invocation (`list`, `full`, `replay`) requires
 *    an explicit, single-use `ProveExecutionAuthorization` token confirmed by the user for
 *    that exact invocation (`--list` still executes clean runs, traced runs, and test collection).
 * 2. All process launches go through `UnifiedProcessRunner.executeGatedProcess` (Windows Job Object
 *    broker, Restricted Mode check, no shell) and participate in `runExclusiveCancelableOperation`
 *    for unified cancellation and mutual exclusion (Issue #3).
 * 3. Each invocation receives its own isolated `TEMP`/`TMP` directory via `VerifiedAdmissionContext`,
 *    which is never deleted by subsequent admission checks (Issue #4).
 * 4. `proveExecutablePath` is canonicalized, verified to be a regular file outside the target
 *    repository, hashed (SHA-256), and probed for pinned version `0.1.0`.
 * 5. Replay (`runSingleMutantReplay`) builds argv exclusively via `buildReplayFromTrustedRecord`
 *    from an in-memory session `TrustedProveExecutionRecord` (`isImportedExternalReport: false`),
 *    ignoring `loss.replay`, `report.python`, and `report.options` in the JSON report.
 * 6. External imported reports (`importExternalProveReportReadOnly`) are strictly read-only
 *    (`isImportedExternalReport: true`) and can NEVER trigger Replay.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import { ValidationResult } from "../core/checkwashSchema";
import {
  classifyProveReport,
  PINNED_PROVE_CATALOGUE_VERSION,
  PINNED_PROVE_GENERATOR_SHA256,
  PINNED_PROVE_VERSION,
  ProveExecutionStatus,
  validateProveReportJson,
} from "../core/proveModel";
import {
  BoundedProveOptions,
  boundedProveOptionsEqual,
  buildProveArgv,
  buildReplayFromTrustedRecord,
  computePreparedProvePlanDigest,
  createFrozenPreparedProvePlan,
  DEFAULT_PROVE_WALL_CLOCK_BUDGET_MS,
  PreparedProveExecutionPlan,
  ProveEntryKind,
  ProveRuntimeIdentity,
  ReplayBuildResult,
  runtimeIdentitiesMatch,
  TrustedProveExecutionRecord,
  validateBoundedProveOptions,
} from "../core/replayBuilder";
import {
  areSameRepositoryPath,
  buildSanitizedProveEnv,
  cleanupIsolatedRunDirectory,
  HostEnvironmentDescriptor,
  isPathInsideOrEqualPlatform,
  verifyBareGitResolutionForProcessLaunch,
  verifyLaunchAdmission,
  verifyLinuxNativeExecutableIdentity,
  verifyWindowsNativeExecutableIdentity,
} from "../runtime/admission";
import { UnifiedProcessRunner } from "../runtime/processRunner";

export const PROVE_EXECUTION_RISK_WARNING =
  "注意：checkwash-prove（包含 --list 候選列出、完整 Prove 與單點 Replay）會在目標儲存庫執行測試收集、Clean Run 與 Traced Run，等同於以目前使用者權限執行專案程式碼。請確認您信任此儲存庫與分支內容。";

export interface ProveExecutionAuthorization {
  readonly tokenId: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly entryKind: ProveEntryKind;
  readonly repositoryRoot: string;
  readonly effectiveBaseOid: string;
  readonly effectiveHeadOid: string;
  readonly recordRunId: number | null;
  readonly selectedMutantId: string | null;
  readonly userConfirmedExecutionRisk: boolean;
}

export interface ProveSessionOutcome {
  status: ProveExecutionStatus;
  errorReason: string | null;
  record: TrustedProveExecutionRecord | null;
  replayPlanUsed?: ReplayBuildResult;
}

export type ProvePreflightResult =
  | { ok: true; value: PreparedProveExecutionPlan }
  | { ok: false; error: string; cancelled?: boolean };

function combineAbortSignals(
  slotSignal: AbortSignal,
  externalSignal?: AbortSignal
): { signal: AbortSignal; dispose: () => void } {
  if (!externalSignal) {
    return { signal: slotSignal, dispose: () => {} };
  }
  const combined = new AbortController();
  const onAbort = () => combined.abort();
  if (slotSignal.aborted || externalSignal.aborted) {
    combined.abort();
    return { signal: combined.signal, dispose: () => {} };
  }
  slotSignal.addEventListener("abort", onAbort, { once: true });
  externalSignal.addEventListener("abort", onAbort, { once: true });
  return {
    signal: combined.signal,
    dispose: () => {
      slotSignal.removeEventListener("abort", onAbort);
      externalSignal.removeEventListener("abort", onAbort);
    },
  };
}

function sha256File(filePath: string): string {
  const bytes = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function sha256String(text: string): string {
  return crypto.createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}

function isPathInsideOrEqualForHost(
  childPath: string,
  parentDirPath: string,
  platform: string
): boolean {
  return isPathInsideOrEqualPlatform(childPath, parentDirPath, platform);
}

function validateWallClockBudgetMs(budgetMs: number): ValidationResult<number> {
  if (
    typeof budgetMs !== "number" ||
    !Number.isFinite(budgetMs) ||
    !Number.isInteger(budgetMs) ||
    budgetMs <= 0 ||
    budgetMs > 2 * 60 * 60 * 1000
  ) {
    return {
      ok: false,
      error: `Invalid Prove wallClockBudgetMs: ${String(budgetMs)} (must be positive integer <= 7200000)`,
    };
  }
  return { ok: true, value: budgetMs };
}

export class ProveSatelliteRunner {
  private monotonicProveRunId = 0;
  private monotonicPreparedPlanSeq = 0;
  private sessionGeneration = 0;
  private latestProveRequestToken = 0;
  private readonly consumedAuthTokens = new Set<string>();
  private readonly preparedPlansById = new Map<string, PreparedProveExecutionPlan>();
  private readonly preparedReplayResultsByPlanId = new Map<string, ReplayBuildResult>();
  private readonly trustedRecordsById = new Map<number, TrustedProveExecutionRecord>();
  private readonly outcomeListeners = new Set<(outcome: ProveSessionOutcome) => void>();
  private latestOutcome: ProveSessionOutcome = {
    status: "Not Run / Cancelled",
    errorReason: null,
    record: null,
  };

  constructor(private readonly processRunner: UnifiedProcessRunner) {}

  private setLatestOutcome(next: ProveSessionOutcome): ProveSessionOutcome {
    this.latestOutcome = next;
    for (const listener of this.outcomeListeners) {
      try {
        listener(this.latestOutcome);
      } catch {
        // Ignore listener error
      }
    }
    return this.latestOutcome;
  }

  private classifyInterruptedProveOutcome(params: {
    abortSignal?: AbortSignal;
    timedOut?: boolean;
    fallbackError: string;
  }): ProveSessionOutcome {
    const unconfirmedReason = this.processRunner.getUnconfirmedCleanupReason();
    if (unconfirmedReason !== null) {
      const timeoutSuffix = params.timedOut ? " (occurred alongside timeout)" : "";
      return {
        status: "Execution error",
        errorReason: `Prove process tree cleanup was not confirmed by Job Object broker: ${unconfirmedReason}${timeoutSuffix}`,
        record: null,
      };
    }
    if (params.timedOut) {
      return {
        status: "Execution error",
        errorReason: params.fallbackError,
        record: null,
      };
    }
    if (params.abortSignal?.aborted) {
      return {
        status: "Not Run / Cancelled",
        errorReason: null,
        record: null,
      };
    }
    return {
      status: "Execution error",
      errorReason: params.fallbackError,
      record: null,
    };
  }

  private classifyFailedPreflightStep(params: {
    abortSignal: AbortSignal;
    fallbackError: string;
  }): { ok: false; error: string; cancelled?: boolean } {
    const unconfirmedReason = this.processRunner.getUnconfirmedCleanupReason();
    if (unconfirmedReason !== null) {
      return {
        ok: false,
        error: `Prove preflight process tree cleanup was not confirmed by Job Object broker: ${unconfirmedReason}`,
        cancelled: false,
      };
    }
    if (params.abortSignal.aborted) {
      return {
        ok: false,
        error: "Prove preflight cancelled by user and confirmed stopped",
        cancelled: true,
      };
    }
    return {
      ok: false,
      error: params.fallbackError,
      cancelled: false,
    };
  }

  public onDidChangeOutcome(listener: (outcome: ProveSessionOutcome) => void): () => void {
    this.outcomeListeners.add(listener);
    return () => {
      this.outcomeListeners.delete(listener);
    };
  }

  public getLatestOutcome(): ProveSessionOutcome {
    return this.latestOutcome;
  }

  public getTrustedRecord(runId: number): TrustedProveExecutionRecord | undefined {
    return this.trustedRecordsById.get(runId);
  }

  public clearSessionForRepositorySwitch(): void {
    this.sessionGeneration++;
    this.latestProveRequestToken++;
    this.preparedPlansById.clear();
    this.preparedReplayResultsByPlanId.clear();
    this.trustedRecordsById.clear();
    this.setLatestOutcome({
      status: "Not Run / Cancelled",
      errorReason: null,
      record: null,
    });
  }

  /**
   * Explicitly discards a prepared plan (e.g., when the user cancels the confirmation dialog).
   */
  public invalidatePreparedPlan(planId: string): void {
    this.preparedPlansById.delete(planId);
    this.preparedReplayResultsByPlanId.delete(planId);
  }

  /**
   * Creates a single-use authorization token strictly bound to an immutable PreparedProveExecutionPlan
   * after the user explicitly confirms the modal dialog displaying that plan's pinned identity & limits.
   */
  public issueManualAuthorizationToken(params: {
    plan: PreparedProveExecutionPlan;
    userConfirmedExecutionRisk: boolean;
  }): ProveExecutionAuthorization {
    const { plan, userConfirmedExecutionRisk } = params;
    return Object.freeze({
      tokenId: `prove-auth-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
      planId: plan.planId,
      planDigest: plan.planDigest,
      entryKind: plan.entryKind,
      repositoryRoot: plan.repositoryRoot,
      effectiveBaseOid: plan.effectiveBaseOid,
      effectiveHeadOid: plan.effectiveHeadOid,
      recordRunId: plan.recordRunId,
      selectedMutantId: plan.selectedMutantId,
      userConfirmedExecutionRisk,
    });
  }

  private verifyAndConsumeBoundPlan(params: {
    auth: ProveExecutionAuthorization | undefined | null;
    expectedKind: ProveEntryKind;
    expectedRepoRoot: string;
    expectedOptions?: Partial<BoundedProveOptions>;
    expectedWallClockBudgetMs?: number;
    expectedRecordRunId?: number;
    expectedSelectedMutantId?: string;
  }): ValidationResult<{
    plan: PreparedProveExecutionPlan;
    replayPlanResult?: ReplayBuildResult;
  }> {
    const {
      auth,
      expectedKind,
      expectedRepoRoot,
      expectedOptions,
      expectedWallClockBudgetMs,
      expectedRecordRunId,
      expectedSelectedMutantId,
    } = params;

    if (!auth) {
      return {
        ok: false,
        error: `Prove '${expectedKind}' blocked: missing explicit manual user authorization`,
      };
    }
    if (auth.userConfirmedExecutionRisk !== true) {
      if (auth.planId) {
        this.invalidatePreparedPlan(auth.planId);
      }
      return {
        ok: false,
        error: `Prove '${expectedKind}' blocked: user did not confirm execution risk warning`,
      };
    }
    if (!auth.tokenId || typeof auth.tokenId !== "string") {
      return {
        ok: false,
        error: `Prove '${expectedKind}' blocked: invalid authorization tokenId`,
      };
    }
    if (this.consumedAuthTokens.has(auth.tokenId)) {
      return {
        ok: false,
        error: `Prove '${expectedKind}' blocked: authorization token '${auth.tokenId}' was already consumed (each Prove run requires fresh confirmation)`,
      };
    }
    // Consume the token immediately before inspecting or spawning anything
    this.consumedAuthTokens.add(auth.tokenId);

    if (!auth.planId || typeof auth.planId !== "string" || !auth.planDigest) {
      return {
        ok: false,
        error: `Prove '${expectedKind}' blocked: authorization token is not bound to a prepared execution plan`,
      };
    }

    const storedPlan = this.preparedPlansById.get(auth.planId);
    const storedReplayResult = this.preparedReplayResultsByPlanId.get(auth.planId);
    // Single-use plan: remove immediately on first execution attempt so it can never be reused
    this.preparedPlansById.delete(auth.planId);
    this.preparedReplayResultsByPlanId.delete(auth.planId);

    if (!storedPlan) {
      return {
        ok: false,
        error: `Prove '${expectedKind}' blocked: prepared execution plan '${auth.planId}' was invalidated, cancelled, or already consumed`,
      };
    }

    const recomputedDigest = computePreparedProvePlanDigest(storedPlan);
    if (recomputedDigest !== storedPlan.planDigest || auth.planDigest !== storedPlan.planDigest) {
      return {
        ok: false,
        error: `Prove '${expectedKind}' blocked: prepared execution plan digest mismatch (plan was tampered with)`,
      };
    }

    if (auth.entryKind !== expectedKind || storedPlan.entryKind !== expectedKind) {
      return {
        ok: false,
        error: `Prove authorization kind mismatch: plan/token authorized '${storedPlan.entryKind}', but '${expectedKind}' was requested`,
      };
    }

    if (
      !areSameRepositoryPath(auth.repositoryRoot, expectedRepoRoot) ||
      !areSameRepositoryPath(storedPlan.repositoryRoot, expectedRepoRoot)
    ) {
      return {
        ok: false,
        error: "Prove authorization repository mismatch: active repository differs from confirmed execution plan",
      };
    }

    if (
      expectedWallClockBudgetMs !== undefined &&
      expectedWallClockBudgetMs !== storedPlan.wallClockBudgetMs
    ) {
      return {
        ok: false,
        error: `Prove execution plan invalidated: wallClockBudgetMs (${expectedWallClockBudgetMs}) differs from confirmed plan (${storedPlan.wallClockBudgetMs})`,
      };
    }

    if (expectedOptions !== undefined) {
      const candidateOptsRes = validateBoundedProveOptions({
        ...expectedOptions,
        listOnly:
          expectedKind === "list"
            ? true
            : expectedKind === "replay"
              ? false
              : (expectedOptions.listOnly ?? false),
        keep: false,
        onlyMutantId:
          expectedKind === "replay"
            ? storedPlan.selectedMutantId
            : null,
      });
      if (
        !candidateOptsRes.ok ||
        !boundedProveOptionsEqual(candidateOptsRes.value, storedPlan.effectiveOptions)
      ) {
        return {
          ok: false,
          error: "Prove execution plan invalidated: options or resource limits changed after user confirmation",
        };
      }
    }

    if (
      expectedRecordRunId !== undefined &&
      expectedRecordRunId !== storedPlan.recordRunId
    ) {
      return {
        ok: false,
        error: `Prove authorization record mismatch: plan bound to record #${String(storedPlan.recordRunId)}, got #${expectedRecordRunId}`,
      };
    }

    if (
      expectedSelectedMutantId !== undefined &&
      expectedSelectedMutantId !== storedPlan.selectedMutantId
    ) {
      return {
        ok: false,
        error: `Prove authorization mutant mismatch: plan bound to '${String(storedPlan.selectedMutantId)}', got '${expectedSelectedMutantId}'`,
      };
    }

    return {
      ok: true,
      value: {
        plan: storedPlan,
        replayPlanResult: storedReplayResult,
      },
    };
  }

  /**
   * Probes and verifies the user-supplied checkwash-prove executable and Python runtime.
   */
  public async verifyProveRuntimeIdentity(
    hostDesc: HostEnvironmentDescriptor,
    configuredProvePath: string,
    configuredTestPythonPath?: string,
    abortSignal?: AbortSignal
  ): Promise<ValidationResult<ProveRuntimeIdentity>> {
    const admRes = verifyLaunchAdmission(hostDesc);
    if (!admRes.ok) {
      return admRes;
    }
    const adm = admRes.value;
    cleanupIsolatedRunDirectory(adm.isolatedTempDir, true);

    if (typeof configuredProvePath !== "string" || configuredProvePath.trim().length === 0) {
      return { ok: false, error: "Prove executable path is not configured" };
    }
    if (/[\0\r\n]/.test(configuredProvePath)) {
      return { ok: false, error: "Prove executable path contains control characters" };
    }

    let canonicalProvePath: string;
    try {
      canonicalProvePath = fs.realpathSync.native(configuredProvePath.trim());
      const proveStat = fs.statSync(canonicalProvePath);
      if (!proveStat.isFile()) {
        return { ok: false, error: `Prove executable path is not a regular file: ${canonicalProvePath}` };
      }
      if (hostDesc.platform !== "win32" && (proveStat.mode & 0o111) === 0) {
        return { ok: false, error: `Prove executable is not marked executable (+x): ${canonicalProvePath}` };
      }
    } catch {
      return { ok: false, error: `Prove executable not found: ${configuredProvePath}` };
    }

    if (isPathInsideOrEqualForHost(canonicalProvePath, adm.canonicalRepositoryRoot, hostDesc.platform)) {
      return {
        ok: false,
        error: `Refusing to execute checkwash-prove binary inside target repository ('${canonicalProvePath}')`,
      };
    }
    if (hostDesc.platform === "linux") {
      const proveNativeCheck = verifyLinuxNativeExecutableIdentity(
        canonicalProvePath,
        "checkwash-prove executable"
      );
      if (!proveNativeCheck.ok) {
        return proveNativeCheck;
      }
    } else if (hostDesc.platform === "win32") {
      const proveWinCheck = verifyWindowsNativeExecutableIdentity(
        canonicalProvePath,
        "checkwash-prove executable"
      );
      if (!proveWinCheck.ok) {
        return proveWinCheck;
      }
    }

    let canonicalTestPythonPath = adm.canonicalPythonPath;
    if (configuredTestPythonPath && configuredTestPythonPath.trim().length > 0) {
      try {
        canonicalTestPythonPath = fs.realpathSync.native(configuredTestPythonPath.trim());
        const testPyStat = fs.statSync(canonicalTestPythonPath);
        if (!testPyStat.isFile()) {
          return { ok: false, error: `Test Python path is not a regular file: ${canonicalTestPythonPath}` };
        }
        if (hostDesc.platform !== "win32" && (testPyStat.mode & 0o111) === 0) {
          return { ok: false, error: `Test Python file is not marked executable (+x): ${canonicalTestPythonPath}` };
        }
      } catch {
        return { ok: false, error: `Test Python executable not found: ${configuredTestPythonPath}` };
      }
      if (isPathInsideOrEqualForHost(canonicalTestPythonPath, adm.canonicalRepositoryRoot, hostDesc.platform)) {
        return {
          ok: false,
          error: `Refusing to use test Python interpreter inside target repository ('${canonicalTestPythonPath}')`,
        };
      }
      if (hostDesc.platform === "linux") {
        const testPyNativeCheck = verifyLinuxNativeExecutableIdentity(
          canonicalTestPythonPath,
          "Prove test Python interpreter"
        );
        if (!testPyNativeCheck.ok) {
          return testPyNativeCheck;
        }
      } else if (hostDesc.platform === "win32") {
        const testPyWinCheck = verifyWindowsNativeExecutableIdentity(
          canonicalTestPythonPath,
          "Prove test Python interpreter"
        );
        if (!testPyWinCheck.ok) {
          return testPyWinCheck;
        }
      }
    }

    const proveSha256 = sha256File(canonicalProvePath);
    const testPythonSha256 = sha256File(canonicalTestPythonPath);

    // Pre-verify bare 'git' canonical identity against the exact Prove launch environment and
    // calling executable chain BEFORE spawning any probe or Prove subprocess.
    const preflightProveEnv = buildSanitizedProveEnv({
      baseStaticEnv: adm.sanitizedStaticEnv,
      canonicalGitDir: adm.canonicalGitDir,
      proveExecutable: canonicalProvePath,
      hostPythonExecutable: adm.canonicalPythonPath,
      testPythonExecutable: canonicalTestPythonPath,
      platform: hostDesc.platform,
    });
    const proveGitCheck = verifyBareGitResolutionForProcessLaunch({
      callingExecutables: [canonicalProvePath, adm.canonicalPythonPath, canonicalTestPythonPath],
      canonicalGitPath: adm.canonicalGitPath,
      cwd: adm.controlledEmptyCwd,
      env: preflightProveEnv,
      platform: hostDesc.platform,
    });
    if (!proveGitCheck.ok) {
      return proveGitCheck;
    }

    // Probe host & test Python versions via common runner
    const rtProbe = await this.processRunner.probeTrustedRuntimeVersions(hostDesc, abortSignal);
    if (!rtProbe.ok) {
      return rtProbe;
    }

    let testPythonVersion = rtProbe.value.pythonVersion;
    if (canonicalTestPythonPath !== adm.canonicalPythonPath) {
      const testPyProbe = await this.processRunner.executeGatedProcess({
        hostDesc,
        executableSelector: () => canonicalTestPythonPath,
        argsBuilder: () => [
          "-I",
          "-S",
          "-B",
          "-X",
          "utf8",
          "-c",
          "import platform; print(platform.python_version())",
        ],
        timeoutMs: 10_000,
        abortSignal,
      });
      if (!testPyProbe.ok) {
        return testPyProbe;
      }
      if (!testPyProbe.value.outcome.cleanupConfirmed) {
        return {
          ok: false,
          error: `Prove test Python probe process tree cleanup was not confirmed (${this.processRunner.getUnconfirmedCleanupReason() ?? "unconfirmed"})`,
        };
      }
      if (testPyProbe.value.outcome.status === "cancelled") {
        return { ok: false, error: "Prove test Python probe cancelled by user" };
      }
      if (
        testPyProbe.value.outcome.status !== "completed" ||
        testPyProbe.value.outcome.exitCode !== 0 ||
        !testPyProbe.value.outcome.stdoutUtf8Valid
      ) {
        return { ok: false, error: "Failed to probe configured test Python version" };
      }
      testPythonVersion = testPyProbe.value.outcome.stdoutText.trim();
    }

    // Probe checkwash-prove --version via common runner (strictly version probe; zero project tests run)
    const versionProc = await this.processRunner.executeGatedProcess({
      hostDesc,
      executableSelector: () => canonicalProvePath,
      additionalBareGitCallers: () => [adm.canonicalPythonPath, canonicalTestPythonPath],
      argsBuilder: () => ["--version"],
      envSelector: (ctx) =>
        buildSanitizedProveEnv({
          baseStaticEnv: ctx.sanitizedStaticEnv,
          canonicalGitDir: ctx.canonicalGitDir,
          proveExecutable: canonicalProvePath,
          hostPythonExecutable: adm.canonicalPythonPath,
          testPythonExecutable: canonicalTestPythonPath,
          platform: hostDesc.platform,
        }),
      timeoutMs: 10_000,
      abortSignal,
    });
    if (!versionProc.ok) {
      return versionProc;
    }
    const vOut = versionProc.value.outcome;
    if (!vOut.cleanupConfirmed) {
      return {
        ok: false,
        error: `Prove version probe process tree cleanup was not confirmed (${this.processRunner.getUnconfirmedCleanupReason() ?? "unconfirmed"})`,
      };
    }
    if (vOut.status === "cancelled") {
      return { ok: false, error: "Prove version probe cancelled by user" };
    }
    if (vOut.status !== "completed" || vOut.exitCode !== 0 || !vOut.stdoutUtf8Valid) {
      return {
        ok: false,
        error: `checkwash-prove --version failed (status=${vOut.status}, exit=${String(vOut.exitCode)}): ${vOut.stderrText.trim()}`,
      };
    }

    const versionLine = vOut.stdoutText.trim();
    // Accept "checkwash-prove 0.1.0" or "0.1.0"
    const versionMatch = /(?:^|\s)(\d+\.\d+\.\d+)$/.exec(versionLine);
    const detectedProveVersion = versionMatch ? versionMatch[1] : versionLine;
    if (detectedProveVersion !== PINNED_PROVE_VERSION) {
      return {
        ok: false,
        error: `Unsupported checkwash-prove binary version '${versionLine}' (expected '${PINNED_PROVE_VERSION}')`,
      };
    }

    const hostPythonSha256 = sha256File(adm.canonicalPythonPath);
    const hostGitSha256 = sha256File(adm.canonicalGitPath);

    return {
      ok: true,
      value: {
        proveExecutable: canonicalProvePath,
        proveExecutableSha256: proveSha256,
        proveVersion: PINNED_PROVE_VERSION,
        hostPythonExecutable: adm.canonicalPythonPath,
        hostPythonVersion: rtProbe.value.pythonVersion,
        hostPythonSha256,
        hostGitExecutable: adm.canonicalGitPath,
        hostGitVersion: rtProbe.value.gitVersion,
        hostGitSha256,
        testPythonExecutable: canonicalTestPythonPath,
        testPythonVersion,
        testPythonSha256,
        catalogueVersion: PINNED_PROVE_CATALOGUE_VERSION,
        catalogueGeneratorSha256: PINNED_PROVE_GENERATOR_SHA256,
      },
    };
  }

  /**
   * Step 1 of 3 (Prepare Plan — List / Full):
   * Verifies Workspace Trust, runtime admission, runtime binary identities/hashes, and resolves
   * `rawRangeSpec` into pinned 40/64-char `effectiveBaseOid` and `effectiveHeadOid` WITHOUT
   * executing any project tests or project code (Review P1 #3).
   */
  public async prepareManualProvePlan(params: {
    hostDesc: HostEnvironmentDescriptor;
    configuredProvePath: string;
    configuredTestPythonPath?: string;
    rawRangeSpec: string;
    entryKind: "list" | "full";
    options?: Partial<BoundedProveOptions>;
    wallClockBudgetMs?: number;
    abortSignal?: AbortSignal;
  }): Promise<ProvePreflightResult> {
    const {
      hostDesc,
      configuredProvePath,
      configuredTestPythonPath,
      rawRangeSpec,
      entryKind,
      options = {},
      wallClockBudgetMs = DEFAULT_PROVE_WALL_CLOCK_BUDGET_MS,
      abortSignal,
    } = params;

    if (this.processRunner.hasUnconfirmedCleanup()) {
      return {
        ok: false,
        error: `Prove preflight blocked: previous run cleanup was not confirmed (${this.processRunner.getUnconfirmedCleanupReason()})`,
      };
    }
    const brokerDisabled = this.processRunner.isExecutionDisabledByBrokerFailure();
    if (brokerDisabled.disabled) {
      return {
        ok: false,
        error: `Prove preflight blocked: ${brokerDisabled.reason ?? "broker capability disabled"}`,
      };
    }

    const budgetRes = validateWallClockBudgetMs(wallClockBudgetMs);
    if (!budgetRes.ok) {
      return budgetRes;
    }

    const admRes = verifyLaunchAdmission(hostDesc);
    if (!admRes.ok) {
      return admRes;
    }
    cleanupIsolatedRunDirectory(admRes.value.isolatedTempDir, true);

    const optsRes = validateBoundedProveOptions({
      ...options,
      listOnly: entryKind === "list",
      keep: false,
      onlyMutantId: null,
    });
    if (!optsRes.ok) {
      return optsRes;
    }
    const effectiveOptions = optsRes.value;

    const sessionGenAtStart = this.sessionGeneration;
    const requestTokenAtStart = ++this.latestProveRequestToken;

    return this.processRunner.runExclusiveCancelableOperation(async (slotSignal) => {
      const combined = combineAbortSignals(slotSignal, abortSignal);
      try {
        if (
          this.sessionGeneration !== sessionGenAtStart ||
          this.latestProveRequestToken !== requestTokenAtStart
        ) {
          return {
            ok: false,
            error: "Prove preflight superseded by repository switch or newer request",
            cancelled: true,
          };
        }
        if (this.processRunner.hasUnconfirmedCleanup() || combined.signal.aborted) {
          return this.classifyFailedPreflightStep({
            abortSignal: combined.signal,
            fallbackError: "Prove preflight cancelled",
          });
        }

        const rtRes = await this.verifyProveRuntimeIdentity(
          hostDesc,
          configuredProvePath,
          configuredTestPythonPath,
          combined.signal
        );
        if (!rtRes.ok) {
          return this.classifyFailedPreflightStep({
            abortSignal: combined.signal,
            fallbackError: rtRes.error,
          });
        }
        const runtimeIdentity = rtRes.value;

        const rangeRes = await this.processRunner.resolveAndPinCommittedRange(
          hostDesc,
          rawRangeSpec,
          combined.signal
        );
        if (!rangeRes.ok) {
          return this.classifyFailedPreflightStep({
            abortSignal: combined.signal,
            fallbackError: rangeRes.error,
          });
        }
        cleanupIsolatedRunDirectory(rangeRes.value.admission.isolatedTempDir, true);
        const pinnedRange = rangeRes.value;

        if (this.processRunner.hasUnconfirmedCleanup() || combined.signal.aborted) {
          return this.classifyFailedPreflightStep({
            abortSignal: combined.signal,
            fallbackError: "Prove preflight cancelled",
          });
        }
        if (
          this.sessionGeneration !== sessionGenAtStart ||
          this.latestProveRequestToken !== requestTokenAtStart
        ) {
          return {
            ok: false,
            error: "Prove preflight superseded by repository switch or newer request",
            cancelled: true,
          };
        }

        const argvRes = buildProveArgv({
          effectiveBaseOid: pinnedRange.effectiveBaseOid,
          effectiveHeadOid: pinnedRange.effectiveHeadOid,
          repositoryRoot: pinnedRange.admission.canonicalRepositoryRoot,
          testPythonExecutable: runtimeIdentity.testPythonExecutable,
          options: effectiveOptions,
        });
        if (!argvRes.ok) {
          return argvRes;
        }

        const planId = `prove-plan-${++this.monotonicPreparedPlanSeq}-${crypto.randomBytes(6).toString("hex")}`;
        const frozenPlan = createFrozenPreparedProvePlan({
          planId,
          entryKind,
          repositoryRoot: pinnedRange.admission.canonicalRepositoryRoot,
          rawRangeSpec: pinnedRange.rawRangeSpec,
          effectiveBaseOid: pinnedRange.effectiveBaseOid,
          effectiveHeadOid: pinnedRange.effectiveHeadOid,
          fromMergeBase: pinnedRange.rangeMode === "three-dot",
          recordRunId: null,
          selectedMutantId: null,
          runtimeIdentity,
          effectiveOptions,
          argv: argvRes.value,
          wallClockBudgetMs: budgetRes.value,
        });

        this.preparedPlansById.set(planId, frozenPlan);
        return { ok: true, value: frozenPlan };
      } finally {
        combined.dispose();
      }
    });
  }

  /**
   * Step 1 of 3 (Prepare Plan — Single-Mutant Replay):
   * Verifies Workspace Trust, trusted non-imported session record ownership, runtime binary
   * identities/hashes, and builds the immutable Replay plan WITHOUT executing project tests (Review P1 #3).
   */
  public async prepareReplayProvePlan(params: {
    hostDesc: HostEnvironmentDescriptor;
    configuredProvePath: string;
    configuredTestPythonPath?: string;
    recordOrRunId: TrustedProveExecutionRecord | number;
    selectedMutantId: string;
    wallClockBudgetMs?: number;
    abortSignal?: AbortSignal;
  }): Promise<ProvePreflightResult> {
    const {
      hostDesc,
      configuredProvePath,
      configuredTestPythonPath,
      recordOrRunId,
      selectedMutantId,
      wallClockBudgetMs = DEFAULT_PROVE_WALL_CLOCK_BUDGET_MS,
      abortSignal,
    } = params;

    if (this.processRunner.hasUnconfirmedCleanup()) {
      return {
        ok: false,
        error: `Prove replay preflight blocked: previous run cleanup was not confirmed (${this.processRunner.getUnconfirmedCleanupReason()})`,
      };
    }
    const brokerDisabled = this.processRunner.isExecutionDisabledByBrokerFailure();
    if (brokerDisabled.disabled) {
      return {
        ok: false,
        error: `Prove replay preflight blocked: ${brokerDisabled.reason ?? "broker capability disabled"}`,
      };
    }

    const budgetRes = validateWallClockBudgetMs(wallClockBudgetMs);
    if (!budgetRes.ok) {
      return budgetRes;
    }

    // Fail closed BEFORE spawning any process if Workspace Trust is false or admission fails
    const admRes = verifyLaunchAdmission(hostDesc);
    if (!admRes.ok) {
      return admRes;
    }
    cleanupIsolatedRunDirectory(admRes.value.isolatedTempDir, true);

    // Fail closed BEFORE spawning any process if record is imported external or not in trustedRecordsById
    let trustedRecord: TrustedProveExecutionRecord | undefined;
    if (typeof recordOrRunId === "number") {
      trustedRecord = this.trustedRecordsById.get(recordOrRunId);
      if (!trustedRecord) {
        return {
          ok: false,
          error: `No trusted session Prove execution record found for runId #${recordOrRunId} (imported external reports are strictly read-only and cannot trigger Replay)`,
        };
      }
    } else {
      if (recordOrRunId.isImportedExternalReport) {
        return {
          ok: false,
          error: "Imported external Prove reports are strictly read-only and cannot trigger Replay execution",
        };
      }
      const registered = this.trustedRecordsById.get(recordOrRunId.runId);
      if (!registered || registered !== recordOrRunId) {
        return {
          ok: false,
          error: `Execution record #${recordOrRunId.runId} is not a registered trusted session record and cannot trigger Replay`,
        };
      }
      trustedRecord = registered;
    }

    if (!areSameRepositoryPath(trustedRecord.repositoryRoot, admRes.value.canonicalRepositoryRoot)) {
      return {
        ok: false,
        error: "Active repository root does not match the execution record's repository root",
      };
    }

    const sessionGenAtStart = this.sessionGeneration;
    const requestTokenAtStart = ++this.latestProveRequestToken;

    return this.processRunner.runExclusiveCancelableOperation(async (slotSignal) => {
      const combined = combineAbortSignals(slotSignal, abortSignal);
      try {
        if (
          this.sessionGeneration !== sessionGenAtStart ||
          this.latestProveRequestToken !== requestTokenAtStart
        ) {
          return {
            ok: false,
            error: "Prove replay preflight superseded by repository switch or newer request",
            cancelled: true,
          };
        }
        if (this.processRunner.hasUnconfirmedCleanup() || combined.signal.aborted) {
          return this.classifyFailedPreflightStep({
            abortSignal: combined.signal,
            fallbackError: "Prove replay preflight cancelled",
          });
        }

        const rtRes = await this.verifyProveRuntimeIdentity(
          hostDesc,
          configuredProvePath,
          configuredTestPythonPath,
          combined.signal
        );
        if (!rtRes.ok) {
          return this.classifyFailedPreflightStep({
            abortSignal: combined.signal,
            fallbackError: rtRes.error,
          });
        }
        const currentRuntimeIdentity = rtRes.value;

        if (this.processRunner.hasUnconfirmedCleanup() || combined.signal.aborted) {
          return this.classifyFailedPreflightStep({
            abortSignal: combined.signal,
            fallbackError: "Prove replay preflight cancelled",
          });
        }
        if (
          this.sessionGeneration !== sessionGenAtStart ||
          this.latestProveRequestToken !== requestTokenAtStart
        ) {
          return {
            ok: false,
            error: "Prove replay preflight superseded by repository switch or newer request",
            cancelled: true,
          };
        }

        const replayBuildRes = buildReplayFromTrustedRecord({
          record: trustedRecord!,
          currentRepositoryRoot: admRes.value.canonicalRepositoryRoot,
          currentRuntimeIdentity,
          selectedMutantId,
        });
        if (!replayBuildRes.ok) {
          return replayBuildRes;
        }
        const replayPlan = replayBuildRes.value;

        const planId = `prove-plan-${++this.monotonicPreparedPlanSeq}-${crypto.randomBytes(6).toString("hex")}`;
        const frozenPlan = createFrozenPreparedProvePlan({
          planId,
          entryKind: "replay",
          repositoryRoot: trustedRecord!.repositoryRoot,
          rawRangeSpec: trustedRecord!.rawRangeSpec,
          effectiveBaseOid: trustedRecord!.effectiveBaseOid,
          effectiveHeadOid: trustedRecord!.effectiveHeadOid,
          fromMergeBase: trustedRecord!.fromMergeBase,
          recordRunId: trustedRecord!.runId,
          selectedMutantId,
          runtimeIdentity: currentRuntimeIdentity,
          effectiveOptions: replayPlan.effectiveOptions,
          argv: replayPlan.argv,
          wallClockBudgetMs: budgetRes.value,
        });

        this.preparedPlansById.set(planId, frozenPlan);
        this.preparedReplayResultsByPlanId.set(planId, {
          ...replayPlan,
          confirmationSummary: {
            ...replayPlan.confirmationSummary,
            wallClockBudgetMs: budgetRes.value,
          },
        });
        return { ok: true, value: frozenPlan };
      } finally {
        combined.dispose();
      }
    });
  }

  /**
   * Step 3 of 3 (Execute Bound Plan — List / Full / Replay):
   * Consumes the single-use plan-bound authorization token and single-use prepared plan,
   * re-verifies Workspace Trust, admission, and runtime binary identities/hashes at execution time
   * (invalidating & refusing execution if anything changed since confirmation), and launches
   * Prove using the already-pinned `effectiveBaseOid..effectiveHeadOid` and `argv` (Review P1 #3).
   */
  public async executeAuthorizedProvePlan(params: {
    hostDesc: HostEnvironmentDescriptor;
    configuredProvePath: string;
    configuredTestPythonPath?: string;
    authorization: ProveExecutionAuthorization | undefined | null;
    expectedEntryKind?: ProveEntryKind;
    expectedOptions?: Partial<BoundedProveOptions>;
    expectedWallClockBudgetMs?: number;
    expectedRecordRunId?: number;
    expectedSelectedMutantId?: string;
  }): Promise<ProveSessionOutcome> {
    const {
      hostDesc,
      configuredProvePath,
      configuredTestPythonPath,
      authorization,
      expectedEntryKind,
      expectedOptions,
      expectedWallClockBudgetMs,
      expectedRecordRunId,
      expectedSelectedMutantId,
    } = params;

    const sessionGenAtStart = this.sessionGeneration;
    const requestTokenAtStart = ++this.latestProveRequestToken;
    const publishIfCurrentSession = (outcome: ProveSessionOutcome): ProveSessionOutcome => {
      if (
        this.sessionGeneration !== sessionGenAtStart ||
        this.latestProveRequestToken !== requestTokenAtStart
      ) {
        return this.latestOutcome;
      }
      return this.setLatestOutcome(outcome);
    };

    const effectiveExpectedKind: ProveEntryKind =
      expectedEntryKind ?? authorization?.entryKind ?? "full";

    // 1. Verify & consume single-use plan-bound authorization BEFORE queuing or spawning anything
    const boundRes = this.verifyAndConsumeBoundPlan({
      auth: authorization,
      expectedKind: effectiveExpectedKind,
      expectedRepoRoot: hostDesc.repositoryRootPath,
      expectedOptions,
      expectedWallClockBudgetMs,
      expectedRecordRunId,
      expectedSelectedMutantId,
    });
    if (!boundRes.ok) {
      return publishIfCurrentSession({
        status: "Execution error",
        errorReason: boundRes.error,
        record: null,
      });
    }

    const { plan, replayPlanResult } = boundRes.value;

    return this.processRunner.runExclusiveCancelableOperation(async (abortSignal) => {
      if (
        this.sessionGeneration !== sessionGenAtStart ||
        this.latestProveRequestToken !== requestTokenAtStart
      ) {
        return this.latestOutcome;
      }
      publishIfCurrentSession({
        status: "Running",
        errorReason: null,
        record: null,
      });

      // 2. Re-verify launch admission at execution time (Workspace Trust, platform, bundled hashes)
      const admAtExec = verifyLaunchAdmission(hostDesc);
      if (!admAtExec.ok) {
        return publishIfCurrentSession({
          status: "Execution error",
          errorReason: `Prove execution plan invalidated: ${admAtExec.error}`,
          record: null,
        });
      }
      cleanupIsolatedRunDirectory(admAtExec.value.isolatedTempDir, true);

      if (!areSameRepositoryPath(admAtExec.value.canonicalRepositoryRoot, plan.repositoryRoot)) {
        return publishIfCurrentSession({
          status: "Execution error",
          errorReason:
            "Prove execution plan invalidated: canonical repository root changed after user confirmation",
          record: null,
        });
      }

      // 3. Re-verify runtime identity at execution time; if any executable path/version/SHA-256 changed,
      //    invalidate and refuse to launch Prove!
      const rtAtExec = await this.verifyProveRuntimeIdentity(
        hostDesc,
        configuredProvePath,
        configuredTestPythonPath,
        abortSignal
      );
      if (!rtAtExec.ok) {
        return publishIfCurrentSession(
          this.classifyInterruptedProveOutcome({
            abortSignal,
            fallbackError: `Prove execution plan invalidated during runtime re-verification: ${rtAtExec.error}`,
          })
        );
      }

      const rtMatch = runtimeIdentitiesMatch(plan.runtimeIdentity, rtAtExec.value);
      if (!rtMatch.ok) {
        return publishIfCurrentSession({
          status: "Execution error",
          errorReason: `Prove execution plan invalidated: ${rtMatch.error}`,
          record: null,
        });
      }

      // 4. Execute using the exact pinned OIDs, argv, and limits from the confirmed immutable plan,
      //    keeping canonicalGitDir first in PATH and re-verifying bare 'git' across all callers.
      const execRes = await this.processRunner.executeGatedProcess({
        hostDesc,
        executableSelector: () => plan.runtimeIdentity.proveExecutable,
        additionalBareGitCallers: () => [
          plan.runtimeIdentity.hostPythonExecutable,
          plan.runtimeIdentity.testPythonExecutable,
        ],
        argsBuilder: () => [...plan.argv],
        envSelector: (ctx) =>
          buildSanitizedProveEnv({
            baseStaticEnv: ctx.sanitizedStaticEnv,
            canonicalGitDir: ctx.canonicalGitDir,
            proveExecutable: plan.runtimeIdentity.proveExecutable,
            hostPythonExecutable: plan.runtimeIdentity.hostPythonExecutable,
            testPythonExecutable: plan.runtimeIdentity.testPythonExecutable,
            platform: hostDesc.platform,
          }),
        timeoutMs: plan.wallClockBudgetMs,
        abortSignal,
      });

      if (!execRes.ok) {
        return publishIfCurrentSession(
          this.classifyInterruptedProveOutcome({
            abortSignal,
            fallbackError: execRes.error,
          })
        );
      }

      const finalized = this.finalizeProveProcessOutcome({
        sessionGenAtStart,
        requestTokenAtStart,
        entryKind: plan.entryKind,
        repositoryRoot: plan.repositoryRoot,
        rawRangeSpec: plan.rawRangeSpec,
        effectiveBaseOid: plan.effectiveBaseOid,
        effectiveHeadOid: plan.effectiveHeadOid,
        fromMergeBase: plan.fromMergeBase,
        runtimeIdentity: plan.runtimeIdentity,
        argv: [...plan.argv],
        effectiveOptions: { ...plan.effectiveOptions },
        brokerOutcome: execRes.value.outcome,
      });

      if (
        this.sessionGeneration !== sessionGenAtStart ||
        this.latestProveRequestToken !== requestTokenAtStart
      ) {
        return this.latestOutcome;
      }
      if (replayPlanResult) {
        finalized.replayPlanUsed = replayPlanResult;
      }
      return publishIfCurrentSession(finalized);
    });
  }

  /**
   * Executes either Prove `--list` (`entryKind: "list"`) or full Prove (`entryKind: "full"`)
   * strictly from a prepared & user-authorized `PreparedProveExecutionPlan`.
   */
  public async runManualProve(params: {
    hostDesc: HostEnvironmentDescriptor;
    configuredProvePath: string;
    configuredTestPythonPath?: string;
    rawRangeSpec: string;
    entryKind: "list" | "full";
    options?: Partial<BoundedProveOptions>;
    authorization: ProveExecutionAuthorization | undefined | null;
    wallClockBudgetMs?: number;
  }): Promise<ProveSessionOutcome> {
    return this.executeAuthorizedProvePlan({
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
   * Executes a single-mutant Replay strictly from a prepared & user-authorized Replay plan.
   */
  public async runSingleMutantReplay(params: {
    hostDesc: HostEnvironmentDescriptor;
    configuredProvePath: string;
    configuredTestPythonPath?: string;
    record: TrustedProveExecutionRecord;
    selectedMutantId: string;
    authorization: ProveExecutionAuthorization | undefined | null;
    wallClockBudgetMs?: number;
  }): Promise<ProveSessionOutcome> {
    if (params.record.isImportedExternalReport) {
      if (params.authorization?.planId) {
        this.invalidatePreparedPlan(params.authorization.planId);
      }
      if (params.authorization?.tokenId) {
        this.consumedAuthTokens.add(params.authorization.tokenId);
      }
      return this.setLatestOutcome({
        status: "Execution error",
        errorReason:
          "Imported external Prove reports are strictly read-only and cannot trigger Replay execution",
        record: null,
      });
    }
    return this.executeAuthorizedProvePlan({
      hostDesc: params.hostDesc,
      configuredProvePath: params.configuredProvePath,
      configuredTestPythonPath: params.configuredTestPythonPath,
      authorization: params.authorization,
      expectedEntryKind: "replay",
      expectedRecordRunId: params.record.runId,
      expectedSelectedMutantId: params.selectedMutantId,
      expectedWallClockBudgetMs: params.wallClockBudgetMs,
    });
  }

  /**
   * Imports an external Prove v0.1.0 JSON report in strictly read-only mode (A14).
   * Never executes any child process and marks `isImportedExternalReport: true` so Replay is blocked.
   */
  public importExternalProveReportReadOnly(
    rawReportJson: string,
    repositoryRoot: string = ""
  ): ValidationResult<ProveSessionOutcome> {
    const valRes = validateProveReportJson(rawReportJson);
    if (!valRes.ok) {
      return valRes;
    }
    const parsedReport = classifyProveReport(valRes.value);
    const runId = ++this.monotonicProveRunId;

    const readOnlyRecord: TrustedProveExecutionRecord = {
      runId,
      entryKind: valRes.value.options.list_only ? "list" : "full",
      adapterVersion: PINNED_PROVE_VERSION,
      isImportedExternalReport: true,
      repositoryRoot,
      rawRangeSpec: valRes.value.range,
      effectiveBaseOid: valRes.value.base,
      effectiveHeadOid: valRes.value.head,
      fromMergeBase: valRes.value.from_merge_base,
      runtimeIdentity: {
        proveExecutable: "<imported-readonly>",
        proveExecutableSha256: "",
        proveVersion: PINNED_PROVE_VERSION,
        hostPythonExecutable: "<imported-readonly>",
        hostPythonVersion: "",
        testPythonExecutable: "<imported-readonly>",
        testPythonVersion: "",
        testPythonSha256: "",
        catalogueVersion: valRes.value.catalogue.version,
        catalogueGeneratorSha256: valRes.value.catalogue.generator_sha256,
      },
      argv: [],
      effectiveOptions: {
        workers: valRes.value.options.workers,
        maxMutants: valRes.value.options.max_mutants,
        timeoutSeconds: valRes.value.options.timeout,
        suiteTimeoutSeconds: valRes.value.options.suite_timeout,
        importRoot: valRes.value.options.import_root,
        strictWarnings: valRes.value.options.strict_warnings,
        listOnly: valRes.value.options.list_only,
        keep: false,
        onlyMutantId: valRes.value.options.only ?? null,
      },
      rawReportSha256: sha256String(rawReportJson),
      parsedReport,
      exitCode: 0,
      cleanupConfirmed: true,
    };

    const outcome: ProveSessionOutcome = {
      status: parsedReport.status,
      errorReason: null,
      record: readOnlyRecord,
    };
    this.setLatestOutcome(outcome);
    return { ok: true, value: outcome };
  }

  private finalizeProveProcessOutcome(params: {
    sessionGenAtStart: number;
    requestTokenAtStart: number;
    entryKind: ProveEntryKind;
    repositoryRoot: string;
    rawRangeSpec: string;
    effectiveBaseOid: string;
    effectiveHeadOid: string;
    fromMergeBase: boolean;
    runtimeIdentity: ProveRuntimeIdentity;
    argv: string[];
    effectiveOptions: BoundedProveOptions;
    brokerOutcome: {
      status: string;
      exitCode: number | null;
      cleanupConfirmed: boolean;
      stdoutUtf8Valid: boolean;
      stderrUtf8Valid: boolean;
      stdoutText: string;
      stderrText: string;
    };
  }): ProveSessionOutcome {
    if (
      this.sessionGeneration !== params.sessionGenAtStart ||
      this.latestProveRequestToken !== params.requestTokenAtStart
    ) {
      return this.latestOutcome;
    }

    const { brokerOutcome } = params;

    if (!brokerOutcome.cleanupConfirmed) {
      const timeoutSuffix =
        brokerOutcome.status === "timed_out" ? " (occurred alongside timeout)" : "";
      const reason = this.processRunner.getUnconfirmedCleanupReason();
      return this.setLatestOutcome({
        status: "Execution error",
        errorReason: `Prove process tree cleanup was not confirmed by Job Object broker${reason ? `: ${reason}` : ""}${timeoutSuffix}`,
        record: null,
      });
    }

    if (brokerOutcome.status === "cancelled") {
      return this.setLatestOutcome({
        status: "Not Run / Cancelled",
        errorReason: null,
        record: null,
      });
    }

    if (
      brokerOutcome.status !== "completed" ||
      !brokerOutcome.stdoutUtf8Valid ||
      !brokerOutcome.stderrUtf8Valid ||
      brokerOutcome.exitCode === null
    ) {
      return this.setLatestOutcome({
        status: "Execution error",
        errorReason: `Prove execution failed (status=${brokerOutcome.status}, exit=${String(brokerOutcome.exitCode)}): ${brokerOutcome.stderrText.trim()}`,
        record: null,
      });
    }

    // Parse JSON report if stdout is non-empty (checkwash-prove emits JSON on exit 0, 1, and some exit 2 cases)
    if (brokerOutcome.stdoutText.trim().length === 0) {
      return this.setLatestOutcome({
        status: "Execution error",
        errorReason: `Prove exited with code ${brokerOutcome.exitCode} and empty stdout: ${brokerOutcome.stderrText.trim()}`,
        record: null,
      });
    }

    const valRes = validateProveReportJson(brokerOutcome.stdoutText);
    if (!valRes.ok) {
      return this.setLatestOutcome({
        status: "Execution error",
        errorReason: `Prove report validation failed (exit=${brokerOutcome.exitCode}): ${valRes.error}`,
        record: null,
      });
    }

    const parsedReport = classifyProveReport(valRes.value);
    const runId = ++this.monotonicProveRunId;
    const rawExitCode = brokerOutcome.exitCode;

    const record: TrustedProveExecutionRecord = {
      runId,
      entryKind: params.entryKind,
      adapterVersion: PINNED_PROVE_VERSION,
      isImportedExternalReport: false,
      repositoryRoot: params.repositoryRoot,
      rawRangeSpec: params.rawRangeSpec,
      effectiveBaseOid: params.effectiveBaseOid,
      effectiveHeadOid: params.effectiveHeadOid,
      fromMergeBase: params.fromMergeBase,
      runtimeIdentity: params.runtimeIdentity,
      argv: params.argv,
      effectiveOptions: params.effectiveOptions,
      rawReportSha256: sha256String(brokerOutcome.stdoutText),
      parsedReport,
      exitCode: rawExitCode,
      cleanupConfirmed: brokerOutcome.cleanupConfirmed,
    };

    if (rawExitCode !== 0) {
      const stderrSuffix =
        brokerOutcome.stderrText.trim().length > 0
          ? `: ${brokerOutcome.stderrText.trim()}`
          : "";
      return this.setLatestOutcome({
        status: "Execution error",
        errorReason: `Prove exited with non-zero code ${rawExitCode}${stderrSuffix}`,
        record,
      });
    }

    this.trustedRecordsById.set(runId, record);

    return this.setLatestOutcome({
      status: parsedReport.status,
      errorReason: null,
      record,
    });
  }
}
