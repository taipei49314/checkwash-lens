/**
 * engine/checkwashRunner.ts
 *
 * Fixed-Revision Checkwash Static Analysis Coordinator (Rev 3 §3, §4, §5, §6).
 *
 * Responsibilities:
 * - Executes two-pass (JSON v2 + SARIF 2.1.0) Checkwash analysis via UnifiedProcessRunner.
 * - Verifies every SARIF line-level finding against the actual immutable blob in effectiveHeadOid
 *   via RevisionProvider (confirming the file exists in effectiveHeadOid, is valid UTF-8, and
 *   startLine1Based <= normalizedLineCount). Fails closed to Error if any SARIF line reference
 *   points to a missing file or out-of-range line.
 * - Prefetches head and base blobs for all changed files in the committed diff so standalone
 *   Fast Guard heuristic hits on files with zero Checkwash findings also have verified head blobs (Issue #8).
 * - Tracks mid-scan document edits so buffers dirtied or modified while a scan is in flight
 *   never receive stale inline diagnostics upon scan completion (Issue #5).
 * - Supports explicit session invalidation on repository switch (Issue #6).
 */

import { JoinedFindingItem } from "../core/reportJoiner";
import {
  canProjectDiagnosticToLiveDocument,
  PinnedScanIdentity,
} from "../core/sourceIdentity";
import {
  CheckwashEvaluatedState,
  createErrorState,
} from "../core/verdictModel";
import {
  areSameRepositoryPath,
  HostEnvironmentDescriptor,
  isFullyQualifiedWindowsPath,
  normalizePlatformLookupKey,
  resolveCanonicalOrNormalizedPath,
} from "../runtime/admission";
import {
  DEFAULT_RUNNER_LIMITS,
  RunnerLimits,
  StaticScanCustomOptions,
  UnifiedProcessRunner,
} from "../runtime/processRunner";
import {
  buildRevisionUriString,
  CommittedDiffSnapshot,
  ImmutableBlobRecord,
  RevisionProvider,
} from "../source/revisionProvider";
import { collectFastGuardHeadCandidatePaths } from "./fastDiffGuard";
import {
  buildSnapshotObjectEnv,
  cleanupEphemeralSnapshotDir,
  createEphemeralSnapshotCommit,
  EphemeralGitObjectOverlay,
  UncommittedSnapshotMode,
} from "./snapshotBuilder";

export interface OpenEditorDocumentSnapshot {
  repositoryRoot: string;
  relativePath: string;
  isDirty: boolean;
  verifiedVersion: number;
  currentVersionAtPublish: number;
  text: string;
  isClosedOrDeleted?: boolean;
}

export interface EnrichedFindingLocation {
  item: JoinedFindingItem;
  /** Immutable checkwash-rev: URI for the resolved provenance file in effectiveHeadOid (if blob exists in head) */
  headRevisionUri: string | null;
  /** Immutable checkwash-rev: URI for the resolved provenance file in effectiveBaseOid (if blob exists in base) */
  baseRevisionUri: string | null;
  /** Preferred immutable checkwash-rev: URI when user clicks the finding in TreeView */
  preferredRevisionUri: string | null;
  /** 1-based line to reveal when opening preferredRevisionUri (null for file-level/base without line) */
  revealLine1Based: number | null;
  /** Whether this finding is permitted to attach a live inline Diagnostic to the open working-tree editor */
  liveProjectionAllowed: boolean;
  /** 0-based line in live editor if liveProjectionAllowed === true; otherwise null */
  liveVscodeLine0Based: number | null;
  /** Explicit explanation of why live projection was allowed or rejected */
  liveProjectionReason: string;
}

export interface CompletedStaticScanSession {
  evaluatedState: CheckwashEvaluatedState;
  scanIdentity: PinnedScanIdentity | null;
  enrichedFindings: EnrichedFindingLocation[];
  diffSnapshot: CommittedDiffSnapshot | null;
  headBlobsByPath: ReadonlyMap<string, ImmutableBlobRecord>;
  baseBlobsByPath: ReadonlyMap<string, ImmutableBlobRecord>;
}

/**
 * Reconciles the initial pre-scan document snapshots with any newer document state observed
 * during the scan (Issue #5). Preserves the pre-scan `verifiedVersion` while taking `isDirty`,
 * `currentVersionAtPublish`, `text`, and closure status from the latest post-scan snapshot.
 */
export function reconcileOpenDocumentsAfterScan(
  initialDocs: readonly OpenEditorDocumentSnapshot[],
  latestDocsAtPublish: readonly OpenEditorDocumentSnapshot[] | null
): OpenEditorDocumentSnapshot[] {
  if (latestDocsAtPublish === null) {
    return [...initialDocs];
  }

  const buildDocKey = (doc: OpenEditorDocumentSnapshot): string => {
    const canonRepo = resolveCanonicalOrNormalizedPath(doc.repositoryRoot);
    const repoKey = normalizePlatformLookupKey(canonRepo);
    const relKey =
      process.platform === "win32" || isFullyQualifiedWindowsPath(canonRepo)
        ? doc.relativePath.toLowerCase()
        : doc.relativePath;
    return `${repoKey}::${relKey}`;
  };

  const initialByKey = new Map<string, OpenEditorDocumentSnapshot>();
  for (const doc of initialDocs) {
    initialByKey.set(buildDocKey(doc), doc);
  }

  const reconciled: OpenEditorDocumentSnapshot[] = [];
  const seenKeys = new Set<string>();

  for (const latest of latestDocsAtPublish) {
    const key = buildDocKey(latest);
    seenKeys.add(key);
    const initial = initialByKey.get(key);
    if (initial) {
      reconciled.push({
        repositoryRoot: latest.repositoryRoot,
        relativePath: latest.relativePath,
        isDirty: latest.isDirty || initial.isDirty,
        verifiedVersion: initial.verifiedVersion,
        currentVersionAtPublish: latest.currentVersionAtPublish,
        text: latest.text,
        isClosedOrDeleted: latest.isClosedOrDeleted,
      });
    } else {
      reconciled.push(latest);
    }
  }

  // Any document that was open at scan start but missing from latestDocsAtPublish was closed during scan
  for (const [key, initial] of initialByKey.entries()) {
    if (!seenKeys.has(key)) {
      reconciled.push({
        ...initial,
        isClosedOrDeleted: true,
      });
    }
  }

  return reconciled;
}

export class CheckwashEngineRunner {
  private latestSession: CompletedStaticScanSession | null = null;
  private sessionGeneration = 0;
  private monotonicEngineScanToken = 0;
  private activeInFlightBaseDocuments: readonly OpenEditorDocumentSnapshot[] | null = null;
  private latestDocumentsDuringInFlightScan: readonly OpenEditorDocumentSnapshot[] | null = null;

  constructor(
    private readonly processRunner: UnifiedProcessRunner,
    private readonly revisionProvider: RevisionProvider
  ) {}

  public getLatestSession(): CompletedStaticScanSession | null {
    return this.latestSession;
  }

  /**
   * Invalidates the current session and bumps generation (called on repository switch, Issue #6).
   */
  public clearSession(): void {
    this.sessionGeneration++;
    this.monotonicEngineScanToken++;
    this.latestSession = null;
    this.activeInFlightBaseDocuments = null;
    this.latestDocumentsDuringInFlightScan = null;
    this.revisionProvider.setActiveSnapshotOverlay(null);
  }

  /**
   * Executes a pre-commit uncommitted snapshot Checkwash scan (`staged` or `worktree`)
   * without modifying `.git/index`, `.git/objects`, `HEAD`, or the working tree.
   */
  public async executeUncommittedSnapshotScan(
    hostDesc: HostEnvironmentDescriptor,
    mode: UncommittedSnapshotMode,
    openDocuments: readonly OpenEditorDocumentSnapshot[] = [],
    limits: RunnerLimits = DEFAULT_RUNNER_LIMITS
  ): Promise<CompletedStaticScanSession> {
    const rawRangeLabel = mode === "staged" ? "HEAD..<staged-index>" : "HEAD..<working-tree>";
    const rightLabel = mode === "staged" ? "<staged-index>" : "<working-tree>";
    const scanScope = mode === "staged" ? "staged-precheck" : "worktree-precheck";

    let createdOverlay: EphemeralGitObjectOverlay | null = null;
    this.revisionProvider.setActiveSnapshotOverlay(null);

    const session = await this.executeStaticScanInternal(
      hostDesc,
      rawRangeLabel,
      openDocuments,
      limits,
      {
        scanScope,
        customTargetResolver: async ({ abortSignal, getRemainingBudgetMs }) => {
          const snapRes = await createEphemeralSnapshotCommit({
            processRunner: this.processRunner,
            hostDesc,
            mode,
            abortSignal,
            getRemainingBudgetMs,
          });
          if (!snapRes.ok) {
            return { kind: "error", errorReason: snapRes.error };
          }
          if (!snapRes.value.hasChanges) {
            return { kind: "empty_not_run", notRunReason: snapRes.value.emptyReason };
          }
          createdOverlay = snapRes.value.overlay;
          this.revisionProvider.setActiveSnapshotOverlay(createdOverlay);
          return {
            kind: "ready",
            rawRangeSpec: rawRangeLabel,
            rangeMode: "two-dot",
            leftRef: "HEAD",
            rightRef: rightLabel,
            resolvedLeftOid: createdOverlay.baseCommitOid,
            resolvedRightOid: createdOverlay.snapshotCommitOid,
            effectiveBaseOid: createdOverlay.baseCommitOid,
            effectiveHeadOid: createdOverlay.snapshotCommitOid,
            extraCheckwashEnv: buildSnapshotObjectEnv(createdOverlay),
          };
        },
      }
    );

    if (createdOverlay !== null) {
      const ov: EphemeralGitObjectOverlay = createdOverlay;
      const isPublishedActiveSession =
        this.latestSession === session &&
        session.evaluatedState.state !== "Error" &&
        session.evaluatedState.state !== "Not Run" &&
        session.scanIdentity?.effectiveHeadOid.toLowerCase() ===
          ov.snapshotCommitOid.toLowerCase();
      if (!isPublishedActiveSession) {
        if (this.revisionProvider.getActiveSnapshotOverlay()?.snapshotDir === ov.snapshotDir) {
          this.revisionProvider.setActiveSnapshotOverlay(null);
        } else {
          cleanupEphemeralSnapshotDir(ov.snapshotDir);
        }
      }
    }

    return session;
  }

  /**
   * Executes a pinned Checkwash static scan, verifies all referenced source blobs in
   * effectiveHeadOid / effectiveBaseOid, prefetches changed diff blobs for Fast Guard (Issue #8),
   * and computes live editor projection bindings using the latest document state at publish time (Issue #5).
   */
  public async executeStaticScan(
    hostDesc: HostEnvironmentDescriptor,
    rawRangeSpec: string,
    openDocuments: readonly OpenEditorDocumentSnapshot[] = [],
    limits: RunnerLimits = DEFAULT_RUNNER_LIMITS
  ): Promise<CompletedStaticScanSession> {
    this.revisionProvider.setActiveSnapshotOverlay(null);
    return this.executeStaticScanInternal(hostDesc, rawRangeSpec, openDocuments, limits, undefined);
  }

  private async executeStaticScanInternal(
    hostDesc: HostEnvironmentDescriptor,
    rawRangeSpec: string,
    openDocuments: readonly OpenEditorDocumentSnapshot[],
    limits: RunnerLimits,
    customOptions?: StaticScanCustomOptions
  ): Promise<CompletedStaticScanSession> {
    const genAtStart = this.sessionGeneration;
    const engineScanToken = ++this.monotonicEngineScanToken;
    const initialOpenDocuments = [...openDocuments];
    this.activeInFlightBaseDocuments = initialOpenDocuments;
    this.latestDocumentsDuringInFlightScan = null;

    let lifecycleSessionResult: {
      scanIdentity: PinnedScanIdentity;
      diffSnapshot: CommittedDiffSnapshot | null;
      headBlobs: Map<string, ImmutableBlobRecord>;
      baseBlobs: Map<string, ImmutableBlobRecord>;
      items: readonly JoinedFindingItem[];
    } | null = null;

    const finalState = await this.processRunner.runCommittedCheckwashScan(
      hostDesc,
      rawRangeSpec,
      limits,
      async ({ rawState, abortSignal, getRemainingBudgetMs }) => {
        const joined = rawState.joinedReport!;
        const id = joined.scanIdentity;
        const headBlobs = new Map<string, ImmutableBlobRecord>();
        const baseBlobs = new Map<string, ImmutableBlobRecord>();

        const checkwashPaths = new Set<string>();
        for (const item of joined.items) {
          checkwashPaths.add(item.resolvedSourcePath);
          checkwashPaths.add(item.declaredUnitPath);
        }

        const checkPostProcessInterrupt = () =>
          this.processRunner.classifyInterruptedStaticScanState({
            abortSignal,
            timedOutByTotalBudget: getRemainingBudgetMs() <= 0,
            partialGaps: rawState.gaps,
          });

        // 1. Verify all SARIF line-level head files exist in effectiveHeadOid and startLine1Based <= normalizedLineCount
        for (const item of joined.items) {
          const preItemInterrupt = checkPostProcessInterrupt();
          if (preItemInterrupt) {
            return preItemInterrupt;
          }

          const pathToRead = item.resolvedSourcePath;
          if (item.locationKind === "line" && item.evidenceSide === "head") {
            let blob = headBlobs.get(pathToRead);
            if (!blob) {
              const blobRes = await this.revisionProvider.readCommitBlob(
                hostDesc,
                id.effectiveHeadOid,
                pathToRead,
                abortSignal,
                getRemainingBudgetMs()
              );
              if (!blobRes.ok) {
                const postBlobInterrupt = checkPostProcessInterrupt();
                if (postBlobInterrupt) {
                  return postBlobInterrupt;
                }
                return createErrorState(
                  `SARIF line-level finding references unreadable or missing file '${pathToRead}' in head commit '${id.effectiveHeadOid}': ${blobRes.error}`,
                  rawState.gaps
                );
              }
              blob = blobRes.value;
              headBlobs.set(pathToRead, blob);
            }

            if (
              item.startLine1Based === null ||
              item.startLine1Based < 1 ||
              item.startLine1Based > blob.normalizedLineCount
            ) {
              return createErrorState(
                `SARIF startLine (${String(item.startLine1Based)}) exceeds normalized line count (${blob.normalizedLineCount}) of '${pathToRead}' in head commit '${id.effectiveHeadOid}'`,
                rawState.gaps
              );
            }
          }
        }

        const preDiffInterrupt = checkPostProcessInterrupt();
        if (preDiffInterrupt) {
          return preDiffInterrupt;
        }

        // 2. Read committed diff snapshot for Fast Guard and Context Diet within active lifecycle & abortSignal
        const diffRes = await this.revisionProvider.readCommittedDiff(
          hostDesc,
          id.effectiveBaseOid,
          id.effectiveHeadOid,
          abortSignal,
          getRemainingBudgetMs()
        );
        const postDiffInterrupt = checkPostProcessInterrupt();
        if (postDiffInterrupt) {
          return postDiffInterrupt;
        }

        const diffSnapshot = diffRes.ok ? diffRes.value : null;

        // 3. Prefetch remaining Checkwash finding paths in head and base commits
        for (const relPath of checkwashPaths) {
          const prePrefetchInterrupt = checkPostProcessInterrupt();
          if (prePrefetchInterrupt) {
            return prePrefetchInterrupt;
          }
          if (!headBlobs.has(relPath)) {
            const hRes = await this.revisionProvider.readCommitBlob(
              hostDesc,
              id.effectiveHeadOid,
              relPath,
              abortSignal,
              getRemainingBudgetMs()
            );
            const postHeadInterrupt = checkPostProcessInterrupt();
            if (postHeadInterrupt) {
              return postHeadInterrupt;
            }
            if (hRes.ok) {
              headBlobs.set(relPath, hRes.value);
            }
          }
          if (!baseBlobs.has(relPath)) {
            const bRes = await this.revisionProvider.readCommitBlob(
              hostDesc,
              id.effectiveBaseOid,
              relPath,
              abortSignal,
              getRemainingBudgetMs()
            );
            const postBaseInterrupt = checkPostProcessInterrupt();
            if (postBaseInterrupt) {
              return postBaseInterrupt;
            }
            if (bRes.ok) {
              baseBlobs.set(relPath, bRes.value);
            }
          }
        }

        // 4. Prefetch ONLY head blobs for changed files that actually contain a Fast Guard head-side candidate hit (Issue #8 & Round 2 Issue #6)
        if (diffSnapshot) {
          const fastGuardHeadPaths = collectFastGuardHeadCandidatePaths(
            diffSnapshot.rawUnifiedDiff
          );
          for (const relPath of fastGuardHeadPaths) {
            const preFgInterrupt = checkPostProcessInterrupt();
            if (preFgInterrupt) {
              return preFgInterrupt;
            }
            if (!headBlobs.has(relPath)) {
              const hRes = await this.revisionProvider.readCommitBlob(
                hostDesc,
                id.effectiveHeadOid,
                relPath,
                abortSignal,
                getRemainingBudgetMs()
              );
              const postFgInterrupt = checkPostProcessInterrupt();
              if (postFgInterrupt) {
                return postFgInterrupt;
              }
              if (hRes.ok) {
                headBlobs.set(relPath, hRes.value);
              }
            }
          }
        }

        lifecycleSessionResult = {
          scanIdentity: id,
          diffSnapshot,
          headBlobs,
          baseBlobs,
          items: joined.items,
        };
        return rawState;
      },
      customOptions
    );

    const activeScanIdAtEnd = this.processRunner.getLatestScanId();
    const isStillCurrentScan =
      this.sessionGeneration === genAtStart &&
      this.monotonicEngineScanToken === engineScanToken;

    if (!isStillCurrentScan) {
      return {
        evaluatedState: finalState,
        scanIdentity:
          (lifecycleSessionResult as { scanIdentity: PinnedScanIdentity } | null)?.scanIdentity ??
          finalState.joinedReport?.scanIdentity ??
          null,
        enrichedFindings: [],
        diffSnapshot: null,
        headBlobsByPath: new Map(),
        baseBlobsByPath: new Map(),
      };
    }

    const midScanDocsSnapshot = this.latestDocumentsDuringInFlightScan;
    this.activeInFlightBaseDocuments = null;
    this.latestDocumentsDuringInFlightScan = null;

    if (
      finalState.state === "Error" ||
      finalState.state === "Not Run" ||
      finalState.joinedReport === null ||
      lifecycleSessionResult === null
    ) {
      const failedOrNotRunSession: CompletedStaticScanSession = {
        evaluatedState: finalState,
        scanIdentity:
          (lifecycleSessionResult as { scanIdentity: PinnedScanIdentity } | null)?.scanIdentity ??
          finalState.joinedReport?.scanIdentity ??
          null,
        enrichedFindings: [],
        diffSnapshot: null,
        headBlobsByPath: new Map(),
        baseBlobsByPath: new Map(),
      };
      this.latestSession = failedOrNotRunSession;
      return failedOrNotRunSession;
    }

    const { scanIdentity: id, diffSnapshot, headBlobs, baseBlobs, items } =
      lifecycleSessionResult as {
        scanIdentity: PinnedScanIdentity;
        diffSnapshot: CommittedDiffSnapshot | null;
        headBlobs: Map<string, ImmutableBlobRecord>;
        baseBlobs: Map<string, ImmutableBlobRecord>;
        items: readonly JoinedFindingItem[];
      };

    // Guard against late completion if another scan started or repository switched (A10, Issue #6)
    if (activeScanIdAtEnd !== id.scanId) {
      return (
        this.latestSession ?? {
          evaluatedState: this.processRunner.getCurrentState(),
          scanIdentity: null,
          enrichedFindings: [],
          diffSnapshot: null,
          headBlobsByPath: new Map(),
          baseBlobsByPath: new Map(),
        }
      );
    }

    // Reconcile initial pre-scan document snapshots with any editor events that arrived mid-scan (Issue #5)
    const effectiveOpenDocsAtPublish = reconcileOpenDocumentsAfterScan(
      initialOpenDocuments,
      midScanDocsSnapshot
    );

    const enrichedFindings = this.computeEnrichedLocations(
      id,
      items,
      headBlobs,
      baseBlobs,
      effectiveOpenDocsAtPublish
    );

    const session: CompletedStaticScanSession = {
      evaluatedState: finalState,
      scanIdentity: id,
      enrichedFindings,
      diffSnapshot,
      headBlobsByPath: headBlobs,
      baseBlobsByPath: baseBlobs,
    };
    this.latestSession = session;
    return session;
  }

  /**
   * Re-evaluates live editor diagnostic eligibility whenever open editor buffers change
   * (e.g., user types in an editor, saves, closes, or switches branches) without re-running Checkwash.
   */
  public refreshLiveEditorBindings(
    openDocuments: readonly OpenEditorDocumentSnapshot[]
  ): EnrichedFindingLocation[] {
    // Record latest open documents even if a scan is currently in flight (Issue #5 & Round 3 Issue #2)
    if (this.activeInFlightBaseDocuments !== null) {
      this.latestDocumentsDuringInFlightScan = reconcileOpenDocumentsAfterScan(
        this.latestDocumentsDuringInFlightScan ?? this.activeInFlightBaseDocuments,
        openDocuments
      );
    } else {
      this.latestDocumentsDuringInFlightScan = [...openDocuments];
    }

    if (
      !this.latestSession ||
      !this.latestSession.scanIdentity ||
      !this.latestSession.evaluatedState.joinedReport
    ) {
      return [];
    }
    const updated = this.computeEnrichedLocations(
      this.latestSession.scanIdentity,
      this.latestSession.evaluatedState.joinedReport.items,
      this.latestSession.headBlobsByPath,
      this.latestSession.baseBlobsByPath,
      openDocuments
    );
    this.latestSession = {
      ...this.latestSession,
      enrichedFindings: updated,
    };
    return updated;
  }

  private computeEnrichedLocations(
    id: PinnedScanIdentity,
    items: readonly JoinedFindingItem[],
    headBlobs: ReadonlyMap<string, ImmutableBlobRecord>,
    baseBlobs: ReadonlyMap<string, ImmutableBlobRecord>,
    openDocuments: readonly OpenEditorDocumentSnapshot[]
  ): EnrichedFindingLocation[] {
    const docByRelPath = new Map<string, OpenEditorDocumentSnapshot>();
    for (const doc of openDocuments) {
      if (areSameRepositoryPath(doc.repositoryRoot, id.repositoryRoot)) {
        docByRelPath.set(doc.relativePath, doc);
      }
    }

    const enriched: EnrichedFindingLocation[] = [];

    for (const item of items) {
      const hasHeadBlob = headBlobs.has(item.resolvedSourcePath);
      const hasBaseBlob = baseBlobs.has(item.resolvedSourcePath);

      const headUriRes = hasHeadBlob
        ? buildRevisionUriString({
            repositoryRoot: id.repositoryRoot,
            commitOid: id.effectiveHeadOid,
            relativePath: item.resolvedSourcePath,
            side: "head",
            scanId: id.scanId,
          })
        : null;
      const baseUriRes = hasBaseBlob
        ? buildRevisionUriString({
            repositoryRoot: id.repositoryRoot,
            commitOid: id.effectiveBaseOid,
            relativePath: item.resolvedSourcePath,
            side: "base",
            scanId: id.scanId,
          })
        : null;

      const headRevisionUri = headUriRes && headUriRes.ok ? headUriRes.value : null;
      const baseRevisionUri = baseUriRes && baseUriRes.ok ? baseUriRes.value : null;

      const preferredRevisionUri =
        item.evidenceSide === "base"
          ? baseRevisionUri ?? headRevisionUri
          : headRevisionUri ?? baseRevisionUri;

      const revealLine1Based =
        item.locationKind === "line" && item.startLine1Based !== null
          ? item.startLine1Based
          : null;

      if (item.finding.allowlisted) {
        enriched.push({
          item,
          headRevisionUri,
          baseRevisionUri,
          preferredRevisionUri,
          revealLine1Based: null,
          liveProjectionAllowed: false,
          liveVscodeLine0Based: null,
          liveProjectionReason: "Allowlisted findings are file-level informational items only",
        });
        continue;
      }

      if (
        item.locationKind !== "line" ||
        item.evidenceSide !== "head" ||
        item.startLine1Based === null ||
        item.vscodeLine0Based === null
      ) {
        enriched.push({
          item,
          headRevisionUri,
          baseRevisionUri,
          preferredRevisionUri,
          revealLine1Based: null,
          liveProjectionAllowed: false,
          liveVscodeLine0Based: null,
          liveProjectionReason: `File-level or non-head finding (locationKind=${item.locationKind}, evidenceSide=${item.evidenceSide}); never fabricates live line 1`,
        });
        continue;
      }

      const headBlob = headBlobs.get(item.resolvedSourcePath);
      if (!headBlob) {
        enriched.push({
          item,
          headRevisionUri,
          baseRevisionUri,
          preferredRevisionUri,
          revealLine1Based,
          liveProjectionAllowed: false,
          liveVscodeLine0Based: null,
          liveProjectionReason: "Head blob is unavailable for live projection verification",
        });
        continue;
      }

      const openDoc = docByRelPath.get(item.resolvedSourcePath);
      if (!openDoc) {
        enriched.push({
          item,
          headRevisionUri,
          baseRevisionUri,
          preferredRevisionUri,
          revealLine1Based,
          liveProjectionAllowed: false,
          liveVscodeLine0Based: null,
          liveProjectionReason: `Document '${item.resolvedSourcePath}' is not open in live editor`,
        });
        continue;
      }

      if (openDoc.isDirty) {
        enriched.push({
          item,
          headRevisionUri,
          baseRevisionUri,
          preferredRevisionUri,
          revealLine1Based,
          liveProjectionAllowed: false,
          liveVscodeLine0Based: null,
          liveProjectionReason: `Live document '${item.resolvedSourcePath}' has unsaved changes (isDirty=true)`,
        });
        continue;
      }

      const projCheck = canProjectDiagnosticToLiveDocument({
        expectedRepositoryRoot: id.repositoryRoot,
        actualRepositoryRoot: areSameRepositoryPath(openDoc.repositoryRoot, id.repositoryRoot)
          ? id.repositoryRoot
          : openDoc.repositoryRoot,
        expectedRelativePath: item.resolvedSourcePath,
        actualRelativePath: openDoc.relativePath,
        analyzedSourceBytes: headBlob.rawBytes,
        liveDocumentText: openDoc.text,
        verifiedDocumentVersion: openDoc.verifiedVersion,
        currentDocumentVersionAtPublish: openDoc.currentVersionAtPublish,
        isDocumentClosedOrDeleted: openDoc.isClosedOrDeleted,
      });

      if (!projCheck.ok) {
        enriched.push({
          item,
          headRevisionUri,
          baseRevisionUri,
          preferredRevisionUri,
          revealLine1Based,
          liveProjectionAllowed: false,
          liveVscodeLine0Based: null,
          liveProjectionReason: projCheck.error,
        });
        continue;
      }

      enriched.push({
        item,
        headRevisionUri,
        baseRevisionUri,
        preferredRevisionUri,
        revealLine1Based,
        liveProjectionAllowed: true,
        liveVscodeLine0Based: item.vscodeLine0Based,
        liveProjectionReason: "Verified exact match with head revision blob and document version",
      });
    }

    return enriched;
  }
}
