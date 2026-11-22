/**
 * runtime/processRunner.ts
 *
 * Unified Process Runner and Lifecycle Coordinator.
 * Every external process invocation (Git, Python probe, Checkwash JSON/SARIF, Prove, Replay)
 * MUST enter through this module. No bypass paths exist.
 *
 * Enforces Rev 3 §4.2, §4.3, §7.1, §7.2, §7.3, §7.4 (A10, B01–B10) & Phase 1–4 Review Fixes:
 * - Enforces verifyLaunchAdmission() and broker capability checks before every launch.
 * - Isolates static Python runs with -I -S -B -X utf8 and controlled empty cwd outside the target repo.
 * - Uses per-invocation isolated TEMP/TMP directories cleaned up ONLY by the owning invocation
 *   after Job Object cleanupConfirmed === true (Issue #4).
 * - Enforces monotonic run IDs, unified mutual exclusion & cancellation across both Checkwash
 *   static scans and Prove/Replay runs (Issue #3), and real-time state listeners (Issue #7).
 * - Enforces default limits: 30s per Checkwash format, 90s per static scan, 16 MiB stdout/stderr.
 */

import { MAX_REPORT_BYTES, ValidationResult } from "../core/checkwashSchema";
import {
  PINNED_CHECKWASH_BUILD_COMMIT,
  PINNED_CHECKWASH_VERSION,
} from "../core/reportJoiner";
import {
  isValidCommitOid,
  parseCommittedRangeSpec,
  PinnedScanIdentity,
} from "../core/sourceIdentity";
import {
  CheckwashEvaluatedState,
  CheckwashGapBreakdown,
  createErrorState,
  createNotRunState,
  evaluateCheckwashPair,
  ProcessInvocationOutcome,
  ScanScopeKind,
  withScanScope,
} from "../core/verdictModel";
import {
  cleanupIsolatedRunDirectory,
  HostEnvironmentDescriptor,
  normalizePlatformLookupKey,
  VerifiedAdmissionContext,
  verifyBareGitResolutionForProcessLaunch,
  verifyLaunchAdmission,
} from "./admission";
import {
  BrokerLaunchOutcome,
  BrokerLaunchRequest,
  executeViaWindowsBroker,
  probeWindowsBroker,
} from "./windowsBroker";

export const DEFAULT_CHECKWASH_FORMAT_TIMEOUT_MS = 30_000; // 30s
export const DEFAULT_STATIC_SCAN_TOTAL_BUDGET_MS = 90_000; // 90s
export const DEFAULT_STREAM_LIMIT_BYTES = MAX_REPORT_BYTES; // 16 MiB

export interface RunnerLimits {
  formatTimeoutMs: number;
  totalScanBudgetMs: number;
  maxStdoutBytes: number;
  maxStderrBytes: number;
}

export const DEFAULT_RUNNER_LIMITS: RunnerLimits = {
  formatTimeoutMs: DEFAULT_CHECKWASH_FORMAT_TIMEOUT_MS,
  totalScanBudgetMs: DEFAULT_STATIC_SCAN_TOTAL_BUDGET_MS,
  maxStdoutBytes: DEFAULT_STREAM_LIMIT_BYTES,
  maxStderrBytes: DEFAULT_STREAM_LIMIT_BYTES,
};

export type CustomBrokerExecutor = (
  req: BrokerLaunchRequest,
  abortSignal?: AbortSignal
) => Promise<BrokerLaunchOutcome>;

interface ExclusiveOperationSlot {
  readonly runId: number;
  readonly abortController: AbortController;
  readonly turnGrantedPromise: Promise<void>;
  readonly grantTurn: () => void;
  readonly completionPromise: Promise<void>;
  readonly markCompleted: () => void;
}

export interface StaticScanPostProcessContext {
  readonly rawState: CheckwashEvaluatedState;
  readonly abortSignal: AbortSignal;
  readonly getRemainingBudgetMs: () => number;
}

export type CustomResolvedScanTargetResult =
  | { readonly kind: "empty_not_run"; readonly notRunReason: string }
  | { readonly kind: "error"; readonly errorReason: string }
  | {
      readonly kind: "ready";
      readonly rawRangeSpec: string;
      readonly rangeMode: "two-dot" | "three-dot";
      readonly leftRef: string;
      readonly rightRef: string;
      readonly resolvedLeftOid: string;
      readonly resolvedRightOid: string;
      readonly effectiveBaseOid: string;
      readonly effectiveHeadOid: string;
      readonly extraCheckwashEnv?: Readonly<Record<string, string>>;
    };

export interface StaticScanCustomOptions {
  readonly scanScope?: ScanScopeKind;
  readonly customTargetResolver?: (ctx: {
    readonly abortSignal: AbortSignal;
    readonly getRemainingBudgetMs: () => number;
  }) => Promise<CustomResolvedScanTargetResult>;
}

export class UnifiedProcessRunner {
  private monotonicRunId = 0;
  private activeSlot: ExclusiveOperationSlot | null = null;
  private readonly exclusiveWaitQueue: ExclusiveOperationSlot[] = [];
  private unconfirmedCleanupError: string | null = null;
  private brokerCapabilityDisabledReason: string | null = null;
  private readonly verifiedBrokerProbeKeys = new Set<string>();
  private currentState: CheckwashEvaluatedState = createNotRunState("No scan has been executed yet");
  private latestCommittedScanId = 0;
  private latestRequestedScanToken = 0;
  private customBrokerExecutor: CustomBrokerExecutor | null = null;
  private readonly stateListeners = new Set<(state: CheckwashEvaluatedState) => void>();

  private setCurrentState(nextState: CheckwashEvaluatedState): void {
    this.currentState = nextState;
    for (const listener of this.stateListeners) {
      try {
        listener(this.currentState);
      } catch {
        // Ignore listener errors so runner lifecycle is never disrupted
      }
    }
  }

  public onDidChangeState(listener: (state: CheckwashEvaluatedState) => void): () => void {
    this.stateListeners.add(listener);
    return () => {
      this.stateListeners.delete(listener);
    };
  }

  public setCustomBrokerExecutorForTests(executor: CustomBrokerExecutor | null): void {
    this.customBrokerExecutor = executor;
  }

  public getCurrentState(): CheckwashEvaluatedState {
    return this.currentState;
  }

  public getLatestScanId(): number {
    return this.latestCommittedScanId;
  }

  public isOperationActive(): boolean {
    return this.activeSlot !== null || this.exclusiveWaitQueue.length > 0;
  }

  public isExecutionDisabledByBrokerFailure(): { disabled: boolean; reason: string | null } {
    return {
      disabled: this.brokerCapabilityDisabledReason !== null,
      reason: this.brokerCapabilityDisabledReason,
    };
  }

  public forceBrokerFailureForTest(reason: string | null): void {
    this.brokerCapabilityDisabledReason = reason;
    this.verifiedBrokerProbeKeys.clear();
  }

  public hasUnconfirmedCleanup(): boolean {
    return this.unconfirmedCleanupError !== null;
  }

  public getUnconfirmedCleanupReason(): string | null {
    return this.unconfirmedCleanupError;
  }

  /**
   * Authoritative final-state classifier across all static scan stages (Rev 3 §6 & §7.3, Review P1 #2).
   * Always prioritizes unconfirmed process-tree cleanup over user cancellation or timeout,
   * ensuring "confirmed stopped" is NEVER claimed unless cleanupConfirmed === true.
   */
  public classifyInterruptedStaticScanState(params: {
    abortSignal?: AbortSignal;
    timedOutByTotalBudget?: boolean;
    timedOutByProcess?: boolean;
    partialGaps?: Partial<CheckwashGapBreakdown>;
  }): CheckwashEvaluatedState | null {
    if (this.unconfirmedCleanupError !== null) {
      const timedOut = Boolean(params.timedOutByTotalBudget || params.timedOutByProcess);
      const timeoutSuffix = timedOut ? " (occurred alongside timeout)" : "";
      return createErrorState(
        `Process tree cleanup was not confirmed by Job Object broker: ${this.unconfirmedCleanupError}${timeoutSuffix}`,
        params.partialGaps
      );
    }
    if (params.timedOutByTotalBudget) {
      return createErrorState("Static scan exceeded total 90-second budget", params.partialGaps);
    }
    if (params.timedOutByProcess) {
      return createErrorState("Checkwash execution timed out", params.partialGaps);
    }
    if (params.abortSignal?.aborted) {
      return createNotRunState("Scan cancelled by user and confirmed stopped");
    }
    return null;
  }

  public resetRunnerStateForTests(): void {
    this.monotonicRunId = 0;
    this.activeSlot = null;
    this.exclusiveWaitQueue.length = 0;
    this.unconfirmedCleanupError = null;
    this.brokerCapabilityDisabledReason = null;
    this.verifiedBrokerProbeKeys.clear();
    this.latestCommittedScanId = 0;
    this.latestRequestedScanToken = 0;
    this.customBrokerExecutor = null;
    this.setCurrentState(createNotRunState("No scan has been executed yet"));
  }

  /**
   * Cancels the currently active run and any queued exclusive waiters (whether Checkwash
   * static scan or Prove/Replay) and waits until all active/queued operations have settled.
   * Only reports `stopped: true` when `cleanupConfirmed === true` (Review P1 #2).
   */
  public async cancelActiveRunAndConfirmStop(): Promise<{ stopped: boolean; cleanupConfirmed: boolean }> {
    while (this.activeSlot !== null || this.exclusiveWaitQueue.length > 0) {
      for (const waiter of this.exclusiveWaitQueue) {
        waiter.abortController.abort();
      }
      if (this.activeSlot) {
        const currentSlot = this.activeSlot;
        if (this.currentState.lifecycle.analyzing && !this.currentState.lifecycle.cancelRequested) {
          this.setCurrentState({
            ...this.currentState,
            lifecycle: {
              ...this.currentState.lifecycle,
              cancelRequested: true,
            },
          });
        }
        currentSlot.abortController.abort();
        await currentSlot.completionPromise;
      }
    }
    const cleanupConfirmed = this.unconfirmedCleanupError === null;
    return { stopped: cleanupConfirmed, cleanupConfirmed };
  }

  /**
   * Coordinates mutually exclusive, cancelable long-running operations (static scans, Prove List,
   * Prove Full, Prove Replay, etc.) using an atomic-handoff FIFO slot queue so neither multiple
   * queued waiters nor microtask arrivals during handoff can ever execute concurrently or leave
   * an uncancelable operation (Round 2 Issue #2 & Round 3 Issue #1).
   */
  public async runExclusiveCancelableOperation<T>(
    work: (abortSignal: AbortSignal, runId: number) => Promise<T>
  ): Promise<T> {
    const runId = ++this.monotonicRunId;
    const abortController = new AbortController();

    let grantTurn!: () => void;
    const turnGrantedPromise = new Promise<void>((resolve) => {
      grantTurn = resolve;
    });

    let markCompleted!: () => void;
    const completionPromise = new Promise<void>((resolve) => {
      markCompleted = resolve;
    });

    const slot: ExclusiveOperationSlot = {
      runId,
      abortController,
      turnGrantedPromise,
      grantTurn,
      completionPromise,
      markCompleted,
    };

    const needsWait = this.activeSlot !== null;
    if (!needsWait) {
      this.activeSlot = slot;
      slot.grantTurn();
    } else {
      for (const waiter of this.exclusiveWaitQueue) {
        waiter.abortController.abort();
      }
      if (this.currentState.lifecycle.analyzing && !this.currentState.lifecycle.cancelRequested) {
        this.setCurrentState({
          ...this.currentState,
          lifecycle: {
            ...this.currentState.lifecycle,
            cancelRequested: true,
          },
        });
      }
      this.activeSlot!.abortController.abort();
      this.exclusiveWaitQueue.push(slot);
    }

    try {
      if (needsWait) {
        await slot.turnGrantedPromise;
      }
      if (this.exclusiveWaitQueue.length > 0) {
        slot.abortController.abort();
      }
      return await work(slot.abortController.signal, runId);
    } finally {
      const nextSlot = this.exclusiveWaitQueue.shift() ?? null;
      this.activeSlot = nextSlot;
      if (nextSlot !== null) {
        if (this.exclusiveWaitQueue.length > 0) {
          nextSlot.abortController.abort();
        }
        nextSlot.grantTurn();
      }
      slot.markCompleted();
    }
  }

  /**
   * Common gated launch entry point for a single managed child process.
   */
  public async executeGatedProcess(params: {
    hostDesc: HostEnvironmentDescriptor;
    executableSelector: (ctx: VerifiedAdmissionContext) => string;
    additionalBareGitCallers?: (ctx: VerifiedAdmissionContext) => readonly string[];
    argsBuilder: (ctx: VerifiedAdmissionContext) => string[];
    cwdSelector?: (ctx: VerifiedAdmissionContext) => string;
    envSelector?: (ctx: VerifiedAdmissionContext) => Record<string, string>;
    timeoutMs: number;
    maxStdoutBytes?: number;
    maxStderrBytes?: number;
    simulateAssignFailure?: boolean;
    pidTrackFilePath?: string;
    abortSignal?: AbortSignal;
  }): Promise<ValidationResult<{ admission: VerifiedAdmissionContext; outcome: BrokerLaunchOutcome }>> {
    // 1. Check if previous run failed cleanup confirmation (§7.3)
    if (this.unconfirmedCleanupError !== null) {
      return {
        ok: false,
        error: `Execution blocked: previous run cleanup was not confirmed (${this.unconfirmedCleanupError})`,
      };
    }

    // 2. Check if broker capability was disabled (§7.3, B09)
    if (this.brokerCapabilityDisabledReason !== null) {
      return {
        ok: false,
        error: `Execution features are disabled: ${this.brokerCapabilityDisabledReason}`,
      };
    }

    // 3. Verify launch admission BEFORE spawning anything (B01, B02, B04, B09, B10)
    const admRes = verifyLaunchAdmission(params.hostDesc);
    if (!admRes.ok) {
      return admRes;
    }
    const ctx = admRes.value;

    // 4. Probe broker capability once per verified (brokerPath, brokerSha256) identity
    const brokerProbeKey = `${normalizePlatformLookupKey(ctx.bundledBrokerPath, params.hostDesc.platform)}::${ctx.bundledBrokerSha256}`;
    if (!this.verifiedBrokerProbeKeys.has(brokerProbeKey)) {
      const probeRes = await probeWindowsBroker(ctx.bundledBrokerPath);
      if (!probeRes.ok) {
        cleanupIsolatedRunDirectory(ctx.isolatedTempDir, true);
        this.brokerCapabilityDisabledReason = probeRes.error;
        return {
          ok: false,
          error: `Process-tree broker capability verification failed: ${probeRes.error}`,
        };
      }
      this.verifiedBrokerProbeKeys.add(brokerProbeKey);
    }

    // If abortSignal was already aborted (or aborted while awaiting probeWindowsBroker),
    // return a clean cancelled outcome without spawning the child process unless a custom
    // test broker executor explicitly intercepts it (Round 2 Issue #3).
    if (params.abortSignal?.aborted && this.customBrokerExecutor === null) {
      cleanupIsolatedRunDirectory(ctx.isolatedTempDir, true);
      return {
        ok: true,
        value: {
          admission: ctx,
          outcome: {
            status: "cancelled",
            exitCode: null,
            childPid: null,
            stdoutRaw: Buffer.alloc(0),
            stderrRaw: Buffer.alloc(0),
            stdoutUtf8Valid: true,
            stderrUtf8Valid: true,
            stdoutText: "",
            stderrText: "",
            cleanupConfirmed: true,
            activeProcessesRemaining: 0,
          },
        },
      };
    }

    const executable = params.executableSelector(ctx);
    const args = params.argsBuilder(ctx);
    const cwd = params.cwdSelector ? params.cwdSelector(ctx) : ctx.controlledEmptyCwd;
    const env = params.envSelector ? params.envSelector(ctx) : ctx.sanitizedStaticEnv;
    const extraGitCallers = params.additionalBareGitCallers
      ? params.additionalBareGitCallers(ctx)
      : [];

    // Re-verify bare 'git' canonical identity against the exact final executable chain, cwd, and env
    // (closes any gap when callers customize executableSelector, cwdSelector, or envSelector/PATH).
    const finalGitIdentityCheck = verifyBareGitResolutionForProcessLaunch({
      callingExecutables: [executable, ...extraGitCallers],
      canonicalGitPath: ctx.canonicalGitPath,
      cwd,
      env,
      platform: params.hostDesc.platform,
    });
    if (!finalGitIdentityCheck.ok) {
      cleanupIsolatedRunDirectory(ctx.isolatedTempDir, true);
      return finalGitIdentityCheck;
    }

    const brokerFn = this.customBrokerExecutor ?? executeViaWindowsBroker;
    let outcome: BrokerLaunchOutcome;
    try {
      outcome = await brokerFn(
        {
          brokerExecutablePath: ctx.bundledBrokerPath,
          executable,
          args,
          cwd,
          env,
          timeoutMs: params.timeoutMs,
          maxStdoutBytes: params.maxStdoutBytes ?? DEFAULT_STREAM_LIMIT_BYTES,
          maxStderrBytes: params.maxStderrBytes ?? DEFAULT_STREAM_LIMIT_BYTES,
          simulateAssignFailure: params.simulateAssignFailure,
          pidTrackFilePath: params.pidTrackFilePath,
        },
        params.abortSignal
      );
    } finally {
      // Clean up ONLY this invocation's isolatedTempDir after broker finishes and confirms cleanup (Issue #4)
      // Note: if outcome is not yet assigned due to unexpected throw, do not force-delete.
    }

    cleanupIsolatedRunDirectory(ctx.isolatedTempDir, outcome.cleanupConfirmed);

    if (!outcome.cleanupConfirmed) {
      const detailSuffix = outcome.brokerErrorDetail ? ` (${outcome.brokerErrorDetail})` : "";
      this.unconfirmedCleanupError = `ActiveProcesses=${outcome.activeProcessesRemaining} after status=${outcome.status}${detailSuffix}`;
      this.setCurrentState(
        createErrorState(
          `Process tree cleanup was not confirmed by Job Object broker: ${this.unconfirmedCleanupError}`
        )
      );
    }

    return {
      ok: true,
      value: {
        admission: ctx,
        outcome,
      },
    };
  }

  /**
   * Runs a read-only Git command against the canonical repository using the trusted Git binary
   * and controlled empty cwd outside the repository.
   */
  public async runTrustedGitRead(
    hostDesc: HostEnvironmentDescriptor,
    gitArgs: string[],
    timeoutMs: number = 15_000,
    abortSignal?: AbortSignal,
    extraEnv?: Readonly<Record<string, string>>
  ): Promise<ValidationResult<{ stdoutText: string; admission: VerifiedAdmissionContext }>> {
    const res = await this.executeGatedProcess({
      hostDesc,
      executableSelector: (ctx) => ctx.canonicalGitPath,
      argsBuilder: (ctx) => [
        "-C",
        ctx.canonicalRepositoryRoot,
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.quotepath=false",
        "-c",
        "core.fsmonitor=false",
        ...gitArgs,
      ],
      envSelector: extraEnv
        ? (ctx) => ({ ...ctx.sanitizedStaticEnv, ...extraEnv })
        : undefined,
      timeoutMs,
      abortSignal,
    });
    if (!res.ok) return res;
    const { admission, outcome } = res.value;
    if (
      outcome.status !== "completed" ||
      outcome.exitCode !== 0 ||
      !outcome.stdoutUtf8Valid ||
      !outcome.cleanupConfirmed
    ) {
      return {
        ok: false,
        error: `Git command failed (status=${outcome.status}, exit=${String(outcome.exitCode)}): ${outcome.stderrText.trim()}`,
      };
    }
    return {
      ok: true,
      value: {
        stdoutText: outcome.stdoutText,
        admission,
      },
    };
  }

  /**
   * Resolves and pins a user-supplied committed range expression (A..B or A...B)
   * into full 40/64-char commit OIDs (Rev 3 §4.2).
   */
  public async resolveAndPinCommittedRange(
    hostDesc: HostEnvironmentDescriptor,
    rawRangeSpec: string,
    abortSignal?: AbortSignal
  ): Promise<
    ValidationResult<{
      rawRangeSpec: string;
      rangeMode: "two-dot" | "three-dot";
      leftRef: string;
      rightRef: string;
      resolvedLeftOid: string;
      resolvedRightOid: string;
      effectiveBaseOid: string;
      effectiveHeadOid: string;
      admission: VerifiedAdmissionContext;
    }>
  > {
    const parsedSpec = parseCommittedRangeSpec(rawRangeSpec);
    if (!parsedSpec.ok) return parsedSpec;
    const { rawSpec, mode, leftRef, rightRef } = parsedSpec.value;

    const leftRes = await this.runTrustedGitRead(
      hostDesc,
      ["rev-parse", "--verify", "--end-of-options", `${leftRef}^{commit}`],
      15_000,
      abortSignal
    );
    if (!leftRes.ok) {
      return { ok: false, error: `Cannot resolve base commit '${leftRef}': ${leftRes.error}` };
    }
    const resolvedLeftOid = leftRes.value.stdoutText.trim();
    if (!isValidCommitOid(resolvedLeftOid)) {
      return { ok: false, error: `Resolved left OID is invalid: '${resolvedLeftOid}'` };
    }

    const rightRes = await this.runTrustedGitRead(
      hostDesc,
      ["rev-parse", "--verify", "--end-of-options", `${rightRef}^{commit}`],
      15_000,
      abortSignal
    );
    if (!rightRes.ok) {
      return { ok: false, error: `Cannot resolve head commit '${rightRef}': ${rightRes.error}` };
    }
    const resolvedRightOid = rightRes.value.stdoutText.trim();
    if (!isValidCommitOid(resolvedRightOid)) {
      return { ok: false, error: `Resolved right OID is invalid: '${resolvedRightOid}'` };
    }

    let effectiveBaseOid = resolvedLeftOid;
    const effectiveHeadOid = resolvedRightOid;

    if (mode === "three-dot") {
      const mbRes = await this.runTrustedGitRead(
        hostDesc,
        ["merge-base", resolvedLeftOid, resolvedRightOid],
        15_000,
        abortSignal
      );
      if (!mbRes.ok) {
        return {
          ok: false,
          error: `Cannot compute merge-base for '${rawSpec}': ${mbRes.error}`,
        };
      }
      const mergeBaseOid = mbRes.value.stdoutText.trim();
      if (!isValidCommitOid(mergeBaseOid)) {
        return { ok: false, error: `Invalid merge-base OID: '${mergeBaseOid}'` };
      }
      effectiveBaseOid = mergeBaseOid;
    }

    return {
      ok: true,
      value: {
        rawRangeSpec: rawSpec,
        rangeMode: mode,
        leftRef,
        rightRef,
        resolvedLeftOid,
        resolvedRightOid,
        effectiveBaseOid,
        effectiveHeadOid,
        admission: rightRes.value.admission,
      },
    };
  }

  /**
   * Probes CPython >= 3.11 and Git versions using isolated -I -S -B -X utf8 flags.
   */
  public async probeTrustedRuntimeVersions(
    hostDesc: HostEnvironmentDescriptor,
    abortSignal?: AbortSignal
  ): Promise<
    ValidationResult<{
      pythonVersion: string;
      gitVersion: string;
      admission: VerifiedAdmissionContext;
    }>
  > {
    const pyRes = await this.executeGatedProcess({
      hostDesc,
      executableSelector: (ctx) => ctx.canonicalPythonPath,
      argsBuilder: () => [
        "-I",
        "-S",
        "-B",
        "-X",
        "utf8",
        "-c",
        "import sys, platform; assert sys.implementation.name == 'cpython' and sys.version_info[:2] >= (3, 11) and sys.flags.utf8_mode == 1; print(platform.python_version())",
      ],
      timeoutMs: 10_000,
      abortSignal,
    });
    if (!pyRes.ok) return pyRes;
    if (
      pyRes.value.outcome.status !== "completed" ||
      pyRes.value.outcome.exitCode !== 0 ||
      !pyRes.value.outcome.stdoutUtf8Valid ||
      !pyRes.value.outcome.cleanupConfirmed
    ) {
      return {
        ok: false,
        error: `Trusted Python interpreter failed CPython 3.11+ verification (status=${pyRes.value.outcome.status}, exit=${String(pyRes.value.outcome.exitCode)})`,
      };
    }
    const pythonVersion = pyRes.value.outcome.stdoutText.trim();

    const gitRes = await this.runTrustedGitRead(hostDesc, ["--version"], 10_000, abortSignal);
    if (!gitRes.ok) return gitRes;
    const gitVersion = gitRes.value.stdoutText.trim();

    return {
      ok: true,
      value: {
        pythonVersion,
        gitVersion,
        admission: gitRes.value.admission,
      },
    };
  }

  /**
   * Runs a full static Checkwash scan (JSON v2 + SARIF 2.1.0) on a pinned committed range,
   * optionally running engine post-processing (source blob verification & diff reading)
   * inside the same active operation lifecycle, cancellation signal, and 90-second total budget
   * before publishing the final evaluatedState (Round 2 Issue #2 & Issue #6).
   */
  public async runCommittedCheckwashScan(
    hostDesc: HostEnvironmentDescriptor,
    rawRangeSpec: string,
    limits: RunnerLimits = DEFAULT_RUNNER_LIMITS,
    postProcessWithinLifecycle?: (
      ctx: StaticScanPostProcessContext
    ) => Promise<CheckwashEvaluatedState>,
    customOptions?: StaticScanCustomOptions
  ): Promise<CheckwashEvaluatedState> {
    const effectiveScope: ScanScopeKind = customOptions?.scanScope ?? "committed";
    const applyScope = (st: CheckwashEvaluatedState): CheckwashEvaluatedState =>
      withScanScope(st, effectiveScope);
    const scanRequestToken = ++this.latestRequestedScanToken;
    return this.runExclusiveCancelableOperation(async (abortSignal, scanId) => {
      if (this.unconfirmedCleanupError !== null) {
        const errState = applyScope(
          createErrorState(
            `Cannot start scan: previous run cleanup was not confirmed (${this.unconfirmedCleanupError})`
          )
        );
        if (scanRequestToken === this.latestRequestedScanToken) {
          this.setCurrentState(errState);
        }
        return errState;
      }

      if (this.brokerCapabilityDisabledReason !== null) {
        const notRun = applyScope(
          createNotRunState(
            `Execution disabled: ${this.brokerCapabilityDisabledReason}`
          )
        );
        if (scanRequestToken === this.latestRequestedScanToken) {
          this.setCurrentState(notRun);
        }
        return notRun;
      }

      // Pre-check admission before marking analyzing
      const preAdmission = verifyLaunchAdmission(hostDesc);
      if (!preAdmission.ok) {
        const isCapabilityOrTrustGate =
          preAdmission.error.startsWith("Restricted Mode:") ||
          preAdmission.error.startsWith("Unsupported platform/architecture") ||
          preAdmission.error.startsWith("Unsupported workspace environment");
        const state = applyScope(
          isCapabilityOrTrustGate
            ? createNotRunState(preAdmission.error)
            : createErrorState(preAdmission.error)
        );
        if (scanRequestToken === this.latestRequestedScanToken) {
          this.setCurrentState(state);
        }
        return state;
      }
      cleanupIsolatedRunDirectory(preAdmission.value.isolatedTempDir, true);

      this.latestCommittedScanId = scanId;

      // Mark current state as analyzing/stale and notify listeners immediately (§6, Issue #7)
      this.setCurrentState(
        applyScope({
          ...this.currentState,
          lifecycle: {
            analyzing: true,
            stale: true,
            cancelRequested: abortSignal.aborted,
          },
        })
      );

      const scanStartedAt = Date.now();
      let timedOutByTotalBudget = false;
      const totalTimer = setTimeout(() => {
        timedOutByTotalBudget = true;
        if (this.activeSlot?.runId === scanId) {
          this.activeSlot.abortController.abort();
        }
      }, limits.totalScanBudgetMs);

      const getRemainingBudgetMs = (): number =>
        limits.totalScanBudgetMs - (Date.now() - scanStartedAt);

      const runWork = async (): Promise<CheckwashEvaluatedState> => {
        const preProbeInterrupt = this.classifyInterruptedStaticScanState({
          abortSignal,
          timedOutByTotalBudget,
        });
        if (preProbeInterrupt) {
          return preProbeInterrupt;
        }

        // 1. Probe runtime versions
        const rtRes = await this.probeTrustedRuntimeVersions(hostDesc, abortSignal);
        if (!rtRes.ok) {
          const probeInterrupt = this.classifyInterruptedStaticScanState({
            abortSignal,
            timedOutByTotalBudget,
          });
          return probeInterrupt ?? createErrorState(rtRes.error);
        }
        const postProbeInterrupt = this.classifyInterruptedStaticScanState({
          abortSignal,
          timedOutByTotalBudget,
        });
        if (postProbeInterrupt) {
          return postProbeInterrupt;
        }

        // 2. Resolve and pin committed range OIDs (or custom ephemeral snapshot target)
        let pinned: {
          rawRangeSpec: string;
          rangeMode: "two-dot" | "three-dot";
          leftRef: string;
          rightRef: string;
          resolvedLeftOid: string;
          resolvedRightOid: string;
          effectiveBaseOid: string;
          effectiveHeadOid: string;
        };
        let extraCheckwashEnv: Readonly<Record<string, string>> | undefined;

        if (customOptions?.customTargetResolver) {
          const customRes = await customOptions.customTargetResolver({
            abortSignal,
            getRemainingBudgetMs,
          });
          const postCustomInterrupt = this.classifyInterruptedStaticScanState({
            abortSignal,
            timedOutByTotalBudget,
          });
          if (postCustomInterrupt) {
            return postCustomInterrupt;
          }
          if (customRes.kind === "empty_not_run") {
            return createNotRunState(customRes.notRunReason);
          }
          if (customRes.kind === "error") {
            return createErrorState(customRes.errorReason);
          }
          pinned = {
            rawRangeSpec: customRes.rawRangeSpec,
            rangeMode: customRes.rangeMode,
            leftRef: customRes.leftRef,
            rightRef: customRes.rightRef,
            resolvedLeftOid: customRes.resolvedLeftOid,
            resolvedRightOid: customRes.resolvedRightOid,
            effectiveBaseOid: customRes.effectiveBaseOid,
            effectiveHeadOid: customRes.effectiveHeadOid,
          };
          extraCheckwashEnv = customRes.extraCheckwashEnv;
        } else {
          const rangeRes = await this.resolveAndPinCommittedRange(
            hostDesc,
            rawRangeSpec,
            abortSignal
          );
          if (!rangeRes.ok) {
            const rangeInterrupt = this.classifyInterruptedStaticScanState({
              abortSignal,
              timedOutByTotalBudget,
            });
            return rangeInterrupt ?? createErrorState(rangeRes.error);
          }
          const postRangeInterrupt = this.classifyInterruptedStaticScanState({
            abortSignal,
            timedOutByTotalBudget,
          });
          if (postRangeInterrupt) {
            return postRangeInterrupt;
          }
          pinned = rangeRes.value;
        }

        const pinnedRangeArg = `${pinned.effectiveBaseOid}..${pinned.effectiveHeadOid}`;

        // 3. Re-verify admission & artifact hash right before JSON run (§4.3)
        const admBeforeJson = verifyLaunchAdmission(hostDesc);
        if (!admBeforeJson.ok) {
          return createErrorState(admBeforeJson.error);
        }
        cleanupIsolatedRunDirectory(admBeforeJson.value.isolatedTempDir, true);

        const jsonIdentity: PinnedScanIdentity = {
          scanId,
          repositoryRoot: admBeforeJson.value.canonicalRepositoryRoot,
          rawRangeSpec: pinned.rawRangeSpec,
          rangeMode: pinned.rangeMode,
          leftRef: pinned.leftRef,
          rightRef: pinned.rightRef,
          resolvedLeftOid: pinned.resolvedLeftOid,
          resolvedRightOid: pinned.resolvedRightOid,
          effectiveBaseOid: pinned.effectiveBaseOid,
          effectiveHeadOid: pinned.effectiveHeadOid,
          checkwashVersion: PINNED_CHECKWASH_VERSION,
          checkwashPyzSha256: admBeforeJson.value.bundledPyzSha256,
          checkwashBuildCommit: PINNED_CHECKWASH_BUILD_COMMIT,
          pythonExecutable: admBeforeJson.value.canonicalPythonPath,
          pythonVersion: rtRes.value.pythonVersion,
          gitExecutable: admBeforeJson.value.canonicalGitPath,
          gitVersion: rtRes.value.gitVersion,
          controlledCwd: admBeforeJson.value.controlledEmptyCwd,
        };

        const remainingBeforeJson = getRemainingBudgetMs();
        if (remainingBeforeJson <= 0 || timedOutByTotalBudget) {
          return (
            this.classifyInterruptedStaticScanState({
              abortSignal,
              timedOutByTotalBudget: true,
            }) ?? createErrorState("Static scan exceeded total 90-second budget")
          );
        }

        const jsonProcRes = await this.executeGatedProcess({
          hostDesc,
          executableSelector: (ctx) => ctx.canonicalPythonPath,
          argsBuilder: (ctx) => [
            "-I",
            "-S",
            "-B",
            "-X",
            "utf8",
            ctx.bundledPyzPath,
            "check",
            pinnedRangeArg,
            "--format",
            "json",
            "--repo",
            ctx.canonicalRepositoryRoot,
          ],
          envSelector: extraCheckwashEnv
            ? (ctx) => ({ ...ctx.sanitizedStaticEnv, ...extraCheckwashEnv })
            : undefined,
          timeoutMs: Math.min(limits.formatTimeoutMs, remainingBeforeJson),
          maxStdoutBytes: limits.maxStdoutBytes,
          maxStderrBytes: limits.maxStderrBytes,
          abortSignal,
        });
        if (!jsonProcRes.ok) {
          return (
            this.classifyInterruptedStaticScanState({
              abortSignal,
              timedOutByTotalBudget,
            }) ?? createErrorState(jsonProcRes.error)
          );
        }
        const postJsonInterrupt = this.classifyInterruptedStaticScanState({
          abortSignal,
          timedOutByTotalBudget,
          timedOutByProcess: jsonProcRes.value.outcome.status === "timed_out",
        });
        if (postJsonInterrupt) {
          return postJsonInterrupt;
        }
        if (jsonProcRes.value.outcome.status === "cancelled") {
          return createNotRunState("Scan was cancelled by user and process tree termination was confirmed");
        }

        // 4. Re-verify admission & artifact hash right before SARIF run (§4.3)
        const admBeforeSarif = verifyLaunchAdmission(hostDesc);
        if (!admBeforeSarif.ok) {
          return createErrorState(admBeforeSarif.error);
        }
        cleanupIsolatedRunDirectory(admBeforeSarif.value.isolatedTempDir, true);

        const sarifIdentity: PinnedScanIdentity = {
          scanId,
          repositoryRoot: admBeforeSarif.value.canonicalRepositoryRoot,
          rawRangeSpec: pinned.rawRangeSpec,
          rangeMode: pinned.rangeMode,
          leftRef: pinned.leftRef,
          rightRef: pinned.rightRef,
          resolvedLeftOid: pinned.resolvedLeftOid,
          resolvedRightOid: pinned.resolvedRightOid,
          effectiveBaseOid: pinned.effectiveBaseOid,
          effectiveHeadOid: pinned.effectiveHeadOid,
          checkwashVersion: PINNED_CHECKWASH_VERSION,
          checkwashPyzSha256: admBeforeSarif.value.bundledPyzSha256,
          checkwashBuildCommit: PINNED_CHECKWASH_BUILD_COMMIT,
          pythonExecutable: admBeforeSarif.value.canonicalPythonPath,
          pythonVersion: rtRes.value.pythonVersion,
          gitExecutable: admBeforeSarif.value.canonicalGitPath,
          gitVersion: rtRes.value.gitVersion,
          controlledCwd: admBeforeSarif.value.controlledEmptyCwd,
        };

        const remainingBeforeSarif = getRemainingBudgetMs();
        if (remainingBeforeSarif <= 0 || timedOutByTotalBudget) {
          return (
            this.classifyInterruptedStaticScanState({
              abortSignal,
              timedOutByTotalBudget: true,
            }) ?? createErrorState("Static scan exceeded total 90-second budget")
          );
        }

        const sarifProcRes = await this.executeGatedProcess({
          hostDesc,
          executableSelector: (ctx) => ctx.canonicalPythonPath,
          argsBuilder: (ctx) => [
            "-I",
            "-S",
            "-B",
            "-X",
            "utf8",
            ctx.bundledPyzPath,
            "check",
            pinnedRangeArg,
            "--format",
            "sarif",
            "--repo",
            ctx.canonicalRepositoryRoot,
          ],
          envSelector: extraCheckwashEnv
            ? (ctx) => ({ ...ctx.sanitizedStaticEnv, ...extraCheckwashEnv })
            : undefined,
          timeoutMs: Math.min(limits.formatTimeoutMs, remainingBeforeSarif),
          maxStdoutBytes: limits.maxStdoutBytes,
          maxStderrBytes: limits.maxStderrBytes,
          abortSignal,
        });
        if (!sarifProcRes.ok) {
          return (
            this.classifyInterruptedStaticScanState({
              abortSignal,
              timedOutByTotalBudget,
            }) ?? createErrorState(sarifProcRes.error)
          );
        }
        if (!sarifProcRes.value.outcome.cleanupConfirmed) {
          const sarifCleanupErr = this.classifyInterruptedStaticScanState({
            abortSignal,
            timedOutByTotalBudget,
            timedOutByProcess: sarifProcRes.value.outcome.status === "timed_out",
          });
          if (sarifCleanupErr) {
            return sarifCleanupErr;
          }
        }

        const toInvocationOutcome = (
          bOut: BrokerLaunchOutcome,
          id: PinnedScanIdentity
        ): ProcessInvocationOutcome => ({
          exitCode: bOut.exitCode,
          signal: bOut.status === "broker_error" || bOut.status === "spawn_failed" ? bOut.status : null,
          timedOut: bOut.status === "timed_out" || timedOutByTotalBudget,
          cancelled: bOut.status === "cancelled" && !timedOutByTotalBudget,
          stdoutOverflow: bOut.status === "stdout_overflow",
          stderrOverflow: bOut.status === "stderr_overflow",
          cleanupConfirmed: bOut.cleanupConfirmed,
          stdoutUtf8Valid: bOut.stdoutUtf8Valid,
          stderrUtf8Valid: bOut.stderrUtf8Valid,
          stdoutText: bOut.stdoutText,
          stderrText: bOut.stderrText,
          identity: id,
        });

        const pairState = evaluateCheckwashPair(
          toInvocationOutcome(jsonProcRes.value.outcome, jsonIdentity),
          toInvocationOutcome(sarifProcRes.value.outcome, sarifIdentity)
        );

        if (
          postProcessWithinLifecycle &&
          pairState.state !== "Error" &&
          pairState.state !== "Not Run" &&
          pairState.joinedReport !== null
        ) {
          const finalState = await postProcessWithinLifecycle({
            rawState: pairState,
            abortSignal,
            getRemainingBudgetMs,
          });
          const postProcessInterrupt = this.classifyInterruptedStaticScanState({
            abortSignal,
            timedOutByTotalBudget,
            partialGaps: pairState.gaps,
          });
          if (postProcessInterrupt) {
            return postProcessInterrupt;
          }
          return finalState;
        }

        return pairState;
      };

      let evaluatedState: CheckwashEvaluatedState;
      try {
        evaluatedState = applyScope(await runWork());
      } finally {
        clearTimeout(totalTimer);
      }

      // Late arrival & superseded scan guard (A10, Round 3 Issue #2):
      // Only commit final state if this scan is still the latest requested static scan
      if (
        scanId === this.latestCommittedScanId &&
        scanRequestToken === this.latestRequestedScanToken
      ) {
        this.setCurrentState(evaluatedState);
      }
      return evaluatedState;
    });
  }
}
