/**
 * core/verdictModel.ts
 *
 * Checkwash 5-State Verdict Model and gap breakdown.
 * Zero VS Code UI dependency; never spawns processes.
 *
 * Enforces Rev 3 §2 & §6 (A07, A08):
 * - Verdict is never recomputed from summary, Fast Guard, or Prove results.
 * - Valid normal exit combinations are strictly:
 *     (jsonExit === 0 && sarifExit === 0 && json.verdict === "pass")
 *     (jsonExit === 1 && sarifExit === 1 && json.verdict === "block")
 *   Any other exit code (2, signal, null), mismatched exits, or contradictory verdict -> Error.
 * - Gaps include: unread, skipped_files, config_errors, SARIF notifications, and ANY non-empty stderr
 *   from either invocation (including ignored exemptions).
 * - Pass + any gap -> Partial / Review.
 * - Block + any gap -> Block (with all gaps preserved and surfaced).
 * - Analyzing, Stale, Cancel requested are separate lifecycle flags, never engine verdicts.
 */

import {
  CheckwashUnreadEntry,
  validateCheckwashSarif,
  validateFindingsJsonV2,
} from "./checkwashSchema";
import {
  joinCheckwashJsonAndSarif,
  JoinedCheckwashReport,
  JoinedNotificationItem,
} from "./reportJoiner";
import { PinnedScanIdentity } from "./sourceIdentity";

export type CheckwashStateKind =
  | "Block"
  | "Partial / Review"
  | "Pass"
  | "Error"
  | "Not Run";

export type ScanScopeKind = "committed" | "staged-precheck" | "worktree-precheck";

export const FIXED_PASS_DISCLAIMER =
  "本次 Checkwash 靜態規則通過，包含已生效的豁免；不代表所有內容均受支援、程式碼正確或完整安全。";

export const UNCOMMITTED_PRECHECK_SCOPE_NOTICE =
  "此結果為未提交變更之暫存快照預檢（Uncommitted Snapshot Pre-Check），僅供 commit 前自我檢查，不取代正式 commit 範圍（A..B / A...B）之驗收裁決。";

export interface CheckwashGapBreakdown {
  hasAnyGap: boolean;
  unread: CheckwashUnreadEntry[];
  skippedFiles: string[];
  configErrors: string[];
  sarifNotifications: JoinedNotificationItem[];
  jsonStderrNotes: string[];
  sarifStderrNotes: string[];
}

export interface LifecycleOverlay {
  analyzing: boolean;
  stale: boolean;
  cancelRequested: boolean;
}

export interface CheckwashEvaluatedState {
  state: CheckwashStateKind;
  verdictFromEngine: "pass" | "block" | null;
  disclaimer: string | null;
  errorReason: string | null;
  notRunReason: string | null;
  gaps: CheckwashGapBreakdown;
  joinedReport: JoinedCheckwashReport | null;
  lifecycle: LifecycleOverlay;
  scanScope?: ScanScopeKind;
}

export function withScanScope(
  evalState: CheckwashEvaluatedState,
  scanScope: ScanScopeKind
): CheckwashEvaluatedState {
  if (scanScope === "committed") {
    return evalState;
  }
  return {
    ...evalState,
    scanScope,
  };
}

export interface ProcessInvocationOutcome {
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  cancelled: boolean;
  stdoutOverflow: boolean;
  stderrOverflow: boolean;
  cleanupConfirmed: boolean;
  stdoutUtf8Valid: boolean;
  stderrUtf8Valid: boolean;
  stdoutText: string;
  stderrText: string;
  identity: PinnedScanIdentity;
}

function emptyGaps(): CheckwashGapBreakdown {
  return {
    hasAnyGap: false,
    unread: [],
    skippedFiles: [],
    configErrors: [],
    sarifNotifications: [],
    jsonStderrNotes: [],
    sarifStderrNotes: [],
  };
}

function splitNonEmptyStderrLines(stderrText: string): string[] {
  const trimmed = stderrText.trim();
  if (trimmed.length === 0) {
    return [];
  }
  return trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export function createNotRunState(
  reason: string,
  lifecycle: Partial<LifecycleOverlay> = {}
): CheckwashEvaluatedState {
  return {
    state: "Not Run",
    verdictFromEngine: null,
    disclaimer: null,
    errorReason: null,
    notRunReason: reason,
    gaps: emptyGaps(),
    joinedReport: null,
    lifecycle: {
      analyzing: lifecycle.analyzing ?? false,
      stale: lifecycle.stale ?? false,
      cancelRequested: lifecycle.cancelRequested ?? false,
    },
  };
}

export function createErrorState(
  errorReason: string,
  partialGaps?: Partial<CheckwashGapBreakdown>,
  lifecycle: Partial<LifecycleOverlay> = {}
): CheckwashEvaluatedState {
  const base = emptyGaps();
  const gaps: CheckwashGapBreakdown = {
    unread: partialGaps?.unread ?? base.unread,
    skippedFiles: partialGaps?.skippedFiles ?? base.skippedFiles,
    configErrors: partialGaps?.configErrors ?? base.configErrors,
    sarifNotifications: partialGaps?.sarifNotifications ?? base.sarifNotifications,
    jsonStderrNotes: partialGaps?.jsonStderrNotes ?? base.jsonStderrNotes,
    sarifStderrNotes: partialGaps?.sarifStderrNotes ?? base.sarifStderrNotes,
    hasAnyGap: false,
  };
  gaps.hasAnyGap =
    gaps.unread.length > 0 ||
    gaps.skippedFiles.length > 0 ||
    gaps.configErrors.length > 0 ||
    gaps.sarifNotifications.length > 0 ||
    gaps.jsonStderrNotes.length > 0 ||
    gaps.sarifStderrNotes.length > 0;

  return {
    state: "Error",
    verdictFromEngine: null,
    disclaimer: null,
    errorReason,
    notRunReason: null,
    gaps,
    joinedReport: null,
    lifecycle: {
      analyzing: lifecycle.analyzing ?? false,
      stale: lifecycle.stale ?? false,
      cancelRequested: lifecycle.cancelRequested ?? false,
    },
  };
}

/**
 * Evaluates a pair of Checkwash JSON v2 and SARIF 2.1.0 process invocations
 * into the canonical 5-State Checkwash Verdict Model (Rev 3 §6).
 */
export function evaluateCheckwashPair(
  jsonRun: ProcessInvocationOutcome,
  sarifRun: ProcessInvocationOutcome,
  headFileLineCounts?: ReadonlyMap<string, number>
): CheckwashEvaluatedState {
  // 1. Cleanup confirmation check (Rev 3 §6 & §7.3: unconfirmed cleanup -> Error, always highest priority)
  if (!jsonRun.cleanupConfirmed || !sarifRun.cleanupConfirmed) {
    const timedOutSuffix =
      jsonRun.timedOut || sarifRun.timedOut ? " (occurred alongside timeout)" : "";
    return createErrorState(
      `Process tree cleanup was not confirmed by Job Object broker${timedOutSuffix}`
    );
  }

  // 2. User cancellation with confirmed stop -> Not Run (Rev 3 §6)
  if (jsonRun.cancelled || sarifRun.cancelled) {
    return createNotRunState("Scan was cancelled by user and process tree termination was confirmed");
  }

  // 3. Timeouts, overflows, or invalid UTF-8 -> Error
  if (jsonRun.timedOut || sarifRun.timedOut) {
    return createErrorState("Checkwash execution timed out");
  }
  if (
    jsonRun.stdoutOverflow ||
    jsonRun.stderrOverflow ||
    sarifRun.stdoutOverflow ||
    sarifRun.stderrOverflow
  ) {
    return createErrorState("Checkwash output exceeded the 16 MiB stream limit");
  }
  if (
    !jsonRun.stdoutUtf8Valid ||
    !jsonRun.stderrUtf8Valid ||
    !sarifRun.stdoutUtf8Valid ||
    !sarifRun.stderrUtf8Valid
  ) {
    return createErrorState("Checkwash output contained invalid UTF-8 byte sequences");
  }

  const jsonStderrNotes = splitNonEmptyStderrLines(jsonRun.stderrText);
  const sarifStderrNotes = splitNonEmptyStderrLines(sarifRun.stderrText);

  // 4. Signal termination or null exit code -> Error
  if (
    jsonRun.signal !== null ||
    sarifRun.signal !== null ||
    jsonRun.exitCode === null ||
    sarifRun.exitCode === null
  ) {
    return createErrorState(
      `Checkwash terminated abnormally (jsonExit=${String(jsonRun.exitCode)}, sarifExit=${String(sarifRun.exitCode)}, signal=${String(jsonRun.signal ?? sarifRun.signal)})`,
      { jsonStderrNotes, sarifStderrNotes }
    );
  }

  // 5. Exit code 2 (including unread-only size refusal JSON on stdout) -> Error (A08)
  if (jsonRun.exitCode === 2 || sarifRun.exitCode === 2) {
    let unreadFromRefusal: CheckwashUnreadEntry[] = [];
    if (jsonRun.stdoutText.trim().length > 0) {
      try {
        const maybeRefusal = JSON.parse(jsonRun.stdoutText);
        if (maybeRefusal && Array.isArray(maybeRefusal.unread)) {
          unreadFromRefusal = maybeRefusal.unread;
        }
      } catch {
        // Ignore parse error on exit 2 stdout; stderr has the reason
      }
    }
    return createErrorState(
      `Checkwash exited with code 2 (engine/input/size refusal error)`,
      { unread: unreadFromRefusal, jsonStderrNotes, sarifStderrNotes }
    );
  }

  // 6. Only 0 and 1 are valid exit codes, and both runs must agree
  if (
    (jsonRun.exitCode !== 0 && jsonRun.exitCode !== 1) ||
    (sarifRun.exitCode !== 0 && sarifRun.exitCode !== 1) ||
    jsonRun.exitCode !== sarifRun.exitCode
  ) {
    return createErrorState(
      `Invalid or mismatched exit codes: JSON exit=${jsonRun.exitCode}, SARIF exit=${sarifRun.exitCode}`,
      { jsonStderrNotes, sarifStderrNotes }
    );
  }

  // 7. Validate JSON v2 schema and SARIF 2.1.0 schema
  const jsonValidation = validateFindingsJsonV2(jsonRun.stdoutText);
  if (!jsonValidation.ok) {
    return createErrorState(`Checkwash JSON v2 validation failed: ${jsonValidation.error}`, {
      jsonStderrNotes,
      sarifStderrNotes,
    });
  }

  const sarifValidation = validateCheckwashSarif(sarifRun.stdoutText);
  if (!sarifValidation.ok) {
    return createErrorState(`Checkwash SARIF validation failed: ${sarifValidation.error}`, {
      jsonStderrNotes,
      sarifStderrNotes,
    });
  }

  const jsonDoc = jsonValidation.value;
  const sarifDoc = sarifValidation.value;

  // 8. Check exit code vs JSON verdict consistency (0+pass or 1+block only; A08)
  if (
    (jsonRun.exitCode === 0 && jsonDoc.verdict !== "pass") ||
    (jsonRun.exitCode === 1 && jsonDoc.verdict !== "block")
  ) {
    return createErrorState(
      `Contradictory exit code (${jsonRun.exitCode}) and JSON verdict ('${jsonDoc.verdict}')`,
      { jsonStderrNotes, sarifStderrNotes }
    );
  }

  // 9. Join JSON and SARIF
  const joinRes = joinCheckwashJsonAndSarif({
    jsonIdentity: jsonRun.identity,
    sarifIdentity: sarifRun.identity,
    jsonDoc,
    sarifDoc,
    headFileLineCounts,
  });
  if (!joinRes.ok) {
    return createErrorState(`JSON/SARIF correlation failed: ${joinRes.error}`, {
      jsonStderrNotes,
      sarifStderrNotes,
    });
  }

  const joined = joinRes.value;
  const gaps: CheckwashGapBreakdown = {
    unread: jsonDoc.unread ? [...jsonDoc.unread] : [],
    skippedFiles: [...jsonDoc.skipped_files],
    configErrors: [...jsonDoc.config_errors],
    sarifNotifications: [...joined.sarifNotifications],
    jsonStderrNotes,
    sarifStderrNotes,
    hasAnyGap: false,
  };
  gaps.hasAnyGap =
    gaps.unread.length > 0 ||
    gaps.skippedFiles.length > 0 ||
    gaps.configErrors.length > 0 ||
    gaps.sarifNotifications.length > 0 ||
    gaps.jsonStderrNotes.length > 0 ||
    gaps.sarifStderrNotes.length > 0;

  // 10. Determine final state
  if (jsonDoc.verdict === "block") {
    return {
      state: "Block",
      verdictFromEngine: "block",
      disclaimer: null,
      errorReason: null,
      notRunReason: null,
      gaps,
      joinedReport: joined,
      lifecycle: { analyzing: false, stale: false, cancelRequested: false },
    };
  }

  if (gaps.hasAnyGap) {
    return {
      state: "Partial / Review",
      verdictFromEngine: "pass",
      disclaimer: FIXED_PASS_DISCLAIMER,
      errorReason: null,
      notRunReason: null,
      gaps,
      joinedReport: joined,
      lifecycle: { analyzing: false, stale: false, cancelRequested: false },
    };
  }

  return {
    state: "Pass",
    verdictFromEngine: "pass",
    disclaimer: FIXED_PASS_DISCLAIMER,
    errorReason: null,
    notRunReason: null,
    gaps,
    joinedReport: joined,
    lifecycle: { analyzing: false, stale: false, cancelRequested: false },
  };
}
