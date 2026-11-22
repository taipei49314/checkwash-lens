/**
 * ui/statusBar.ts
 *
 * 5-State Status Bar View-Model & Controller (Rev 3 §6).
 *
 * Enforces:
 * - Five distinct engine states: Block, Partial / Review, Pass, Error, Not Run.
 * - Lifecycle overlay (analyzing / stale / cancelRequested) never displays a stale
 *   green Pass badge as the current active verdict.
 * - Pass + any gap is always Partial / Review (never Pass).
 * - Block + any gap remains Block while explicitly surfacing "(+ Gaps)" in label/tooltip.
 * - Pass tooltip always includes FIXED_PASS_DISCLAIMER.
 */

import {
  CheckwashEvaluatedState,
  CheckwashStateKind,
  FIXED_PASS_DISCLAIMER,
  UNCOMMITTED_PRECHECK_SCOPE_NOTICE,
} from "../core/verdictModel";

export type StatusBarColorTheme = "default" | "warning" | "error";

export interface StatusBarViewModel {
  state: CheckwashStateKind;
  text: string;
  tooltip: string;
  colorTheme: StatusBarColorTheme;
  isAnalyzing: boolean;
  isStale: boolean;
}

/**
 * Pure function that computes the exact Status Bar presentation from CheckwashEvaluatedState.
 */
export function buildStatusBarViewModel(
  evalState: CheckwashEvaluatedState
): StatusBarViewModel {
  const { state, lifecycle, gaps, errorReason, notRunReason, joinedReport, scanScope } = evalState;
  const isPreCheck = scanScope === "staged-precheck" || scanScope === "worktree-precheck";
  const prefixLabel =
    scanScope === "staged-precheck"
      ? "Checkwash [Staged Pre-Check]"
      : scanScope === "worktree-precheck"
      ? "Checkwash [Worktree Pre-Check]"
      : "Checkwash";
  const preCheckTooltipNotice = isPreCheck ? UNCOMMITTED_PRECHECK_SCOPE_NOTICE : null;

  if (lifecycle.analyzing) {
    const cancelText = lifecycle.cancelRequested
      ? `$(sync~spin) ${prefixLabel}: Cancelling...`
      : `$(sync~spin) ${prefixLabel}: Analyzing...`;
    const prevNote =
      state !== "Not Run" ? `Previous result (${state}) is stale while scan is running.` : "";
    return {
      state,
      text: cancelText,
      tooltip: [
        "Checkwash Lens — Static Scan in Progress",
        preCheckTooltipNotice ?? "",
        prevNote,
        "Click to cancel active scan or open Quick Actions.",
      ]
        .filter((s) => s.length > 0)
        .join("\n"),
      colorTheme: "default",
      isAnalyzing: true,
      isStale: true,
    };
  }

  const staleSuffix = lifecycle.stale ? " (Stale)" : "";
  const rangeLine = joinedReport
    ? isPreCheck
      ? `Pre-Check Snapshot: ${joinedReport.scanIdentity.rawRangeSpec} (base ${joinedReport.scanIdentity.effectiveBaseOid.slice(0, 12)})`
      : `Range: ${joinedReport.scanIdentity.effectiveBaseOid.slice(0, 12)}..${joinedReport.scanIdentity.effectiveHeadOid.slice(0, 12)}`
    : null;

  switch (state) {
    case "Block": {
      const gapBadge = gaps.hasAnyGap ? " (+Gaps)" : "";
      const tooltipLines = [
        `${prefixLabel} Verdict: BLOCK${staleSuffix}`,
        preCheckTooltipNotice,
        rangeLine,
        `Blocking/Advisory Findings: ${joinedReport?.nonAllowlistedCount ?? 0} (Allowlisted: ${joinedReport?.allowlistedCount ?? 0})`,
        gaps.hasAnyGap
          ? `Coverage Gaps Present: unread=${gaps.unread.length}, skipped=${gaps.skippedFiles.length}, configErrors=${gaps.configErrors.length}, notifications=${gaps.sarifNotifications.length}, stderr=${gaps.jsonStderrNotes.length + gaps.sarifStderrNotes.length}`
          : null,
        "Click to open Checkwash Lens Quick Actions.",
      ].filter((x): x is string => x !== null);
      return {
        state: "Block",
        text: `$(error) ${prefixLabel}: Block${gapBadge}${staleSuffix}`,
        tooltip: tooltipLines.join("\n"),
        colorTheme: "error",
        isAnalyzing: false,
        isStale: lifecycle.stale,
      };
    }

    case "Partial / Review": {
      const tooltipLines = [
        `${prefixLabel} Verdict: PARTIAL / REVIEW${staleSuffix}`,
        preCheckTooltipNotice,
        rangeLine,
        `Engine verdict was pass, but analysis gaps or configuration warnings were detected:`,
        `- Unread files: ${gaps.unread.length}`,
        `- Skipped files: ${gaps.skippedFiles.length}`,
        `- Config errors: ${gaps.configErrors.length}`,
        `- SARIF notifications: ${gaps.sarifNotifications.length}`,
        `- Stderr notes: ${gaps.jsonStderrNotes.length + gaps.sarifStderrNotes.length}`,
        "",
        FIXED_PASS_DISCLAIMER,
        "Click to open Checkwash Lens Quick Actions.",
      ].filter((x): x is string => x !== null);
      return {
        state: "Partial / Review",
        text: `$(warning) ${prefixLabel}: Partial / Review${staleSuffix}`,
        tooltip: tooltipLines.join("\n"),
        colorTheme: "warning",
        isAnalyzing: false,
        isStale: lifecycle.stale,
      };
    }

    case "Pass": {
      const tooltipLines = [
        `${prefixLabel} Verdict: PASS${staleSuffix}`,
        lifecycle.stale
          ? "WARNING: Working-tree files were edited after this Pre-Check ran. Re-run Pre-Check to verify current contents."
          : null,
        preCheckTooltipNotice,
        rangeLine,
        `Allowlisted findings: ${joinedReport?.allowlistedCount ?? 0}`,
        "",
        FIXED_PASS_DISCLAIMER,
        "Click to open Checkwash Lens Quick Actions.",
      ].filter((x): x is string => x !== null);
      return {
        state: "Pass",
        text: `${lifecycle.stale ? "$(warning)" : "$(check)"} ${prefixLabel}: Pass${staleSuffix}`,
        tooltip: tooltipLines.join("\n"),
        colorTheme: lifecycle.stale ? "warning" : "default",
        isAnalyzing: false,
        isStale: lifecycle.stale,
      };
    }

    case "Error": {
      const tooltipLines = [
        `${prefixLabel} Verdict: ERROR (Result Unavailable)${staleSuffix}`,
        preCheckTooltipNotice,
        errorReason ? `Reason: ${errorReason}` : "Reason: Unknown execution or schema error",
        gaps.unread.length > 0 ? `Unread size refusals: ${gaps.unread.length}` : null,
        "Click to open Checkwash Lens Quick Actions.",
      ].filter((x): x is string => x !== null);
      return {
        state: "Error",
        text: `$(flame) ${prefixLabel}: Error${staleSuffix}`,
        tooltip: tooltipLines.join("\n"),
        colorTheme: "error",
        isAnalyzing: false,
        isStale: lifecycle.stale,
      };
    }

    case "Not Run":
    default: {
      return {
        state: "Not Run",
        text: `$(circle-slash) ${prefixLabel}: Not Run`,
        tooltip: [
          `Checkwash Lens: Not Run`,
          preCheckTooltipNotice,
          notRunReason ?? "Run 'Checkwash: Scan Committed Range' to analyze a commit range.",
          "Click to open Checkwash Lens Quick Actions.",
        ]
          .filter((x): x is string => x !== null)
          .join("\n"),
        colorTheme: "default",
        isAnalyzing: false,
        isStale: false,
      };
    }
  }
}
