/**
 * ui/treeView.ts
 *
 * Sidebar TreeView Hierarchy Model & Provider (Rev 3 §5, §6, §9 + v0.5.0 UX Cockpit).
 *
 * Enforces:
 * - Strict separation between:
 *   1. Checkwash Verdict & Pinned Scan Identity (plus Quick-Start actions when idle)
 *   2. Analysis Gaps & Configuration Warnings (never hidden under Pass or Block)
 *   3. Checkwash Static Findings (Non-Allowlisted vs Allowlisted; preserves duplicate identities 1-to-1;
 *      shows cross-file helper/conftest provenance; never invents line 1 for file-level/base findings)
 *   4. Fast Guard Heuristic Hints (strictly non-verdict, never deduplicated against Checkwash)
 *   5. Checkwash Prove Satellite Results (shows all coexisting groups; shows fixed disclaimer on 0 loss;
 *      exposes Replay action ONLY for session-trusted records, never for imported external reports)
 * - Pure data view-model (zero `vscode` module dependency; plain-string tooltips only).
 */

import { CheckwashFindingsDocumentV2 } from "../core/checkwashSchema";
import { NO_CONFIRMED_LOSS_FIXED_MESSAGE } from "../core/proveModel";
import { sanitizeUntrustedDisplayString } from "../core/sourceIdentity";
import {
  CheckwashEvaluatedState,
  UNCOMMITTED_PRECHECK_SCOPE_NOTICE,
} from "../core/verdictModel";
import { EnrichedFindingLocation } from "../engine/checkwashRunner";
import {
  FAST_GUARD_NON_VERDICT_NOTICE,
  FastGuardAnalysisResult,
} from "../engine/fastDiffGuard";
import { ProveSessionOutcome } from "../satellite/proveRunner";
import { buildRevisionUriString } from "../source/revisionProvider";

export type TreeNodeCommandId =
  | "checkwashLens.openImmutableRevision"
  | "checkwashLens.replayMutant"
  | "checkwashLens.scanUncommittedSnapshot"
  | "checkwashLens.scanCommittedRange"
  | "checkwashLens.runEnvironmentDoctor"
  | "checkwashLens.viewOfflineReport"
  | "checkwashLens.openQuickActions";

export interface TreeNodeCommand {
  commandId: TreeNodeCommandId;
  title: string;
  arguments: unknown[];
}

export interface TreeNodeFindingNavigation {
  relativePath: string;
  baseRevisionUri: string | null;
  headRevisionUri: string | null;
  preferredRevisionUri: string | null;
  revealLine1Based: number | null;
  evidenceSide: "head" | "base" | "unknown";
  ruleLabel: string;
}

export interface CheckwashTreeNode {
  id: string;
  kind:
    | "verdict_root"
    | "gaps_root"
    | "findings_root"
    | "fast_guard_root"
    | "prove_root"
    | "offline_checkwash_root"
    | "group"
    | "item";
  label: string;
  description?: string;
  tooltip?: string;
  iconId?: string;
  iconColor?: string;
  contextValue?: string;
  collapsibleDefault?: "none" | "collapsed" | "expanded";
  findingNav?: TreeNodeFindingNavigation;
  children: CheckwashTreeNode[];
  command?: TreeNodeCommand;
}

export interface BuildTreeModelInput {
  evaluatedState: CheckwashEvaluatedState;
  enrichedFindings: readonly EnrichedFindingLocation[];
  fastGuardResult: FastGuardAnalysisResult | null;
  proveOutcome: ProveSessionOutcome;
  offlineFindingsPreview?: CheckwashFindingsDocumentV2 | null;
}

function resolveVerdictRootIcon(
  evaluatedState: CheckwashEvaluatedState
): { iconId: string; iconColor?: string } {
  if (evaluatedState.lifecycle.analyzing) {
    return { iconId: "sync~spin" };
  }
  switch (evaluatedState.state) {
    case "Block":
      return { iconId: "error", iconColor: "testing.iconFailed" };
    case "Partial / Review":
      return { iconId: "warning", iconColor: "list.warningForeground" };
    case "Pass":
      if (evaluatedState.lifecycle.stale) {
        return { iconId: "warning", iconColor: "list.warningForeground" };
      }
      return { iconId: "pass-filled", iconColor: "testing.iconPassed" };
    case "Error":
      return { iconId: "flame", iconColor: "testing.iconFailed" };
    case "Not Run":
    default:
      return { iconId: "shield" };
  }
}

/**
 * Pure function that builds the complete sidebar TreeView model.
 */
export function buildCheckwashTreeModel(input: BuildTreeModelInput): CheckwashTreeNode[] {
  const {
    evaluatedState,
    enrichedFindings,
    fastGuardResult,
    proveOutcome,
    offlineFindingsPreview,
  } = input;
  const roots: CheckwashTreeNode[] = [];

  // =========================================================================
  // 1. Verdict & Identity Root Node
  // =========================================================================
  const verdictChildren: CheckwashTreeNode[] = [];
  const scanScope = evaluatedState.scanScope ?? "committed";
  const isPreCheck = scanScope === "staged-precheck" || scanScope === "worktree-precheck";

  if (isPreCheck) {
    const scopeTargetLabel =
      scanScope === "staged-precheck" ? "HEAD -> Staged Index" : "HEAD -> Working Tree";
    verdictChildren.push({
      id: "verdict_precheck_scope_notice",
      kind: "item",
      label: `Scope: Uncommitted Snapshot Pre-Check (${scopeTargetLabel})`,
      description: "Pre-commit preview — does NOT replace a committed-range verdict",
      tooltip: UNCOMMITTED_PRECHECK_SCOPE_NOTICE,
      iconId: "info",
      children: [],
    });
  }

  if (evaluatedState.disclaimer) {
    verdictChildren.push({
      id: "verdict_disclaimer",
      kind: "item",
      label: evaluatedState.disclaimer,
      iconId: "info",
      children: [],
    });
  }
  if (evaluatedState.errorReason) {
    verdictChildren.push({
      id: "verdict_error_reason",
      kind: "item",
      label: `Error: ${evaluatedState.errorReason}`,
      iconId: "error",
      iconColor: "testing.iconFailed",
      children: [],
    });
  }
  if (evaluatedState.notRunReason) {
    verdictChildren.push({
      id: "verdict_notrun_reason",
      kind: "item",
      label: `Status: ${evaluatedState.notRunReason}`,
      iconId: "info",
      children: [],
    });
  }
  if (evaluatedState.joinedReport) {
    const id = evaluatedState.joinedReport.scanIdentity;
    verdictChildren.push(
      {
        id: "verdict_range",
        kind: "item",
        label: isPreCheck
          ? `Pinned Snapshot: ${id.effectiveBaseOid.slice(0, 12)}..${id.effectiveHeadOid.slice(0, 12)}`
          : `Pinned Range: ${id.effectiveBaseOid.slice(0, 12)}..${id.effectiveHeadOid.slice(0, 12)}`,
        description: `(${id.rawRangeSpec}, ${id.rangeMode})`,
        tooltip: isPreCheck
          ? `Base HEAD OID: ${id.effectiveBaseOid}\nEphemeral Snapshot OID: ${id.effectiveHeadOid}`
          : `Base OID: ${id.effectiveBaseOid}\nHead OID: ${id.effectiveHeadOid}`,
        iconId: "git-commit",
        children: [],
      },
      {
        id: "verdict_engine",
        kind: "item",
        label: `Engine: Checkwash v${id.checkwashVersion}`,
        description: `sha256:${id.checkwashPyzSha256.slice(0, 12)} (build:${id.checkwashBuildCommit.slice(0, 10)})`,
        iconId: "verified",
        children: [],
      }
    );
  }

  // Idle Quick-Start cockpit items when Checkwash has not yet run
  if (evaluatedState.state === "Not Run" && !evaluatedState.lifecycle.analyzing) {
    verdictChildren.push({
      id: "verdict_quickstart_group",
      kind: "group",
      label: "Quick Start Actions",
      description: "1-click entry points",
      iconId: "zap",
      collapsibleDefault: "expanded",
      children: [
        {
          id: "quickstart_worktree",
          kind: "item",
          label: "Pre-Check Working Tree",
          description: "HEAD -> Worktree + untracked",
          tooltip:
            "Builds an ephemeral snapshot (never mutates .git) and checks all working-tree changes against HEAD.",
          iconId: "shield",
          children: [],
          command: {
            commandId: "checkwashLens.scanUncommittedSnapshot",
            title: "Pre-Check Working Tree",
            arguments: ["worktree"],
          },
        },
        {
          id: "quickstart_staged",
          kind: "item",
          label: "Pre-Check Staged Changes",
          description: "HEAD -> Git Index",
          tooltip:
            "Checks only git-staged index changes against HEAD (ignores unstaged working-tree edits).",
          iconId: "git-pull-request-draft",
          children: [],
          command: {
            commandId: "checkwashLens.scanUncommittedSnapshot",
            title: "Pre-Check Staged Changes",
            arguments: ["staged"],
          },
        },
        {
          id: "quickstart_committed",
          kind: "item",
          label: "Scan Committed Range",
          description: "Branch / last commit",
          tooltip:
            "Select a local branch preset (e.g., HEAD~1..HEAD or main...HEAD) for authoritative Checkwash analysis.",
          iconId: "git-compare",
          children: [],
          command: {
            commandId: "checkwashLens.scanCommittedRange",
            title: "Scan Committed Range",
            arguments: [],
          },
        },
        {
          id: "quickstart_doctor",
          kind: "item",
          label: "Run Environment Doctor",
          description: "Python, Git & Broker check",
          tooltip:
            "Inspects runtime binaries, Workspace Trust, and machine-scoped security settings.",
          iconId: "pulse",
          children: [],
          command: {
            commandId: "checkwashLens.runEnvironmentDoctor",
            title: "Run Environment Doctor",
            arguments: [],
          },
        },
        {
          id: "quickstart_offline",
          kind: "item",
          label: "View Offline Report",
          description: "Read-only JSON viewer",
          tooltip:
            "Opens an existing Checkwash JSON v2 or Prove v0.1.0 report in read-only mode without spawning processes.",
          iconId: "file-code",
          children: [],
          command: {
            commandId: "checkwashLens.viewOfflineReport",
            title: "View Offline Report",
            arguments: [],
          },
        },
      ],
    });
  }

  const verdictRootLabel =
    scanScope === "staged-precheck"
      ? `Checkwash Pre-Check (Staged Index): ${evaluatedState.state}`
      : scanScope === "worktree-precheck"
      ? `Checkwash Pre-Check (Working Tree): ${evaluatedState.state}`
      : `Checkwash Verdict: ${evaluatedState.state}`;
  const verdictIcon = resolveVerdictRootIcon(evaluatedState);

  roots.push({
    id: "verdict_root",
    kind: "verdict_root",
    label: verdictRootLabel,
    description: evaluatedState.lifecycle.analyzing
      ? "Analyzing..."
      : evaluatedState.lifecycle.stale
      ? "Stale"
      : isPreCheck
      ? "Pre-Commit Snapshot — Non-Authoritative"
      : undefined,
    iconId: verdictIcon.iconId,
    iconColor: verdictIcon.iconColor,
    collapsibleDefault: "expanded",
    children: verdictChildren,
  });

  // =========================================================================
  // 2. Coverage Gaps & Configuration Warnings Root Node
  // =========================================================================
  const { gaps } = evaluatedState;
  if (gaps.hasAnyGap) {
    const gapChildren: CheckwashTreeNode[] = [];
    gaps.unread.forEach((u, idx) => {
      gapChildren.push({
        id: `gap_unread_${idx}`,
        kind: "item",
        label: `[Unread] ${u.path} (${u.side})`,
        description: `${u.size} bytes > limit ${u.limit} bytes`,
        iconId: "warning",
        iconColor: "list.warningForeground",
        children: [],
      });
    });
    gaps.skippedFiles.forEach((p, idx) => {
      gapChildren.push({
        id: `gap_skipped_${idx}`,
        kind: "item",
        label: `[Skipped File] ${p}`,
        iconId: "warning",
        iconColor: "list.warningForeground",
        children: [],
      });
    });
    gaps.configErrors.forEach((ce, idx) => {
      gapChildren.push({
        id: `gap_cfg_${idx}`,
        kind: "item",
        label: `[Config Error] ${ce}`,
        iconId: "error",
        iconColor: "testing.iconFailed",
        children: [],
      });
    });
    gaps.sarifNotifications.forEach((n, idx) => {
      gapChildren.push({
        id: `gap_sarif_notif_${idx}`,
        kind: "item",
        label: `[SARIF ${n.kind}] ${n.path ?? ""}`,
        description: n.message,
        iconId: "warning",
        iconColor: "list.warningForeground",
        children: [],
      });
    });
    gaps.jsonStderrNotes.forEach((line, idx) => {
      gapChildren.push({
        id: `gap_json_stderr_${idx}`,
        kind: "item",
        label: `[JSON stderr] ${line}`,
        iconId: "note",
        children: [],
      });
    });
    gaps.sarifStderrNotes.forEach((line, idx) => {
      gapChildren.push({
        id: `gap_sarif_stderr_${idx}`,
        kind: "item",
        label: `[SARIF stderr] ${line}`,
        iconId: "note",
        children: [],
      });
    });

    roots.push({
      id: "gaps_root",
      kind: "gaps_root",
      label: `Analysis Gaps & Warnings (${gapChildren.length})`,
      description: "Incomplete coverage or configuration issues",
      iconId: "warning",
      iconColor: "list.warningForeground",
      collapsibleDefault: "expanded",
      children: gapChildren,
    });
  }

  // =========================================================================
  // 3. Checkwash Static Findings Root Node (Non-Allowlisted vs Allowlisted)
  // =========================================================================
  const activeFindingNodes: CheckwashTreeNode[] = [];
  const allowlistedFindingNodes: CheckwashTreeNode[] = [];

  for (const ef of enrichedFindings) {
    const f = ef.item.finding;
    const isCrossFile = ef.item.declaredUnitPath !== ef.item.resolvedSourcePath;
    const normalizedSourcePath = ef.item.resolvedSourcePath.replace(/\\/g, "/");
    const fileBasename =
      normalizedSourcePath.split("/").pop() || ef.item.resolvedSourcePath;
    const shortLoc =
      ef.item.locationKind === "line" && ef.item.startLine1Based !== null
        ? `${fileBasename}:${ef.item.startLine1Based}`
        : fileBasename;
    const provenanceSuffix = isCrossFile
      ? ` [from unit: ${ef.item.declaredUnitPath}]`
      : normalizedSourcePath.includes("/")
      ? ` (${normalizedSourcePath})`
      : "";

    const cmd: TreeNodeCommand | undefined = ef.preferredRevisionUri
      ? {
          commandId: "checkwashLens.openImmutableRevision",
          title: "Open Analyzed Revision",
          arguments: [ef.preferredRevisionUri, ef.revealLine1Based],
        }
      : undefined;

    const sevLower = String(f.severity).toLowerCase();
    const isErrorSev = sevLower === "critical" || sevLower === "high" || sevLower === "error";
    const node: CheckwashTreeNode = {
      id: `cw_finding_${ef.item.jsonIndex}`,
      kind: "item",
      label: `${shortLoc} · ${f.rule}`,
      description: `(${f.severity}, ${ef.item.evidenceSide})${provenanceSuffix} — ${f.message}`,
      tooltip: [
        `Rule: ${f.rule} (${f.severity})`,
        `Message: ${f.message}`,
        `Declared Unit Path: ${ef.item.declaredUnitPath}`,
        `Resolved Source Path: ${ef.item.resolvedSourcePath}`,
        `Evidence Side: ${ef.item.evidenceSide}`,
        `Line: ${ef.item.startLine1Based ?? "null (file-level)"}`,
        `Live Projection: ${ef.liveProjectionAllowed ? "Allowed" : `Withheld (${ef.liveProjectionReason})`}`,
        `Actions: Click row to open analyzed revision, or use inline icons to Compare Base <-> Head Diff or Open Editable File.`,
      ].join("\n"),
      iconId: f.allowlisted ? "circle-large-outline" : isErrorSev ? "error" : "warning",
      iconColor: f.allowlisted
        ? "disabledForeground"
        : isErrorSev
        ? "testing.iconFailed"
        : "list.warningForeground",
      contextValue: "checkwashFinding",
      findingNav: {
        relativePath: ef.item.resolvedSourcePath,
        baseRevisionUri: ef.baseRevisionUri,
        headRevisionUri: ef.headRevisionUri,
        preferredRevisionUri: ef.preferredRevisionUri,
        revealLine1Based: ef.revealLine1Based,
        evidenceSide: ef.item.evidenceSide,
        ruleLabel: `${f.rule} (${f.severity})`,
      },
      children: [],
      command: cmd,
    };

    if (f.allowlisted) {
      allowlistedFindingNodes.push(node);
    } else {
      activeFindingNodes.push(node);
    }
  }

  const totalFindingsCount = activeFindingNodes.length + allowlistedFindingNodes.length;
  const findingsSubGroups: CheckwashTreeNode[] = [
    {
      id: "findings_active_group",
      kind: "group",
      label: `Active Findings (${activeFindingNodes.length})`,
      iconId: activeFindingNodes.length > 0 ? "flame" : "check",
      iconColor: activeFindingNodes.length > 0 ? "testing.iconFailed" : undefined,
      collapsibleDefault: activeFindingNodes.length > 0 ? "expanded" : "collapsed",
      children: activeFindingNodes,
    },
  ];
  if (allowlistedFindingNodes.length > 0) {
    findingsSubGroups.push({
      id: "findings_allowlisted_group",
      kind: "group",
      label: `Allowlisted Findings (${allowlistedFindingNodes.length})`,
      description: "Exempted via allowlist; preserved for audit",
      iconId: "shield",
      collapsibleDefault: "collapsed",
      children: allowlistedFindingNodes,
    });
  }

  roots.push({
    id: "findings_root",
    kind: "findings_root",
    label: `Checkwash Findings (${activeFindingNodes.length} active, ${allowlistedFindingNodes.length} allowlisted)`,
    iconId:
      activeFindingNodes.length > 0
        ? "error"
        : evaluatedState.state === "Pass"
        ? "pass-filled"
        : "checklist",
    iconColor:
      activeFindingNodes.length > 0
        ? "testing.iconFailed"
        : evaluatedState.state === "Pass"
        ? "testing.iconPassed"
        : undefined,
    collapsibleDefault: totalFindingsCount > 0 ? "expanded" : "collapsed",
    children: findingsSubGroups,
  });

  // =========================================================================
  // 4. Fast Guard Heuristic Hints Root Node (Independent Layer)
  // =========================================================================
  const fgHintNodes: CheckwashTreeNode[] = [];
  const scanIdInfo = evaluatedState.joinedReport?.scanIdentity ?? null;

  if (fastGuardResult) {
    for (const h of fastGuardResult.hints) {
      const lineLabel =
        h.side === "head" && h.headLine1Based !== null
          ? `head line ${h.headLine1Based}`
          : h.side === "base" && h.baseLine1Based !== null
          ? `base line ${h.baseLine1Based}`
          : h.side;
      const revealLine = h.headLine1Based ?? h.baseLine1Based;

      const cmd: TreeNodeCommand | undefined = h.revisionUri
        ? {
            commandId: "checkwashLens.openImmutableRevision",
            title: "Open Revision for Hint",
            arguments: [h.revisionUri, revealLine],
          }
        : undefined;

      const candidateBaseRes = scanIdInfo
        ? buildRevisionUriString({
            repositoryRoot: scanIdInfo.repositoryRoot,
            commitOid: fastGuardResult.effectiveBaseOid,
            relativePath: h.relativePath,
            side: "base",
            scanId: scanIdInfo.scanId,
          })
        : null;
      const candidateHeadRes = scanIdInfo
        ? buildRevisionUriString({
            repositoryRoot: scanIdInfo.repositoryRoot,
            commitOid: fastGuardResult.effectiveHeadOid,
            relativePath: h.relativePath,
            side: "head",
            scanId: scanIdInfo.scanId,
          })
        : null;

      const normalizedHintPath = h.relativePath.replace(/\\/g, "/");
      const hintBasename = normalizedHintPath.split("/").pop() || h.relativePath;
      const hintLineNum = h.side === "head" ? h.headLine1Based : h.baseLine1Based;
      const hintShortLoc =
        hintLineNum !== null ? `${hintBasename}:${hintLineNum}` : hintBasename;
      const hintShortRule = h.ruleId.replace(/^FG-/, "");

      fgHintNodes.push({
        id: `fg_hint_${h.hintIndex}`,
        kind: "item",
        label: `${hintShortLoc} · ${hintShortRule}`,
        description: `[${h.ruleId}, ${lineLabel}] ${h.message}`,
        tooltip: [
          h.sourceLabel,
          h.message,
          `Snippet: ${h.snippet}`,
          `Actions: Click row to open analyzed revision, or use inline icons to Compare Base <-> Head Diff or Open Editable File.`,
        ].join("\n"),
        iconId: "lightbulb",
        iconColor: "editorInfo.foreground",
        contextValue: "checkwashFinding",
        findingNav: {
          relativePath: h.relativePath,
          baseRevisionUri: candidateBaseRes && candidateBaseRes.ok ? candidateBaseRes.value : null,
          headRevisionUri: candidateHeadRes && candidateHeadRes.ok ? candidateHeadRes.value : null,
          preferredRevisionUri: h.revisionUri,
          revealLine1Based: revealLine,
          evidenceSide: h.side,
          ruleLabel: `${h.ruleId} (Fast Guard)`,
        },
        children: [],
        command: cmd,
      });
    }
  }

  roots.push({
    id: "fast_guard_root",
    kind: "fast_guard_root",
    label: `Fast Guard (Heuristic — Non-Verdict) (${fgHintNodes.length})`,
    description: FAST_GUARD_NON_VERDICT_NOTICE,
    iconId: "eye",
    collapsibleDefault: fgHintNodes.length > 0 ? "expanded" : "collapsed",
    children: fgHintNodes,
  });

  // =========================================================================
  // 5. Checkwash Prove Satellite Root Node (Manual Execution & Read-Only View)
  // =========================================================================
  const proveChildren: CheckwashTreeNode[] = [];
  const rec = proveOutcome.record;

  if (proveOutcome.errorReason) {
    proveChildren.push({
      id: "prove_error_reason",
      kind: "item",
      label: `Error: ${proveOutcome.errorReason}`,
      iconId: "error",
      iconColor: "testing.iconFailed",
      children: [],
    });
  }

  if (rec) {
    const pr = rec.parsedReport;
    const canReplay =
      !rec.isImportedExternalReport &&
      rec.exitCode === 0 &&
      proveOutcome.status !== "Execution error";

    const modeLabel = rec.isImportedExternalReport
      ? "Mode: Imported External Report (Read-Only)"
      : rec.exitCode !== 0
      ? `Mode: ${rec.entryKind.toUpperCase()} (Read-Only Diagnostic — Exit ${rec.exitCode})`
      : `Mode: ${rec.entryKind.toUpperCase()}`;

    const reportStatusLabel = `${pr.status}${pr.notComparedReason ? ` (${pr.notComparedReason})` : ""}`;
    const metaDescription =
      proveOutcome.status !== pr.status
        ? `Outcome: ${proveOutcome.status} | Report Status: ${reportStatusLabel}`
        : `Status: ${reportStatusLabel}`;

    proveChildren.push({
      id: "prove_meta",
      kind: "item",
      label: modeLabel,
      description: metaDescription,
      iconId: "info",
      children: [],
    });

    const scopeDescription =
      pr.skippedOverCapCount > 0 && pr.runCount === 0
        ? `Cap-limited & zero executed: ${pr.skippedOverCapCount} of ${pr.generatedCount} generated mutant(s) exceeded cap (max_mutants=${rec.effectiveOptions.maxMutants}); 0 executed`
        : pr.skippedOverCapCount > 0
        ? `Cap-limited scope: ${pr.skippedOverCapCount} of ${pr.generatedCount} generated mutant(s) skipped over cap (max_mutants=${rec.effectiveOptions.maxMutants})`
        : pr.runCount === 0
        ? `Zero mutants executed (generated=${pr.generatedCount}, max_mutants=${rec.effectiveOptions.maxMutants})`
        : `All ${pr.runCount} generated mutant(s) executed within cap (max_mutants=${rec.effectiveOptions.maxMutants})`;

    proveChildren.push({
      id: "prove_scope_summary",
      kind: "item",
      label: `Scope: generated=${pr.generatedCount}, run=${pr.runCount}, skipped_over_cap=${pr.skippedOverCapCount}`,
      description: scopeDescription,
      tooltip: [
        `Generated mutants: ${pr.generatedCount}`,
        `Executed mutants: ${pr.runCount}`,
        `Skipped over cap: ${pr.skippedOverCapCount}`,
        `Configured max_mutants: ${rec.effectiveOptions.maxMutants}`,
      ].join("\n"),
      iconId: "symbol-numeric",
      children: [],
    });

    if (pr.rawStatusText.length > 0) {
      const statusLines = pr.rawStatusText.split(/\r?\n/);
      proveChildren.push({
        id: "prove_raw_status",
        kind: statusLines.length > 1 ? "group" : "item",
        label: `Upstream Status: ${statusLines[0]}`,
        description: statusLines.length > 1 ? `(+${statusLines.length - 1} more line(s))` : undefined,
        tooltip: pr.rawStatusText,
        iconId: "output",
        collapsibleDefault: "collapsed",
        children:
          statusLines.length > 1
            ? statusLines.map((line, idx) => ({
                id: `prove_raw_status_line_${idx}`,
                kind: "item" as const,
                label: line,
                tooltip: pr.rawStatusText,
                children: [],
              }))
            : [],
      });
    }

    if (pr.noConfirmedLossExplanation) {
      proveChildren.push({
        id: "prove_zero_loss_disclaimer",
        kind: "item",
        label: pr.noConfirmedLossExplanation,
        description: NO_CONFIRMED_LOSS_FIXED_MESSAGE,
        iconId: "info",
        children: [],
      });
    }

    if (pr.notes.length > 0) {
      proveChildren.push({
        id: "prove_group_notes",
        kind: "group",
        label: `Upstream Notes & Limitations (${pr.notes.length})`,
        iconId: "note",
        collapsibleDefault: "expanded",
        children: pr.notes.map((note, idx) => {
          const noteLines = note.split(/\r?\n/);
          if (noteLines.length > 1) {
            return {
              id: `prove_note_${idx}`,
              kind: "group" as const,
              label: noteLines[0],
              description: `(+${noteLines.length - 1} more line(s))`,
              tooltip: note,
              collapsibleDefault: "collapsed" as const,
              children: noteLines.map((line, lIdx) => ({
                id: `prove_note_${idx}_line_${lIdx}`,
                kind: "item" as const,
                label: line,
                tooltip: note,
                children: [],
              })),
            };
          }
          return {
            id: `prove_note_${idx}`,
            kind: "item" as const,
            label: note,
            tooltip: note,
            children: [],
          };
        }),
      });
    }

    // Coexisting Group A: protection_losses
    if (pr.protectionLosses.length > 0) {
      proveChildren.push({
        id: "prove_group_protection_losses",
        kind: "group",
        label: `Protection Losses (${pr.protectionLosses.length})`,
        iconId: "bug",
        iconColor: "testing.iconFailed",
        collapsibleDefault: "expanded",
        children: pr.protectionLosses.map((loss, idx) => ({
          id: `prove_pl_${idx}_${loss.id}`,
          kind: "item",
          label: `[${loss.id}] ${loss.path}:${loss.line} (${loss.op})`,
          description: `${loss.before} -> ${loss.after}`,
          tooltip: `Display-only replay hint: ${loss.replay}`,
          iconId: "error",
          iconColor: "testing.iconFailed",
          contextValue: canReplay ? "checkwashProveReplayable" : undefined,
          children: [],
          command: canReplay
            ? {
                commandId: "checkwashLens.replayMutant",
                title: "Replay Single Mutant",
                arguments: [rec.runId, loss.id],
              }
            : undefined,
        })),
      });
    }

    // Coexisting Group B: unconfirmed_losses
    if (pr.unconfirmedLosses.length > 0) {
      proveChildren.push({
        id: "prove_group_unconfirmed_losses",
        kind: "group",
        label: `Unconfirmed Losses (${pr.unconfirmedLosses.length})`,
        iconId: "warning",
        iconColor: "list.warningForeground",
        collapsibleDefault: "expanded",
        children: pr.unconfirmedLosses.map((loss, idx) => ({
          id: `prove_ul_${idx}_${loss.id}`,
          kind: "item",
          label: `[${loss.id}] ${loss.path}:${loss.line} (${loss.op})`,
          description: loss.why ?? `${loss.before} -> ${loss.after}`,
          iconId: "warning",
          iconColor: "list.warningForeground",
          contextValue: canReplay ? "checkwashProveReplayable" : undefined,
          children: [],
          command: canReplay
            ? {
                commandId: "checkwashLens.replayMutant",
                title: "Replay Single Mutant",
                arguments: [rec.runId, loss.id],
              }
            : undefined,
        })),
      });
    }

    // Coexisting Group C: needs_clarification (strictly plain data; never executes commands or Replay)
    if (pr.needsClarification.length > 0) {
      proveChildren.push({
        id: "prove_group_needs_clarification",
        kind: "group",
        label: `Needs Clarification (${pr.needsClarification.length})`,
        iconId: "question",
        collapsibleDefault: "expanded",
        children: pr.needsClarification.map((nc, idx) => {
          const detailLines = nc.detail.length > 0 ? nc.detail.split(/\r?\n/) : [];
          const firstDetailPreview = detailLines.length > 0 ? ` | ${detailLines[0]}` : "";
          const tooltipLines = [
            `Test: ${nc.test}`,
            `Reason: ${nc.reason}`,
            `Also fails in new: ${nc.also_fails_in_new}`,
          ];
          if (nc.detail.length > 0) {
            tooltipLines.push(`Detail:\n${nc.detail}`);
          }
          return {
            id: `prove_nc_${idx}`,
            kind: detailLines.length > 0 ? ("group" as const) : ("item" as const),
            label: `${nc.test} — ${nc.reason}`,
            description: `also_fails_in_new=${nc.also_fails_in_new}${firstDetailPreview}`,
            tooltip: tooltipLines.join("\n"),
            iconId: "question",
            collapsibleDefault: detailLines.length > 0 ? ("collapsed" as const) : undefined,
            children: detailLines.map((line, lIdx) => ({
              id: `prove_nc_${idx}_detail_${lIdx}`,
              kind: "item" as const,
              label: line,
              tooltip: nc.detail,
              children: [],
            })),
          };
        }),
      });
    }

    // Coexisting Group D: undecided rows
    if (pr.undecidedRows.length > 0) {
      proveChildren.push({
        id: "prove_group_undecided",
        kind: "group",
        label: `Undecided Mutants (${pr.undecidedRows.length})`,
        iconId: "question",
        collapsibleDefault: "collapsed",
        children: pr.undecidedRows.map((u, idx) => ({
          id: `prove_undecided_${idx}_${u.id}`,
          kind: "item",
          label: `[${u.id}] ${u.path ?? ""}:${String(u.line ?? "")}`,
          description: u.reason ?? "undecided",
          iconId: "circle-outline",
          contextValue: canReplay ? "checkwashProveReplayable" : undefined,
          children: [],
          command: canReplay
            ? {
                commandId: "checkwashLens.replayMutant",
                title: "Replay Single Mutant",
                arguments: [rec.runId, u.id],
              }
            : undefined,
        })),
      });
    }

    // Coexisting Group E: listed candidates (--list)
    if (pr.candidates.length > 0) {
      proveChildren.push({
        id: "prove_group_candidates",
        kind: "group",
        label: `Listed Mutant Candidates (${pr.candidates.length}) — Mutants Not Executed`,
        iconId: "list-ordered",
        collapsibleDefault: "expanded",
        children: pr.candidates.map((c, idx) => ({
          id: `prove_cand_${idx}_${c.id}`,
          kind: "item",
          label: `[#${c.rank} ${c.id}] ${c.path}:${c.line} (${c.op})`,
          description: `${c.before} -> ${c.after} (within_cap=${c.within_cap})`,
          iconId: "beaker",
          contextValue: canReplay ? "checkwashProveReplayable" : undefined,
          children: [],
          command: canReplay
            ? {
                commandId: "checkwashLens.replayMutant",
                title: "Replay Single Mutant",
                arguments: [rec.runId, c.id],
              }
            : undefined,
        })),
      });
    }
  }

  const isImportedProve = Boolean(rec?.isImportedExternalReport);
  roots.push({
    id: "prove_root",
    kind: "prove_root",
    label: isImportedProve
      ? `Checkwash Prove (Satellite) [Imported Read-Only]: ${proveOutcome.status}`
      : `Checkwash Prove (Satellite): ${proveOutcome.status}`,
    description: isImportedProve
      ? "Imported Offline Report — Read-Only Preview"
      : "Experimental — Manual Execution Only",
    iconId: isImportedProve ? "file-code" : "beaker",
    iconColor:
      (rec?.parsedReport.protectionLosses.length ?? 0) > 0 ||
      proveOutcome.status === "Execution error"
        ? "testing.iconFailed"
        : undefined,
    collapsibleDefault: proveChildren.length > 0 ? "expanded" : "collapsed",
    children: proveChildren,
  });

  // =========================================================================
  // 6. Offline Checkwash Report Preview (Read-Only, Non-Session-Altering)
  // =========================================================================
  if (offlineFindingsPreview) {
    const offlineChildren: CheckwashTreeNode[] = [
      {
        id: "offline_cw_meta",
        kind: "item",
        label: `Schema v${offlineFindingsPreview.schema_version} — Verdict: ${offlineFindingsPreview.verdict} (${offlineFindingsPreview.findings.length} finding(s))`,
        description: "Imported offline JSON v2 report (read-only)",
        iconId: "info",
        children: [],
      },
    ];

    const offlineGapChildren: CheckwashTreeNode[] = [];
    (offlineFindingsPreview.unread ?? []).forEach((u, idx) => {
      offlineGapChildren.push({
        id: `offline_cw_gap_unread_${idx}`,
        kind: "item",
        label: `[Unread] ${u.path} (${u.side})`,
        description: `${u.size} bytes > limit ${u.limit} bytes`,
        iconId: "warning",
        iconColor: "list.warningForeground",
        children: [],
      });
    });
    (offlineFindingsPreview.skipped_files ?? []).forEach((s, idx) => {
      offlineGapChildren.push({
        id: `offline_cw_gap_skipped_${idx}`,
        kind: "item",
        label: `[Skipped File] ${s}`,
        iconId: "warning",
        iconColor: "list.warningForeground",
        children: [],
      });
    });
    (offlineFindingsPreview.config_errors ?? []).forEach((ce, idx) => {
      offlineGapChildren.push({
        id: `offline_cw_gap_cfg_${idx}`,
        kind: "item",
        label: `[Config Error] ${ce}`,
        iconId: "error",
        iconColor: "testing.iconFailed",
        children: [],
      });
    });

    if (offlineGapChildren.length > 0) {
      offlineChildren.push({
        id: "offline_cw_gaps",
        kind: "group",
        label: `Offline Report Gaps (${offlineGapChildren.length})`,
        iconId: "warning",
        collapsibleDefault: "expanded",
        children: offlineGapChildren,
      });
    }

    const offlineFindingItems: CheckwashTreeNode[] = offlineFindingsPreview.findings.map(
      (f, idx) => {
        const lineInfo =
          f.after?.span?.[0] !== undefined
            ? `line ${f.after.span[0]} [after]`
            : f.before?.span?.[0] !== undefined
            ? `line ${f.before.span[0]} [before]`
            : "file-level";
        return {
          id: `offline_cw_finding_${idx}`,
          kind: "item",
          label: `[${f.rule}] (${f.severity}) ${f.path}${f.allowlisted ? " [allowlisted]" : ""}`,
          description: `${lineInfo} — ${f.message}`,
          tooltip: [
            `Rule: ${f.rule} (${f.severity})`,
            `Path: ${f.path}`,
            `Allowlisted: ${Boolean(f.allowlisted)}`,
            `Message: ${f.message}`,
          ].join("\n"),
          iconId: f.allowlisted ? "circle-large-outline" : "warning",
          children: [],
        };
      }
    );

    offlineChildren.push({
      id: "offline_cw_findings_group",
      kind: "group",
      label: `Offline Findings (${offlineFindingItems.length})`,
      iconId: "checklist",
      collapsibleDefault: offlineFindingItems.length > 0 ? "expanded" : "collapsed",
      children: offlineFindingItems,
    });

    roots.push({
      id: "offline_checkwash_root",
      kind: "offline_checkwash_root",
      label: `Offline Checkwash Report (Read-Only Preview): ${offlineFindingsPreview.verdict.toUpperCase()}`,
      description: "Read-only preview — does not alter active session verdict",
      iconId: "file-code",
      collapsibleDefault: "expanded",
      children: offlineChildren,
    });
  }

  const sanitizeTreeNodes = (nodes: CheckwashTreeNode[]): CheckwashTreeNode[] =>
    nodes.map((n) => ({
      ...n,
      label: sanitizeUntrustedDisplayString(n.label, { allowNewlines: false }),
      description:
        n.description !== undefined
          ? sanitizeUntrustedDisplayString(n.description, { allowNewlines: false })
          : undefined,
      tooltip:
        n.tooltip !== undefined
          ? sanitizeUntrustedDisplayString(n.tooltip, { allowNewlines: true })
          : undefined,
      children: n.children.length > 0 ? sanitizeTreeNodes(n.children) : [],
    }));

  return sanitizeTreeNodes(roots);
}
