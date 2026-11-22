/**
 * ui/diagnostics.ts
 *
 * Live Editor Diagnostic Projection Model & Controller (Rev 3 §5.3, §5.4, §6).
 *
 * Strict Contract Guarantees:
 * 1. Only findings/hints with `liveProjectionAllowed === true` and `liveVscodeLine0Based !== null`
 *    are projected into live editor Diagnostics.
 * 2. Base-side (`side === "base"`), file-level (`startLine1Based === null`), or `allowlisted`
 *    findings are NEVER projected into live editor Diagnostics (never fabricates line 1).
 * 3. Checkwash findings (`source: "Checkwash (v0.13.1)"`) and Fast Guard hints
 *    (`source: "Fast Guard (Heuristic — Non-Verdict)"`) are kept in separate collections
 *    and NEVER deduplicated against each other.
 * 4. Fast Guard hints use strictly informational severity (`"Information"`), never `"Error"`.
 */

import { EnrichedFindingLocation } from "../engine/checkwashRunner";
import { FAST_GUARD_SOURCE_LABEL, FastGuardHint } from "../engine/fastDiffGuard";

export const CHECKWASH_DIAGNOSTIC_SOURCE = "Checkwash (v0.13.1)";

export type PlannedDiagnosticSeverity = "Error" | "Warning" | "Information";

export interface PlannedLiveDiagnosticItem {
  layer: "checkwash" | "fast_guard";
  source: string;
  ruleId: string;
  severity: PlannedDiagnosticSeverity;
  relativePath: string;
  vscodeLine0Based: number;
  message: string;
  fingerprintOrId: string;
  declaredUnitPath: string | null;
  preferredRevisionUri: string | null;
}

export interface LiveDiagnosticsPlan {
  /** Map of repository-relative file path -> Checkwash engine diagnostics */
  checkwashByFile: ReadonlyMap<string, PlannedLiveDiagnosticItem[]>;
  /** Map of repository-relative file path -> Fast Guard heuristic diagnostics */
  fastGuardByFile: ReadonlyMap<string, PlannedLiveDiagnosticItem[]>;
  /** Count of Checkwash findings intentionally withheld from live editor (kept in TreeView) */
  withheldCheckwashCount: number;
  /** Count of Fast Guard hints intentionally withheld from live editor (kept in TreeView) */
  withheldFastGuardCount: number;
}

/**
 * Pure function that computes the exact Live Editor Diagnostic projection plan
 * from `EnrichedFindingLocation[]` and `FastGuardHint[]`.
 */
export function buildLiveDiagnosticsPlan(
  enrichedFindings: readonly EnrichedFindingLocation[],
  fastGuardHints: readonly FastGuardHint[] = []
): LiveDiagnosticsPlan {
  const checkwashByFile = new Map<string, PlannedLiveDiagnosticItem[]>();
  const fastGuardByFile = new Map<string, PlannedLiveDiagnosticItem[]>();
  let withheldCheckwashCount = 0;
  let withheldFastGuardCount = 0;

  for (const ef of enrichedFindings) {
    if (
      !ef.liveProjectionAllowed ||
      ef.liveVscodeLine0Based === null ||
      ef.item.finding.allowlisted ||
      ef.item.locationKind !== "line" ||
      ef.item.evidenceSide !== "head" ||
      ef.item.startLine1Based === null ||
      ef.item.vscodeLine0Based === null ||
      ef.liveVscodeLine0Based < 0
    ) {
      withheldCheckwashCount++;
      continue;
    }

    const relPath = ef.item.resolvedSourcePath;
    const crossFileNote =
      ef.item.declaredUnitPath !== ef.item.resolvedSourcePath
        ? ` [provenance for unit: ${ef.item.declaredUnitPath}]`
        : "";
    const diagSeverity: PlannedDiagnosticSeverity =
      ef.item.finding.severity === "critical" || ef.item.finding.severity === "high"
        ? "Error"
        : ef.item.finding.severity === "warn"
        ? "Warning"
        : "Information";

    const list = checkwashByFile.get(relPath) ?? [];
    list.push({
      layer: "checkwash",
      source: CHECKWASH_DIAGNOSTIC_SOURCE,
      ruleId: ef.item.finding.rule,
      severity: diagSeverity,
      relativePath: relPath,
      vscodeLine0Based: ef.liveVscodeLine0Based,
      message: `[${ef.item.finding.rule}] ${ef.item.finding.message}${crossFileNote}`,
      fingerprintOrId: ef.item.finding.fingerprint,
      declaredUnitPath: ef.item.declaredUnitPath,
      preferredRevisionUri: ef.preferredRevisionUri,
    });
    checkwashByFile.set(relPath, list);
  }

  for (const hint of fastGuardHints) {
    if (
      !hint.liveProjectionAllowed ||
      hint.liveVscodeLine0Based === null ||
      hint.side !== "head" ||
      hint.headLine1Based === null ||
      hint.liveVscodeLine0Based < 0
    ) {
      withheldFastGuardCount++;
      continue;
    }

    const relPath = hint.relativePath;
    const list = fastGuardByFile.get(relPath) ?? [];
    list.push({
      layer: "fast_guard",
      source: FAST_GUARD_SOURCE_LABEL,
      ruleId: hint.ruleId,
      severity: "Information",
      relativePath: relPath,
      vscodeLine0Based: hint.liveVscodeLine0Based,
      message: `[${hint.ruleId}] ${hint.message}`,
      fingerprintOrId: `fg-${hint.hintIndex}-${hint.ruleId}`,
      declaredUnitPath: null,
      preferredRevisionUri: hint.revisionUri,
    });
    fastGuardByFile.set(relPath, list);
  }

  return {
    checkwashByFile,
    fastGuardByFile,
    withheldCheckwashCount,
    withheldFastGuardCount,
  };
}
