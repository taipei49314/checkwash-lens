/**
 * core/reportJoiner.ts
 *
 * Complete pairing and consistency verification between Checkwash JSON v2 and SARIF 2.1.0.
 * Zero VS Code UI dependency; never spawns processes.
 *
 * Enforces Rev 3 §4.3, §5.1, §5.2, §5.3, §5.5 (A01, A02, A03, A04, A05, A06):
 * - Verifies shared PinnedScanIdentity between JSON and SARIF invocations.
 * - Preserves all findings (including allowlisted: true).
 * - Pairs non-allowlisted findings 1-to-1 in exact output order with SARIF results.
 *   Rejects length mismatches, out-of-order items, fingerprint/rule/level/message mismatches.
 *   Never truncates and never deduplicates repeated identities via a single-key map.
 * - Does not require JSON finding.path to equal SARIF artifactLocation.uri (supports helper/conftest provenance).
 * - Only produces a line-level location when SARIF provides a valid, in-range region.startLine
 *   (converting 1-based SARIF startLine to 0-based VS Code line).
 * - Keeps startLine1Based: null / vscodeLine0Based: null when region is absent or finding is allowlisted
 *   (never invents line 1). Uses actual checkwash.evidenceSide property ('head' | 'base'), or 'unknown' when absent.
 */

import {
  CheckwashFinding,
  CheckwashFindingsDocumentV2,
  CheckwashSarifDocument,
  SEVERITY_TO_SARIF_LEVEL,
  ValidationResult,
} from "./checkwashSchema";
import { decodeAndValidateSarifUri, isValidCommitOid, PinnedScanIdentity } from "./sourceIdentity";

export const PINNED_CHECKWASH_VERSION = "0.13.1";
export const PINNED_CHECKWASH_PYZ_SHA256 =
  "0a987325c6f738129f5dbdc1e0287cfeab40517342b46df80707cccff8dd2839";
export const PINNED_CHECKWASH_BUILD_COMMIT = "5e2a89ef0d447ae6e08c289f4a3357325b7286e9";

export type EvidenceSideLabel = "head" | "base" | "unknown";

export interface JoinedFindingItem {
  /** Deterministic index in JSON findings array (0-based) */
  jsonIndex: number;
  /** Deterministic index in SARIF results array (0-based), or null if allowlisted */
  sarifIndex: number | null;
  finding: CheckwashFinding;
  /** The unit path reported in JSON finding.path (validated repository-relative) */
  declaredUnitPath: string;
  /** The resolved provenance source file path from SARIF (may be helper/conftest) */
  resolvedSourcePath: string;
  /** 1-based line number from SARIF region.startLine, or null if file-level / no region / allowlisted */
  startLine1Based: number | null;
  /** 0-based line number for VS Code Range, or null if file-level / no region / allowlisted */
  vscodeLine0Based: number | null;
  /** 'line' only when SARIF provided a verified region.startLine; 'file' otherwise */
  locationKind: "line" | "file";
  /** Evidence side from SARIF properties['checkwash.evidenceSide'] ('head'|'base') or 'unknown' */
  evidenceSide: EvidenceSideLabel;
  /** Optional evidenceText from SARIF properties['checkwash.evidenceText'] when region is absent */
  sarifEvidenceText: string | null;
}

export interface JoinedNotificationItem {
  kind: "coverage_gap" | "unread_side" | "other";
  message: string;
  path: string | null;
  side: string | null;
  line1Based: number | null;
  column1Based: number | null;
  size: number | null;
  limit: number | null;
}

export interface JoinedCheckwashReport {
  scanIdentity: PinnedScanIdentity;
  jsonDoc: CheckwashFindingsDocumentV2;
  sarifDoc: CheckwashSarifDocument;
  items: JoinedFindingItem[];
  allowlistedCount: number;
  nonAllowlistedCount: number;
  sarifNotifications: JoinedNotificationItem[];
}

export interface JoinCheckwashInput {
  jsonIdentity: PinnedScanIdentity;
  sarifIdentity: PinnedScanIdentity;
  jsonDoc: CheckwashFindingsDocumentV2;
  sarifDoc: CheckwashSarifDocument;
  /** Optional map of repository-relative path -> total line count in head revision */
  headFileLineCounts?: ReadonlyMap<string, number>;
}

function identitiesMatch(a: PinnedScanIdentity, b: PinnedScanIdentity): ValidationResult<true> {
  if (a.scanId !== b.scanId) {
    return { ok: false, error: `Scan ID mismatch between JSON (${a.scanId}) and SARIF (${b.scanId})` };
  }
  if (a.repositoryRoot !== b.repositoryRoot) {
    return { ok: false, error: "Repository root mismatch between JSON and SARIF runs" };
  }
  if (
    a.effectiveBaseOid !== b.effectiveBaseOid ||
    a.effectiveHeadOid !== b.effectiveHeadOid ||
    a.rawRangeSpec !== b.rawRangeSpec ||
    a.rangeMode !== b.rangeMode
  ) {
    return { ok: false, error: "Effective base/head commit OIDs differ between JSON and SARIF runs" };
  }
  if (
    !isValidCommitOid(a.effectiveBaseOid) ||
    !isValidCommitOid(a.effectiveHeadOid)
  ) {
    return { ok: false, error: "Effective base/head OIDs are not valid 40/64-char commit hashes" };
  }
  if (
    a.checkwashVersion !== PINNED_CHECKWASH_VERSION ||
    b.checkwashVersion !== PINNED_CHECKWASH_VERSION ||
    a.checkwashPyzSha256 !== PINNED_CHECKWASH_PYZ_SHA256 ||
    b.checkwashPyzSha256 !== PINNED_CHECKWASH_PYZ_SHA256
  ) {
    return { ok: false, error: "Checkwash artifact version or SHA-256 identity mismatch" };
  }
  if (
    a.pythonExecutable !== b.pythonExecutable ||
    a.pythonVersion !== b.pythonVersion ||
    a.gitExecutable !== b.gitExecutable ||
    a.gitVersion !== b.gitVersion ||
    a.controlledCwd !== b.controlledCwd
  ) {
    return { ok: false, error: "Runtime (Python/Git/cwd) identity changed between JSON and SARIF runs" };
  }
  return { ok: true, value: true };
}

export function joinCheckwashJsonAndSarif(
  input: JoinCheckwashInput
): ValidationResult<JoinedCheckwashReport> {
  const { jsonIdentity, sarifIdentity, jsonDoc, sarifDoc, headFileLineCounts } = input;

  const idCheck = identitiesMatch(jsonIdentity, sarifIdentity);
  if (!idCheck.ok) {
    return idCheck;
  }

  const sarifRun = sarifDoc.runs[0];
  if (
    jsonDoc.run.checkwash_version !== PINNED_CHECKWASH_VERSION ||
    sarifRun.tool.driver.semanticVersion !== PINNED_CHECKWASH_VERSION
  ) {
    return {
      ok: false,
      error: `Engine version mismatch: JSON=${jsonDoc.run.checkwash_version}, SARIF=${sarifRun.tool.driver.semanticVersion}, expected=${PINNED_CHECKWASH_VERSION}`,
    };
  }

  const sarifBase = sarifRun.properties["checkwash.base"];
  const sarifHead = sarifRun.properties["checkwash.head"];
  if (jsonDoc.run.base !== sarifBase || jsonDoc.run.head !== sarifHead) {
    return {
      ok: false,
      error: `Revision label mismatch between JSON (${jsonDoc.run.base}..${jsonDoc.run.head}) and SARIF (${sarifBase}..${sarifHead})`,
    };
  }

  if (
    !jsonIdentity.effectiveBaseOid.startsWith(jsonDoc.run.base) ||
    !jsonIdentity.effectiveHeadOid.startsWith(jsonDoc.run.head)
  ) {
    return {
      ok: false,
      error: `JSON run labels (${jsonDoc.run.base}..${jsonDoc.run.head}) do not match pinned OIDs (${jsonIdentity.effectiveBaseOid}..${jsonIdentity.effectiveHeadOid})`,
    };
  }

  const nonAllowlistedIndices: number[] = [];
  for (let i = 0; i < jsonDoc.findings.length; i++) {
    if (!jsonDoc.findings[i].allowlisted) {
      nonAllowlistedIndices.push(i);
    }
  }

  const sarifResults = sarifRun.results;
  if (nonAllowlistedIndices.length !== sarifResults.length) {
    return {
      ok: false,
      error: `Finding count mismatch: JSON has ${nonAllowlistedIndices.length} non-allowlisted findings, but SARIF has ${sarifResults.length} results`,
    };
  }

  const items: JoinedFindingItem[] = [];
  let sarifCursor = 0;

  for (let jsonIdx = 0; jsonIdx < jsonDoc.findings.length; jsonIdx++) {
    const finding = jsonDoc.findings[jsonIdx];

    // Validate finding.path as a safe repository-relative path by encoding segments then validating
    const encodedFindingPath = finding.path
      .split("/")
      .map((s) => encodeURIComponent(s))
      .join("/");
    const findingPathCheck = decodeAndValidateSarifUri(encodedFindingPath);
    if (!findingPathCheck.ok || findingPathCheck.value !== finding.path) {
      return {
        ok: false,
        error: `Invalid finding.path at findings[${jsonIdx}]: ${finding.path}`,
      };
    }

    if (finding.allowlisted) {
      items.push({
        jsonIndex: jsonIdx,
        sarifIndex: null,
        finding,
        declaredUnitPath: finding.path,
        resolvedSourcePath: finding.path,
        startLine1Based: null,
        vscodeLine0Based: null,
        locationKind: "file",
        evidenceSide: "unknown",
        sarifEvidenceText: null,
      });
      continue;
    }

    const sarifIdx = sarifCursor++;
    const result = sarifResults[sarifIdx];

    if (finding.rule !== result.ruleId) {
      return {
        ok: false,
        error: `Rule mismatch at pair (json[${jsonIdx}], sarif[${sarifIdx}]): '${finding.rule}' vs '${result.ruleId}'`,
      };
    }

    const sarifFp =
      result.partialFingerprints["checkwash/v2"] ?? result.partialFingerprints["checkwash/v1"];
    if (finding.fingerprint !== sarifFp) {
      return {
        ok: false,
        error: `Fingerprint mismatch at pair (json[${jsonIdx}], sarif[${sarifIdx}]): '${finding.fingerprint}' vs '${String(sarifFp)}'`,
      };
    }

    const expectedLevel = SEVERITY_TO_SARIF_LEVEL[finding.severity];
    if (expectedLevel !== result.level) {
      return {
        ok: false,
        error: `Severity/level mismatch at pair (json[${jsonIdx}], sarif[${sarifIdx}]): '${finding.severity}' (${expectedLevel}) vs '${result.level}'`,
      };
    }

    if (finding.message !== result.message.text) {
      return {
        ok: false,
        error: `Message mismatch at pair (json[${jsonIdx}], sarif[${sarifIdx}])`,
      };
    }

    const phys = result.locations[0].physicalLocation;
    const uriRes = decodeAndValidateSarifUri(phys.artifactLocation.uri);
    if (!uriRes.ok) {
      return {
        ok: false,
        error: `Unsafe or invalid SARIF artifactLocation.uri at results[${sarifIdx}]: ${uriRes.error}`,
      };
    }
    const resolvedSourcePath = uriRes.value;

    let startLine1Based: number | null = null;
    let vscodeLine0Based: number | null = null;
    let locationKind: "line" | "file" = "file";
    let evidenceSide: EvidenceSideLabel = "unknown";
    let sarifEvidenceText: string | null = null;

    if (phys.region !== undefined && phys.region.startLine !== undefined) {
      const line = phys.region.startLine;
      if (!Number.isInteger(line) || line < 1) {
        return {
          ok: false,
          error: `Invalid SARIF startLine (${String(line)}) at results[${sarifIdx}]`,
        };
      }
      if (headFileLineCounts && headFileLineCounts.has(resolvedSourcePath)) {
        const maxLines = headFileLineCounts.get(resolvedSourcePath)!;
        if (line > maxLines) {
          return {
            ok: false,
            error: `SARIF startLine (${line}) exceeds file line count (${maxLines}) for '${resolvedSourcePath}'`,
          };
        }
      }
      startLine1Based = line;
      vscodeLine0Based = line - 1;
      locationKind = "line";
      evidenceSide = "head";
    } else {
      const propSide = result.properties?.["checkwash.evidenceSide"];
      if (propSide === "head" || propSide === "base") {
        evidenceSide = propSide;
      } else {
        evidenceSide = "unknown";
      }
      const propText = result.properties?.["checkwash.evidenceText"];
      if (typeof propText === "string") {
        sarifEvidenceText = propText;
      }
    }

    items.push({
      jsonIndex: jsonIdx,
      sarifIndex: sarifIdx,
      finding,
      declaredUnitPath: finding.path,
      resolvedSourcePath,
      startLine1Based,
      vscodeLine0Based,
      locationKind,
      evidenceSide,
      sarifEvidenceText,
    });
  }

  const sarifNotifications: JoinedNotificationItem[] = [];
  const rawNotifications = sarifRun.invocations?.[0]?.toolExecutionNotifications ?? [];
  for (let i = 0; i < rawNotifications.length; i++) {
    const n = rawNotifications[i];
    const props = n.properties ?? {};
    let nPath: string | null = null;
    if (typeof props["checkwash.path"] === "string") {
      const encodedPropPath = props["checkwash.path"]
        .split("/")
        .map((s) => encodeURIComponent(s))
        .join("/");
      const pCheck = decodeAndValidateSarifUri(encodedPropPath);
      if (!pCheck.ok) {
        return { ok: false, error: `Invalid path in SARIF notification[${i}]: ${pCheck.error}` };
      }
      nPath = pCheck.value;
    }
    if (n.locations && n.locations.length > 0) {
      const locUri = n.locations[0].physicalLocation.artifactLocation.uri;
      const locCheck = decodeAndValidateSarifUri(locUri);
      if (!locCheck.ok) {
        return { ok: false, error: `Invalid location URI in SARIF notification[${i}]: ${locCheck.error}` };
      }
    }
    const isCoverageGap = typeof props["checkwash.line"] === "number";
    const isUnreadSide = typeof props["checkwash.size"] === "number";
    sarifNotifications.push({
      kind: isCoverageGap ? "coverage_gap" : isUnreadSide ? "unread_side" : "other",
      message: n.message.text,
      path: nPath,
      side: typeof props["checkwash.side"] === "string" ? props["checkwash.side"] : null,
      line1Based: typeof props["checkwash.line"] === "number" ? props["checkwash.line"] : null,
      column1Based: typeof props["checkwash.column"] === "number" ? props["checkwash.column"] : null,
      size: typeof props["checkwash.size"] === "number" ? props["checkwash.size"] : null,
      limit: typeof props["checkwash.limit"] === "number" ? props["checkwash.limit"] : null,
    });
  }

  return {
    ok: true,
    value: {
      scanIdentity: jsonIdentity,
      jsonDoc,
      sarifDoc,
      items,
      allowlistedCount: jsonDoc.findings.length - nonAllowlistedIndices.length,
      nonAllowlistedCount: nonAllowlistedIndices.length,
      sarifNotifications,
    },
  };
}
