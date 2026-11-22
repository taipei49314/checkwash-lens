/**
 * core/sourceIdentity.ts
 *
 * Repository, commit OID (40/64 hex), SARIF single-decode URI validation,
 * and Live Editor document content & version binding.
 * Zero VS Code UI dependency; never spawns processes.
 *
 * Enforces Rev 3 §4.2, §4.3, §5.3, §5.4, §5.5 (A06, A09, A10).
 */

import { TextDecoder } from "util";
import { ValidationResult } from "./checkwashSchema";

export type RangeMode = "two-dot" | "three-dot";

export interface CommittedRangeSpec {
  rawSpec: string;
  mode: RangeMode;
  leftRef: string;
  rightRef: string;
}

export interface PinnedScanIdentity {
  scanId: number;
  repositoryRoot: string;
  rawRangeSpec: string;
  rangeMode: RangeMode;
  leftRef: string;
  rightRef: string;
  resolvedLeftOid: string;
  resolvedRightOid: string;
  effectiveBaseOid: string;
  effectiveHeadOid: string;
  checkwashVersion: string;
  checkwashPyzSha256: string;
  checkwashBuildCommit: string;
  pythonExecutable: string;
  pythonVersion: string;
  gitExecutable: string;
  gitVersion: string;
  controlledCwd: string;
}

const OID_REGEX = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const WINDOWS_RESERVED_NAMES = new Set([
  "CON", "PRN", "AUX", "NUL",
  "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
  "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
]);

export function isValidCommitOid(oid: string): boolean {
  return typeof oid === "string" && OID_REGEX.test(oid);
}

/**
 * Parses a committed range expression A..B or A...B.
 * Rejects empty sides, leading dots on right side, multiple '..' segments, or whitespace-only refs.
 */
export function parseCommittedRangeSpec(rawSpec: string): ValidationResult<CommittedRangeSpec> {
  if (typeof rawSpec !== "string" || rawSpec.trim().length === 0) {
    return { ok: false, error: "Range specification cannot be empty" };
  }
  const trimmed = rawSpec.trim();
  if (/[\0\r\n]/.test(trimmed)) {
    return { ok: false, error: "Range specification contains forbidden control characters" };
  }
  const isThreeDot = trimmed.includes("...");
  const separator = isThreeDot ? "..." : "..";
  const idx = trimmed.indexOf(separator);
  if (idx <= 0) {
    return { ok: false, error: `Range must be A..B or A...B, got '${rawSpec}'` };
  }
  const leftRef = trimmed.slice(0, idx);
  const rightRef = trimmed.slice(idx + separator.length);
  if (
    !leftRef ||
    !rightRef ||
    rightRef.startsWith(".") ||
    leftRef.includes("..") ||
    rightRef.includes("..") ||
    leftRef.startsWith("-") ||
    rightRef.startsWith("-")
  ) {
    return { ok: false, error: `Invalid committed range '${rawSpec}'` };
  }
  return {
    ok: true,
    value: {
      rawSpec: trimmed,
      mode: isThreeDot ? "three-dot" : "two-dot",
      leftRef,
      rightRef,
    },
  };
}

/**
 * Decodes a SARIF artifactLocation.uri ONCE and validates that the decoded path is
 * a safe, normalized repository-relative path (§5.5, A06).
 *
 * Rejects:
 * - URI schemes (e.g. file:, http:, command:, vscode:)
 * - Backslashes in the encoded URI or decoded path
 * - Absolute paths (/foo, \foo, C:\foo)
 * - Empty segments, '.' or '..' traversal
 * - NUL bytes or control characters (< 0x20, 0x7F)
 * - Windows Alternate Data Streams or drive colons (':')
 * - Windows trailing dots or spaces on any segment
 * - Windows reserved device names (CON, NUL, AUX, COM1..9, LPT1..9)
 */
export function decodeAndValidateSarifUri(uri: string): ValidationResult<string> {
  if (typeof uri !== "string" || uri.length === 0) {
    return { ok: false, error: "SARIF URI must be a non-empty string" };
  }
  if (uri.includes("\\")) {
    return { ok: false, error: `SARIF URI contains backslash before decoding: ${uri}` };
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(uri)) {
    return { ok: false, error: `SARIF URI must be repository-relative without scheme: ${uri}` };
  }
  if (uri.startsWith("/")) {
    return { ok: false, error: `SARIF URI must not start with '/': ${uri}` };
  }

  let decoded: string;
  try {
    decoded = decodeURIComponent(uri);
  } catch (err) {
    return { ok: false, error: `Malformed percent-encoding in SARIF URI: ${uri}` };
  }

  if (decoded.length === 0) {
    return { ok: false, error: "Decoded SARIF path is empty" };
  }
  for (let i = 0; i < decoded.length; i++) {
    const code = decoded.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return { ok: false, error: `Decoded SARIF path contains control character (0x${code.toString(16)})` };
    }
  }
  if (decoded.includes("\\") || decoded.includes(":")) {
    return {
      ok: false,
      error: `Decoded SARIF path contains forbidden backslash or colon (ADS / drive letter): ${decoded}`,
    };
  }
  if (decoded.startsWith("/")) {
    return { ok: false, error: `Decoded SARIF path is absolute: ${decoded}` };
  }

  const segments = decoded.split("/");
  for (const seg of segments) {
    if (seg.length === 0 || seg === "." || seg === "..") {
      return { ok: false, error: `Decoded SARIF path contains invalid segment '${seg}' in '${decoded}'` };
    }
    if (seg.endsWith(".") || seg.endsWith(" ")) {
      return { ok: false, error: `Decoded SARIF path segment has trailing dot or space: '${seg}'` };
    }
    const baseName = seg.split(".")[0].toUpperCase();
    if (WINDOWS_RESERVED_NAMES.has(baseName)) {
      return { ok: false, error: `Decoded SARIF path contains Windows reserved device name: '${seg}'` };
    }
  }

  return { ok: true, value: decoded };
}

/**
 * Decodes raw bytes as strict UTF-8 (fatal on invalid byte sequences).
 * Enforces Rev 3 §5.4 & B10: invalid UTF-8 sources are rejected for live projection.
 */
export function decodeStrictUtf8(bytes: Uint8Array): ValidationResult<string> {
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
    return { ok: true, value: decoder.decode(bytes) };
  } catch (err) {
    return {
      ok: false,
      error: `Invalid UTF-8 byte sequence: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * Normalizes source text per Rev 3 §5.4:
 * 1. Strips leading UTF-8 BOM (U+FEFF) if present.
 * 2. Replaces all CRLF (\r\n) and standalone CR (\r) with LF (\n).
 */
export function normalizeSourceForComparison(text: string): string {
  const withoutBom = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  return withoutBom.replace(/\r\n|\r/g, "\n");
}

/**
 * Computes the number of 1-based lines in normalized source text.
 */
export function countNormalizedLines(normalizedText: string): number {
  if (normalizedText.length === 0) {
    return 1;
  }
  const lines = normalizedText.split("\n");
  return lines.length;
}

export interface LiveEditorProjectionCheckInput {
  expectedRepositoryRoot: string;
  actualRepositoryRoot: string;
  expectedRelativePath: string;
  actualRelativePath: string;
  analyzedSourceBytes: Uint8Array;
  liveDocumentText: string;
  verifiedDocumentVersion: number;
  currentDocumentVersionAtPublish: number;
  isDocumentClosedOrDeleted?: boolean;
}

/**
 * Verifies whether a SARIF line-level diagnostic from a fixed head revision may be
 * projected onto the user's currently open live TextDocument (Rev 3 §5.4, A09).
 */
export function canProjectDiagnosticToLiveDocument(
  input: LiveEditorProjectionCheckInput
): ValidationResult<{ normalizedLineCount: number }> {
  if (input.isDocumentClosedOrDeleted) {
    return { ok: false, error: "Target document is closed, deleted, or rebound" };
  }
  const isWinStyle =
    process.platform === "win32" ||
    /^[a-zA-Z]:[\\/]/.test(input.expectedRepositoryRoot) ||
    /^[a-zA-Z]:[\\/]/.test(input.actualRepositoryRoot);
  const normExpectedRepo = isWinStyle
    ? input.expectedRepositoryRoot.replace(/[\\/]+$/, "").toLowerCase()
    : input.expectedRepositoryRoot.replace(/\/+$/, "") || "/";
  const normActualRepo = isWinStyle
    ? input.actualRepositoryRoot.replace(/[\\/]+$/, "").toLowerCase()
    : input.actualRepositoryRoot.replace(/\/+$/, "") || "/";
  if (normExpectedRepo !== normActualRepo) {
    return { ok: false, error: "Repository root changed since scan" };
  }
  if (input.expectedRelativePath !== input.actualRelativePath) {
    return { ok: false, error: "Document path does not match SARIF artifact source path" };
  }
  if (input.verifiedDocumentVersion !== input.currentDocumentVersionAtPublish) {
    return {
      ok: false,
      error: `Document version changed before publish (${input.verifiedDocumentVersion} -> ${input.currentDocumentVersionAtPublish})`,
    };
  }

  const utf8Res = decodeStrictUtf8(input.analyzedSourceBytes);
  if (!utf8Res.ok) {
    return { ok: false, error: `Analyzed source is not valid UTF-8: ${utf8Res.error}` };
  }

  const normalizedAnalyzed = normalizeSourceForComparison(utf8Res.value);
  const normalizedLive = normalizeSourceForComparison(input.liveDocumentText);

  if (normalizedAnalyzed !== normalizedLive) {
    return {
      ok: false,
      error: "Live document content differs from analyzed head revision source after normalization",
    };
  }

  return {
    ok: true,
    value: {
      normalizedLineCount: countNormalizedLines(normalizedAnalyzed),
    },
  };
}

const BIDI_AND_CONTROL_CHAR_RE =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

/**
 * Neutralizes Unicode BiDi directional overrides (Trojan Source RLO/LRO/PDI) and C0/C1 control
 * characters in untrusted repository/report strings before rendering in VS Code UI surfaces (RT-09).
 */
export function sanitizeUntrustedDisplayString(
  raw: string,
  options?: { allowNewlines?: boolean; maxLen?: number }
): string {
  if (typeof raw !== "string" || raw.length === 0) {
    return "";
  }
  const allowNewlines = options?.allowNewlines ?? false;
  let cleaned = raw.replace(BIDI_AND_CONTROL_CHAR_RE, (ch) => {
    const code = ch.charCodeAt(0);
    return `\\u${code.toString(16).toUpperCase().padStart(4, "0")}`;
  });
  if (!allowNewlines) {
    cleaned = cleaned.replace(/\r\n|\r|\n|\t/g, " ");
  }
  if (typeof options?.maxLen === "number" && options.maxLen > 0 && cleaned.length > options.maxLen) {
    cleaned = `${cleaned.slice(0, options.maxLen)}...`;
  }
  return cleaned;
}
