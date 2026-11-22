/**
 * engine/contextDiet.ts
 *
 * Diff Filtering, Explicit Omission Disclosure & Sensitive Data Guard (Rev 3 §1, §3, §6).
 *
 * Strict Contract Guarantees:
 * 1. Omitted files (lockfiles, minified bundles, source maps, binary files, or budget-truncated files)
 *    are NEVER silently dropped. Every omitted file is recorded in `omittedFiles` and rendered in an
 *    explicit `[Context Diet Omission Disclosure]` block in the output text.
 * 2. Sensitive data (private keys, API tokens, credentials, connection strings, `.env` / `.pem` files)
 *    is scanned across all diff sections. When `hasSensitiveData === true`, copying to the clipboard
 *    is BLOCKED unless the caller either chooses `mode: "redacted"` or passes an explicit
 *    per-invocation confirmation (`userConfirmedUnredactedCopy: true`).
 * 3. Size budget truncation operates strictly on complete line/section boundaries so multi-byte UTF-8
 *    sequences (e.g. Chinese characters, emojis) are never split into invalid UTF-8 bytes.
 */

import { ValidationResult } from "../core/checkwashSchema";
import { CommittedDiffSnapshot } from "../source/revisionProvider";
import { stripGitDiffPrefix, unquoteGitCPath } from "./fastDiffGuard";

export const DEFAULT_CONTEXT_DIET_MAX_BYTES = 128 * 1024; // 128 KiB

export type OmissionReason =
  | "lockfile"
  | "minified_or_sourcemap"
  | "generated_or_build_dir"
  | "binary_diff"
  | "budget_truncated";

export interface OmittedDiffFileEntry {
  path: string;
  reason: OmissionReason;
  omittedLineCount: number;
  omittedByteCount: number;
}

export type SensitivePatternKind =
  | "sensitive_filename"
  | "private_key_block"
  | "github_token"
  | "aws_access_key"
  | "cloud_or_ai_api_key"
  | "bearer_authorization"
  | "credential_assignment"
  | "connection_uri_credentials";

export interface SensitiveDataFinding {
  path: string;
  kind: SensitivePatternKind;
  diffLineOffset1Based: number;
  previewRedacted: string;
}

export interface ContextDietResult {
  effectiveBaseOid: string;
  effectiveHeadOid: string;
  keptFilePaths: string[];
  omittedFiles: OmittedDiffFileEntry[];
  sensitiveFindings: SensitiveDataFinding[];
  hasSensitiveData: boolean;
  requiresUserConfirmationBeforeCopy: boolean;
  unredactedFormattedPayload: string;
  redactedFormattedPayload: string;
}

export interface ClipboardCopyAuthorizationInput {
  dietResult: ContextDietResult;
  mode: "redacted" | "unredacted";
  userConfirmedUnredactedCopy?: boolean;
}

const LOCKFILE_BASENAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
  "bun.lock",
  "cargo.lock",
  "poetry.lock",
  "pipfile.lock",
  "uv.lock",
  "composer.lock",
  "gemfile.lock",
  "go.sum",
]);

const SENSITIVE_FILENAME_RE =
  /(?:^|\/)(?:\.env(?:\.[A-Za-z0-9._-]+)?|id_rsa|id_ed25519|.*\.(?:pem|key|p12|pfx)|credentials\.json|\.npmrc|\.pypirc)$/i;

interface RawFileDiffBlock {
  displayPath: string;
  rawBlockText: string;
  lineCount: number;
  byteCount: number;
  isBinary: boolean;
}

function classifyFilterablePath(relativePath: string, isBinary: boolean): OmissionReason | null {
  if (isBinary) {
    return "binary_diff";
  }
  const normalized = relativePath.replace(/\\/g, "/");
  const lower = normalized.toLowerCase();
  const base = lower.split("/").pop() ?? "";

  if (LOCKFILE_BASENAMES.has(base)) {
    return "lockfile";
  }
  if (
    base.endsWith(".min.js") ||
    base.endsWith(".min.mjs") ||
    base.endsWith(".min.css") ||
    base.endsWith(".map")
  ) {
    return "minified_or_sourcemap";
  }
  if (
    lower.startsWith("dist/") ||
    lower.includes("/dist/") ||
    lower.startsWith("build/") ||
    lower.includes("/build/") ||
    lower.startsWith("node_modules/") ||
    lower.includes("/node_modules/") ||
    lower.startsWith(".next/") ||
    lower.startsWith("coverage/")
  ) {
    return "generated_or_build_dir";
  }
  return null;
}

function extractPathFromDiffGitHeader(line: string): string | null {
  const rest = line.slice("diff --git ".length).trim();
  if (!rest) {
    return null;
  }
  if (rest.startsWith('"')) {
    let i = 1;
    while (i < rest.length) {
      if (rest[i] === "\\") {
        i += 2;
        continue;
      }
      if (rest[i] === '"') {
        const firstRaw = rest.slice(0, i + 1);
        const secondRaw = rest.slice(i + 1).trim();
        const secondParsed = secondRaw ? stripGitDiffPrefix(secondRaw) : null;
        const firstParsed = stripGitDiffPrefix(firstRaw);
        return secondParsed ?? firstParsed;
      }
      i++;
    }
  }
  const quotedSecondIdx = rest.indexOf(' "');
  if (quotedSecondIdx > 0 && rest.endsWith('"')) {
    const firstRaw = rest.slice(0, quotedSecondIdx);
    const secondRaw = rest.slice(quotedSecondIdx + 1);
    return stripGitDiffPrefix(secondRaw) ?? stripGitDiffPrefix(firstRaw);
  }
  const m = /^a\/(.+?) b\/(.+)$/.exec(rest);
  if (m) {
    return m[2];
  }
  return null;
}

export function splitRawUnifiedDiffIntoFileBlocks(rawDiff: string): RawFileDiffBlock[] {
  const normalized = rawDiff.replace(/\r\n|\r/g, "\n");
  if (normalized.trim().length === 0) {
    return [];
  }

  const lines = normalized.split("\n");
  const blocks: RawFileDiffBlock[] = [];
  let currentLines: string[] = [];
  let currentPath = "unknown";
  let currentIsBinary = false;
  let currentInHunk = false;

  const flush = () => {
    if (currentLines.length === 0) {
      return;
    }
    const rawBlockText = currentLines.join("\n");
    blocks.push({
      displayPath: currentPath,
      rawBlockText,
      lineCount: currentLines.length,
      byteCount: Buffer.byteLength(rawBlockText, "utf8"),
      isBinary: currentIsBinary,
    });
    currentLines = [];
    currentPath = "unknown";
    currentIsBinary = false;
    currentInHunk = false;
  };

  for (const line of lines) {
    if (line.startsWith("diff --git ")) {
      flush();
      currentLines.push(line);
      const parsedHeaderPath = extractPathFromDiffGitHeader(line);
      if (parsedHeaderPath) {
        currentPath = parsedHeaderPath;
      }
      continue;
    }
    if (currentLines.length === 0) {
      continue;
    }
    if (line.startsWith("@@ ")) {
      currentInHunk = true;
    } else if (!currentInHunk && line.startsWith("+++ ")) {
      const plusPath = stripGitDiffPrefix(line.slice(4));
      if (plusPath) {
        currentPath = plusPath;
      }
    } else if (!currentInHunk && line.startsWith("--- ") && currentPath === "unknown") {
      const minusPath = stripGitDiffPrefix(line.slice(4));
      if (minusPath) {
        currentPath = minusPath;
      }
    } else if (!currentInHunk && line.startsWith("rename to ")) {
      const renamedTo = unquoteGitCPath(line.slice("rename to ".length));
      if (renamedTo) {
        currentPath = renamedTo;
      }
    } else if (
      !currentInHunk &&
      (line.startsWith("Binary files ") || line.startsWith("GIT binary patch"))
    ) {
      currentIsBinary = true;
    }
    currentLines.push(line);
  }
  flush();
  return blocks;
}

interface SensitiveRuleSpec {
  kind: SensitivePatternKind;
  regex: RegExp;
  redactReplacement: string;
}

const SENSITIVE_CONTENT_RULES: SensitiveRuleSpec[] = [
  {
    kind: "private_key_block",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g,
    redactReplacement: "[REDACTED:private_key_block]",
  },
  {
    kind: "github_token",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    redactReplacement: "[REDACTED:github_token]",
  },
  {
    kind: "aws_access_key",
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    redactReplacement: "[REDACTED:aws_access_key]",
  },
  {
    kind: "cloud_or_ai_api_key",
    regex: /\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b|https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    redactReplacement: "[REDACTED:cloud_or_ai_api_key]",
  },
  {
    kind: "bearer_authorization",
    regex: /(Authorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi,
    redactReplacement: "$1[REDACTED:bearer_authorization]",
  },
  {
    kind: "connection_uri_credentials",
    regex: /\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|amqps):\/\/[^:\s/]+:)([^@\s]+)(@)/gi,
    redactReplacement: "$1[REDACTED:connection_uri_credentials]$3",
  },
  {
    kind: "credential_assignment",
    regex: /\b([A-Za-z0-9_.-]*?(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|client_secret|private_key|db_pass)\s*(?<![=!<>])[:=](?!=)\s*["'])([^"'\r\n]{6,})(["'])/gi,
    redactReplacement: "$1[REDACTED:credential_assignment]$3",
  },
  {
    kind: "credential_assignment",
    regex: /\b([A-Za-z0-9_.-]*?(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|client_secret|private_key|db_pass)\s*(?<![=!<>])[:=](?!=)\s*)(?!["']|(?:true|false|null|none|undefined|changeme|example|placeholder|string|number|boolean|object|bytes|optional|str|int)\b|\$\{|\$[A-Za-z_])([^\s"'#;,\r\n]{6,})/gi,
    redactReplacement: "$1[REDACTED:credential_assignment]",
  },
];

function scanAndRedactBlock(
  displayPath: string,
  rawBlockText: string
): { findings: SensitiveDataFinding[]; redactedBlockText: string } {
  const findings: SensitiveDataFinding[] = [];

  if (SENSITIVE_FILENAME_RE.test(displayPath)) {
    findings.push({
      path: displayPath,
      kind: "sensitive_filename",
      diffLineOffset1Based: 1,
      previewRedacted: `Sensitive file path modified: ${displayPath}`,
    });
  }

  const lines = rawBlockText.split("\n");
  const redactedLines: string[] = [];
  let inHunk = false;
  let insidePrivateKeyBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];

    // Before the first `@@` hunk header (`!inHunk`), skip unified diff file headers
    // (`--- a/...`, `+++ b/...`, `diff --git ...`, `index ...`, mode/rename metadata)
    // to avoid false positives on file names. Once inside a hunk (`inHunk === true`),
    // NEVER skip `--- ...` or `+++ ...` (e.g. deleted `-- api_key = ...` or added `++ ...`)!
    if (!inHunk) {
      if (rawLine.startsWith("@@ ")) {
        inHunk = true;
      } else if (
        rawLine.startsWith("diff --git ") ||
        rawLine.startsWith("index ") ||
        rawLine.startsWith("--- ") ||
        rawLine.startsWith("+++ ") ||
        rawLine.startsWith("old mode ") ||
        rawLine.startsWith("new mode ") ||
        rawLine.startsWith("deleted file mode ") ||
        rawLine.startsWith("new file mode ") ||
        rawLine.startsWith("similarity index ") ||
        rawLine.startsWith("dissimilarity index ") ||
        rawLine.startsWith("rename from ") ||
        rawLine.startsWith("rename to ") ||
        rawLine.startsWith("copy from ") ||
        rawLine.startsWith("copy to ")
      ) {
        insidePrivateKeyBlock = false;
        redactedLines.push(rawLine);
        continue;
      }
    }

    // Parse hunk header (`@@ -a,b +c,d @@ <optional context>`) vs hunk body (`+`, `-`, ` `, `\`)
    let preservedLinePrefix = "";
    let lineText = rawLine;
    let isHunkBodyLine = false;

    if (rawLine.startsWith("@@ ")) {
      inHunk = true;
      insidePrivateKeyBlock = false;
      const hunkMatch = /^(@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@ ?)(.*)$/.exec(rawLine);
      if (hunkMatch) {
        preservedLinePrefix = hunkMatch[1];
        lineText = hunkMatch[2];
        if (lineText.length === 0) {
          redactedLines.push(preservedLinePrefix);
          continue;
        }
      }
    } else if (inHunk) {
      if (rawLine.startsWith("\\")) {
        // Unified diff metadata line inside hunk (e.g. `\ No newline at end of file`)
        redactedLines.push(rawLine);
        continue;
      }
      if (
        rawLine.startsWith("+") ||
        rawLine.startsWith("-") ||
        rawLine.startsWith(" ")
      ) {
        preservedLinePrefix = rawLine[0];
        lineText = rawLine.slice(1);
        isHunkBodyLine = true;
      }
    }

    const beginKeyMatch = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.exec(lineText);
    const endKeyMatch = /-----END [A-Z0-9 ]*PRIVATE KEY-----/.exec(lineText);

    if (beginKeyMatch) {
      const matchedLineKinds: SensitivePatternKind[] = ["private_key_block"];
      const fallbackRawPrefix =
        preservedLinePrefix.length === 0 &&
        (lineText.startsWith("+") || lineText.startsWith("-") || lineText.startsWith(" "))
          ? lineText[0]
          : "";
      const beforeBegin = lineText.slice(0, beginKeyMatch.index);
      if (endKeyMatch && endKeyMatch.index > beginKeyMatch.index) {
        const afterEnd = lineText.slice(endKeyMatch.index + endKeyMatch[0].length);
        lineText = `${beforeBegin}[REDACTED:private_key_block]${afterEnd}`;
        insidePrivateKeyBlock = false;
      } else {
        lineText = `${beforeBegin || fallbackRawPrefix}[REDACTED:private_key_block]`;
        insidePrivateKeyBlock = isHunkBodyLine || preservedLinePrefix.length === 0;
      }
      // Also run all remaining content rules on any text before/after the inline key block
      for (const rule of SENSITIVE_CONTENT_RULES) {
        if (rule.kind === "private_key_block") {
          continue;
        }
        rule.regex.lastIndex = 0;
        if (rule.regex.test(lineText)) {
          matchedLineKinds.push(rule.kind);
          rule.regex.lastIndex = 0;
          lineText = lineText.replace(rule.regex, rule.redactReplacement);
        }
      }
      const combinedLine = preservedLinePrefix + lineText;
      const fullyRedactedPreview = combinedLine.trim().slice(0, 120);
      for (const k of matchedLineKinds) {
        findings.push({
          path: displayPath,
          kind: k,
          diffLineOffset1Based: i + 1,
          previewRedacted: fullyRedactedPreview,
        });
      }
      redactedLines.push(combinedLine);
      continue;
    }

    if (insidePrivateKeyBlock) {
      const fallbackRawPrefix =
        preservedLinePrefix.length === 0 &&
        (lineText.startsWith("+") || lineText.startsWith("-") || lineText.startsWith(" "))
          ? lineText[0]
          : "";
      if (endKeyMatch) {
        const afterEnd = lineText.slice(endKeyMatch.index + endKeyMatch[0].length);
        lineText = `${fallbackRawPrefix}[REDACTED:private_key_block]${afterEnd}`;
        insidePrivateKeyBlock = false;
        // Also redact any secret appearing after -----END ... PRIVATE KEY----- on the same line
        for (const rule of SENSITIVE_CONTENT_RULES) {
          if (rule.kind === "private_key_block") {
            continue;
          }
          rule.regex.lastIndex = 0;
          if (rule.regex.test(lineText)) {
            rule.regex.lastIndex = 0;
            lineText = lineText.replace(rule.regex, rule.redactReplacement);
          }
        }
      } else {
        lineText = `${fallbackRawPrefix}[REDACTED:private_key_block_body]`;
      }
      redactedLines.push(preservedLinePrefix + lineText);
      continue;
    }

    const matchedKindsOnLine: SensitivePatternKind[] = [];
    for (const rule of SENSITIVE_CONTENT_RULES) {
      if (rule.kind === "private_key_block") {
        continue;
      }
      rule.regex.lastIndex = 0;
      if (rule.regex.test(lineText)) {
        matchedKindsOnLine.push(rule.kind);
        rule.regex.lastIndex = 0;
        lineText = lineText.replace(rule.regex, rule.redactReplacement);
      }
    }

    const finalLineText = preservedLinePrefix + lineText;
    if (matchedKindsOnLine.length > 0) {
      const fullyRedactedPreview = finalLineText.trim().slice(0, 120);
      for (const matchedKind of matchedKindsOnLine) {
        findings.push({
          path: displayPath,
          kind: matchedKind,
          diffLineOffset1Based: i + 1,
          previewRedacted: fullyRedactedPreview,
        });
      }
    }

    redactedLines.push(finalLineText);
  }

  return {
    findings,
    redactedBlockText: redactedLines.join("\n"),
  };
}

function buildFormattedDiffPayload(params: {
  effectiveBaseOid: string;
  effectiveHeadOid: string;
  keptFilePaths: string[];
  omittedFiles: OmittedDiffFileEntry[];
  sensitiveFindings: SensitiveDataFinding[];
  diffBody: string;
  isRedacted: boolean;
}): string {
  const {
    effectiveBaseOid,
    effectiveHeadOid,
    keptFilePaths,
    omittedFiles,
    sensitiveFindings,
    diffBody,
    isRedacted,
  } = params;

  const headerLines: string[] = [
    "# === Checkwash Lens — Context Diet Diff ===",
    `# Range: ${effectiveBaseOid}..${effectiveHeadOid}`,
    `# Included files: ${keptFilePaths.length}`,
    `# Omitted files: ${omittedFiles.length}`,
    `# Sensitive findings: ${sensitiveFindings.length} (mode: ${isRedacted ? "REDACTED" : "UNREDACTED"})`,
  ];

  if (omittedFiles.length > 0) {
    headerLines.push("#");
    headerLines.push("# [Context Diet Omission Disclosure]");
    for (const om of omittedFiles) {
      headerLines.push(
        `# - OMITTED: ${om.path} (reason=${om.reason}, lines=${om.omittedLineCount}, bytes=${om.omittedByteCount})`
      );
    }
  }

  if (sensitiveFindings.length > 0) {
    headerLines.push("#");
    headerLines.push("# [Sensitive Data Guard Notice]");
    for (const sf of sensitiveFindings) {
      headerLines.push(
        `# - SENSITIVE (${sf.kind}) in ${sf.path} [diff line ${sf.diffLineOffset1Based}]: ${sf.previewRedacted}`
      );
    }
  }

  headerLines.push("# ==========================================");

  const body =
    diffBody.trim().length > 0
      ? diffBody
      : "# (No non-omitted diff hunks remain in this range; see Omission Disclosure above.)";

  return `${headerLines.join("\n")}\n\n${body}\n`;
}

/**
 * Applies Context Diet filtering, omission disclosure, budget truncation, and sensitive data scanning
 * to a committed diff snapshot.
 */
export function buildContextDietDiff(
  diffSnapshot: CommittedDiffSnapshot,
  maxOutputBytes: number = DEFAULT_CONTEXT_DIET_MAX_BYTES
): ContextDietResult {
  const blocks = splitRawUnifiedDiffIntoFileBlocks(diffSnapshot.rawUnifiedDiff);
  const keptFilePaths: string[] = [];
  const omittedFiles: OmittedDiffFileEntry[] = [];
  const sensitiveFindings: SensitiveDataFinding[] = [];
  const unredactedChunks: string[] = [];
  const redactedChunks: string[] = [];

  let currentUsedBytes = 0;

  for (const block of blocks) {
    const filterReason = classifyFilterablePath(block.displayPath, block.isBinary);
    if (filterReason !== null) {
      omittedFiles.push({
        path: block.displayPath,
        reason: filterReason,
        omittedLineCount: block.lineCount,
        omittedByteCount: block.byteCount,
      });
      continue;
    }

    // Even if a file will be budget-truncated or kept, scan it for sensitive data
    const scanned = scanAndRedactBlock(block.displayPath, block.rawBlockText);

    if (currentUsedBytes + block.byteCount > maxOutputBytes) {
      // Can we fit a line-boundary prefix of this block, or should we omit/truncate cleanly?
      const remainingBudget = maxOutputBytes - currentUsedBytes;
      if (remainingBudget <= 256) {
        omittedFiles.push({
          path: block.displayPath,
          reason: "budget_truncated",
          omittedLineCount: block.lineCount,
          omittedByteCount: block.byteCount,
        });
        continue;
      }

      // Truncate strictly at complete newline boundaries so UTF-8 codepoints are never split
      const unredactedLines = block.rawBlockText.split("\n");
      const redactedLines = scanned.redactedBlockText.split("\n");
      const keptUnredactedLines: string[] = [];
      const keptRedactedLines: string[] = [];
      let accBytes = 0;
      let includedLineCount = 0;

      for (let i = 0; i < unredactedLines.length; i++) {
        const lineBytes = Buffer.byteLength(unredactedLines[i] + "\n", "utf8");
        if (accBytes + lineBytes > remainingBudget) {
          break;
        }
        accBytes += lineBytes;
        keptUnredactedLines.push(unredactedLines[i]);
        keptRedactedLines.push(redactedLines[i]);
        includedLineCount++;
      }

      const omittedLineCount = Math.max(0, block.lineCount - includedLineCount);
      const omittedByteCount = Math.max(0, block.byteCount - accBytes);

      if (includedLineCount > 0) {
        const truncMarker = `\n# [Context Diet: truncated ${omittedLineCount} lines (${omittedByteCount} bytes) of ${block.displayPath} due to budget]`;
        keptFilePaths.push(block.displayPath);
        unredactedChunks.push(keptUnredactedLines.join("\n") + truncMarker);
        redactedChunks.push(keptRedactedLines.join("\n") + truncMarker);
        // Only record sensitive findings that fell within the kept lines (or filename)
        for (const sf of scanned.findings) {
          if (sf.kind === "sensitive_filename" || sf.diffLineOffset1Based <= includedLineCount) {
            sensitiveFindings.push(sf);
          }
        }
      }

      omittedFiles.push({
        path: block.displayPath,
        reason: "budget_truncated",
        omittedLineCount,
        omittedByteCount,
      });
      currentUsedBytes = maxOutputBytes;
      continue;
    }

    keptFilePaths.push(block.displayPath);
    unredactedChunks.push(block.rawBlockText);
    redactedChunks.push(scanned.redactedBlockText);
    sensitiveFindings.push(...scanned.findings);
    currentUsedBytes += block.byteCount;
  }

  const hasSensitiveData = sensitiveFindings.length > 0;
  const unredactedFormattedPayload = buildFormattedDiffPayload({
    effectiveBaseOid: diffSnapshot.effectiveBaseOid,
    effectiveHeadOid: diffSnapshot.effectiveHeadOid,
    keptFilePaths,
    omittedFiles,
    sensitiveFindings,
    diffBody: unredactedChunks.join("\n\n"),
    isRedacted: false,
  });

  const redactedFormattedPayload = buildFormattedDiffPayload({
    effectiveBaseOid: diffSnapshot.effectiveBaseOid,
    effectiveHeadOid: diffSnapshot.effectiveHeadOid,
    keptFilePaths,
    omittedFiles,
    sensitiveFindings,
    diffBody: redactedChunks.join("\n\n"),
    isRedacted: true,
  });

  return {
    effectiveBaseOid: diffSnapshot.effectiveBaseOid,
    effectiveHeadOid: diffSnapshot.effectiveHeadOid,
    keptFilePaths,
    omittedFiles,
    sensitiveFindings,
    hasSensitiveData,
    requiresUserConfirmationBeforeCopy: hasSensitiveData,
    unredactedFormattedPayload,
    redactedFormattedPayload,
  };
}

/**
 * Enforces the Sensitive Data Copy Gate before placing a Context Diet diff onto the system clipboard.
 */
export function authorizeClipboardCopy(
  input: ClipboardCopyAuthorizationInput
): ValidationResult<{ payloadToCopy: string; modeUsed: "redacted" | "unredacted" }> {
  const { dietResult, mode, userConfirmedUnredactedCopy } = input;

  if (mode === "redacted") {
    return {
      ok: true,
      value: {
        payloadToCopy: dietResult.redactedFormattedPayload,
        modeUsed: "redacted",
      },
    };
  }

  if (dietResult.hasSensitiveData && userConfirmedUnredactedCopy !== true) {
    return {
      ok: false,
      error: `Clipboard copy blocked: Diff contains ${dietResult.sensitiveFindings.length} sensitive data item(s). Choose redacted copy or explicitly confirm unredacted copy.`,
    };
  }

  return {
    ok: true,
    value: {
      payloadToCopy: dietResult.unredactedFormattedPayload,
      modeUsed: "unredacted",
    },
  };
}
