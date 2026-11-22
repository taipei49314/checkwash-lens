/**
 * engine/fastDiffGuard.ts
 *
 * Independent Heuristic Diff Hint Scanner ("Fast Guard") (Rev 3 §1, §2, §3, §6).
 *
 * Strict Contract Guarantees:
 * 1. Fast Guard is an independent heuristic hint layer (`source: "Fast Guard (Heuristic — Non-Verdict)"`).
 * 2. Fast Guard NEVER computes, alters, upgrades, or downgrades the Checkwash 5-State Verdict.
 * 3. Fast Guard hints are NEVER deduplicated against Checkwash findings (nor vice versa).
 * 4. Added-line (`+`) hints record `side: "head"` and exact `headLine1Based` in `effectiveHeadOid`.
 *    Removed-line (`-`) hints record `side: "base"`, `baseLine1Based` in `effectiveBaseOid`, and
 *    `headLine1Based: null` — they NEVER attach inline live diagnostics to the working-tree editor.
 * 5. Live editor projection for `side: "head"` hints requires the exact same `canProjectDiagnosticToLiveDocument`
 *    verification against the `effectiveHeadOid` blob and clean `OpenEditorDocumentSnapshot`.
 */

import { canProjectDiagnosticToLiveDocument } from "../core/sourceIdentity";
import { areSameWinRepositoryPath } from "../runtime/admission";
import { OpenEditorDocumentSnapshot } from "./checkwashRunner";
import {
  buildRevisionUriString,
  CommittedDiffSnapshot,
  ImmutableBlobRecord,
  validateRepoRelativePath,
} from "../source/revisionProvider";

export const FAST_GUARD_SOURCE_LABEL = "Fast Guard (Heuristic — Non-Verdict)";
export const FAST_GUARD_NON_VERDICT_NOTICE =
  "Fast Guard 僅提供獨立 Diff 啟發式提示，不代表 Checkwash 引擎判定，亦不影響 Pass／Block 狀態。";

export type FastGuardRuleId =
  | "FG-SKIP-XFAIL-ADDED"
  | "FG-LINT-TYPE-SUPPRESS-ADDED"
  | "FG-COVERAGE-PRAGMA-ADDED"
  | "FG-ASSERT-REMOVED-IN-TEST"
  | "FG-TIMEOUT-SLEEP-ADDED";

export interface FastGuardHint {
  /** Deterministic index within the Fast Guard scan (0-based) */
  hintIndex: number;
  ruleId: FastGuardRuleId;
  sourceLabel: typeof FAST_GUARD_SOURCE_LABEL;
  relativePath: string;
  side: "head" | "base";
  /** 1-based line in effectiveHeadOid when side === 'head', otherwise null */
  headLine1Based: number | null;
  /** 1-based line in effectiveBaseOid when side === 'base', otherwise null */
  baseLine1Based: number | null;
  message: string;
  snippet: string;
  /** Immutable checkwash-rev: URI for inspecting the exact commit revision */
  revisionUri: string | null;
  /** Whether this hint may be projected onto the open working-tree editor as an Information/Hint diagnostic */
  liveProjectionAllowed: boolean;
  /** 0-based line in the open editor if liveProjectionAllowed === true; otherwise null */
  liveVscodeLine0Based: number | null;
  liveProjectionReason: string;
}

export interface FastGuardAnalysisResult {
  notice: typeof FAST_GUARD_NON_VERDICT_NOTICE;
  effectiveBaseOid: string;
  effectiveHeadOid: string;
  hints: FastGuardHint[];
}

interface ParsedDiffFileSection {
  oldPath: string | null;
  newPath: string | null;
  hunks: Array<{
    oldStart: number;
    newStart: number;
    lines: Array<{
      prefix: "+" | "-" | " ";
      content: string;
      oldLine1Based: number | null;
      newLine1Based: number | null;
    }>;
  }>;
}

const HUNK_HEADER_RE = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

export function unquoteGitCPath(raw: string): string {
  const trimmed = raw.trim();
  if (!(trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2)) {
    return trimmed;
  }
  const inner = trimmed.slice(1, -1);
  const bytes: number[] = [];
  let i = 0;
  while (i < inner.length) {
    const ch = inner[i];
    if (ch !== "\\") {
      const encoded = Buffer.from(ch, "utf8");
      for (const b of encoded) bytes.push(b);
      i++;
      continue;
    }
    if (i + 1 >= inner.length) {
      bytes.push(0x5c);
      i++;
      continue;
    }
    const next = inner[i + 1];
    if (next >= "0" && next <= "7") {
      let oct = next;
      let consumed = 2;
      if (i + 2 < inner.length && inner[i + 2] >= "0" && inner[i + 2] <= "7") {
        oct += inner[i + 2];
        consumed++;
        if (i + 3 < inner.length && inner[i + 3] >= "0" && inner[i + 3] <= "7") {
          oct += inner[i + 3];
          consumed++;
        }
      }
      bytes.push(parseInt(oct, 8) & 0xff);
      i += consumed;
      continue;
    }
    switch (next) {
      case "\\":
        bytes.push(0x5c);
        break;
      case '"':
        bytes.push(0x22);
        break;
      case "t":
        bytes.push(0x09);
        break;
      case "n":
        bytes.push(0x0a);
        break;
      case "r":
        bytes.push(0x0d);
        break;
      case "a":
        bytes.push(0x07);
        break;
      case "b":
        bytes.push(0x08);
        break;
      case "f":
        bytes.push(0x0c);
        break;
      case "v":
        bytes.push(0x0b);
        break;
      default: {
        const encoded = Buffer.from(next, "utf8");
        for (const b of encoded) bytes.push(b);
        break;
      }
    }
    i += 2;
  }
  return Buffer.from(bytes).toString("utf8");
}

export function stripGitDiffPrefix(rawDiffPath: string): string | null {
  const trimmed = rawDiffPath.trim();
  if (trimmed === "/dev/null" || trimmed === '"/dev/null"') {
    return null;
  }
  // Strip trailing tab timestamp if present on unquoted unified diff headers
  const withoutTrailingMeta = trimmed.startsWith('"') ? trimmed : trimmed.split("\t")[0].trim();
  const unquoted = unquoteGitCPath(withoutTrailingMeta);
  if (unquoted === "/dev/null") {
    return null;
  }
  if (unquoted.startsWith("a/") || unquoted.startsWith("b/")) {
    return unquoted.slice(2);
  }
  return unquoted;
}

/**
 * Parses a unified diff string (`git diff --no-color --no-ext-diff --unified=3`) into structured file hunks.
 */
export function parseUnifiedDiffSections(rawUnifiedDiff: string): ParsedDiffFileSection[] {
  const sections: ParsedDiffFileSection[] = [];
  if (!rawUnifiedDiff || rawUnifiedDiff.trim().length === 0) {
    return sections;
  }

  const lines = rawUnifiedDiff.replace(/\r\n|\r/g, "\n").split("\n");
  let currentSection: ParsedDiffFileSection | null = null;
  let currentHunk: ParsedDiffFileSection["hunks"][number] | null = null;
  let oldCursor = 0;
  let newCursor = 0;

  for (const line of lines) {
    if (line.startsWith("diff --git ")) {
      currentSection = {
        oldPath: null,
        newPath: null,
        hunks: [],
      };
      sections.push(currentSection);
      currentHunk = null;
      continue;
    }

    if (!currentSection) {
      continue;
    }

    if (line.startsWith("--- ") && currentHunk === null) {
      currentSection.oldPath = stripGitDiffPrefix(line.slice(4));
      continue;
    }

    if (line.startsWith("+++ ") && currentHunk === null) {
      currentSection.newPath = stripGitDiffPrefix(line.slice(4));
      continue;
    }

    const hunkMatch = HUNK_HEADER_RE.exec(line);
    if (hunkMatch) {
      oldCursor = Number(hunkMatch[1]);
      newCursor = Number(hunkMatch[2]);
      currentHunk = {
        oldStart: oldCursor,
        newStart: newCursor,
        lines: [],
      };
      currentSection.hunks.push(currentHunk);
      continue;
    }

    if (!currentHunk) {
      continue;
    }

    if (line.startsWith("+")) {
      currentHunk.lines.push({
        prefix: "+",
        content: line.slice(1),
        oldLine1Based: null,
        newLine1Based: newCursor++,
      });
    } else if (line.startsWith("-")) {
      currentHunk.lines.push({
        prefix: "-",
        content: line.slice(1),
        oldLine1Based: oldCursor++,
        newLine1Based: null,
      });
    } else if (line.startsWith(" ")) {
      currentHunk.lines.push({
        prefix: " ",
        content: line.slice(1),
        oldLine1Based: oldCursor++,
        newLine1Based: newCursor++,
      });
    }
  }

  return sections;
}

function isTestFilePath(relativePath: string): boolean {
  const lower = relativePath.toLowerCase();
  const base = lower.split("/").pop() ?? "";
  return (
    lower.startsWith("tests/") ||
    lower.includes("/tests/") ||
    lower.startsWith("test/") ||
    lower.includes("/test/") ||
    base.startsWith("test_") ||
    base.endsWith("_test.py") ||
    base.endsWith(".test.ts") ||
    base.endsWith(".spec.ts") ||
    base === "conftest.py"
  );
}

const SKIP_XFAIL_RE =
  /(?:@pytest\.mark\.(?:skip|skipif|xfail)\b|\bpytest\.(?:skip|xfail)\s*\(|\bunittest\.(?:skip|skipIf|skipUnless|expectedFailure)\b|\b(?:it|test|describe)\.(?:skip|todo)\s*\()/;
const SUPPRESS_COMMENT_RE =
  /(?:#\s*(?:type:\s*ignore|noqa\b|pylint:\s*disable|pyright:\s*ignore|ruff:\s*noqa)|\/\/\s*(?:@ts-ignore|@ts-expect-error|eslint-disable))/;
const COVERAGE_PRAGMA_RE =
  /(?:#\s*pragma:\s*no\s*cover\b|\/\*\s*istanbul\s+ignore\b|\/\/\s*c8\s+ignore\b)/i;
const REMOVED_ASSERT_RE =
  /^\s*(?:assert\b|self\.assert[A-Za-z]+\s*\(|expect\s*\(.+\)\.(?:to|not)\b)/;
const SLEEP_TIMEOUT_RE =
  /(?:\btime\.sleep\s*\(\s*\d+|\basyncio\.sleep\s*\(\s*\d+|\bsetTimeout\s*\([^,]+,\s*\d{4,})/;

/**
 * Pure in-memory pre-scan that returns ONLY the relative paths in a unified diff
 * that contain at least one added (`+`) line matching a Fast Guard head-side rule.
 * Used to avoid unnecessary git blob prefetching for changed files without Fast Guard hits (Round 2 Issue #6).
 */
export function collectFastGuardHeadCandidatePaths(rawUnifiedDiff: string): Set<string> {
  const candidatePaths = new Set<string>();
  const sections = parseUnifiedDiffSections(rawUnifiedDiff);
  for (const sec of sections) {
    const newPathValid = sec.newPath ? validateRepoRelativePath(sec.newPath) : null;
    if (!newPathValid || !newPathValid.ok) {
      continue;
    }
    const relPath = newPathValid.value;
    let matched = false;
    for (const hunk of sec.hunks) {
      for (const line of hunk.lines) {
        if (
          line.prefix === "+" &&
          line.newLine1Based !== null &&
          (SKIP_XFAIL_RE.test(line.content) ||
            SUPPRESS_COMMENT_RE.test(line.content) ||
            COVERAGE_PRAGMA_RE.test(line.content) ||
            SLEEP_TIMEOUT_RE.test(line.content))
        ) {
          candidatePaths.add(relPath);
          matched = true;
          break;
        }
      }
      if (matched) {
        break;
      }
    }
  }
  return candidatePaths;
}

/**
 * Runs the Fast Guard heuristic diff analysis on a committed diff snapshot.
 */
export function analyzeCommittedDiffWithFastGuard(params: {
  scanId: number;
  diffSnapshot: CommittedDiffSnapshot;
  headBlobsByPath?: ReadonlyMap<string, ImmutableBlobRecord>;
  openDocuments?: readonly OpenEditorDocumentSnapshot[];
}): FastGuardAnalysisResult {
  const { scanId, diffSnapshot, headBlobsByPath, openDocuments = [] } = params;
  const sections = parseUnifiedDiffSections(diffSnapshot.rawUnifiedDiff);
  const hints: FastGuardHint[] = [];

  const openDocMap = new Map<string, OpenEditorDocumentSnapshot>();
  for (const doc of openDocuments) {
    if (areSameWinRepositoryPath(doc.repositoryRoot, diffSnapshot.repositoryRoot)) {
      openDocMap.set(doc.relativePath, doc);
    }
  }

  for (const sec of sections) {
    const newPathValid = sec.newPath ? validateRepoRelativePath(sec.newPath) : null;
    const oldPathValid = sec.oldPath ? validateRepoRelativePath(sec.oldPath) : null;

    for (const hunk of sec.hunks) {
      for (const line of hunk.lines) {
        if (line.prefix === "+" && newPathValid && newPathValid.ok && line.newLine1Based !== null) {
          const relPath = newPathValid.value;
          const headLine = line.newLine1Based;
          const trimmed = line.content.trim();

          let matchedRule: FastGuardRuleId | null = null;
          let message = "";

          if (SKIP_XFAIL_RE.test(line.content)) {
            matchedRule = "FG-SKIP-XFAIL-ADDED";
            message =
              "[Fast Guard Heuristic] 新增測試跳過或預期失敗標記 (skip / xfail / todo)；請確認是否掩蓋回歸失敗。";
          } else if (SUPPRESS_COMMENT_RE.test(line.content)) {
            matchedRule = "FG-LINT-TYPE-SUPPRESS-ADDED";
            message =
              "[Fast Guard Heuristic] 新增靜態檢查／型別抑制註解 (noqa / type: ignore / eslint-disable)。";
          } else if (COVERAGE_PRAGMA_RE.test(line.content)) {
            matchedRule = "FG-COVERAGE-PRAGMA-ADDED";
            message =
              "[Fast Guard Heuristic] 新增覆蓋率排除標記 (pragma: no cover / ignore)。";
          } else if (SLEEP_TIMEOUT_RE.test(line.content)) {
            matchedRule = "FG-TIMEOUT-SLEEP-ADDED";
            message =
              "[Fast Guard Heuristic] 新增固定延遲或長等待呼叫 (sleep / setTimeout)。";
          }

          if (matchedRule !== null) {
            const revUriRes = buildRevisionUriString({
              repositoryRoot: diffSnapshot.repositoryRoot,
              commitOid: diffSnapshot.effectiveHeadOid,
              relativePath: relPath,
              side: "head",
              scanId,
            });
            const revisionUri = revUriRes.ok ? revUriRes.value : null;

            const proj = checkFastGuardHeadLiveProjection({
              repositoryRoot: diffSnapshot.repositoryRoot,
              relativePath: relPath,
              headLine1Based: headLine,
              headBlob: headBlobsByPath?.get(relPath),
              openDoc: openDocMap.get(relPath),
            });

            hints.push({
              hintIndex: hints.length,
              ruleId: matchedRule,
              sourceLabel: FAST_GUARD_SOURCE_LABEL,
              relativePath: relPath,
              side: "head",
              headLine1Based: headLine,
              baseLine1Based: null,
              message,
              snippet: trimmed.slice(0, 160),
              revisionUri,
              liveProjectionAllowed: proj.allowed,
              liveVscodeLine0Based: proj.vscodeLine0Based,
              liveProjectionReason: proj.reason,
            });
          }
        } else if (
          line.prefix === "-" &&
          oldPathValid &&
          oldPathValid.ok &&
          line.oldLine1Based !== null
        ) {
          const relPath = oldPathValid.value;
          if (isTestFilePath(relPath) && REMOVED_ASSERT_RE.test(line.content)) {
            const baseLine = line.oldLine1Based;
            const revUriRes = buildRevisionUriString({
              repositoryRoot: diffSnapshot.repositoryRoot,
              commitOid: diffSnapshot.effectiveBaseOid,
              relativePath: relPath,
              side: "base",
              scanId,
            });
            const revisionUri = revUriRes.ok ? revUriRes.value : null;

            hints.push({
              hintIndex: hints.length,
              ruleId: "FG-ASSERT-REMOVED-IN-TEST",
              sourceLabel: FAST_GUARD_SOURCE_LABEL,
              relativePath: relPath,
              side: "base",
              headLine1Based: null,
              baseLine1Based: baseLine,
              message:
                "[Fast Guard Heuristic] 測試檔案中移除了斷言敘述 (base revision)；請開啟 base 版本核對是否減弱測試保護。",
              snippet: line.content.trim().slice(0, 160),
              revisionUri,
              liveProjectionAllowed: false,
              liveVscodeLine0Based: null,
              liveProjectionReason:
                "Removed line belongs to base revision (side=base); never projected onto live working-tree editor",
            });
          }
        }
      }
    }
  }

  return {
    notice: FAST_GUARD_NON_VERDICT_NOTICE,
    effectiveBaseOid: diffSnapshot.effectiveBaseOid,
    effectiveHeadOid: diffSnapshot.effectiveHeadOid,
    hints,
  };
}

function checkFastGuardHeadLiveProjection(params: {
  repositoryRoot: string;
  relativePath: string;
  headLine1Based: number;
  headBlob: ImmutableBlobRecord | undefined;
  openDoc: OpenEditorDocumentSnapshot | undefined;
}): { allowed: boolean; vscodeLine0Based: number | null; reason: string } {
  const { repositoryRoot, relativePath, headLine1Based, headBlob, openDoc } = params;
  if (!headBlob) {
    return {
      allowed: false,
      vscodeLine0Based: null,
      reason: "Head revision blob not cached for live projection verification",
    };
  }
  if (headLine1Based < 1 || headLine1Based > headBlob.normalizedLineCount) {
    return {
      allowed: false,
      vscodeLine0Based: null,
      reason: `Diff line ${headLine1Based} exceeds normalized line count ${headBlob.normalizedLineCount}`,
    };
  }
  if (!openDoc) {
    return {
      allowed: false,
      vscodeLine0Based: null,
      reason: `Document '${relativePath}' is not open in live editor`,
    };
  }
  if (openDoc.isDirty) {
    return {
      allowed: false,
      vscodeLine0Based: null,
      reason: `Live document '${relativePath}' has unsaved changes (isDirty=true)`,
    };
  }
  const projCheck = canProjectDiagnosticToLiveDocument({
    expectedRepositoryRoot: repositoryRoot,
    actualRepositoryRoot: areSameWinRepositoryPath(openDoc.repositoryRoot, repositoryRoot)
      ? repositoryRoot
      : openDoc.repositoryRoot,
    expectedRelativePath: relativePath,
    actualRelativePath: openDoc.relativePath,
    analyzedSourceBytes: headBlob.rawBytes,
    liveDocumentText: openDoc.text,
    verifiedDocumentVersion: openDoc.verifiedVersion,
    currentDocumentVersionAtPublish: openDoc.currentVersionAtPublish,
    isDocumentClosedOrDeleted: openDoc.isClosedOrDeleted,
  });
  if (!projCheck.ok) {
    return {
      allowed: false,
      vscodeLine0Based: null,
      reason: projCheck.error,
    };
  }
  return {
    allowed: true,
    vscodeLine0Based: headLine1Based - 1,
    reason: "Verified exact match with head revision blob and document version",
  };
}
