/**
 * source/revisionProvider.ts
 *
 * Immutable Git Revision & Diff Provider (Rev 3 §3, §4.2, §5.3, §5.4).
 *
 * Responsibilities:
 * - Reads immutable blobs (<commitOid>:<relativePath>) from the canonical repository
 *   exclusively through UnifiedProcessRunner (never spawns processes directly).
 * - Validates commitOid (40/64 hex) and repository-relative paths before any Git call.
 * - Verifies that the target object is a Git 'blob' (rejecting trees, submodules, or missing paths).
 * - Verifies strict UTF-8 decoding and computes normalized line counts (BOM stripped, CRLF/CR -> LF)
 *   for exact SARIF startLine bounds checking and live editor document comparison.
 * - Reads committed unified diffs and changed file lists for <effectiveBaseOid>..<effectiveHeadOid>.
 * - Encodes and validates read-only `checkwash-rev:` virtual document URIs bound to
 *   { repositoryRoot, commitOid, relativePath, side, scanId }.
 */

import { ValidationResult } from "../core/checkwashSchema";
import { EvidenceSideLabel } from "../core/reportJoiner";
import {
  countNormalizedLines,
  decodeAndValidateSarifUri,
  decodeStrictUtf8,
  isValidCommitOid,
  normalizeSourceForComparison,
} from "../core/sourceIdentity";
import {
  areSameWinRepositoryPath,
  HostEnvironmentDescriptor,
  normalizePlatformLookupKey,
  resolveCanonicalOrNormalizedWinPath,
  verifyWorkspaceHostEnvironment,
} from "../runtime/admission";
import { UnifiedProcessRunner } from "../runtime/processRunner";
import {
  buildSnapshotObjectEnv,
  cleanupEphemeralSnapshotDir,
  EphemeralGitObjectOverlay,
} from "../engine/snapshotBuilder";

export const CHECKWASH_REVISION_URI_SCHEME = "checkwash-rev";

export interface ImmutableBlobRecord {
  repositoryRoot: string;
  commitOid: string;
  relativePath: string;
  rawBytes: Uint8Array;
  utf8Text: string;
  normalizedText: string;
  normalizedLineCount: number;
}

export interface RevisionUriTarget {
  repositoryRoot: string;
  commitOid: string;
  relativePath: string;
  side: EvidenceSideLabel;
  scanId: number;
}

export interface CommittedDiffFileEntry {
  status: "A" | "M" | "D" | "R" | "C" | "T" | "U" | "X";
  oldPath: string | null;
  newPath: string;
}

export interface CommittedDiffSnapshot {
  repositoryRoot: string;
  effectiveBaseOid: string;
  effectiveHeadOid: string;
  changedFiles: CommittedDiffFileEntry[];
  rawUnifiedDiff: string;
}

/**
 * Validates a repository-relative path using the same strict single-decode rules as SARIF URIs.
 */
export function validateRepoRelativePath(relativePath: string): ValidationResult<string> {
  if (typeof relativePath !== "string" || relativePath.length === 0) {
    return { ok: false, error: "Repository-relative path must be a non-empty string" };
  }
  if (relativePath.includes("\\") || relativePath.startsWith("/")) {
    return {
      ok: false,
      error: `Repository-relative path must use forward slashes and be relative: '${relativePath}'`,
    };
  }
  const encoded = relativePath
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  const check = decodeAndValidateSarifUri(encoded);
  if (!check.ok) {
    return check;
  }
  if (check.value !== relativePath) {
    return {
      ok: false,
      error: `Repository-relative path did not round-trip normalization: '${relativePath}'`,
    };
  }
  return { ok: true, value: relativePath };
}

/**
 * Builds a canonical `checkwash-rev:` URI string for opening an immutable revision in VS Code.
 */
export function buildRevisionUriString(target: RevisionUriTarget): ValidationResult<string> {
  if (!isValidCommitOid(target.commitOid)) {
    return { ok: false, error: `Invalid commit OID for revision URI: '${target.commitOid}'` };
  }
  const pathCheck = validateRepoRelativePath(target.relativePath);
  if (!pathCheck.ok) {
    return pathCheck;
  }
  if (typeof target.repositoryRoot !== "string" || target.repositoryRoot.trim().length === 0) {
    return { ok: false, error: "Repository root is required for revision URI" };
  }
  if (!Number.isInteger(target.scanId) || target.scanId < 1) {
    return { ok: false, error: `Invalid scanId for revision URI: ${String(target.scanId)}` };
  }
  if (target.side !== "head" && target.side !== "base" && target.side !== "unknown") {
    return { ok: false, error: `Invalid side for revision URI: ${String(target.side)}` };
  }

  const encodedSegments = pathCheck.value
    .split("/")
    .map((s) => encodeURIComponent(s))
    .join("/");
  const repoB64 = Buffer.from(target.repositoryRoot, "utf8").toString("base64url");
  const query = `repoB64=${repoB64}&oid=${target.commitOid}&side=${target.side}&scanId=${String(target.scanId)}`;

  return {
    ok: true,
    value: `${CHECKWASH_REVISION_URI_SCHEME}:/${encodedSegments}?${query}`,
  };
}

/**
 * Parses and validates a `checkwash-rev:` URI string back into a RevisionUriTarget.
 */
export function parseRevisionUriString(uriString: string): ValidationResult<RevisionUriTarget> {
  if (typeof uriString !== "string" || !uriString.startsWith(`${CHECKWASH_REVISION_URI_SCHEME}:/`)) {
    return { ok: false, error: `Invalid revision URI scheme: '${uriString}'` };
  }
  const withoutScheme = uriString.slice(`${CHECKWASH_REVISION_URI_SCHEME}:/`.length);
  const qIndex = withoutScheme.indexOf("?");
  if (qIndex <= 0) {
    return { ok: false, error: `Revision URI missing path or query parameters: '${uriString}'` };
  }
  const encodedPath = withoutScheme.slice(0, qIndex);
  const queryStr = withoutScheme.slice(qIndex + 1);

  const pathRes = decodeAndValidateSarifUri(encodedPath);
  if (!pathRes.ok) {
    return { ok: false, error: `Invalid path in revision URI: ${pathRes.error}` };
  }

  let effectiveQueryStr = queryStr;
  if (!effectiveQueryStr.includes("=") && /%3d/i.test(effectiveQueryStr)) {
    try {
      effectiveQueryStr = decodeURIComponent(effectiveQueryStr);
    } catch {
      return { ok: false, error: "Malformed percent-encoding in revision URI query" };
    }
  }

  const params = new URLSearchParams(effectiveQueryStr);
  const repoB64 = params.get("repoB64");
  let repositoryRoot = "";
  if (repoB64 !== null) {
    if (!/^[A-Za-z0-9_-]+$/.test(repoB64)) {
      return { ok: false, error: "Invalid 'repoB64' base64url parameter in revision URI" };
    }
    const repoBytes = Buffer.from(repoB64, "base64url");
    const repoUtf8 = decodeStrictUtf8(repoBytes);
    if (!repoUtf8.ok) {
      return { ok: false, error: "Invalid UTF-8 in 'repoB64' parameter in revision URI" };
    }
    repositoryRoot = repoUtf8.value;
  } else {
    repositoryRoot = params.get("repo") ?? "";
  }
  const commitOid = params.get("oid") ?? "";
  const sideRaw = params.get("side") ?? "";
  const scanIdRaw = params.get("scanId") ?? "";

  if (!repositoryRoot || /[\0\r\n]/.test(repositoryRoot)) {
    return { ok: false, error: "Invalid 'repo' parameter in revision URI" };
  }
  if (!isValidCommitOid(commitOid)) {
    return { ok: false, error: `Invalid 'oid' parameter in revision URI: '${commitOid}'` };
  }
  if (sideRaw !== "head" && sideRaw !== "base" && sideRaw !== "unknown") {
    return { ok: false, error: `Invalid 'side' parameter in revision URI: '${sideRaw}'` };
  }
  if (!/^[1-9]\d*$/.test(scanIdRaw)) {
    return { ok: false, error: `Invalid 'scanId' parameter in revision URI: '${scanIdRaw}'` };
  }
  const scanId = Number(scanIdRaw);
  if (!Number.isSafeInteger(scanId) || scanId < 1) {
    return { ok: false, error: `Out-of-range 'scanId' parameter in revision URI: '${scanIdRaw}'` };
  }

  return {
    ok: true,
    value: {
      repositoryRoot,
      commitOid,
      relativePath: pathRes.value,
      side: sideRaw,
      scanId,
    },
  };
}

export class RevisionProvider {
  private readonly blobCache = new Map<string, ImmutableBlobRecord>();
  private readonly verifiedCommitOids = new Set<string>();
  private activeSnapshotOverlay: EphemeralGitObjectOverlay | null = null;

  constructor(private readonly runner: UnifiedProcessRunner) {}

  public setActiveSnapshotOverlay(overlay: EphemeralGitObjectOverlay | null): void {
    if (
      this.activeSnapshotOverlay &&
      this.activeSnapshotOverlay.snapshotDir !== overlay?.snapshotDir
    ) {
      cleanupEphemeralSnapshotDir(this.activeSnapshotOverlay.snapshotDir);
    }
    this.activeSnapshotOverlay = overlay;
  }

  public getActiveSnapshotOverlay(): EphemeralGitObjectOverlay | null {
    return this.activeSnapshotOverlay;
  }

  private getSnapshotEnvIfApplicable(
    repositoryRoot: string,
    commitOids: readonly string[]
  ): Readonly<Record<string, string>> | undefined {
    const ov = this.activeSnapshotOverlay;
    if (!ov || !repositoryRoot) {
      return undefined;
    }
    if (!areSameWinRepositoryPath(repositoryRoot, ov.repositoryRoot)) {
      return undefined;
    }
    const snapOid = ov.snapshotCommitOid.toLowerCase();
    if (!commitOids.some((oid) => oid.toLowerCase() === snapOid)) {
      return undefined;
    }
    return buildSnapshotObjectEnv(ov);
  }

  public clearCache(): void {
    this.setActiveSnapshotOverlay(null);
    this.blobCache.clear();
    this.verifiedCommitOids.clear();
  }

  /**
   * Reads an immutable file blob (<commitOid>:<relativePath>) from the canonical Git repository.
   * Verifies that:
   * 1. commitOid is a valid 40/64-char hex commit OID.
   * 2. relativePath passes strict path validation (no traversal, ADS, reserved names, or leading '-').
   * 3. commitOid resolves to a valid commit object (`git cat-file -t <commitOid>` === 'commit').
   * 4. `<commitOid>:<relativePath>` is a `blob` (rejecting directories/trees, submodules, or missing paths).
   * 5. The blob content is valid UTF-8.
   */
  public async readCommitBlob(
    hostDesc: HostEnvironmentDescriptor,
    commitOid: string,
    relativePath: string,
    abortSignal?: AbortSignal,
    timeoutBudgetMs?: number
  ): Promise<ValidationResult<ImmutableBlobRecord>> {
    if (!isValidCommitOid(commitOid)) {
      return { ok: false, error: `Invalid commit OID '${commitOid}'` };
    }
    const pathCheck = validateRepoRelativePath(relativePath);
    if (!pathCheck.ok) {
      return pathCheck;
    }
    if (!hostDesc.isWorkspaceTrusted) {
      return {
        ok: false,
        error: "Restricted Mode: external process execution is disabled in untrusted workspaces",
      };
    }
    const hostEnvCheck = verifyWorkspaceHostEnvironment(hostDesc);
    if (!hostEnvCheck.ok) {
      return hostEnvCheck;
    }
    if (this.runner.hasUnconfirmedCleanup()) {
      return {
        ok: false,
        error: "Execution blocked: previous run cleanup was not confirmed",
      };
    }
    const brokerDisabled = this.runner.isExecutionDisabledByBrokerFailure();
    if (brokerDisabled.disabled) {
      return {
        ok: false,
        error: `Execution features are disabled: ${brokerDisabled.reason ?? "broker failure"}`,
      };
    }

    const safePath = pathCheck.value;
    const normalizedOid = commitOid.toLowerCase();
    const lookupRepoRoot = resolveCanonicalOrNormalizedWinPath(hostDesc.repositoryRootPath);
    const lookupRepoKey = lookupRepoRoot
      ? normalizePlatformLookupKey(lookupRepoRoot, hostDesc.platform)
      : "";
    if (lookupRepoKey) {
      const preCacheKey = `${lookupRepoKey}::${normalizedOid}::${safePath}`;
      const preCached = this.blobCache.get(preCacheKey);
      if (preCached) {
        return { ok: true, value: preCached };
      }
    }

    const stepTimeout = (defaultMs: number): number =>
      timeoutBudgetMs !== undefined ? Math.max(1, Math.min(defaultMs, timeoutBudgetMs)) : defaultMs;
    const extraGitEnv = this.getSnapshotEnvIfApplicable(hostDesc.repositoryRootPath, [commitOid]);

    let canonicalRepoRoot = lookupRepoRoot;
    const preCommitKey = `${lookupRepoKey}::${normalizedOid}`;
    if (!lookupRepoKey || !this.verifiedCommitOids.has(preCommitKey)) {
      // Verify commit object type once per (canonicalRepoRoot, commitOid)
      const commitTypeRes = await this.runner.runTrustedGitRead(
        hostDesc,
        ["cat-file", "-t", commitOid],
        stepTimeout(10_000),
        abortSignal,
        extraGitEnv
      );
      if (!commitTypeRes.ok) {
        return {
          ok: false,
          error: `Failed to verify commit object '${commitOid}': ${commitTypeRes.error}`,
        };
      }
      canonicalRepoRoot = commitTypeRes.value.admission.canonicalRepositoryRoot;
      if (commitTypeRes.value.stdoutText.trim() !== "commit") {
        return {
          ok: false,
          error: `Object '${commitOid}' is not a commit (got '${commitTypeRes.value.stdoutText.trim()}')`,
        };
      }
      this.verifiedCommitOids.add(
        `${normalizePlatformLookupKey(canonicalRepoRoot, hostDesc.platform)}::${normalizedOid}`
      );
    }

    const cacheKey = `${normalizePlatformLookupKey(canonicalRepoRoot, hostDesc.platform)}::${normalizedOid}::${safePath}`;
    const cached = this.blobCache.get(cacheKey);
    if (cached) {
      return { ok: true, value: cached };
    }

    const objectSpec = `${commitOid}:${safePath}`;

    // Verify target is a blob (not a tree/directory or submodule commit)
    const objTypeRes = await this.runner.runTrustedGitRead(
      hostDesc,
      ["cat-file", "-t", objectSpec],
      stepTimeout(10_000),
      abortSignal,
      extraGitEnv
    );
    if (!objTypeRes.ok) {
      return {
        ok: false,
        error: `Path '${safePath}' does not exist in commit '${commitOid}': ${objTypeRes.error}`,
      };
    }
    const objType = objTypeRes.value.stdoutText.trim();
    if (objType !== "blob") {
      return {
        ok: false,
        error: `Path '${safePath}' in commit '${commitOid}' is not a regular file blob (type='${objType}')`,
      };
    }

    // Read blob content via executeGatedProcess so we inspect raw bytes & strict UTF-8
    const blobProcRes = await this.runner.executeGatedProcess({
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
        "cat-file",
        "blob",
        objectSpec,
      ],
      envSelector: extraGitEnv
        ? (ctx) => ({ ...ctx.sanitizedStaticEnv, ...extraGitEnv })
        : undefined,
      timeoutMs: stepTimeout(15_000),
      abortSignal,
    });
    if (!blobProcRes.ok) {
      return blobProcRes;
    }

    const { admission, outcome } = blobProcRes.value;
    canonicalRepoRoot = admission.canonicalRepositoryRoot;
    if (outcome.status !== "completed" || outcome.exitCode !== 0 || !outcome.cleanupConfirmed) {
      return {
        ok: false,
        error: `git cat-file blob failed for '${objectSpec}' (status=${outcome.status}, exit=${String(outcome.exitCode)})`,
      };
    }
    if (!outcome.stdoutUtf8Valid) {
      return {
        ok: false,
        error: `File '${safePath}' in commit '${commitOid}' contains invalid UTF-8 bytes`,
      };
    }

    const rawBytes = new Uint8Array(outcome.stdoutRaw);
    const utf8Check = decodeStrictUtf8(rawBytes);
    if (!utf8Check.ok) {
      return utf8Check;
    }

    const utf8Text = utf8Check.value;
    const normalizedText = normalizeSourceForComparison(utf8Text);
    const normalizedLineCount = countNormalizedLines(normalizedText);

    const record: ImmutableBlobRecord = {
      repositoryRoot: canonicalRepoRoot,
      commitOid,
      relativePath: safePath,
      rawBytes,
      utf8Text,
      normalizedText,
      normalizedLineCount,
    };

    const finalCacheKey = `${normalizePlatformLookupKey(canonicalRepoRoot, hostDesc.platform)}::${normalizedOid}::${safePath}`;
    this.blobCache.set(finalCacheKey, record);
    return { ok: true, value: record };
  }

  /**
   * Reads the committed unified diff and changed file list for <effectiveBaseOid>..<effectiveHeadOid>.
   */
  public async readCommittedDiff(
    hostDesc: HostEnvironmentDescriptor,
    effectiveBaseOid: string,
    effectiveHeadOid: string,
    abortSignal?: AbortSignal,
    timeoutBudgetMs?: number
  ): Promise<ValidationResult<CommittedDiffSnapshot>> {
    if (!isValidCommitOid(effectiveBaseOid) || !isValidCommitOid(effectiveHeadOid)) {
      return {
        ok: false,
        error: `Invalid base/head commit OIDs for diff: '${effectiveBaseOid}'..'${effectiveHeadOid}'`,
      };
    }

    const rangeArg = `${effectiveBaseOid}..${effectiveHeadOid}`;
    const stepTimeout = (defaultMs: number): number =>
      timeoutBudgetMs !== undefined ? Math.max(1, Math.min(defaultMs, timeoutBudgetMs)) : defaultMs;
    const extraGitEnv = this.getSnapshotEnvIfApplicable(hostDesc.repositoryRootPath, [
      effectiveBaseOid,
      effectiveHeadOid,
    ]);

    const nameStatusRes = await this.runner.runTrustedGitRead(
      hostDesc,
      [
        "diff",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--name-status",
        rangeArg,
        "--",
      ],
      stepTimeout(15_000),
      abortSignal,
      extraGitEnv
    );
    if (!nameStatusRes.ok) {
      return {
        ok: false,
        error: `Failed to list changed files for '${rangeArg}': ${nameStatusRes.error}`,
      };
    }

    const changedFiles: CommittedDiffFileEntry[] = [];
    const lines = nameStatusRes.value.stdoutText
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0);

    for (const line of lines) {
      const parts = line.split("\t");
      const rawStatus = parts[0] ?? "";
      const statusChar = (rawStatus[0] ?? "M") as CommittedDiffFileEntry["status"];
      if ((statusChar === "R" || statusChar === "C") && parts.length >= 3) {
        changedFiles.push({
          status: statusChar,
          oldPath: parts[1],
          newPath: parts[2],
        });
      } else if (parts.length >= 2) {
        changedFiles.push({
          status: statusChar,
          oldPath: statusChar === "A" ? null : parts[1],
          newPath: parts[1],
        });
      }
    }

    const diffRes = await this.runner.runTrustedGitRead(
      hostDesc,
      [
        "diff",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--unified=3",
        rangeArg,
        "--",
      ],
      stepTimeout(20_000),
      abortSignal,
      extraGitEnv
    );
    if (!diffRes.ok) {
      return {
        ok: false,
        error: `Failed to read unified diff for '${rangeArg}': ${diffRes.error}`,
      };
    }

    return {
      ok: true,
      value: {
        repositoryRoot: nameStatusRes.value.admission.canonicalRepositoryRoot,
        effectiveBaseOid,
        effectiveHeadOid,
        changedFiles,
        rawUnifiedDiff: diffRes.value.stdoutText,
      },
    };
  }
}
