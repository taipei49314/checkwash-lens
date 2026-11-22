/**
 * engine/snapshotBuilder.ts
 *
 * Ephemeral Git Snapshot Builder for Pre-Commit Staged & Working-Tree Checks.
 *
 * Security & Repository Integrity Invariants:
 * 1. Zero repository mutation: NEVER modifies `<repo>/.git/index`, NEVER writes loose or pack
 *    objects into `<repo>/.git/objects`, NEVER moves `HEAD` or creates refs/stashes, and NEVER
 *    touches working-tree files.
 * 2. Isolated object & index store: Uses a per-scan temporary directory in `os.tmpdir()` via
 *    `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, and `GIT_INDEX_FILE`.
 * 3. Filter, hook, and fsmonitor immunity:
 *    - Always passes `-c core.fsmonitor=false`.
 *    - Never calls `git status` or `git add` (which can trigger `.gitattributes` `filter.*.clean`).
 *    - Uses pure plumbing (`ls-tree`, `ls-files --stage`, `ls-files --others --exclude-standard`,
 *      `hash-object -w --no-filters`, `update-index --cacheinfo`, `write-tree`, `commit-tree`).
 * 4. Symlink / junction escape protection: Rejects symbolic links, directory junctions, and any
 *    canonical path escaping `canonicalRepositoryRoot` fail-closed.
 * 5. Unified brokered execution: All Git plumbing calls go exclusively through
 *    `UnifiedProcessRunner.runTrustedGitRead` (no direct process creation).
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { ValidationResult } from "../core/checkwashSchema";
import { decodeStrictUtf8, isValidCommitOid } from "../core/sourceIdentity";
import {
  createIsolatedRunDirectory,
  HostEnvironmentDescriptor,
  isPathInsideOrEqualPlatform,
  normalizePlatformLookupKey,
  resolveCanonicalOrNormalizedPath,
  resolveCanonicalPath,
} from "../runtime/admission";
import { UnifiedProcessRunner } from "../runtime/processRunner";
import { validateRepoRelativePath } from "../source/revisionProvider";

export type UncommittedSnapshotMode = "staged" | "worktree";

export interface EphemeralGitObjectOverlay {
  readonly repositoryRoot: string;
  readonly snapshotDir: string;
  readonly gitObjectDirectory: string;
  readonly gitAlternateObjectDirectories: string;
  readonly baseCommitOid: string;
  readonly snapshotCommitOid: string;
  readonly mode: UncommittedSnapshotMode;
}

export type SnapshotBuildOutcome =
  | {
      readonly hasChanges: false;
      readonly mode: UncommittedSnapshotMode;
      readonly baseCommitOid: string;
      readonly emptyReason: string;
    }
  | {
      readonly hasChanges: true;
      readonly overlay: EphemeralGitObjectOverlay;
    };

interface HeadTreeEntry {
  readonly mode: string;
  readonly type: string;
  readonly oid: string;
  readonly relPath: string;
}

interface DirListingCacheEntry {
  readonly exactNames: ReadonlySet<string>;
  readonly byLowerName: ReadonlyMap<string, string>;
  readonly isCaseInsensitive: boolean;
}

const BATCH_CHUNK_SIZE = 25;
const FAST_HASH_MAX_BYTES = 8 * 1024 * 1024; // 8 MiB

export function cleanupEphemeralSnapshotDir(snapshotDir: string | null | undefined): void {
  if (!snapshotDir) {
    return;
  }
  try {
    fs.rmSync(snapshotDir, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup of temp snapshot directory
  }
}

export function buildSnapshotObjectEnv(overlay: EphemeralGitObjectOverlay): Record<string, string> {
  return {
    GIT_OBJECT_DIRECTORY: overlay.gitObjectDirectory,
    GIT_ALTERNATE_OBJECT_DIRECTORIES: overlay.gitAlternateObjectDirectories,
  };
}

function computeGitBlobDigest(buf: Buffer, oidHexLength: number): string {
  const alg = oidHexLength === 64 ? "sha256" : "sha1";
  return crypto
    .createHash(alg)
    .update(`blob ${buf.length}\0`, "utf8")
    .update(buf)
    .digest("hex")
    .toLowerCase();
}

function isBlobUnchangedFromHead(rawBuf: Buffer, headOidLower: string): boolean {
  const rawDigest = computeGitBlobDigest(rawBuf, headOidLower.length);
  if (rawDigest === headOidLower) {
    return true;
  }
  // Textual CRLF/LF checkout equivalence (matching Checkwash's own non-lossy rule:
  // UTF-8 valid, zero NUL bytes, CRLF -> LF only).
  if (!rawBuf.includes(0) && rawBuf.includes(0x0d)) {
    const utf8Res = decodeStrictUtf8(rawBuf);
    if (utf8Res.ok) {
      const lfBuf = Buffer.from(utf8Res.value.replace(/\r\n/g, "\n"), "utf8");
      const lfDigest = computeGitBlobDigest(lfBuf, headOidLower.length);
      if (lfDigest === headOidLower) {
        return true;
      }
    }
  }
  return false;
}

function parseLsTreeZ(stdoutText: string): Map<string, HeadTreeEntry> {
  const out = new Map<string, HeadTreeEntry>();
  const records = stdoutText.split("\0");
  for (const rec of records) {
    if (!rec) {
      continue;
    }
    const tabIdx = rec.indexOf("\t");
    if (tabIdx <= 0) {
      continue;
    }
    const meta = rec.slice(0, tabIdx).trim().split(/\s+/);
    const relPath = rec.slice(tabIdx + 1);
    if (meta.length >= 3 && relPath.length > 0) {
      out.set(relPath, {
        mode: meta[0],
        type: meta[1],
        oid: meta[2].toLowerCase(),
        relPath,
      });
    }
  }
  return out;
}

function parseLsFilesStageZ(
  stdoutText: string
): ValidationResult<Map<string, { mode: string; oid: string }>> {
  const out = new Map<string, { mode: string; oid: string }>();
  const records = stdoutText.split("\0");
  for (const rec of records) {
    if (!rec) {
      continue;
    }
    const tabIdx = rec.indexOf("\t");
    if (tabIdx <= 0) {
      continue;
    }
    const meta = rec.slice(0, tabIdx).trim().split(/\s+/);
    const relPath = rec.slice(tabIdx + 1);
    if (meta.length >= 3 && relPath.length > 0) {
      const [mode, oid, stage] = meta;
      if (stage !== "0") {
        return {
          ok: false,
          error: `Cannot scan uncommitted snapshot while repository index has unresolved merge conflicts ('${relPath}', stage=${stage}).`,
        };
      }
      out.set(relPath, { mode, oid: oid.toLowerCase() });
    }
  }
  return { ok: true, value: out };
}

function detectDirectoryCaseInsensitive(
  dirPath: string,
  exactNames: ReadonlySet<string>,
  platform: string
): boolean {
  if (platform === "win32") {
    return true;
  }
  for (const name of exactNames) {
    if (!/[a-zA-Z]/.test(name)) {
      continue;
    }
    const toggled = name.replace(/[a-zA-Z]/g, (ch) =>
      ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()
    );
    if (toggled === name || exactNames.has(toggled)) {
      continue;
    }
    try {
      const stOrig = fs.lstatSync(path.join(dirPath, name), { bigint: true });
      const stAlt = fs.lstatSync(path.join(dirPath, toggled), { bigint: true });
      if (
        (stOrig.dev !== 0n || stOrig.ino !== 0n) &&
        stOrig.dev === stAlt.dev &&
        stOrig.ino === stAlt.ino
      ) {
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }
  return false;
}

function readDirectoryCacheEntry(
  dirPath: string,
  cache: Map<string, DirListingCacheEntry | null>,
  platform: string
): DirListingCacheEntry | null {
  const key = normalizePlatformLookupKey(dirPath, platform);
  if (cache.has(key)) {
    return cache.get(key) ?? null;
  }
  try {
    const names = fs.readdirSync(dirPath);
    const exactNames = new Set<string>();
    const byLowerName = new Map<string, string>();
    for (const name of names) {
      exactNames.add(name);
      byLowerName.set(name.toLowerCase(), name);
    }
    const isCaseInsensitive = detectDirectoryCaseInsensitive(dirPath, exactNames, platform);
    const entry: DirListingCacheEntry = { exactNames, byLowerName, isCaseInsensitive };
    cache.set(key, entry);
    return entry;
  } catch {
    cache.set(key, null);
    return null;
  }
}

type WorktreePathInspection =
  | { state: "missing"; caseRenamedActualRelPath?: string }
  | { state: "submodule_gitlink" }
  | { state: "regular_file"; absPath: string; size: number }
  | { state: "error"; error: string };

function inspectWorktreePathExact(params: {
  canonicalRepoRoot: string;
  relPath: string;
  headEntry: HeadTreeEntry | undefined;
  dirCache: Map<string, DirListingCacheEntry | null>;
  platform: string;
}): WorktreePathInspection {
  const { canonicalRepoRoot, relPath, headEntry, dirCache, platform } = params;
  const segments = relPath.split("/");

  let currentDir = canonicalRepoRoot;
  const actualOnDiskSegments: string[] = [];
  let hadCaseDifference = false;

  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    const isLeaf = i === segments.length - 1;
    const listing = readDirectoryCacheEntry(currentDir, dirCache, platform);
    if (!listing) {
      return { state: "missing" };
    }

    const exactExists = listing.exactNames.has(seg);
    const ciMatch = listing.isCaseInsensitive
      ? listing.byLowerName.get(seg.toLowerCase())
      : undefined;
    if (!exactExists) {
      if (listing.isCaseInsensitive && ciMatch && ciMatch !== seg) {
        hadCaseDifference = true;
        actualOnDiskSegments.push(ciMatch);
      } else {
        return { state: "missing" };
      }
    } else {
      actualOnDiskSegments.push(seg);
    }

    const onDiskSeg = actualOnDiskSegments[i];
    const nextAbsPath = path.join(currentDir, onDiskSeg);

    let lstat: fs.Stats;
    try {
      lstat = fs.lstatSync(nextAbsPath);
    } catch {
      return { state: "missing" };
    }

    if (lstat.isSymbolicLink()) {
      const displaySegPath = actualOnDiskSegments.slice(0, i + 1).join("/");
      return {
        state: "error",
        error: isLeaf
          ? `Refusing to snapshot symbolic link '${displaySegPath}' in working tree.`
          : `Refusing to snapshot path '${relPath}' inside symbolic link or junction directory '${displaySegPath}'.`,
      };
    }

    const canonSegRes = resolveCanonicalPath(nextAbsPath);
    if (!canonSegRes.ok) {
      return {
        state: "error",
        error: `Cannot canonicalize working-tree path '${nextAbsPath}': ${canonSegRes.error}`,
      };
    }
    if (!isPathInsideOrEqualPlatform(canonSegRes.value, canonicalRepoRoot, platform)) {
      return {
        state: "error",
        error: `Refusing working-tree path '${relPath}' whose canonical target '${canonSegRes.value}' escapes repository root '${canonicalRepoRoot}'.`,
      };
    }

    if (!isLeaf) {
      if (!lstat.isDirectory()) {
        return { state: "missing" };
      }
      currentDir = nextAbsPath;
      continue;
    }

    // If a parent or leaf segment differed only in letter casing on case-insensitive NTFS,
    // treat the old-case path as missing/deleted and surface the actual on-disk relative path!
    if (hadCaseDifference) {
      const actualRel = actualOnDiskSegments.join("/");
      return {
        state: "missing",
        caseRenamedActualRelPath: lstat.isFile() ? actualRel : undefined,
      };
    }

    if (lstat.isDirectory()) {
      if (headEntry?.mode === "160000") {
        return { state: "submodule_gitlink" };
      }
      return { state: "missing" };
    }

    if (!lstat.isFile()) {
      return {
        state: "error",
        error: `Refusing to snapshot non-regular working-tree entry '${relPath}'.`,
      };
    }

    return {
      state: "regular_file",
      absPath: canonSegRes.value,
      size: lstat.size,
    };
  }

  return { state: "missing" };
}

/**
 * Builds an isolated, immutable snapshot commit (`HEAD -> Staged` or `HEAD -> Worktree`)
 * inside a temporary object/index directory outside `<repo>/.git`.
 */
export async function createEphemeralSnapshotCommit(params: {
  processRunner: UnifiedProcessRunner;
  hostDesc: HostEnvironmentDescriptor;
  mode: UncommittedSnapshotMode;
  abortSignal?: AbortSignal;
  getRemainingBudgetMs?: () => number;
}): Promise<ValidationResult<SnapshotBuildOutcome>> {
  const { processRunner, hostDesc, mode, abortSignal, getRemainingBudgetMs } = params;

  const stepTimeout = (defaultMs: number): number => {
    if (!getRemainingBudgetMs) {
      return defaultMs;
    }
    return Math.max(1, Math.min(defaultMs, getRemainingBudgetMs()));
  };

  // 1. Resolve canonical git-dir, git-common-dir, HEAD^{commit}, and HEAD^{tree}
  const gitDirsRes = await processRunner.runTrustedGitRead(
    hostDesc,
    ["rev-parse", "--path-format=absolute", "--git-dir", "--git-common-dir"],
    stepTimeout(10_000),
    abortSignal
  );
  if (!gitDirsRes.ok) {
    return {
      ok: false,
      error: `Failed to resolve repository Git metadata directories: ${gitDirsRes.error}`,
    };
  }

  const canonicalRepoRoot = gitDirsRes.value.admission.canonicalRepositoryRoot;
  const dirLines = gitDirsRes.value.stdoutText
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  if (dirLines.length < 2) {
    return {
      ok: false,
      error: "Unexpected git rev-parse --git-dir / --git-common-dir output",
    };
  }

  const canonicalGitDir = resolveCanonicalOrNormalizedPath(dirLines[0]);
  const canonicalGitCommonDir = resolveCanonicalOrNormalizedPath(dirLines[1]);
  const repoObjectsDir = resolveCanonicalOrNormalizedPath(
    path.join(canonicalGitCommonDir, "objects")
  );
  if (!repoObjectsDir || !fs.existsSync(repoObjectsDir)) {
    return {
      ok: false,
      error: `Repository Git objects directory not found: '${repoObjectsDir}'`,
    };
  }

  const headCommitRes = await processRunner.runTrustedGitRead(
    hostDesc,
    ["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"],
    stepTimeout(10_000),
    abortSignal
  );
  if (!headCommitRes.ok) {
    return {
      ok: false,
      error:
        "Repository HEAD does not resolve to an existing commit (unborn branch). Create at least one commit before running uncommitted snapshot pre-check.",
    };
  }
  const headCommitOid = headCommitRes.value.stdoutText.trim().toLowerCase();
  if (!isValidCommitOid(headCommitOid)) {
    return { ok: false, error: `Invalid HEAD commit OID: '${headCommitOid}'` };
  }

  const headTreeRes = await processRunner.runTrustedGitRead(
    hostDesc,
    ["rev-parse", "--verify", "--end-of-options", "HEAD^{tree}"],
    stepTimeout(10_000),
    abortSignal
  );
  if (!headTreeRes.ok) {
    return { ok: false, error: `Failed to resolve HEAD^{tree}: ${headTreeRes.error}` };
  }
  const headTreeOid = headTreeRes.value.stdoutText.trim().toLowerCase();
  if (!isValidCommitOid(headTreeOid)) {
    return { ok: false, error: `Invalid HEAD tree OID: '${headTreeOid}'` };
  }

  // 2. Allocate isolated ephemeral snapshot directory outside the repository
  const snapshotDir = createIsolatedRunDirectory("checkwash-lens-snap-");
  const snapObjectsDir = path.join(snapshotDir, "objects");
  const snapIndexFile = path.join(snapshotDir, "index");
  fs.mkdirSync(snapObjectsDir, { recursive: true });

  const snapPlumbingEnv: Record<string, string> = {
    GIT_OBJECT_DIRECTORY: snapObjectsDir,
    GIT_ALTERNATE_OBJECT_DIRECTORIES: repoObjectsDir,
    GIT_INDEX_FILE: snapIndexFile,
    GIT_AUTHOR_NAME: "Checkwash Lens Snapshot",
    GIT_AUTHOR_EMAIL: "snapshot@checkwash.local",
    GIT_AUTHOR_DATE: "1700000000 +0000",
    GIT_COMMITTER_NAME: "Checkwash Lens Snapshot",
    GIT_COMMITTER_EMAIL: "snapshot@checkwash.local",
    GIT_COMMITTER_DATE: "1700000000 +0000",
  };

  let keepSnapshotDir = false;
  try {
    if (mode === "staged") {
      const repoIndexPath = path.join(canonicalGitDir, "index");
      let repoIndexStat: fs.Stats | null = null;
      try {
        repoIndexStat = fs.lstatSync(repoIndexPath);
      } catch {
        repoIndexStat = null;
      }
      if (repoIndexStat && repoIndexStat.isSymbolicLink()) {
        return {
          ok: false,
          error: `Refusing to pre-check staged snapshot: repository Git index is a symbolic link ('${repoIndexPath}')`,
        };
      }
      if (repoIndexStat && repoIndexStat.isFile()) {
        fs.copyFileSync(repoIndexPath, snapIndexFile);
      } else {
        const seedRes = await processRunner.runTrustedGitRead(
          hostDesc,
          ["read-tree", headCommitOid],
          stepTimeout(15_000),
          abortSignal,
          snapPlumbingEnv
        );
        if (!seedRes.ok) {
          return { ok: false, error: `Failed to initialize staged snapshot index: ${seedRes.error}` };
        }
      }

      // Reject unresolved merge conflicts in index
      const unmergedRes = await processRunner.runTrustedGitRead(
        hostDesc,
        ["ls-files", "-u"],
        stepTimeout(10_000),
        abortSignal,
        snapPlumbingEnv
      );
      if (!unmergedRes.ok) {
        return { ok: false, error: `Failed to inspect staged index conflicts: ${unmergedRes.error}` };
      }
      if (unmergedRes.value.stdoutText.trim().length > 0) {
        return {
          ok: false,
          error:
            "Cannot scan staged snapshot while repository index has unresolved merge conflicts.",
        };
      }
    } else {
      // Mode "worktree":
      // 1) Inspect real repository index strictly via ls-files --stage -z to reject merge conflicts
      //    and include any force-added paths (`git add -f` on gitignored files).
      const realStageRes = await processRunner.runTrustedGitRead(
        hostDesc,
        ["ls-files", "--stage", "-z"],
        stepTimeout(15_000),
        abortSignal
      );
      if (!realStageRes.ok) {
        return { ok: false, error: `Failed to read repository index state: ${realStageRes.error}` };
      }
      const parsedRealIndex = parseLsFilesStageZ(realStageRes.value.stdoutText);
      if (!parsedRealIndex.ok) {
        return parsedRealIndex;
      }
      const realIndexMap = parsedRealIndex.value;

      // 2) Seed ephemeral snapIndexFile from HEAD
      const readTreeRes = await processRunner.runTrustedGitRead(
        hostDesc,
        ["read-tree", headCommitOid],
        stepTimeout(15_000),
        abortSignal,
        snapPlumbingEnv
      );
      if (!readTreeRes.ok) {
        return { ok: false, error: `Failed to seed working-tree snapshot index: ${readTreeRes.error}` };
      }

      // 3) Read HEAD tree entries (zero working-tree reads, zero filters)
      const lsTreeRes = await processRunner.runTrustedGitRead(
        hostDesc,
        ["ls-tree", "-r", "-z", headCommitOid],
        stepTimeout(15_000),
        abortSignal,
        snapPlumbingEnv
      );
      if (!lsTreeRes.ok) {
        return { ok: false, error: `Failed to enumerate HEAD tree entries: ${lsTreeRes.error}` };
      }
      const headEntries = parseLsTreeZ(lsTreeRes.value.stdoutText);

      // 4) Enumerate non-ignored untracked paths relative to HEAD index (zero content reads, zero clean filters)
      const othersRes = await processRunner.runTrustedGitRead(
        hostDesc,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        stepTimeout(15_000),
        abortSignal,
        snapPlumbingEnv
      );
      if (!othersRes.ok) {
        return {
          ok: false,
          error: `Failed to enumerate untracked working-tree files: ${othersRes.error}`,
        };
      }

      const candidateSet = new Set<string>();
      for (const relPath of headEntries.keys()) {
        candidateSet.add(relPath);
      }
      for (const relPath of realIndexMap.keys()) {
        candidateSet.add(relPath);
      }
      for (const rawOther of othersRes.value.stdoutText.split("\0")) {
        if (!rawOther || rawOther.endsWith("/")) {
          // Trailing '/' indicates an untracked nested git repository directory; skip directory pointer
          continue;
        }
        candidateSet.add(rawOther);
      }

      const dirCache = new Map<string, DirListingCacheEntry | null>();
      const pathsToRemoveFromIndex: string[] = [];
      const filesToHashAndStage: Array<{
        relPath: string;
        absPath: string;
        mode: "100644" | "100755";
      }> = [];

      const queue = [...candidateSet];
      const visitedCandidates = new Set<string>();

      while (queue.length > 0) {
        const relPath = queue.shift()!;
        if (visitedCandidates.has(relPath)) {
          continue;
        }
        visitedCandidates.add(relPath);

        const pathValid = validateRepoRelativePath(relPath);
        if (!pathValid.ok) {
          return {
            ok: false,
            error: `Invalid repository-relative path '${relPath}' in working tree: ${pathValid.error}`,
          };
        }

        const headEntry = headEntries.get(relPath);
        const inspection = inspectWorktreePathExact({
          canonicalRepoRoot,
          relPath,
          headEntry,
          dirCache,
          platform: hostDesc.platform,
        });

        if (inspection.state === "error") {
          return { ok: false, error: inspection.error };
        }

        if (inspection.state === "submodule_gitlink") {
          continue;
        }

        if (inspection.state === "missing") {
          if (headEntry) {
            pathsToRemoveFromIndex.push(relPath);
          }
          if (
            inspection.caseRenamedActualRelPath &&
            !visitedCandidates.has(inspection.caseRenamedActualRelPath)
          ) {
            queue.push(inspection.caseRenamedActualRelPath);
          }
          continue;
        }

        const realIdxEntry = realIndexMap.get(relPath);
        const fileMode: "100644" | "100755" =
          headEntry?.mode === "100755" || realIdxEntry?.mode === "100755" ? "100755" : "100644";

        // Fast-path skip if tracked blob in HEAD is byte-identical (or LF/CRLF checkout equivalent)
        if (
          headEntry &&
          headEntry.type === "blob" &&
          headEntry.mode === fileMode &&
          inspection.size <= FAST_HASH_MAX_BYTES
        ) {
          let rawBuf: Buffer | null = null;
          try {
            rawBuf = fs.readFileSync(inspection.absPath);
          } catch (err) {
            return {
              ok: false,
              error: `Failed to read working-tree file '${relPath}': ${String(err)}`,
            };
          }
          if (isBlobUnchangedFromHead(rawBuf, headEntry.oid)) {
            continue;
          }
        }

        filesToHashAndStage.push({
          relPath,
          absPath: inspection.absPath,
          mode: fileMode,
        });
      }

      // 5) Remove deleted HEAD entries from ephemeral index in batches
      for (let i = 0; i < pathsToRemoveFromIndex.length; i += BATCH_CHUNK_SIZE) {
        const batch = pathsToRemoveFromIndex.slice(i, i + BATCH_CHUNK_SIZE);
        const rmRes = await processRunner.runTrustedGitRead(
          hostDesc,
          ["update-index", "--force-remove", "--", ...batch],
          stepTimeout(15_000),
          abortSignal,
          snapPlumbingEnv
        );
        if (!rmRes.ok) {
          return {
            ok: false,
            error: `Failed to remove deleted paths from ephemeral snapshot index: ${rmRes.error}`,
          };
        }
      }

      // 6) Hash modified/untracked files with `--no-filters` into ephemeral object store and stage them
      for (let i = 0; i < filesToHashAndStage.length; i += BATCH_CHUNK_SIZE) {
        const batch = filesToHashAndStage.slice(i, i + BATCH_CHUNK_SIZE);
        const hashRes = await processRunner.runTrustedGitRead(
          hostDesc,
          ["hash-object", "-w", "--no-filters", "--", ...batch.map((b) => b.absPath)],
          stepTimeout(20_000),
          abortSignal,
          snapPlumbingEnv
        );
        if (!hashRes.ok) {
          return {
            ok: false,
            error: `Failed to hash working-tree files into ephemeral snapshot store: ${hashRes.error}`,
          };
        }
        const oids = hashRes.value.stdoutText
          .split(/\r?\n/)
          .map((s) => s.trim().toLowerCase())
          .filter((s) => s.length > 0);
        if (oids.length !== batch.length || oids.some((oid) => !isValidCommitOid(oid))) {
          return {
            ok: false,
            error: `Unexpected git hash-object output count (${oids.length} vs expected ${batch.length})`,
          };
        }

        const updateArgs: string[] = ["update-index", "--add"];
        for (let j = 0; j < batch.length; j++) {
          updateArgs.push("--cacheinfo", `${batch[j].mode},${oids[j]},${batch[j].relPath}`);
        }
        const updRes = await processRunner.runTrustedGitRead(
          hostDesc,
          updateArgs,
          stepTimeout(15_000),
          abortSignal,
          snapPlumbingEnv
        );
        if (!updRes.ok) {
          return {
            ok: false,
            error: `Failed to stage hashed blobs into ephemeral snapshot index: ${updRes.error}`,
          };
        }
      }
    }

    // 3. Write snapshot tree and compare against HEAD^{tree}
    const writeTreeRes = await processRunner.runTrustedGitRead(
      hostDesc,
      ["write-tree"],
      stepTimeout(15_000),
      abortSignal,
      snapPlumbingEnv
    );
    if (!writeTreeRes.ok) {
      return { ok: false, error: `Failed to write ephemeral snapshot tree: ${writeTreeRes.error}` };
    }
    const snapshotTreeOid = writeTreeRes.value.stdoutText.trim().toLowerCase();
    if (!isValidCommitOid(snapshotTreeOid)) {
      return { ok: false, error: `Invalid snapshot tree OID: '${snapshotTreeOid}'` };
    }

    if (snapshotTreeOid === headTreeOid) {
      const emptyReason =
        mode === "staged"
          ? "No staged changes relative to HEAD (staged index matches HEAD)."
          : "No uncommitted or untracked changes relative to HEAD (working tree matches HEAD).";
      return {
        ok: true,
        value: {
          hasChanges: false,
          mode,
          baseCommitOid: headCommitOid,
          emptyReason,
        },
      };
    }

    // 4. Create immutable ephemeral snapshot commit in snapObjectsDir
    const commitTreeRes = await processRunner.runTrustedGitRead(
      hostDesc,
      [
        "commit-tree",
        snapshotTreeOid,
        "-p",
        headCommitOid,
        "-m",
        `checkwash-lens ephemeral ${mode} pre-check snapshot`,
      ],
      stepTimeout(15_000),
      abortSignal,
      snapPlumbingEnv
    );
    if (!commitTreeRes.ok) {
      return {
        ok: false,
        error: `Failed to create ephemeral snapshot commit: ${commitTreeRes.error}`,
      };
    }
    const snapshotCommitOid = commitTreeRes.value.stdoutText.trim().toLowerCase();
    if (!isValidCommitOid(snapshotCommitOid)) {
      return { ok: false, error: `Invalid snapshot commit OID: '${snapshotCommitOid}'` };
    }

    // Remove temporary index file now that tree & commit objects are frozen in snapObjectsDir
    try {
      fs.rmSync(snapIndexFile, { force: true });
    } catch {
      // Ignore
    }

    keepSnapshotDir = true;
    return {
      ok: true,
      value: {
        hasChanges: true,
        overlay: {
          repositoryRoot: canonicalRepoRoot,
          snapshotDir,
          gitObjectDirectory: snapObjectsDir,
          gitAlternateObjectDirectories: repoObjectsDir,
          baseCommitOid: headCommitOid,
          snapshotCommitOid,
          mode,
        },
      },
    };
  } finally {
    if (!keepSnapshotDir) {
      cleanupEphemeralSnapshotDir(snapshotDir);
    }
  }
}
