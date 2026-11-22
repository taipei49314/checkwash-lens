/**
 * extension.ts
 *
 * Checkwash Lens — VS Code Extension Entry Point (Rev 3 §1–§12 + v0.5.0 UX Cockpit).
 *
 * Strict Invariants:
 * 1. Activation, file save, text edit, configuration change, and Workspace Trust grant
 *    NEVER spawn any external process or auto-scan (Rev 3 §1.1 & B01).
 * 2. Multi-folder workspaces require selecting a single repository root; all results,
 *    revision URIs, live diagnostics, and Prove records bind to that repository.
 * 3. Every external process (Git, Python, Checkwash, Prove, Replay) passes through
 *    CheckwashLensController -> UnifiedProcessRunner -> verifyLaunchAdmission -> Native Process-Tree Broker.
 * 4. Prove (List, Full, Replay) requires a per-invocation modal user confirmation with
 *    PROVE_EXECUTION_RISK_WARNING before issuing a single-use authorization token.
 */

import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import {
  areSameRepositoryPath,
  HostEnvironmentDescriptor,
  isDangerousUncOrDevicePath,
  isFullyQualifiedWindowsPath,
  normalizePlatformLookupKey,
  resolveCanonicalOrNormalizedPath,
  resolveTrustedExecutableFromPath,
  tryRelativeInsidePosixInodeRoot,
  verifyRepositoryGitMetadataSafety,
} from "./runtime/admission";
import { sanitizeUntrustedDisplayString } from "./core/sourceIdentity";
import {
  DoctorSettingKey,
  WorkspaceSettingOverrideInspection,
} from "./runtime/environmentDoctor";
import { OpenEditorDocumentSnapshot } from "./engine/checkwashRunner";
import { UncommittedSnapshotMode } from "./engine/snapshotBuilder";
import { PROVE_EXECUTION_RISK_WARNING } from "./satellite/proveRunner";
import {
  buildRevisionUriString,
  CHECKWASH_REVISION_URI_SCHEME,
  parseRevisionUriString,
  validateRepoRelativePath,
} from "./source/revisionProvider";
import { CheckwashLensController, ControllerViewSnapshot } from "./ui/commands";
import { CHECKWASH_DIAGNOSTIC_SOURCE, PlannedDiagnosticSeverity } from "./ui/diagnostics";
import { FAST_GUARD_SOURCE_LABEL } from "./engine/fastDiffGuard";
import { CheckwashTreeNode, TreeNodeFindingNavigation } from "./ui/treeView";

let activeController: CheckwashLensController | null = null;

export function getActiveController(): CheckwashLensController | null {
  return activeController;
}

/**
 * Reads a machine-scoped string setting from `checkwashLens.<key>`.
 * Strictly ignores `workspaceValue`, `workspaceFolderValue`, and language-scoped overrides
 * so untrusted `.vscode/settings.json` files cannot hijack executable paths (Rev 3 §7.1).
 */
export const CHECKWASH_DOCTOR_URI_SCHEME = "checkwash-doctor";
export const CHECKWASH_EMPTY_URI_SCHEME = "checkwash-empty";

export interface FindingDiffOpenResult {
  relativePath: string;
  leftUri: string;
  rightUri: string;
  title: string;
  revealLine1Based: number | null;
}

interface ExtendedConfigurationInspect {
  globalValue?: string;
  globalLocalValue?: string;
  globalRemoteValue?: string;
  workspaceValue?: string;
  workspaceFolderValue?: string;
}

function resolveMachineScopedStringInspection(
  inspected: ExtendedConfigurationInspect | undefined,
  key: string,
  fallback: string
): { effectiveGlobalValue: string; ignoredCrossOsLocalValue: string } {
  const isRemoteHost = Boolean(vscode.env.remoteName);
  const isPathKey = key.endsWith("Path");
  if (isRemoteHost && inspected) {
    if (typeof inspected.globalRemoteValue === "string") {
      const trimmedRemote = inspected.globalRemoteValue.trim();
      return {
        effectiveGlobalValue: trimmedRemote.length > 0 ? trimmedRemote : fallback,
        ignoredCrossOsLocalValue: "",
      };
    }
    if (typeof inspected.globalValue === "string" && inspected.globalValue.trim().length > 0) {
      const trimmedGlobal = inspected.globalValue.trim();
      if (isPathKey) {
        if (process.platform !== "win32" && isFullyQualifiedWindowsPath(trimmedGlobal)) {
          return {
            effectiveGlobalValue: fallback,
            ignoredCrossOsLocalValue: trimmedGlobal,
          };
        }
        if (process.platform === "win32" && trimmedGlobal.startsWith("/")) {
          return {
            effectiveGlobalValue: fallback,
            ignoredCrossOsLocalValue: trimmedGlobal,
          };
        }
      }
      return {
        effectiveGlobalValue: trimmedGlobal,
        ignoredCrossOsLocalValue: "",
      };
    }
    return { effectiveGlobalValue: fallback, ignoredCrossOsLocalValue: "" };
  }

  const val = inspected?.globalValue;
  return {
    effectiveGlobalValue: typeof val === "string" && val.trim().length > 0 ? val.trim() : fallback,
    ignoredCrossOsLocalValue: "",
  };
}

export function readTrustedMachineStringSetting(key: string, fallback: string = ""): string {
  const cfg = vscode.workspace.getConfiguration("checkwashLens");
  const inspected = cfg.inspect<string>(key) as ExtendedConfigurationInspect | undefined;
  return resolveMachineScopedStringInspection(inspected, key, fallback).effectiveGlobalValue;
}

export function inspectAllCheckwashSettings(
  repoRoot?: string
): WorkspaceSettingOverrideInspection[] {
  const matchingFolder = repoRoot
    ? findMatchingWorkspaceFolder(vscode.workspace.workspaceFolders, repoRoot)
    : undefined;
  const cfg = vscode.workspace.getConfiguration("checkwashLens", matchingFolder?.uri);
  const keys: DoctorSettingKey[] = [
    "pythonPath",
    "gitPath",
    "provePath",
    "proveTestPythonPath",
  ];
  return keys.map((key) => {
    const inspected = cfg.inspect<string>(key) as ExtendedConfigurationInspect | undefined;
    const resolved = resolveMachineScopedStringInspection(inspected, key, "");
    return {
      key,
      globalValue: resolved.effectiveGlobalValue,
      workspaceValue:
        typeof inspected?.workspaceValue === "string" ? inspected.workspaceValue : "",
      workspaceFolderValue:
        typeof inspected?.workspaceFolderValue === "string"
          ? inspected.workspaceFolderValue
          : "",
      ...(resolved.ignoredCrossOsLocalValue
        ? { ignoredCrossOsLocalValue: resolved.ignoredCrossOsLocalValue }
        : {}),
    };
  });
}

function findMatchingWorkspaceFolder(
  workspaceFolders: readonly vscode.WorkspaceFolder[] | undefined,
  selectedRepoRoot: string
): vscode.WorkspaceFolder | undefined {
  if (!workspaceFolders || !selectedRepoRoot || selectedRepoRoot.trim().length === 0) {
    return undefined;
  }
  for (const folder of workspaceFolders) {
    if (
      folder.uri.scheme === "file" &&
      folder.uri.fsPath &&
      areSameRepositoryPath(folder.uri.fsPath, selectedRepoRoot)
    ) {
      return folder;
    }
  }
  for (const folder of workspaceFolders) {
    if (folder.uri.fsPath && areSameRepositoryPath(folder.uri.fsPath, selectedRepoRoot)) {
      return folder;
    }
  }
  return undefined;
}

function tryRelativeInsideRoot(rootPath: string, targetPath: string): string | null {
  if (!rootPath || !targetPath) {
    return null;
  }
  const useWin =
    process.platform === "win32" ||
    isFullyQualifiedWindowsPath(rootPath) ||
    isFullyQualifiedWindowsPath(targetPath);
  if (useWin) {
    const rel = path.win32.relative(
      path.win32.resolve(rootPath),
      path.win32.resolve(targetPath)
    );
    if (!rel || rel.startsWith("..") || path.win32.isAbsolute(rel)) {
      return null;
    }
    return rel.replace(/\\/g, "/");
  }
  const rel = path.posix.relative(
    path.posix.resolve(rootPath),
    path.posix.resolve(targetPath)
  );
  if (!rel || rel.startsWith("..") || path.posix.isAbsolute(rel)) {
    return null;
  }
  return rel;
}

function resolveRepoRelativeDocPath(
  boundRepoRoot: string,
  docFsPath: string,
  workspaceFolders: readonly vscode.WorkspaceFolder[] | undefined
): string | null {
  const directRel = tryRelativeInsideRoot(boundRepoRoot, docFsPath);
  if (directRel !== null) {
    return directRel;
  }
  const matchedFolder = findMatchingWorkspaceFolder(workspaceFolders, boundRepoRoot);
  if (matchedFolder?.uri.fsPath) {
    const folderRel = tryRelativeInsideRoot(matchedFolder.uri.fsPath, docFsPath);
    if (folderRel !== null) {
      return folderRel;
    }
  }
  const canonRepo = resolveCanonicalOrNormalizedPath(boundRepoRoot);
  const canonDoc = resolveCanonicalOrNormalizedPath(docFsPath);
  const canonRel = tryRelativeInsideRoot(canonRepo, canonDoc);
  if (canonRel !== null) {
    return canonRel;
  }
  return tryRelativeInsidePosixInodeRoot(canonRepo, canonDoc);
}

/**
 * Safely resolves an editable workspace file path inside `boundRepoRoot` while rejecting
 * path traversal, symbolic links along any segment, directories, orcanonical escapes.
 * Spawns zero external processes.
 */
export function resolveSafeEditableWorkspaceFilePath(
  boundRepoRoot: string,
  relativePath: string,
  workspaceFolders?: readonly vscode.WorkspaceFolder[]
):
  | { ok: true; fsPath: string; normalizedRelativePath: string }
  | { ok: false; missingInWorktree: boolean; error: string } {
  if (!boundRepoRoot || boundRepoRoot.trim().length === 0) {
    return {
      ok: false,
      missingInWorktree: false,
      error: "No active Git repository is bound in Checkwash Lens.",
    };
  }
  const relCheck = validateRepoRelativePath(relativePath);
  if (!relCheck.ok) {
    return { ok: false, missingInWorktree: false, error: relCheck.error };
  }

  const matchedFolder = findMatchingWorkspaceFolder(workspaceFolders, boundRepoRoot);
  const baseRoot =
    matchedFolder && matchedFolder.uri.scheme === "file" && matchedFolder.uri.fsPath
      ? matchedFolder.uri.fsPath
      : boundRepoRoot;

  if (!areSameRepositoryPath(baseRoot, boundRepoRoot)) {
    return {
      ok: false,
      missingInWorktree: false,
      error: `Workspace folder '${baseRoot}' does not match bound repository '${boundRepoRoot}'.`,
    };
  }

  let rootLstat: fs.Stats;
  try {
    rootLstat = fs.lstatSync(baseRoot);
  } catch (err) {
    return {
      ok: false,
      missingInWorktree: false,
      error: `Cannot access repository root '${baseRoot}': ${String(err)}`,
    };
  }
  if (!rootLstat.isDirectory()) {
    return {
      ok: false,
      missingInWorktree: false,
      error: `Repository root '${baseRoot}' is not a directory.`,
    };
  }

  const segments = relCheck.value.split("/").filter((s) => s.length > 0);
  const useWinJoin = process.platform === "win32" || isFullyQualifiedWindowsPath(baseRoot);
  let cursor = baseRoot;

  for (let i = 0; i < segments.length; i++) {
    cursor = useWinJoin ? path.win32.join(cursor, segments[i]) : path.posix.join(cursor, segments[i]);
    let st: fs.Stats;
    try {
      st = fs.lstatSync(cursor);
    } catch {
      return {
        ok: false,
        missingInWorktree: true,
        error: `File '${relCheck.value}' does not exist in the current working tree (it may have been deleted or renamed).`,
      };
    }
    if (st.isSymbolicLink()) {
      return {
        ok: false,
        missingInWorktree: false,
        error: `Refusing to open symbolic link segment '${segments.slice(0, i + 1).join("/")}' inside workspace.`,
      };
    }
    if (i < segments.length - 1 && !st.isDirectory()) {
      return {
        ok: false,
        missingInWorktree: true,
        error: `Intermediate path '${segments.slice(0, i + 1).join("/")}' is not a directory.`,
      };
    }
    if (i === segments.length - 1 && !st.isFile()) {
      return {
        ok: false,
        missingInWorktree: false,
        error: `Target '${relCheck.value}' is not a regular file in the working tree.`,
      };
    }
  }

  const canonBound = resolveCanonicalOrNormalizedPath(boundRepoRoot);
  const canonTarget = resolveCanonicalOrNormalizedPath(cursor);
  const relInside =
    tryRelativeInsideRoot(canonBound, canonTarget) ??
    tryRelativeInsidePosixInodeRoot(canonBound, canonTarget);
  if (relInside === null) {
    return {
      ok: false,
      missingInWorktree: false,
      error: `Refusing to open '${relCheck.value}': canonical path escapes bound repository root.`,
    };
  }

  return {
    ok: true,
    fsPath: cursor,
    normalizedRelativePath: relCheck.value,
  };
}

export interface SmartGitRangePresetItem {
  label: string;
  description: string;
  detail?: string;
  rangeSpec: string;
  isCustomInput?: boolean;
}

/**
 * Zero-process smart Git range preset collector.
 * Reads bounded `.git/HEAD`, `.git/refs/heads/*`, `.git/refs/remotes/origin/*`, and `.git/packed-refs`
 * with non-symlink `lstatSync` + `verifyRepositoryGitMetadataSafety` checks so zero external processes
 * are spawned, UNC/device/escaping `gitdir:` pointers are rejected, and Restricted Mode touches zero `.git` files (RT-01).
 */
export function collectSmartGitRangePresetsZeroProcess(
  repoRoot: string,
  options?: { isWorkspaceTrusted?: boolean }
): SmartGitRangePresetItem[] {
  const presets: SmartGitRangePresetItem[] = [];
  let currentBranch: string | null = null;
  const localBranches = new Set<string>();
  const originBranches = new Set<string>();
  const isTrusted = options?.isWorkspaceTrusted ?? vscode.workspace.isTrusted;

  try {
    if (isTrusted && repoRoot && repoRoot.trim().length > 0 && !isDangerousUncOrDevicePath(repoRoot)) {
      const repoStat = fs.lstatSync(repoRoot);
      if (!repoStat.isSymbolicLink() && repoStat.isDirectory()) {
        const canonicalRepoRoot = fs.realpathSync.native(repoRoot);
        if (!isDangerousUncOrDevicePath(canonicalRepoRoot)) {
          const safety = verifyRepositoryGitMetadataSafety(canonicalRepoRoot);
          if (safety.ok) {
            const dotGitCand = path.join(canonicalRepoRoot, ".git");
            let gitDir: string | null = null;
            try {
              const st = fs.lstatSync(dotGitCand);
              if (!st.isSymbolicLink()) {
                if (st.isDirectory()) {
                  const realDir = fs.realpathSync.native(dotGitCand);
                  if (!isDangerousUncOrDevicePath(realDir)) {
                    gitDir = realDir;
                  }
                } else if (st.isFile() && st.size > 0 && st.size <= 4096) {
                  const rawGitFile = fs.readFileSync(dotGitCand, "utf8").trim();
                  if (rawGitFile.startsWith("gitdir:")) {
                    const rawPtr = rawGitFile.slice("gitdir:".length).trim();
                    if (rawPtr && !rawPtr.includes("\0") && !isDangerousUncOrDevicePath(rawPtr)) {
                      const resolvedGitDir = path.resolve(canonicalRepoRoot, rawPtr);
                      if (!isDangerousUncOrDevicePath(resolvedGitDir)) {
                        const gdStat = fs.lstatSync(resolvedGitDir);
                        if (!gdStat.isSymbolicLink() && gdStat.isDirectory()) {
                          const realGitDir = fs.realpathSync.native(resolvedGitDir);
                          if (!isDangerousUncOrDevicePath(realGitDir)) {
                            gitDir = realGitDir;
                          }
                        }
                      }
                    }
                  }
                }
              }
            } catch {
              // Ignore unreadable .git metadata and fall back to standard range presets
            }

            if (gitDir) {
              // Resolve optional `commondir` for linked Git worktrees (`refs/` and `packed-refs` live in commonDir)
              let commonDir = gitDir;
              try {
                const cdFile = path.join(gitDir, "commondir");
                const cdStat = fs.lstatSync(cdFile);
                if (!cdStat.isSymbolicLink() && cdStat.isFile() && cdStat.size > 0 && cdStat.size <= 4096) {
                  const rawCommonRel = fs.readFileSync(cdFile, "utf8").trim();
                  if (rawCommonRel && !rawCommonRel.includes("\0") && !isDangerousUncOrDevicePath(rawCommonRel)) {
                    const resolvedCommon = path.resolve(gitDir, rawCommonRel);
                    if (!isDangerousUncOrDevicePath(resolvedCommon)) {
                      const commonStat = fs.lstatSync(resolvedCommon);
                      if (!commonStat.isSymbolicLink() && commonStat.isDirectory()) {
                        const realCommon = fs.realpathSync.native(resolvedCommon);
                        if (!isDangerousUncOrDevicePath(realCommon)) {
                          commonDir = realCommon;
                        }
                      }
                    }
                  }
                }
              } catch {
                // Standard single-worktree repository
              }

              // 1. Read HEAD branch name if symbolic ref and strictly validate safe ref characters (RT-01 / RT-09)
              try {
                const headFile = path.join(gitDir, "HEAD");
                const hStat = fs.lstatSync(headFile);
                if (!hStat.isSymbolicLink() && hStat.isFile() && hStat.size > 0 && hStat.size <= 1024) {
                  const headText = fs.readFileSync(headFile, "utf8").trim();
                  const m = /^ref:\s*refs\/heads\/([^\r\n]+)$/.exec(headText);
                  if (m && m[1]) {
                    const branchCand = m[1].trim();
                    if (
                      /^[A-Za-z0-9._/-]{1,128}$/.test(branchCand) &&
                      !branchCand.includes("..") &&
                      !branchCand.startsWith("/") &&
                      !branchCand.endsWith("/")
                    ) {
                      currentBranch = sanitizeUntrustedDisplayString(branchCand, { maxLen: 128 });
                    }
                  }
                }
              } catch {
                // Ignore
              }

              const candidateBaseNames = ["main", "master", "develop", "trunk"];
              for (const baseName of candidateBaseNames) {
                try {
                  const localRefPath = path.join(commonDir, "refs", "heads", baseName);
                  const lst = fs.lstatSync(localRefPath);
                  if (!lst.isSymbolicLink() && lst.isFile() && lst.size <= 256) {
                    localBranches.add(baseName);
                  }
                } catch {
                  // Not unpacked
                }
                try {
                  const remoteRefPath = path.join(commonDir, "refs", "remotes", "origin", baseName);
                  const rst = fs.lstatSync(remoteRefPath);
                  if (!rst.isSymbolicLink() && rst.isFile() && rst.size <= 256) {
                    originBranches.add(baseName);
                  }
                } catch {
                  // Not unpacked
                }
              }

              // Also inspect bounded packed-refs (<= 256 KiB)
              try {
                const packedRefsPath = path.join(commonDir, "packed-refs");
                const pst = fs.lstatSync(packedRefsPath);
                if (!pst.isSymbolicLink() && pst.isFile() && pst.size > 0 && pst.size <= 262_144) {
                  const packedText = fs.readFileSync(packedRefsPath, "utf8");
                  for (const line of packedText.split(/\r?\n/)) {
                    if (!line || line.startsWith("#") || line.startsWith("^")) {
                      continue;
                    }
                    const spaceIdx = line.indexOf(" ");
                    if (spaceIdx <= 0) {
                      continue;
                    }
                    const refName = line.slice(spaceIdx + 1).trim();
                    for (const baseName of candidateBaseNames) {
                      if (refName === `refs/heads/${baseName}`) {
                        localBranches.add(baseName);
                      } else if (refName === `refs/remotes/origin/${baseName}`) {
                        originBranches.add(baseName);
                      }
                    }
                  }
                }
              } catch {
                // Ignore
              }
            }
          }
        }
      }
    }
  } catch {
    // Fall back cleanly to standard presets
  }

  for (const baseName of ["main", "master", "develop", "trunk"]) {
    if (originBranches.has(baseName) && currentBranch !== baseName) {
      presets.push({
        label: `$(git-pull-request) origin/${baseName}...HEAD`,
        description: `Branch changes since merge-base with origin/${baseName}${currentBranch ? ` (on ${currentBranch})` : ""}`,
        rangeSpec: `origin/${baseName}...HEAD`,
      });
    }
    if (localBranches.has(baseName) && currentBranch !== baseName) {
      presets.push({
        label: `$(git-branch) ${baseName}...HEAD`,
        description: `Branch changes since merge-base with local ${baseName}${currentBranch ? ` (on ${currentBranch})` : ""}`,
        rangeSpec: `${baseName}...HEAD`,
      });
    }
  }

  presets.push(
    {
      label: "$(git-commit) HEAD~1..HEAD",
      description: "Latest commit (single-commit diff)",
      rangeSpec: "HEAD~1..HEAD",
    },
    {
      label: "$(history) HEAD~3..HEAD",
      description: "Last 3 commits",
      rangeSpec: "HEAD~3..HEAD",
    },
    {
      label: "$(edit) Custom Git Range (A..B or A...B)...",
      description: "Type any commit SHA, tag, or branch range manually",
      rangeSpec: "",
      isCustomInput: true,
    }
  );

  return presets;
}

function buildEmptyRevisionUri(
  relativePath: string,
  side: "base" | "head",
  reason: string
): vscode.Uri {
  const pathCheck = validateRepoRelativePath(relativePath);
  const cleanRel = pathCheck.ok ? pathCheck.value : "empty.txt";
  const encodedSegments = cleanRel
    .split("/")
    .map((s) => encodeURIComponent(s))
    .join("/");
  return vscode.Uri.parse(
    `${CHECKWASH_EMPTY_URI_SCHEME}:/${encodedSegments}?side=${side}&reason=${encodeURIComponent(reason)}`
  );
}

export function buildHostDescriptor(
  context: vscode.ExtensionContext,
  selectedRepoRoot: string,
  inheritedEnv: NodeJS.ProcessEnv = process.env
): HostEnvironmentDescriptor {
  const folders = vscode.workspace.workspaceFolders ?? [];
  const matchedFolder = findMatchingWorkspaceFolder(folders, selectedRepoRoot);
  const nonFileFolder = folders.find((f) => f.uri.scheme !== "file");

  const workspaceScheme = matchedFolder
    ? matchedFolder.uri.scheme
    : nonFileFolder
      ? nonFileFolder.uri.scheme
      : "unmatched";
  const isVirtualWorkspace = matchedFolder ? matchedFolder.uri.scheme !== "file" : true;

  const configuredPython = readTrustedMachineStringSetting("pythonPath", "");
  const configuredGit = readTrustedMachineStringSetting("gitPath", "");
  const rawPathEnv = inheritedEnv.PATH ?? inheritedEnv.Path ?? "";

  const isWin32 = process.platform === "win32";
  const pythonPath =
    configuredPython.length > 0
      ? configuredPython
      : (() => {
          const res = isWin32
            ? resolveTrustedExecutableFromPath({
                executableName: "python.exe",
                repositoryRootPath: selectedRepoRoot,
                pathEnv: rawPathEnv,
                platform: "win32",
              })
            : resolveTrustedExecutableFromPath({
                executableNames: ["python3", "python3.13", "python3.12", "python3.11", "python"],
                repositoryRootPath: selectedRepoRoot,
                pathEnv: rawPathEnv,
                platform: process.platform,
              });
          return res.ok ? res.value : "";
        })();

  const gitPath =
    configuredGit.length > 0
      ? configuredGit
      : (() => {
          const res = resolveTrustedExecutableFromPath({
            executableName: isWin32 ? "git.exe" : "git",
            repositoryRootPath: selectedRepoRoot,
            pathEnv: rawPathEnv,
            platform: process.platform,
          });
          return res.ok ? res.value : "";
        })();

  return {
    isWorkspaceTrusted: vscode.workspace.isTrusted,
    platform: process.platform,
    arch: process.arch,
    workspaceScheme,
    isRemote: Boolean(vscode.env.remoteName),
    remoteName: vscode.env.remoteName ?? null,
    isVirtualWorkspace,
    extensionRootPath: context.extensionPath,
    repositoryRootPath: selectedRepoRoot,
    configuredPythonPath: pythonPath,
    configuredGitPath: gitPath,
    inheritedEnv,
  };
}

function buildOpenDocKey(canonRepo: string, relNormalized: string): string {
  const repoKey = normalizePlatformLookupKey(canonRepo);
  const relKey =
    process.platform === "win32" || isFullyQualifiedWindowsPath(canonRepo)
      ? relNormalized.toLowerCase()
      : relNormalized;
  return `${repoKey}::${relKey}`;
}

function collectOpenEditorSnapshots(
  boundRepoRoot: string | null,
  verifiedVersionsByKey?: ReadonlyMap<string, number>
): OpenEditorDocumentSnapshot[] {
  if (!boundRepoRoot) {
    return [];
  }
  const canonRepo = resolveCanonicalOrNormalizedPath(boundRepoRoot);
  const wsFolders = vscode.workspace.workspaceFolders;
  const snapshots: OpenEditorDocumentSnapshot[] = [];

  for (const doc of vscode.workspace.textDocuments) {
    if (doc.uri.scheme !== "file") {
      continue;
    }
    const relNormalized = resolveRepoRelativeDocPath(boundRepoRoot, doc.uri.fsPath, wsFolders);
    if (!relNormalized) {
      continue;
    }
    const key = buildOpenDocKey(canonRepo, relNormalized);
    const verifiedVersion = verifiedVersionsByKey?.get(key) ?? doc.version;
    snapshots.push({
      repositoryRoot: canonRepo,
      relativePath: relNormalized,
      isDirty: doc.isDirty,
      verifiedVersion,
      currentVersionAtPublish: doc.version,
      text: doc.getText(),
      isClosedOrDeleted: doc.isClosed,
    });
  }
  return snapshots;
}

function mapDiagnosticSeverity(sev: PlannedDiagnosticSeverity): vscode.DiagnosticSeverity {
  switch (sev) {
    case "Error":
      return vscode.DiagnosticSeverity.Error;
    case "Warning":
      return vscode.DiagnosticSeverity.Warning;
    case "Information":
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

class CheckwashTreeDataProvider implements vscode.TreeDataProvider<CheckwashTreeNode> {
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<CheckwashTreeNode | undefined | void>();
  public readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private nodes: CheckwashTreeNode[] = [];

  public updateNodes(newNodes: CheckwashTreeNode[]): void {
    this.nodes = newNodes;
    this._onDidChangeTreeData.fire();
  }

  public getTreeItem(element: CheckwashTreeNode): vscode.TreeItem {
    const collapsibleState =
      element.children.length === 0
        ? vscode.TreeItemCollapsibleState.None
        : element.collapsibleDefault === "collapsed"
          ? vscode.TreeItemCollapsibleState.Collapsed
          : vscode.TreeItemCollapsibleState.Expanded;
    const item = new vscode.TreeItem(element.label, collapsibleState);
    item.id =
      element.children.length > 0 ? `${element.id}::${String(collapsibleState)}` : element.id;
    item.description = element.description;
    item.tooltip = element.tooltip;
    if (element.contextValue) {
      item.contextValue = element.contextValue;
    }
    const ThemeIconCtor = (
      vscode as unknown as {
        ThemeIcon?: new (id: string, color?: vscode.ThemeColor) => vscode.ThemeIcon;
      }
    ).ThemeIcon;
    if (element.iconId && typeof ThemeIconCtor === "function") {
      item.iconPath = element.iconColor
        ? new ThemeIconCtor(element.iconId, new vscode.ThemeColor(element.iconColor))
        : new ThemeIconCtor(element.iconId);
    }
    if (element.command) {
      item.command = {
        command: element.command.commandId,
        title: element.command.title,
        arguments: element.command.arguments,
      };
    }
    return item;
  }

  public getChildren(element?: CheckwashTreeNode): CheckwashTreeNode[] {
    if (!element) {
      return this.nodes;
    }
    return element.children;
  }
}

function collectAllFindingNavNodes(nodes: readonly CheckwashTreeNode[]): CheckwashTreeNode[] {
  const out: CheckwashTreeNode[] = [];
  for (const n of nodes) {
    if (n.findingNav) {
      out.push(n);
    }
    if (n.children.length > 0) {
      out.push(...collectAllFindingNavNodes(n.children));
    }
  }
  return out;
}

export function activate(
  context: vscode.ExtensionContext,
  customController?: CheckwashLensController
): CheckwashLensController {
  // Zero external processes on activation (Rev 3 §1.1 & B01)
  const controller = customController ?? new CheckwashLensController();
  activeController = controller;

  const folders = vscode.workspace.workspaceFolders ?? [];
  if (folders.length === 1 && folders[0].uri.scheme === "file") {
    controller.selectRepository(folders[0].uri.fsPath);
  }

  const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = "checkwashLens.openQuickActions";
  statusBarItem.show();

  const checkwashDiagnostics = vscode.languages.createDiagnosticCollection(
    CHECKWASH_DIAGNOSTIC_SOURCE
  );
  const fastGuardDiagnostics = vscode.languages.createDiagnosticCollection(
    FAST_GUARD_SOURCE_LABEL
  );
  const treeProvider = new CheckwashTreeDataProvider();
  const treeView = vscode.window.createTreeView("checkwashLens.findingsView", {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  });

  const applyViewSnapshot = (snap: ControllerViewSnapshot): void => {
    statusBarItem.text = snap.statusBar.text;
    statusBarItem.tooltip = snap.statusBar.tooltip;
    if (snap.statusBar.colorTheme === "error") {
      statusBarItem.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
    } else if (snap.statusBar.colorTheme === "warning") {
      statusBarItem.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
    } else {
      statusBarItem.backgroundColor = undefined;
    }

    treeProvider.updateNodes(snap.treeNodes);

    checkwashDiagnostics.clear();
    fastGuardDiagnostics.clear();

    if (snap.boundRepositoryRoot) {
      const matchedWsFolder = findMatchingWorkspaceFolder(
        vscode.workspace.workspaceFolders,
        snap.boundRepositoryRoot
      );
      const diagBaseRoot =
        matchedWsFolder && matchedWsFolder.uri.scheme === "file" && matchedWsFolder.uri.fsPath
          ? matchedWsFolder.uri.fsPath
          : snap.boundRepositoryRoot;

      const joinDiagTargetPath = (baseRoot: string, relPosix: string): string => {
        const segs = relPosix.split("/").filter((s) => s.length > 0);
        if (process.platform === "win32" || isFullyQualifiedWindowsPath(baseRoot)) {
          return path.win32.join(baseRoot, ...segs);
        }
        return path.posix.join(baseRoot, ...segs);
      };

      for (const [relPath, items] of snap.diagnosticsPlan.checkwashByFile.entries()) {
        const fileUri = vscode.Uri.file(joinDiagTargetPath(diagBaseRoot, relPath));
        const diags = items.map((d) => {
          const range = new vscode.Range(d.vscodeLine0Based, 0, d.vscodeLine0Based, 200);
          const diag = new vscode.Diagnostic(range, d.message, mapDiagnosticSeverity(d.severity));
          diag.source = d.source;
          diag.code = d.ruleId;
          return diag;
        });
        checkwashDiagnostics.set(fileUri, diags);
      }

      for (const [relPath, items] of snap.diagnosticsPlan.fastGuardByFile.entries()) {
        const fileUri = vscode.Uri.file(joinDiagTargetPath(diagBaseRoot, relPath));
        const diags = items.map((d) => {
          const range = new vscode.Range(d.vscodeLine0Based, 0, d.vscodeLine0Based, 200);
          const diag = new vscode.Diagnostic(range, d.message, mapDiagnosticSeverity(d.severity));
          diag.source = d.source;
          diag.code = d.ruleId;
          return diag;
        });
        fastGuardDiagnostics.set(fileUri, diags);
      }
    }
  };

  applyViewSnapshot(controller.getViewSnapshot());
  const unsubscribeView = controller.onDidChangeViewSnapshot((snap) => {
    applyViewSnapshot(snap);
  });

  const scanVerifiedVersionsByKey = new Map<string, number>();
  const recordScanVerifiedVersions = (snaps: readonly OpenEditorDocumentSnapshot[]): void => {
    scanVerifiedVersionsByKey.clear();
    for (const s of snaps) {
      const canonRepo = resolveCanonicalOrNormalizedPath(s.repositoryRoot);
      const key = buildOpenDocKey(canonRepo, s.relativePath);
      scanVerifiedVersionsByKey.set(key, s.verifiedVersion);
    }
  };

  // Read-only `checkwash-rev:` virtual document provider
  const revisionDocProvider: vscode.TextDocumentContentProvider = {
    provideTextDocumentContent: async (uri: vscode.Uri): Promise<string> => {
      const snap = controller.getViewSnapshot();
      const repoRoot = snap.boundRepositoryRoot ?? "";
      const hostDesc = buildHostDescriptor(context, repoRoot);
      const res = await controller.resolveImmutableRevisionUri(hostDesc, uri.toString());
      if (!res.ok) {
        return `# Checkwash Lens — Unable to load revision\n# ${res.error}\n`;
      }
      return res.value.utf8Text;
    },
  };

  // Read-only `checkwash-empty:` virtual document provider for added/deleted file diffs
  const emptyRevisionDocProvider: vscode.TextDocumentContentProvider = {
    provideTextDocumentContent: async (): Promise<string> => "",
  };

  let latestDoctorMarkdown =
    "# Checkwash Lens — Environment Doctor\n\nRun `Checkwash Lens: Run Environment Doctor` to inspect runtime readiness.\n";
  const doctorDocChangeEmitter = new vscode.EventEmitter<vscode.Uri>();
  const doctorDocProvider: vscode.TextDocumentContentProvider = {
    onDidChange: doctorDocChangeEmitter.event,
    provideTextDocumentContent: async (): Promise<string> => latestDoctorMarkdown,
  };

  // Untrusted-safe HoverProvider for live Checkwash Engine & Fast Guard diagnostics (Rev 3 §3, §6.2)
  const hoverProvider: vscode.HoverProvider = {
    provideHover: (document: vscode.TextDocument, position: vscode.Position): vscode.Hover | null => {
      if (document.uri.scheme !== "file") {
        return null;
      }
      const snap = controller.getViewSnapshot();
      if (!snap.boundRepositoryRoot) {
        return null;
      }
      const relNormalized = resolveRepoRelativeDocPath(
        snap.boundRepositoryRoot,
        document.uri.fsPath,
        vscode.workspace.workspaceFolders
      );
      if (!relNormalized) {
        return null;
      }
      const engineMatches = (snap.diagnosticsPlan.checkwashByFile.get(relNormalized) ?? []).filter(
        (d) => d.vscodeLine0Based === position.line
      );
      const fastMatches = (snap.diagnosticsPlan.fastGuardByFile.get(relNormalized) ?? []).filter(
        (d) => d.vscodeLine0Based === position.line
      );
      if (engineMatches.length === 0 && fastMatches.length === 0) {
        return null;
      }

      const lines: string[] = [];
      for (const item of engineMatches) {
        lines.push(`**[${item.source}] \`${item.ruleId}\`** (${item.severity})`);
        lines.push(item.message);
        if (item.preferredRevisionUri) {
          lines.push(`_Immutable revision: \`${item.preferredRevisionUri}\`_`);
        }
        lines.push(
          `_Tip: Use the Checkwash Lens sidebar inline buttons to compare Base ↔ Head Diff._`
        );
      }
      for (const item of fastMatches) {
        lines.push(`**[${item.source}] \`${item.ruleId}\`** (Heuristic Hint)`);
        lines.push(item.message);
        lines.push(`_Does not alter official Checkwash engine verdict._`);
      }
      const md = new vscode.MarkdownString(lines.join("\n\n"));
      md.isTrusted = false;
      return new vscode.Hover(md, new vscode.Range(position.line, 0, position.line, 200));
    },
  };

  const ensureSelectedRepo = async (): Promise<string | null> => {
    const snap = controller.getViewSnapshot();
    const wsFolders = (vscode.workspace.workspaceFolders ?? []).filter(
      (f) => f.uri.scheme === "file"
    );
    if (snap.boundRepositoryRoot) {
      const stillPresent = findMatchingWorkspaceFolder(wsFolders, snap.boundRepositoryRoot);
      if (stillPresent) {
        return snap.boundRepositoryRoot;
      }
      controller.clearBoundRepository("Previously bound repository is no longer in workspace.");
      scanVerifiedVersionsByKey.clear();
    }
    if (wsFolders.length === 0) {
      void vscode.window.showErrorMessage(
        "Checkwash Lens requires a local physical Git repository folder."
      );
      return null;
    }
    if (wsFolders.length === 1) {
      controller.selectRepository(wsFolders[0].uri.fsPath);
      return wsFolders[0].uri.fsPath;
    }
    const picked = await vscode.window.showQuickPick(
      wsFolders.map((f) => ({ label: f.name, description: f.uri.fsPath, folder: f })),
      { placeHolder: "Select the Git repository to bind for Checkwash Lens" }
    );
    if (!picked) {
      return null;
    }
    controller.selectRepository(picked.folder.uri.fsPath);
    scanVerifiedVersionsByKey.clear();
    applyViewSnapshot(controller.getViewSnapshot());
    return picked.folder.uri.fsPath;
  };

  const promptCommittedGitRange = async (
    repoRoot: string,
    purposeLabel: string
  ): Promise<string | null> => {
    const presets = collectSmartGitRangePresetsZeroProcess(repoRoot);
    const picked = await vscode.window.showQuickPick(presets, {
      placeHolder: `${purposeLabel} — Choose a Git range or enter a custom range (A..B / A...B)`,
    });
    if (!picked) {
      return null;
    }
    if (picked.isCustomInput) {
      const typed = await vscode.window.showInputBox({
        prompt: `Enter committed Git range for ${purposeLabel} (A..B or A...B)`,
        placeHolder: "HEAD~1..HEAD or main...HEAD",
        value: "HEAD~1..HEAD",
      });
      return typed && typed.trim().length > 0 ? typed.trim() : null;
    }
    return picked.rangeSpec.trim().length > 0 ? picked.rangeSpec.trim() : null;
  };

  /**
   * Resolves a finding navigation target from:
   * - a `CheckwashTreeNode` (inline button / context menu on TreeItem),
   * - a `vscode.Uri` or `checkwash-rev:` URI string (`editor/title` button),
   * - an explicit `TreeNodeFindingNavigation`-like object, or
   * - interactive QuickPick among active session findings when invoked without arguments.
   */
  const resolveFindingNavigationTarget = async (
    rawArg: unknown,
    explicitLine1Based?: number | null
  ): Promise<TreeNodeFindingNavigation | null> => {
    const snap = controller.getViewSnapshot();
    const boundRepo = snap.boundRepositoryRoot;
    if (!boundRepo) {
      void vscode.window.showWarningMessage(
        "Checkwash Lens: No active Git repository is bound."
      );
      return null;
    }

    // 1. CheckwashTreeNode with `findingNav`
    if (rawArg && typeof rawArg === "object" && "findingNav" in rawArg) {
      const nav = (rawArg as CheckwashTreeNode).findingNav;
      if (nav) {
        return {
          ...nav,
          revealLine1Based:
            typeof explicitLine1Based === "number" ? explicitLine1Based : nav.revealLine1Based,
        };
      }
    }

    // 2. Direct `TreeNodeFindingNavigation`-shaped object
    if (
      rawArg &&
      typeof rawArg === "object" &&
      "relativePath" in rawArg &&
      typeof (rawArg as { relativePath?: unknown }).relativePath === "string" &&
      !("scheme" in rawArg)
    ) {
      const partial = rawArg as Partial<TreeNodeFindingNavigation> & { relativePath: string };
      const scanId = snap.evaluatedState.joinedReport?.scanIdentity ?? null;
      const fallbackBase =
        partial.baseRevisionUri !== undefined
          ? partial.baseRevisionUri
          : scanId
            ? (() => {
                const r = buildRevisionUriString({
                  repositoryRoot: scanId.repositoryRoot,
                  commitOid: scanId.effectiveBaseOid,
                  relativePath: partial.relativePath,
                  side: "base",
                  scanId: scanId.scanId,
                });
                return r.ok ? r.value : null;
              })()
            : null;
      const fallbackHead =
        partial.headRevisionUri !== undefined
          ? partial.headRevisionUri
          : scanId
            ? (() => {
                const r = buildRevisionUriString({
                  repositoryRoot: scanId.repositoryRoot,
                  commitOid: scanId.effectiveHeadOid,
                  relativePath: partial.relativePath,
                  side: "head",
                  scanId: scanId.scanId,
                });
                return r.ok ? r.value : null;
              })()
            : null;
      return {
        relativePath: partial.relativePath,
        baseRevisionUri: fallbackBase,
        headRevisionUri: fallbackHead,
        preferredRevisionUri: partial.preferredRevisionUri ?? fallbackHead ?? fallbackBase,
        revealLine1Based:
          typeof explicitLine1Based === "number"
            ? explicitLine1Based
            : partial.revealLine1Based ?? null,
        evidenceSide: partial.evidenceSide ?? "head",
        ruleLabel: partial.ruleLabel ?? partial.relativePath,
      };
    }

    // 3. `vscode.Uri` or `checkwash-rev:` URI string (or fallback to active `checkwash-rev:` editor)
    let candidateRevUriStr: string | null = null;
    if (typeof rawArg === "string" && rawArg.startsWith(`${CHECKWASH_REVISION_URI_SCHEME}:/`)) {
      candidateRevUriStr = rawArg;
    } else if (
      rawArg &&
      typeof rawArg === "object" &&
      "scheme" in rawArg &&
      (rawArg as vscode.Uri).scheme === CHECKWASH_REVISION_URI_SCHEME
    ) {
      candidateRevUriStr = (rawArg as vscode.Uri).toString();
    } else if (
      rawArg === undefined &&
      vscode.window.activeTextEditor &&
      vscode.window.activeTextEditor.document.uri.scheme === CHECKWASH_REVISION_URI_SCHEME
    ) {
      candidateRevUriStr = vscode.window.activeTextEditor.document.uri.toString();
    }

    if (candidateRevUriStr) {
      const parsed = parseRevisionUriString(candidateRevUriStr);
      if (!parsed.ok) {
        void vscode.window.showErrorMessage(`Invalid Checkwash revision URI: ${parsed.error}`);
        return null;
      }
      if (!areSameRepositoryPath(parsed.value.repositoryRoot, boundRepo)) {
        void vscode.window.showErrorMessage(
          `Revision URI belongs to '${parsed.value.repositoryRoot}', which does not match active repository '${boundRepo}'.`
        );
        return null;
      }

      const activeEditor = vscode.window.activeTextEditor;
      const activeCursorLine1 =
        activeEditor &&
        activeEditor.document.uri.toString() === candidateRevUriStr &&
        activeEditor.selection
          ? activeEditor.selection.active.line + 1
          : null;

      const allNavNodes = collectAllFindingNavNodes(snap.treeNodes);
      const matchedNode = allNavNodes.find(
        (n) =>
          n.findingNav?.preferredRevisionUri === candidateRevUriStr ||
          n.findingNav?.headRevisionUri === candidateRevUriStr ||
          n.findingNav?.baseRevisionUri === candidateRevUriStr ||
          n.findingNav?.relativePath === parsed.value.relativePath
      );

      if (matchedNode?.findingNav) {
        return {
          ...matchedNode.findingNav,
          revealLine1Based:
            typeof explicitLine1Based === "number"
              ? explicitLine1Based
              : activeCursorLine1 ?? matchedNode.findingNav.revealLine1Based,
        };
      }

      const scanId = snap.evaluatedState.joinedReport?.scanIdentity ?? null;
      if (scanId && scanId.scanId === parsed.value.scanId) {
        const baseRes = buildRevisionUriString({
          repositoryRoot: scanId.repositoryRoot,
          commitOid: scanId.effectiveBaseOid,
          relativePath: parsed.value.relativePath,
          side: "base",
          scanId: scanId.scanId,
        });
        const headRes = buildRevisionUriString({
          repositoryRoot: scanId.repositoryRoot,
          commitOid: scanId.effectiveHeadOid,
          relativePath: parsed.value.relativePath,
          side: "head",
          scanId: scanId.scanId,
        });
        return {
          relativePath: parsed.value.relativePath,
          baseRevisionUri: baseRes.ok ? baseRes.value : null,
          headRevisionUri: headRes.ok ? headRes.value : null,
          preferredRevisionUri: candidateRevUriStr,
          revealLine1Based:
            typeof explicitLine1Based === "number" ? explicitLine1Based : activeCursorLine1,
          evidenceSide: parsed.value.side,
          ruleLabel: parsed.value.relativePath,
        };
      }
    }

    // 4. Interactive QuickPick across current session findings & Fast Guard hints
    const navNodes = collectAllFindingNavNodes(snap.treeNodes);
    if (navNodes.length === 0) {
      void vscode.window.showInformationMessage(
        "No Checkwash findings or Fast Guard hints in the current session. Run a Pre-Check or Committed Scan first."
      );
      return null;
    }
    const picked = await vscode.window.showQuickPick(
      navNodes.map((n) => ({
        label: n.label,
        description: n.description,
        nav: n.findingNav!,
      })),
      { placeHolder: "Select a Checkwash finding or Fast Guard hint" }
    );
    return picked ? picked.nav : null;
  };

  // Document & workspace listeners (NEVER spawn external processes; only refresh in-memory bindings)
  const refreshLiveEditorDiagnosticsOnly = () => {
    const bound = controller.getViewSnapshot().boundRepositoryRoot;
    const openSnaps = collectOpenEditorSnapshots(bound, scanVerifiedVersionsByKey);
    applyViewSnapshot(controller.onOpenDocumentsChanged(openSnaps));
  };

  context.subscriptions.push(
    { dispose: () => unsubscribeView() },
    statusBarItem,
    checkwashDiagnostics,
    fastGuardDiagnostics,
    treeView,
    vscode.workspace.registerTextDocumentContentProvider(
      CHECKWASH_REVISION_URI_SCHEME,
      revisionDocProvider
    ),
    vscode.workspace.registerTextDocumentContentProvider(
      CHECKWASH_EMPTY_URI_SCHEME,
      emptyRevisionDocProvider
    ),
    { dispose: () => doctorDocChangeEmitter.dispose?.() },
    vscode.workspace.registerTextDocumentContentProvider(
      CHECKWASH_DOCTOR_URI_SCHEME,
      doctorDocProvider
    ),
    ...(typeof vscode.languages.registerHoverProvider === "function"
      ? [vscode.languages.registerHoverProvider({ scheme: "file" }, hoverProvider)]
      : []),
    vscode.workspace.onDidChangeTextDocument(() => {
      refreshLiveEditorDiagnosticsOnly();
    }),
    vscode.workspace.onDidCloseTextDocument(() => {
      refreshLiveEditorDiagnosticsOnly();
    }),
    vscode.workspace.onDidSaveTextDocument(() => {
      // Save never triggers a scan; only refreshes live buffer dirty state
      refreshLiveEditorDiagnosticsOnly();
    }),
    vscode.workspace.onDidGrantWorkspaceTrust(() => {
      // Granting trust never auto-scans (§1.1)
      applyViewSnapshot(controller.getViewSnapshot());
    }),
    ...(typeof vscode.workspace.onDidChangeWorkspaceFolders === "function"
      ? [
          vscode.workspace.onDidChangeWorkspaceFolders(() => {
            const bound = controller.getViewSnapshot().boundRepositoryRoot;
            const fileFolders = (vscode.workspace.workspaceFolders ?? []).filter(
              (f) => f.uri.scheme === "file"
            );
            if (bound && !findMatchingWorkspaceFolder(fileFolders, bound)) {
              controller.clearBoundRepository(
                "Bound repository folder was removed from the workspace."
              );
              scanVerifiedVersionsByKey.clear();
              applyViewSnapshot(controller.getViewSnapshot());
            }
          }),
        ]
      : []),
    ...(typeof vscode.workspace.onDidChangeConfiguration === "function"
      ? [
          vscode.workspace.onDidChangeConfiguration(() => {
            // Config changes never auto-scan (§1.1)
            applyViewSnapshot(controller.getViewSnapshot());
          }),
        ]
      : []),
    vscode.commands.registerCommand("checkwashLens.openQuickActions", async () => {
      const snap = controller.getViewSnapshot();
      const isTrusted = vscode.workspace.isTrusted;
      const isAnalyzing = snap.evaluatedState.lifecycle.analyzing;
      const wsFolders = (vscode.workspace.workspaceFolders ?? []).filter(
        (f) => f.uri.scheme === "file"
      );
      const navNodes = collectAllFindingNavNodes(snap.treeNodes);

      type QuickActionChoice = {
        label: string;
        description: string;
        actionId: string;
        commandId: string;
        args: unknown[];
      };

      const actions: QuickActionChoice[] = [];

      if (isAnalyzing) {
        actions.push({
          label: "$(stop-circle) Cancel Active Scan",
          description: "Stop the running Checkwash / Prove process tree immediately",
          actionId: "cancel",
          commandId: "checkwashLens.cancelActiveScan",
          args: [],
        });
      }

      if (!isTrusted) {
        actions.push({
          label: "$(file-code) View Offline JSON Report (Read-Only)",
          description: "Available in Restricted Mode (0 external processes spawned)",
          actionId: "offline",
          commandId: "checkwashLens.viewOfflineReport",
          args: [],
        });
      }

      actions.push(
        {
          label: "$(shield) Pre-Check Working Tree (HEAD -> Worktree)",
          description: isTrusted
            ? "Inspect uncommitted & untracked edits before staging/committing"
            : "Requires Workspace Trust",
          actionId: "precheck-worktree",
          commandId: "checkwashLens.scanUncommittedSnapshot",
          args: ["worktree"],
        },
        {
          label: "$(git-pull-request-draft) Pre-Check Staged Changes (HEAD -> Index)",
          description: isTrusted
            ? "Verify git-staged index changes right before git commit"
            : "Requires Workspace Trust",
          actionId: "precheck-staged",
          commandId: "checkwashLens.scanUncommittedSnapshot",
          args: ["staged"],
        },
        {
          label: "$(git-commit) Scan Last Commit (HEAD~1..HEAD)",
          description: isTrusted
            ? "Authoritative verdict on the most recent commit"
            : "Requires Workspace Trust",
          actionId: "scan-last-commit",
          commandId: "checkwashLens.scanCommittedRange",
          args: ["HEAD~1..HEAD"],
        },
        {
          label: "$(git-compare) Scan Branch or Custom Git Range...",
          description: isTrusted
            ? "Pick local/origin base branch (e.g. main...HEAD) or custom A..B range"
            : "Requires Workspace Trust",
          actionId: "scan-range-picker",
          commandId: "checkwashLens.scanCommittedRange",
          args: [],
        }
      );

      if (navNodes.length > 0) {
        actions.push(
          {
            label: `$(diff) Compare Base ↔ Head Revision Diff (${navNodes.length} item(s))`,
            description: "Open side-by-side red/green Git revision diff for a finding",
            actionId: "finding-diff",
            commandId: "checkwashLens.openFindingDiff",
            args: [],
          },
          {
            label: `$(go-to-file) Open Editable Workspace File at Finding`,
            description: "Jump straight to the live working-tree file to fix weakened tests",
            actionId: "finding-edit",
            commandId: "checkwashLens.openWorkspaceFileAtFinding",
            args: [],
          }
        );
      }

      if (snap.contextDietResult) {
        actions.push({
          label: "$(clippy) Copy Context Diet Diff",
          description: `Noise-filtered & secret-guarded diff (${snap.contextDietResult.keptFilePaths.length} kept, ${snap.contextDietResult.omittedFiles.length} omitted)`,
          actionId: "copy-diet",
          commandId: "checkwashLens.copyContextDietDiff",
          args: [],
        });
      }

      actions.push(
        {
          label: "$(pulse) Run Environment Doctor",
          description: "Verify Python, Git, native broker & optional Prove configuration",
          actionId: "doctor",
          commandId: "checkwashLens.runEnvironmentDoctor",
          args: [],
        },
        {
          label: "$(beaker) Run Prove (--list Candidate Mutants)",
          description: "Manual satellite preview (requires checkwashLens.provePath)",
          actionId: "prove-list",
          commandId: "checkwashLens.runProveList",
          args: [],
        },
        {
          label: "$(flame) Run Full Prove Analysis",
          description: "Manual mutation analysis (requires modal confirmation)",
          actionId: "prove-full",
          commandId: "checkwashLens.runProveFull",
          args: [],
        }
      );

      if (isTrusted) {
        actions.push({
          label: "$(file-code) View Offline JSON Report (Read-Only)",
          description: "Inspect a saved Checkwash JSON v2 or Prove v0.1.0 report",
          actionId: "offline",
          commandId: "checkwashLens.viewOfflineReport",
          args: [],
        });
      }

      if (
        snap.offlineFindingsPreview !== null ||
        snap.proveOutcome.record?.isImportedExternalReport === true
      ) {
        actions.push({
          label: "$(clear-all) Clear Offline Report Preview",
          description: "Dismiss imported read-only report preview from Checkwash Lens",
          actionId: "clear-offline-preview",
          commandId: "checkwashLens.clearOfflineReportPreview",
          args: [],
        });
      }

      if (wsFolders.length > 1) {
        actions.push({
          label: "$(repo) Select Active Repository...",
          description: `Currently bound: ${snap.boundRepositoryRoot ?? "(none)"}`,
          actionId: "select-repo",
          commandId: "checkwashLens.selectRepository",
          args: [],
        });
      }

      const stateHeadline = isAnalyzing
        ? "Analyzing..."
        : `${snap.evaluatedState.state}${snap.enrichedFindings.length > 0 ? ` (${snap.enrichedFindings.length} finding(s))` : ""}`;
      const picked = await vscode.window.showQuickPick(actions, {
        placeHolder: `Checkwash Lens (${stateHeadline}) — Select an action`,
      });
      if (!picked) {
        return null;
      }
      return vscode.commands.executeCommand(picked.commandId, ...picked.args);
    }),
    vscode.commands.registerCommand("checkwashLens.selectRepository", async () => {
      const wsFolders = (vscode.workspace.workspaceFolders ?? []).filter(
        (f) => f.uri.scheme === "file"
      );
      if (wsFolders.length === 0) {
        void vscode.window.showWarningMessage("No local workspace folders found.");
        return null;
      }
      const picked = await vscode.window.showQuickPick(
        wsFolders.map((f) => ({ label: f.name, description: f.uri.fsPath })),
        { placeHolder: "Select active Git repository for Checkwash Lens" }
      );
      if (picked && picked.description) {
        controller.selectRepository(picked.description);
        scanVerifiedVersionsByKey.clear();
        const snap = controller.getViewSnapshot();
        applyViewSnapshot(snap);
        return snap;
      }
      return null;
    }),
    vscode.commands.registerCommand(
      "checkwashLens.scanCommittedRange",
      async (rangeArg?: string) => {
        const repoRoot = await ensureSelectedRepo();
        if (!repoRoot) {
          return null;
        }
        if (!vscode.workspace.isTrusted) {
          // RT-01: Never probe `.git` or collect open-editor buffers in Restricted Mode;
          // delegate directly to controller so `verifyLaunchAdmission` fails closed cleanly.
          const fallbackRange =
            typeof rangeArg === "string" && rangeArg.trim().length > 0
              ? rangeArg.trim()
              : "HEAD~1..HEAD";
          const hostDesc = buildHostDescriptor(context, repoRoot);
          const snap = await controller.scanCommittedRange(hostDesc, fallbackRange, []);
          applyViewSnapshot(snap);
          void vscode.window.showWarningMessage(
            "Checkwash Lens: Execution is disabled in Restricted Mode. Grant Workspace Trust to scan committed ranges, or use 'View Offline Report'."
          );
          return snap;
        }
        const rangeSpec =
          typeof rangeArg === "string" && rangeArg.trim().length > 0
            ? rangeArg.trim()
            : await promptCommittedGitRange(repoRoot, "Checkwash Committed Scan");
        if (!rangeSpec) {
          return null;
        }
        const hostDesc = buildHostDescriptor(context, repoRoot);
        const openSnaps = collectOpenEditorSnapshots(repoRoot);
        recordScanVerifiedVersions(openSnaps);
        const runScanTask = () => controller.scanCommittedRange(hostDesc, rangeSpec, openSnaps);
        const snap =
          typeof vscode.window.withProgress === "function"
            ? await vscode.window.withProgress(
                {
                  location: vscode.ProgressLocation.Notification,
                  title: `Checkwash Lens: Scanning committed range (${rangeSpec})...`,
                  cancellable: true,
                },
                async (_progress, token) => {
                  const cancelSub = token?.onCancellationRequested?.(() => {
                    void controller.getProcessRunner().cancelActiveRunAndConfirmStop();
                  });
                  try {
                    return await runScanTask();
                  } finally {
                    cancelSub?.dispose?.();
                  }
                }
              )
            : await runScanTask();
        applyViewSnapshot(snap);
        if (snap.evaluatedState.state === "Error") {
          void vscode.window.showErrorMessage(
            `Checkwash Lens scan failed: ${snap.evaluatedState.errorReason ?? "Unknown error"}`
          );
        } else if (
          snap.evaluatedState.state === "Not Run" &&
          (snap.evaluatedState.notRunReason ?? "").includes("Restricted Mode")
        ) {
          void vscode.window.showWarningMessage(
            "Checkwash Lens: Execution is disabled in Restricted Mode. Grant Workspace Trust to scan committed ranges, or use 'View Offline Report'."
          );
        }
        return snap;
      }
    ),
    vscode.commands.registerCommand(
      "checkwashLens.scanUncommittedSnapshot",
      async (modeArg?: UncommittedSnapshotMode) => {
        const repoRoot = await ensureSelectedRepo();
        if (!repoRoot) {
          return null;
        }
        if (!vscode.workspace.isTrusted) {
          // RT-01: Never prompt or collect buffers in Restricted Mode; fail closed cleanly via controller.
          const fallbackMode: UncommittedSnapshotMode =
            modeArg === "staged" || modeArg === "worktree" ? modeArg : "worktree";
          const hostDesc = buildHostDescriptor(context, repoRoot);
          const snap = await controller.scanUncommittedSnapshot(hostDesc, fallbackMode, []);
          applyViewSnapshot(snap);
          void vscode.window.showWarningMessage(
            "Checkwash Lens: Execution is disabled in Restricted Mode. Grant Workspace Trust to run pre-checks, or use 'View Offline Report'."
          );
          return snap;
        }
        let selectedMode: UncommittedSnapshotMode | undefined =
          modeArg === "staged" || modeArg === "worktree" ? modeArg : undefined;

        if (!selectedMode) {
          const picked = await vscode.window.showQuickPick(
            [
              {
                label: "$(shield) Working Tree (HEAD -> Worktree, incl. untracked)",
                description:
                  "Pre-check all uncommitted & non-ignored untracked files before staging/committing",
                mode: "worktree" as const,
              },
              {
                label: "$(git-pull-request-draft) Staged Changes (HEAD -> Index)",
                description:
                  "Pre-check staged git index changes before committing (ignores unstaged edits)",
                mode: "staged" as const,
              },
            ],
            {
              placeHolder:
                "Select Uncommitted Snapshot Pre-Check mode (does NOT mutate .git or replace committed-range verdict)",
            }
          );
          if (!picked) {
            return null;
          }
          selectedMode = picked.mode;
        }

        const modeToRun = selectedMode;
        const hostDesc = buildHostDescriptor(context, repoRoot);
        const openSnaps = collectOpenEditorSnapshots(repoRoot);
        recordScanVerifiedVersions(openSnaps);
        const titleScope =
          modeToRun === "staged" ? "Staged Index (HEAD -> Index)" : "Working Tree (HEAD -> Worktree)";
        const runPreCheckTask = () =>
          controller.scanUncommittedSnapshot(hostDesc, modeToRun, openSnaps);

        const snap =
          typeof vscode.window.withProgress === "function"
            ? await vscode.window.withProgress(
                {
                  location: vscode.ProgressLocation.Notification,
                  title: `Checkwash Lens: Pre-checking uncommitted ${titleScope}...`,
                  cancellable: true,
                },
                async (_progress, token) => {
                  const cancelSub = token?.onCancellationRequested?.(() => {
                    void controller.getProcessRunner().cancelActiveRunAndConfirmStop();
                  });
                  try {
                    return await runPreCheckTask();
                  } finally {
                    cancelSub?.dispose?.();
                  }
                }
              )
            : await runPreCheckTask();

        applyViewSnapshot(snap);
        if (snap.evaluatedState.state === "Error") {
          void vscode.window.showErrorMessage(
            `Checkwash Lens uncommitted pre-check failed: ${snap.evaluatedState.errorReason ?? "Unknown error"}`
          );
        } else if (
          snap.evaluatedState.state === "Not Run" &&
          (snap.evaluatedState.notRunReason ?? "").includes("Restricted Mode")
        ) {
          void vscode.window.showWarningMessage(
            "Checkwash Lens: Execution is disabled in Restricted Mode. Grant Workspace Trust to run pre-checks, or use 'View Offline Report'."
          );
        }
        return snap;
      }
    ),
    vscode.commands.registerCommand(
      "checkwashLens.runEnvironmentDoctor",
      async (options?: { silentUi?: boolean }) => {
        const wsFileFolders = (vscode.workspace.workspaceFolders ?? []).filter(
          (f) => f.uri.scheme === "file"
        );
        let repoRoot = "";
        if (wsFileFolders.length > 0) {
          const pickedRepo = await ensureSelectedRepo();
          if (!pickedRepo) {
            return null;
          }
          repoRoot = pickedRepo;
        }

        const hostDesc = buildHostDescriptor(context, repoRoot);
        const configuredProvePath = readTrustedMachineStringSetting("provePath", "");
        const configuredProveTestPythonPath = readTrustedMachineStringSetting(
          "proveTestPythonPath",
          ""
        );
        const settingInspections = inspectAllCheckwashSettings(repoRoot);

        const runDoctorTask = () =>
          controller.runEnvironmentDoctor({
            hostDesc,
            configuredProvePath,
            configuredProveTestPythonPath,
            settingInspections,
          });

        const report =
          typeof vscode.window.withProgress === "function"
            ? await vscode.window.withProgress(
                {
                  location: vscode.ProgressLocation.Notification,
                  title: "Checkwash Lens: Running Environment Doctor...",
                  cancellable: true,
                },
                async (_progress, token) => {
                  const cancelSub = token?.onCancellationRequested?.(() => {
                    void controller.getProcessRunner().cancelActiveRunAndConfirmStop();
                  });
                  try {
                    return await runDoctorTask();
                  } finally {
                    cancelSub?.dispose?.();
                  }
                }
              )
            : await runDoctorTask();

        latestDoctorMarkdown = report.markdownSummary;
        const doctorUri = vscode.Uri.parse(
          `${CHECKWASH_DOCTOR_URI_SCHEME}:/Environment-Doctor-Report.md`
        );
        doctorDocChangeEmitter.fire(doctorUri);

        if (!options?.silentUi) {
          const doc = await vscode.workspace.openTextDocument(doctorUri);
          await vscode.window.showTextDocument(doc, { preview: true });
        }

        const patchEntries = Object.entries(report.recommendedUserSettingsPatch).filter(
          (entry): entry is [string, string] =>
            typeof entry[1] === "string" && entry[1].trim().length > 0
        );

        // RT-05: Never auto-apply settings silently via command arguments (`tasks.json` / URI link).
        // Global user settings may ONLY be updated after explicit interactive user button click.
        if (report.isWorkspaceTrusted && patchEntries.length > 0 && !options?.silentUi) {
          const action = await vscode.window.showInformationMessage(
            `Checkwash Lens Environment Doctor found ${patchEntries.length} verified runtime path(s) outside the repository (${patchEntries.map(([k]) => k).join(", ")}).`,
            "Save Verified Paths to User Settings"
          );
          if (action === "Save Verified Paths to User Settings") {
            const cfg = vscode.workspace.getConfiguration("checkwashLens") as vscode.WorkspaceConfiguration & {
              update?: (section: string, value: unknown, configurationTarget?: unknown) => Thenable<void>;
            };
            const globalTarget = vscode.ConfigurationTarget
              ? vscode.ConfigurationTarget.Global
              : 1;
            if (typeof cfg.update === "function") {
              for (const [key, val] of patchEntries) {
                await cfg.update(key, val, globalTarget);
              }
            }
            void vscode.window.showInformationMessage(
              `Saved ${patchEntries.length} verified path(s) to User Settings (Global).`
            );
          }
        }

        return report;
      }
    ),
    vscode.commands.registerCommand("checkwashLens.cancelActiveScan", async () => {
      const stopRes = await controller.getProcessRunner().cancelActiveRunAndConfirmStop();
      const snap = controller.getViewSnapshot();
      applyViewSnapshot(snap);
      if (!stopRes.cleanupConfirmed) {
        void vscode.window.showErrorMessage(
          `Checkwash Lens: Process tree cleanup was not confirmed (${snap.evaluatedState.errorReason ?? "unconfirmed cleanup"}). Subsequent runs are blocked.`
        );
      }
      return snap;
    }),
    vscode.commands.registerCommand("checkwashLens.copyContextDietDiff", async () => {
      const snap = controller.getViewSnapshot();
      if (!snap.contextDietResult) {
        void vscode.window.showWarningMessage(
          "No Context Diet diff available. Run 'Scan Committed Range' or 'Pre-Check Uncommitted Changes' first."
        );
        return null;
      }
      let mode: "redacted" | "unredacted" = "redacted";
      let userConfirmedUnredactedCopy = false;

      if (snap.contextDietResult.hasSensitiveData) {
        const choice = await vscode.window.showWarningMessage(
          `Sensitive Data Guard detected ${snap.contextDietResult.sensitiveFindings.length} potential secret(s) in this diff.`,
          { modal: true },
          "Copy Redacted Diff (Recommended)",
          "Copy Unredacted Diff (Unsafe)"
        );
        if (!choice) {
          return null;
        }
        if (choice === "Copy Unredacted Diff (Unsafe)") {
          mode = "unredacted";
          userConfirmedUnredactedCopy = true;
        }
      }

      const copyRes = controller.prepareContextDietCopy({
        mode,
        userConfirmedUnredactedCopy,
      });
      if (!copyRes.ok) {
        void vscode.window.showErrorMessage(copyRes.error);
        return null;
      }
      await vscode.env.clipboard.writeText(copyRes.value.payloadToCopy);
      void vscode.window.showInformationMessage(
        `Copied Context Diet diff (${copyRes.value.modeUsed}, omitted=${snap.contextDietResult.omittedFiles.length} file(s)).`
      );
      return copyRes.value;
    }),
    vscode.commands.registerCommand(
      "checkwashLens.openImmutableRevision",
      async (revUriString?: string, line1Based?: number | null) => {
        if (!revUriString || typeof revUriString !== "string") {
          void vscode.window.showInformationMessage(
            "Select a finding or Fast Guard item in the Checkwash Lens view to open its analyzed Git revision."
          );
          return null;
        }
        // RT-05: Strictly enforce `checkwash-rev:` scheme and canonical revision URI format
        // before delegating to `openTextDocument` so arbitrary `file:`, `vscode-vfs:`, or UNC URIs are rejected.
        const parsedCheck = parseRevisionUriString(revUriString);
        if (!parsedCheck.ok) {
          void vscode.window.showErrorMessage(
            `Checkwash Lens: Refusing to open invalid revision URI (${parsedCheck.error}).`
          );
          return null;
        }
        const uri = vscode.Uri.parse(revUriString);
        if (uri.scheme !== CHECKWASH_REVISION_URI_SCHEME) {
          void vscode.window.showErrorMessage(
            `Checkwash Lens: Refusing non-revision URI scheme '${uri.scheme}'.`
          );
          return null;
        }
        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc, { preview: true });
        if (typeof line1Based === "number" && line1Based >= 1) {
          const line0 = Math.max(0, line1Based - 1);
          const pos = new vscode.Position(line0, 0);
          editor.selection = new vscode.Selection(pos, pos);
          editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
        }
        return doc;
      }
    ),
    vscode.commands.registerCommand(
      "checkwashLens.openFindingDiff",
      async (targetArg?: unknown, explicitLine1Based?: number | null): Promise<FindingDiffOpenResult | null> => {
        if (!vscode.workspace.isTrusted) {
          void vscode.window.showWarningMessage(
            "Checkwash Lens: Git revision comparison is disabled in Restricted Mode."
          );
          return null;
        }
        const nav = await resolveFindingNavigationTarget(targetArg, explicitLine1Based);
        if (!nav) {
          return null;
        }
        const snap = controller.getViewSnapshot();
        const repoRoot = snap.boundRepositoryRoot ?? "";
        const hostDesc = buildHostDescriptor(context, repoRoot);

        let leftUri: vscode.Uri;
        let baseLabel = "Added";
        if (nav.baseRevisionUri) {
          const baseCheck = await controller.resolveImmutableRevisionUri(
            hostDesc,
            nav.baseRevisionUri
          );
          if (baseCheck.ok) {
            leftUri = vscode.Uri.parse(nav.baseRevisionUri);
            baseLabel = `Base ${baseCheck.value.commitOid.slice(0, 8)}`;
          } else {
            leftUri = buildEmptyRevisionUri(nav.relativePath, "base", "missing-in-base");
          }
        } else {
          leftUri = buildEmptyRevisionUri(nav.relativePath, "base", "added-in-head");
        }

        let rightUri: vscode.Uri;
        let headLabel = "Deleted";
        if (nav.headRevisionUri) {
          const headCheck = await controller.resolveImmutableRevisionUri(
            hostDesc,
            nav.headRevisionUri
          );
          if (headCheck.ok) {
            rightUri = vscode.Uri.parse(nav.headRevisionUri);
            const scope = snap.evaluatedState.scanScope;
            headLabel =
              scope === "worktree-precheck"
                ? "Worktree Snapshot"
                : scope === "staged-precheck"
                  ? "Staged Snapshot"
                  : `Head ${headCheck.value.commitOid.slice(0, 8)}`;
          } else {
            rightUri = buildEmptyRevisionUri(nav.relativePath, "head", "missing-in-head");
          }
        } else {
          rightUri = buildEmptyRevisionUri(nav.relativePath, "head", "deleted-in-head");
        }

        const baseName = path.posix.basename(nav.relativePath);
        const diffTitle = `${baseName} (${baseLabel} ↔ ${headLabel}) — ${nav.ruleLabel}`;
        const showOptions: vscode.TextDocumentShowOptions = { preview: true };
        if (typeof nav.revealLine1Based === "number" && nav.revealLine1Based >= 1) {
          const line0 = Math.max(0, nav.revealLine1Based - 1);
          showOptions.selection = new vscode.Range(line0, 0, line0, 0);
        }

        await vscode.commands.executeCommand("vscode.diff", leftUri, rightUri, diffTitle, showOptions);
        return {
          relativePath: nav.relativePath,
          leftUri: leftUri.toString(),
          rightUri: rightUri.toString(),
          title: diffTitle,
          revealLine1Based: nav.revealLine1Based,
        };
      }
    ),
    vscode.commands.registerCommand(
      "checkwashLens.openWorkspaceFileAtFinding",
      async (targetArg?: unknown, explicitLine1Based?: number | null) => {
        const nav = await resolveFindingNavigationTarget(targetArg, explicitLine1Based);
        if (!nav) {
          return null;
        }
        const snap = controller.getViewSnapshot();
        const boundRepo = snap.boundRepositoryRoot ?? "";
        const safePathRes = resolveSafeEditableWorkspaceFilePath(
          boundRepo,
          nav.relativePath,
          vscode.workspace.workspaceFolders
        );

        if (!safePathRes.ok) {
          if (safePathRes.missingInWorktree && vscode.workspace.isTrusted) {
            const action = await vscode.window.showInformationMessage(
              safePathRes.error,
              "Compare Base ↔ Head Diff"
            );
            if (action === "Compare Base ↔ Head Diff") {
              await vscode.commands.executeCommand("checkwashLens.openFindingDiff", nav);
            }
            return null;
          }
          void vscode.window.showErrorMessage(safePathRes.error);
          return null;
        }

        const fileUri = vscode.Uri.file(safePathRes.fsPath);
        const doc = await vscode.workspace.openTextDocument(fileUri);
        const editor = await vscode.window.showTextDocument(doc, { preview: false });
        if (typeof nav.revealLine1Based === "number" && nav.revealLine1Based >= 1) {
          const rawLineCount = (doc as unknown as { lineCount?: number }).lineCount;
          const maxLine0 =
            typeof rawLineCount === "number" && rawLineCount > 0
              ? rawLineCount - 1
              : Math.max(0, nav.revealLine1Based - 1);
          const line0 = Math.max(0, Math.min(nav.revealLine1Based - 1, maxLine0));
          const pos = new vscode.Position(line0, 0);
          editor.selection = new vscode.Selection(pos, pos);
          editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
        }
        return doc;
      }
    ),
    vscode.commands.registerCommand(
      "checkwashLens.runProveList",
      async (rangeArg?: string) => {
        const repoRoot = await ensureSelectedRepo();
        if (!repoRoot) return null;
        if (!vscode.workspace.isTrusted) {
          void vscode.window.showWarningMessage(
            "Checkwash Lens: Prove execution is disabled in Restricted Mode. Grant Workspace Trust first."
          );
          return null;
        }
        const initialProvePath = readTrustedMachineStringSetting("provePath", "");
        if (!initialProvePath) {
          void vscode.window.showErrorMessage(
            "Checkwash Lens: 'checkwashLens.provePath' is not configured in User/Machine Settings. Configure a trusted checkwash-prove v0.1.0 executable path first."
          );
          return null;
        }
        const rangeSpec =
          typeof rangeArg === "string" && rangeArg.trim().length > 0
            ? rangeArg.trim()
            : await promptCommittedGitRange(repoRoot, "Prove --list");
        if (!rangeSpec) return null;

        const initialHostDesc = buildHostDescriptor(context, repoRoot);
        const initialTestPyPath = readTrustedMachineStringSetting("proveTestPythonPath", "");
        const prepareListTask = () =>
          controller.prepareProveManualCommandPlan({
            hostDesc: initialHostDesc,
            configuredProvePath: initialProvePath,
            configuredTestPythonPath: initialTestPyPath || undefined,
            rawRangeSpec: rangeSpec,
            entryKind: "list",
          });
        const planRes =
          typeof vscode.window.withProgress === "function"
            ? await vscode.window.withProgress(
                {
                  location: vscode.ProgressLocation.Notification,
                  title: "Checkwash Lens: Preparing Prove (--list) execution plan...",
                  cancellable: true,
                },
                async (_progress, token) => {
                  const cancelSub = token?.onCancellationRequested?.(() => {
                    void controller.getProcessRunner().cancelActiveRunAndConfirmStop();
                  });
                  try {
                    return await prepareListTask();
                  } finally {
                    cancelSub?.dispose?.();
                  }
                }
              )
            : await prepareListTask();
        if (!planRes.ok) {
          const errSnap = controller.getViewSnapshot();
          applyViewSnapshot(errSnap);
          if (planRes.cancelled && !controller.getProcessRunner().hasUnconfirmedCleanup()) {
            return null;
          }
          void vscode.window.showErrorMessage(
            `Checkwash Prove (--list) preflight failed: ${planRes.error}`
          );
          return errSnap;
        }
        const plan = planRes.value;

        const confirm = await vscode.window.showWarningMessage(
          `${PROVE_EXECUTION_RISK_WARNING}\n\n${plan.confirmationDetailsText}`,
          { modal: true },
          "Confirm & Run Prove --list"
        );
        if (confirm !== "Confirm & Run Prove --list") {
          controller.getProveRunner().invalidatePreparedPlan(plan.planId);
          return null;
        }

        const auth = controller.getProveRunner().issueManualAuthorizationToken({
          plan,
          userConfirmedExecutionRisk: true,
        });
        const postConfirmRepoRoot = controller.getViewSnapshot().boundRepositoryRoot ?? repoRoot;
        const execHostDesc = buildHostDescriptor(context, postConfirmRepoRoot);
        const execProvePath = readTrustedMachineStringSetting("provePath", "");
        const execTestPyPath = readTrustedMachineStringSetting("proveTestPythonPath", "");
        const runTask = () =>
          controller.executeAuthorizedProveCommand({
            hostDesc: execHostDesc,
            configuredProvePath: execProvePath,
            configuredTestPythonPath: execTestPyPath || undefined,
            authorization: auth,
            expectedEntryKind: "list",
          });
        const snap =
          typeof vscode.window.withProgress === "function"
            ? await vscode.window.withProgress(
                {
                  location: vscode.ProgressLocation.Notification,
                  title: `Checkwash Lens: Running Prove --list (${plan.effectiveBaseOid.slice(0, 8)}..${plan.effectiveHeadOid.slice(0, 8)})...`,
                  cancellable: true,
                },
                async (_progress, token) => {
                  const cancelSub = token?.onCancellationRequested?.(() => {
                    void controller.getProcessRunner().cancelActiveRunAndConfirmStop();
                  });
                  try {
                    return await runTask();
                  } finally {
                    cancelSub?.dispose?.();
                  }
                }
              )
            : await runTask();
        applyViewSnapshot(snap);
        if (snap.proveOutcome.status === "Execution error") {
          void vscode.window.showErrorMessage(
            `Checkwash Prove (--list) failed: ${snap.proveOutcome.errorReason ?? "Unknown error"}`
          );
        }
        return snap;
      }
    ),
    vscode.commands.registerCommand(
      "checkwashLens.runProveFull",
      async (rangeArg?: string) => {
        const repoRoot = await ensureSelectedRepo();
        if (!repoRoot) return null;
        if (!vscode.workspace.isTrusted) {
          void vscode.window.showWarningMessage(
            "Checkwash Lens: Prove execution is disabled in Restricted Mode. Grant Workspace Trust first."
          );
          return null;
        }
        const initialProvePath = readTrustedMachineStringSetting("provePath", "");
        if (!initialProvePath) {
          void vscode.window.showErrorMessage(
            "Checkwash Lens: 'checkwashLens.provePath' is not configured in User/Machine Settings. Configure a trusted checkwash-prove v0.1.0 executable path first."
          );
          return null;
        }
        const rangeSpec =
          typeof rangeArg === "string" && rangeArg.trim().length > 0
            ? rangeArg.trim()
            : await promptCommittedGitRange(repoRoot, "Full Prove Analysis");
        if (!rangeSpec) return null;

        const initialHostDesc = buildHostDescriptor(context, repoRoot);
        const initialTestPyPath = readTrustedMachineStringSetting("proveTestPythonPath", "");
        const prepareFullTask = () =>
          controller.prepareProveManualCommandPlan({
            hostDesc: initialHostDesc,
            configuredProvePath: initialProvePath,
            configuredTestPythonPath: initialTestPyPath || undefined,
            rawRangeSpec: rangeSpec,
            entryKind: "full",
          });
        const planRes =
          typeof vscode.window.withProgress === "function"
            ? await vscode.window.withProgress(
                {
                  location: vscode.ProgressLocation.Notification,
                  title: "Checkwash Lens: Preparing full Prove execution plan...",
                  cancellable: true,
                },
                async (_progress, token) => {
                  const cancelSub = token?.onCancellationRequested?.(() => {
                    void controller.getProcessRunner().cancelActiveRunAndConfirmStop();
                  });
                  try {
                    return await prepareFullTask();
                  } finally {
                    cancelSub?.dispose?.();
                  }
                }
              )
            : await prepareFullTask();
        if (!planRes.ok) {
          const errSnap = controller.getViewSnapshot();
          applyViewSnapshot(errSnap);
          if (planRes.cancelled && !controller.getProcessRunner().hasUnconfirmedCleanup()) {
            return null;
          }
          void vscode.window.showErrorMessage(
            `Checkwash Prove preflight failed: ${planRes.error}`
          );
          return errSnap;
        }
        const plan = planRes.value;

        const confirm = await vscode.window.showWarningMessage(
          `${PROVE_EXECUTION_RISK_WARNING}\n\n${plan.confirmationDetailsText}`,
          { modal: true },
          "Confirm & Run Full Prove"
        );
        if (confirm !== "Confirm & Run Full Prove") {
          controller.getProveRunner().invalidatePreparedPlan(plan.planId);
          return null;
        }

        const auth = controller.getProveRunner().issueManualAuthorizationToken({
          plan,
          userConfirmedExecutionRisk: true,
        });
        const postConfirmRepoRoot = controller.getViewSnapshot().boundRepositoryRoot ?? repoRoot;
        const execHostDesc = buildHostDescriptor(context, postConfirmRepoRoot);
        const execProvePath = readTrustedMachineStringSetting("provePath", "");
        const execTestPyPath = readTrustedMachineStringSetting("proveTestPythonPath", "");
        const runTask = () =>
          controller.executeAuthorizedProveCommand({
            hostDesc: execHostDesc,
            configuredProvePath: execProvePath,
            configuredTestPythonPath: execTestPyPath || undefined,
            authorization: auth,
            expectedEntryKind: "full",
          });
        const snap =
          typeof vscode.window.withProgress === "function"
            ? await vscode.window.withProgress(
                {
                  location: vscode.ProgressLocation.Notification,
                  title: `Checkwash Lens: Running full Prove analysis (${plan.effectiveBaseOid.slice(0, 8)}..${plan.effectiveHeadOid.slice(0, 8)})...`,
                  cancellable: true,
                },
                async (_progress, token) => {
                  const cancelSub = token?.onCancellationRequested?.(() => {
                    void controller.getProcessRunner().cancelActiveRunAndConfirmStop();
                  });
                  try {
                    return await runTask();
                  } finally {
                    cancelSub?.dispose?.();
                  }
                }
              )
            : await runTask();
        applyViewSnapshot(snap);
        if (snap.proveOutcome.status === "Execution error") {
          void vscode.window.showErrorMessage(
            `Checkwash Prove failed: ${snap.proveOutcome.errorReason ?? "Unknown error"}`
          );
        }
        return snap;
      }
    ),
    vscode.commands.registerCommand(
      "checkwashLens.replayMutant",
      async (recordRunIdArg?: number | CheckwashTreeNode, mutantIdArg?: string) => {
        const repoRoot = await ensureSelectedRepo();
        if (!repoRoot) {
          return null;
        }
        let recordRunId: number | undefined =
          typeof recordRunIdArg === "number" ? recordRunIdArg : undefined;
        let mutantId: string | undefined =
          typeof mutantIdArg === "string" ? mutantIdArg : undefined;

        // Also support inline TreeItem button invocation `(treeNode: CheckwashTreeNode)`!
        if (
          recordRunId === undefined &&
          recordRunIdArg &&
          typeof recordRunIdArg === "object" &&
          "command" in recordRunIdArg
        ) {
          const cmdArgs = (recordRunIdArg as CheckwashTreeNode).command?.arguments;
          if (
            Array.isArray(cmdArgs) &&
            typeof cmdArgs[0] === "number" &&
            typeof cmdArgs[1] === "string"
          ) {
            recordRunId = cmdArgs[0];
            mutantId = cmdArgs[1];
          }
        }

        if (typeof recordRunId !== "number" || typeof mutantId !== "string" || !mutantId) {
          void vscode.window.showInformationMessage(
            "Select a mutant item under an active session Prove result in the Checkwash Lens view to replay it."
          );
          return null;
        }
        if (!vscode.workspace.isTrusted) {
          void vscode.window.showWarningMessage(
            "Checkwash Lens: Mutant replay is disabled in Restricted Mode. Grant Workspace Trust first."
          );
          return null;
        }
        const initialProvePath = readTrustedMachineStringSetting("provePath", "");
        if (!initialProvePath) {
          void vscode.window.showErrorMessage(
            "Checkwash Lens: 'checkwashLens.provePath' is not configured in User/Machine Settings. Configure a trusted checkwash-prove v0.1.0 executable path first."
          );
          return null;
        }

        const resolvedRunId = recordRunId;
        const resolvedMutantId = mutantId;
        const initialHostDesc = buildHostDescriptor(context, repoRoot);
        const initialTestPyPath = readTrustedMachineStringSetting("proveTestPythonPath", "");
        const prepareReplayTask = () =>
          controller.prepareProveReplayCommandPlan({
            hostDesc: initialHostDesc,
            configuredProvePath: initialProvePath,
            configuredTestPythonPath: initialTestPyPath || undefined,
            recordRunId: resolvedRunId,
            selectedMutantId: resolvedMutantId,
          });
        const planRes =
          typeof vscode.window.withProgress === "function"
            ? await vscode.window.withProgress(
                {
                  location: vscode.ProgressLocation.Notification,
                  title: `Checkwash Lens: Preparing replay plan for ${resolvedMutantId}...`,
                  cancellable: true,
                },
                async (_progress, token) => {
                  const cancelSub = token?.onCancellationRequested?.(() => {
                    void controller.getProcessRunner().cancelActiveRunAndConfirmStop();
                  });
                  try {
                    return await prepareReplayTask();
                  } finally {
                    cancelSub?.dispose?.();
                  }
                }
              )
            : await prepareReplayTask();
        if (!planRes.ok) {
          const errSnap = controller.getViewSnapshot();
          applyViewSnapshot(errSnap);
          if (planRes.cancelled && !controller.getProcessRunner().hasUnconfirmedCleanup()) {
            return null;
          }
          void vscode.window.showErrorMessage(
            `Checkwash Prove replay preflight failed: ${planRes.error}`
          );
          return errSnap;
        }
        const plan = planRes.value;

        const confirm = await vscode.window.showWarningMessage(
          `${PROVE_EXECUTION_RISK_WARNING}\n\n${plan.confirmationDetailsText}`,
          { modal: true },
          "Confirm & Replay Single Mutant"
        );
        if (confirm !== "Confirm & Replay Single Mutant") {
          controller.getProveRunner().invalidatePreparedPlan(plan.planId);
          return null;
        }

        const auth = controller.getProveRunner().issueManualAuthorizationToken({
          plan,
          userConfirmedExecutionRisk: true,
        });
        const postConfirmRepoRoot = controller.getViewSnapshot().boundRepositoryRoot ?? repoRoot;
        const execHostDesc = buildHostDescriptor(context, postConfirmRepoRoot);
        const execProvePath = readTrustedMachineStringSetting("provePath", "");
        const execTestPyPath = readTrustedMachineStringSetting("proveTestPythonPath", "");
        const runTask = () =>
          controller.executeAuthorizedProveCommand({
            hostDesc: execHostDesc,
            configuredProvePath: execProvePath,
            configuredTestPythonPath: execTestPyPath || undefined,
            authorization: auth,
            expectedEntryKind: "replay",
            expectedRecordRunId: resolvedRunId,
            expectedSelectedMutantId: resolvedMutantId,
          });
        const snap =
          typeof vscode.window.withProgress === "function"
            ? await vscode.window.withProgress(
                {
                  location: vscode.ProgressLocation.Notification,
                  title: `Checkwash Lens: Replaying mutant ${resolvedMutantId}...`,
                  cancellable: true,
                },
                async (_progress, token) => {
                  const cancelSub = token?.onCancellationRequested?.(() => {
                    void controller.getProcessRunner().cancelActiveRunAndConfirmStop();
                  });
                  try {
                    return await runTask();
                  } finally {
                    cancelSub?.dispose?.();
                  }
                }
              )
            : await runTask();
        applyViewSnapshot(snap);
        if (snap.proveOutcome.status === "Execution error") {
          void vscode.window.showErrorMessage(
            `Checkwash Prove replay failed: ${snap.proveOutcome.errorReason ?? "Unknown error"}`
          );
        }
        return snap;
      }
    ),
    vscode.commands.registerCommand(
      "checkwashLens.viewOfflineReport",
      async (uri?: vscode.Uri) => {
        let targetUri = uri;
        if (!targetUri) {
          const picked = await vscode.window.showOpenDialog({
            canSelectMany: false,
            filters: { "JSON Reports": ["json"] },
            openLabel: "Open Offline Checkwash / Prove Report (Read-Only)",
          });
          if (!picked || picked.length === 0) {
            return null;
          }
          targetUri = picked[0];
        }
        if (targetUri.scheme !== "file") {
          void vscode.window.showErrorMessage("Offline report must be a local file.");
          return null;
        }
        const res = controller.viewOfflineReportFileReadOnly(targetUri.fsPath);
        if (!res.ok) {
          void vscode.window.showErrorMessage(res.error);
          return null;
        }
        const snap = controller.getViewSnapshot();
        applyViewSnapshot(snap);
        void vscode.window.showInformationMessage(
          `Loaded offline report (${res.value.kind}) in read-only mode.`
        );
        return snap;
      }
    ),
    vscode.commands.registerCommand("checkwashLens.clearOfflineReportPreview", async () => {
      const snap = controller.clearOfflineReadOnlyPreview();
      applyViewSnapshot(snap);
      void vscode.window.showInformationMessage("Cleared read-only offline report preview.");
      return snap;
    })
  );

  return controller;
}

export async function deactivate(): Promise<void> {
  if (activeController) {
    await activeController.getProcessRunner().cancelActiveRunAndConfirmStop();
    activeController.dispose();
    activeController = null;
  }
}
