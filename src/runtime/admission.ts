/**
 * runtime/admission.ts
 *
 * Unified execution admission gate, artifact hash verification,
 * trusted runtime path validation, and sanitized environment builder.
 *
 * Enforces Rev 3 §4.1, §7.1, §7.2 (B01, B02, B03, B04, B09, B10):
 * - Every external process launch MUST pass through verifyLaunchAdmission().
 * - Rejects untrusted workspaces (Restricted Mode -> zero child processes).
 * - Supports local win32/x64, local linux/x64, and Linux x64 WSL2 ('wsl') / Dev Containers ('dev-container', 'attached-container'); rejects mismatched host OS/arch, unsupported remote hosts (e.g. ssh-remote, tunnel, codespaces), and virtual workspaces.
 * - Verifies bundled/checkwash.pyz and the platform-native CWBROKER1 broker binary exact byte size and SHA-256.
 * - Verifies canonical paths for Python and Git are regular native executable files outside the target repository (including POSIX inode containment for case-insensitive WSL2/bind mounts and PE/WSLInterop rejection on Linux).
 * - Builds a sanitized environment with controlled PATH and controlled empty cwd outside the target repository.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ValidationResult } from "../core/checkwashSchema";

export const EXPECTED_CHECKWASH_VERSION = "0.13.1";
export const EXPECTED_CHECKWASH_BYTES = 1079499;
export const EXPECTED_CHECKWASH_SHA256 =
  "0a987325c6f738129f5dbdc1e0287cfeab40517342b46df80707cccff8dd2839";
export const EXPECTED_CHECKWASH_BUILD_COMMIT =
  "5e2a89ef0d447ae6e08c289f4a3357325b7286e9";

export interface BrokerArtifactEntry {
  protocol: string;
  relativePath: string;
  sourceRelativePath?: string;
  bytes: number;
  sha256: string;
}

export interface BundledManifest {
  schemaVersion: number;
  checkwash: {
    version: string;
    relativePath: string;
    bytes: number;
    sha256: string;
    artifactBuildSourceCommit: string;
    releaseTagCommit: string;
    findingsSchemaVersion: number;
    sarifVersion: string;
  };
  windowsBroker?: BrokerArtifactEntry;
  linuxBroker?: BrokerArtifactEntry;
  proveAdapter: {
    version: string;
    sourceCommit: string;
    catalogueVersion: string;
    generatorSha256: string;
  };
}

export const SUPPORTED_LINUX_REMOTE_NAMES = [
  "wsl",
  "dev-container",
  "attached-container",
] as const;

export type SupportedLinuxRemoteName = (typeof SUPPORTED_LINUX_REMOTE_NAMES)[number];

export interface HostEnvironmentDescriptor {
  isWorkspaceTrusted: boolean;
  platform: string;
  arch: string;
  workspaceScheme: string;
  isRemote: boolean;
  /** VS Code `vscode.env.remoteName` when `isRemote` is true (e.g. `'wsl'`, `'dev-container'`, `'attached-container'`, `'ssh-remote'`). */
  remoteName?: string | null;
  isVirtualWorkspace: boolean;
  extensionRootPath: string;
  repositoryRootPath: string;
  configuredPythonPath: string;
  configuredGitPath: string;
  /** Optional inherited env for testing B03 pollution stripping */
  inheritedEnv?: NodeJS.ProcessEnv;
}

export interface VerifiedAdmissionContext {
  canonicalExtensionRoot: string;
  canonicalRepositoryRoot: string;
  canonicalPythonPath: string;
  canonicalGitPath: string;
  canonicalGitDir: string;
  bundledPyzPath: string;
  bundledPyzSha256: string;
  bundledBrokerPath: string;
  bundledBrokerSha256: string;
  controlledEmptyCwd: string;
  isolatedTempDir: string;
  sanitizedStaticEnv: Record<string, string>;
}

export interface CapabilityState {
  executionFeaturesEnabled: boolean;
  offlineViewingEnabled: true;
  disableReason: string | null;
}

export function isSupportedHostPlatformArch(platform: string, arch: string): boolean {
  return (platform === "win32" || platform === "linux") && arch === "x64";
}

export function isSupportedLinuxRemoteName(
  remoteName: string | null | undefined
): remoteName is SupportedLinuxRemoteName {
  if (typeof remoteName !== "string") {
    return false;
  }
  const normalized = remoteName.trim().toLowerCase();
  return (SUPPORTED_LINUX_REMOTE_NAMES as readonly string[]).includes(normalized);
}

/**
 * Validates host OS/architecture and physical/remote workspace eligibility (B02, v0.4.0).
 * Allows:
 *   - Local physical workspaces (`isRemote === false`, `workspaceScheme === "file"`, `!isVirtualWorkspace`) on `win32/x64` or `linux/x64`.
 *   - Remote physical workspaces (`isRemote === true`, `workspaceScheme === "file"`, `!isVirtualWorkspace`) ONLY on `linux/x64` when `remoteName` is `'wsl'`, `'dev-container'`, or `'attached-container'`.
 * Rejects `'ssh-remote'`, `'tunnel'`, `'codespaces'`, unspecified remote authorities, and all virtual workspaces.
 */
export function verifyWorkspaceHostEnvironment(
  desc: Pick<
    HostEnvironmentDescriptor,
    "platform" | "arch" | "workspaceScheme" | "isRemote" | "remoteName" | "isVirtualWorkspace"
  >
): ValidationResult<{
  mode: "local" | "linux-remote";
  remoteName: SupportedLinuxRemoteName | null;
}> {
  if (
    !isSupportedHostPlatformArch(desc.platform, desc.arch) ||
    desc.platform !== process.platform ||
    desc.arch !== process.arch
  ) {
    return {
      ok: false,
      error: `Unsupported platform/architecture '${desc.platform}/${desc.arch}' on host '${process.platform}/${process.arch}' (Checkwash Lens requires win32/x64 or linux/x64)`,
    };
  }

  const normalizedRemote =
    typeof desc.remoteName === "string" ? desc.remoteName.trim().toLowerCase() : "";

  if (desc.isVirtualWorkspace || desc.workspaceScheme !== "file") {
    return {
      ok: false,
      error: `Unsupported workspace environment (scheme='${desc.workspaceScheme}', remote=${desc.isRemote}, remoteName='${normalizedRemote}', virtual=${desc.isVirtualWorkspace}); physical 'file' filesystem required`,
    };
  }

  if (!desc.isRemote && normalizedRemote.length === 0) {
    return { ok: true, value: { mode: "local", remoteName: null } };
  }

  if (
    desc.isRemote &&
    desc.platform === "linux" &&
    desc.arch === "x64" &&
    isSupportedLinuxRemoteName(normalizedRemote)
  ) {
    return {
      ok: true,
      value: { mode: "linux-remote", remoteName: normalizedRemote },
    };
  }

  return {
    ok: false,
    error: `Unsupported remote workspace environment (remote=${desc.isRemote}, remoteName='${normalizedRemote || "(unspecified)"}', platform='${desc.platform}/${desc.arch}'); only local win32/x64, local linux/x64, and Linux x64 WSL2 ('wsl') or Dev Containers ('dev-container', 'attached-container') are supported`,
  };
}

export function computeFileSha256AndSize(
  filePath: string
): ValidationResult<{ bytes: number; sha256: string }> {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) {
      return { ok: false, error: `Path is not a regular file: ${filePath}` };
    }
    const buf = fs.readFileSync(filePath);
    const sha256 = crypto.createHash("sha256").update(buf).digest("hex").toLowerCase();
    return {
      ok: true,
      value: { bytes: buf.length, sha256 },
    };
  } catch (err) {
    return {
      ok: false,
      error: `Failed to read artifact '${filePath}': ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

export function isFullyQualifiedWindowsPath(p: string): boolean {
  const trimmed = p.trim();
  return /^[a-zA-Z]:[\\/]/.test(trimmed) || /^\\\\[^\\/?*:<>|]+\\[^\\/?*:<>|]+/.test(trimmed);
}

export function isFullyQualifiedPosixPath(p: string): boolean {
  const trimmed = p.trim();
  return trimmed.startsWith("/") && !trimmed.includes("\0");
}

export function isFullyQualifiedPlatformPath(
  p: string,
  platform: string = process.platform
): boolean {
  return platform === "win32" ? isFullyQualifiedWindowsPath(p) : isFullyQualifiedPosixPath(p);
}

export function normalizePlatformLookupKey(
  p: string,
  platform: string = process.platform
): string {
  if (platform === "win32" || isFullyQualifiedWindowsPath(p)) {
    return p.replace(/[\\/]+$/, "").toLowerCase();
  }
  return p.replace(/\/+$/, "") || "/";
}

export function resolveCanonicalPath(p: string): ValidationResult<string> {
  if (typeof p !== "string" || p.trim().length === 0) {
    return { ok: false, error: "Path cannot be empty" };
  }
  const trimmed = p.trim();
  if (
    !path.isAbsolute(trimmed) ||
    (process.platform === "win32" && !isFullyQualifiedWindowsPath(trimmed)) ||
    (process.platform !== "win32" && !isFullyQualifiedPosixPath(trimmed))
  ) {
    return { ok: false, error: `Path must be a fully-qualified absolute path: ${p}` };
  }
  try {
    const real = fs.realpathSync.native(trimmed);
    return { ok: true, value: real };
  } catch (err) {
    return {
      ok: false,
      error: `Cannot resolve canonical path for '${p}': ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * Resolves a filesystem path to its canonical OS target (`fs.realpathSync.native`)
 * when it exists on disk (resolving junctions, symlinks, and 8.3 short names), falling back
 * cleanly to platform `path.resolve` (or `path.win32.resolve` for synthetic Windows strings)
 * in unit tests. Spawns zero external processes.
 */
export function resolveCanonicalOrNormalizedPath(inputPath: string): string {
  if (typeof inputPath !== "string" || inputPath.trim().length === 0) {
    return "";
  }
  const trimmed = inputPath.trim();
  if (process.platform !== "win32" && isFullyQualifiedWindowsPath(trimmed)) {
    return path.win32.resolve(trimmed);
  }
  try {
    return fs.realpathSync.native(trimmed);
  } catch {
    return process.platform === "win32"
      ? path.win32.resolve(trimmed)
      : path.posix.resolve(trimmed);
  }
}

export const resolveCanonicalOrNormalizedWinPath = resolveCanonicalOrNormalizedPath;

function tryStatBigIntPosix(p: string): fs.BigIntStats | null {
  try {
    const st = fs.statSync(p, { bigint: true });
    if (st.dev === 0n && st.ino === 0n) {
      return null;
    }
    return st;
  } catch {
    return null;
  }
}

function areSamePosixInode(pathA: string, pathB: string): boolean {
  if (process.platform === "win32") {
    return false;
  }
  const stA = tryStatBigIntPosix(pathA);
  if (!stA) {
    return false;
  }
  const stB = tryStatBigIntPosix(pathB);
  if (!stB) {
    return false;
  }
  return stA.dev === stB.dev && stA.ino === stB.ino;
}

function isPathInsideDirectoryByPosixInode(candidatePath: string, containerDir: string): boolean {
  if (process.platform === "win32") {
    return false;
  }
  const dirStat = tryStatBigIntPosix(containerDir);
  if (!dirStat) {
    return false;
  }
  let current = path.posix.resolve(candidatePath);
  for (let depth = 0; depth < 128; depth++) {
    const curStat = tryStatBigIntPosix(current);
    if (curStat && curStat.dev === dirStat.dev && curStat.ino === dirStat.ino) {
      return true;
    }
    const parent = path.posix.dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  return false;
}

/**
 * Compares two repository/folder paths canonically on the current OS (case-insensitive on Windows,
 * case-sensitive + kernel `(st_dev, st_ino)` alias check on POSIX/Linux so WSL2 `/mnt/c` DrvFS and
 * bind mounts cannot split repository identity across case variants) without spawning processes.
 */
export function areSameRepositoryPath(pathA: string, pathB: string): boolean {
  if (typeof pathA !== "string" || typeof pathB !== "string") {
    return false;
  }
  const canonA = resolveCanonicalOrNormalizedPath(pathA);
  const canonB = resolveCanonicalOrNormalizedPath(pathB);
  if (canonA.length === 0 || canonB.length === 0) {
    return false;
  }
  const useWinCompare =
    process.platform === "win32" ||
    (isFullyQualifiedWindowsPath(canonA) && isFullyQualifiedWindowsPath(canonB));
  if (useWinCompare) {
    const normA = canonA.replace(/[\\/]+$/, "").toLowerCase();
    const normB = canonB.replace(/[\\/]+$/, "").toLowerCase();
    return normA.length > 0 && normA === normB;
  }
  const normA = canonA.replace(/\/+$/, "") || "/";
  const normB = canonB.replace(/\/+$/, "") || "/";
  if (normA === normB) {
    return true;
  }
  return areSamePosixInode(normA, normB);
}

export const areSameWinRepositoryPath = areSameRepositoryPath;

/**
 * Case-insensitive Windows path containment check.
 * Returns true if candidatePath is equal to or inside containerDir.
 */
export function isPathInsideOrEqualWindows(candidatePath: string, containerDir: string): boolean {
  if (
    process.platform !== "win32" &&
    !isFullyQualifiedWindowsPath(candidatePath) &&
    !isFullyQualifiedWindowsPath(containerDir)
  ) {
    return isPathInsideOrEqualPlatform(candidatePath, containerDir, "linux");
  }
  const normCandidate = path.win32.resolve(candidatePath).toLowerCase();
  const normContainer = path.win32.resolve(containerDir).toLowerCase();
  if (normCandidate === normContainer) {
    return true;
  }
  const withSep = normContainer.endsWith("\\") ? normContainer : normContainer + "\\";
  return normCandidate.startsWith(withSep);
}

/**
 * Platform-aware path containment check (case-insensitive on Windows; lexical + POSIX `(st_dev, st_ino)`
 * ancestor containment on Linux so case-insensitive WSL2 `/mnt/c` DrvFS or bind-mount aliases cannot
 * bypass inside-repository runtime blocking).
 */
export function isPathInsideOrEqualPlatform(
  candidatePath: string,
  containerDir: string,
  platform: string = process.platform
): boolean {
  if (
    platform === "win32" ||
    (isFullyQualifiedWindowsPath(candidatePath) && isFullyQualifiedWindowsPath(containerDir))
  ) {
    const normCandidate = path.win32.resolve(candidatePath).toLowerCase();
    const normContainer = path.win32.resolve(containerDir).toLowerCase();
    if (normCandidate === normContainer) {
      return true;
    }
    const withSep = normContainer.endsWith("\\") ? normContainer : normContainer + "\\";
    return normCandidate.startsWith(withSep);
  }
  const normCandidate = path.posix.resolve(candidatePath);
  const normContainer = path.posix.resolve(containerDir);
  if (normCandidate === normContainer) {
    return true;
  }
  const withSep = normContainer.endsWith("/") ? normContainer : normContainer + "/";
  if (normCandidate.startsWith(withSep)) {
    return true;
  }
  if (
    process.platform !== "win32" &&
    normCandidate.startsWith("/") &&
    normContainer.startsWith("/")
  ) {
    return isPathInsideDirectoryByPosixInode(normCandidate, normContainer);
  }
  return false;
}

/**
 * Resolves the relative POSIX path of `targetPath` inside `rootPath` when the two paths traverse
 * different case/mount aliases of the same underlying directory `(st_dev, st_ino)` (e.g. `/mnt/c/users`
 * vs `/mnt/c/Users` on WSL2 DrvFS or bind mounts).
 */
export function tryRelativeInsidePosixInodeRoot(
  rootPath: string,
  targetPath: string
): string | null {
  if (process.platform === "win32" || !rootPath.startsWith("/") || !targetPath.startsWith("/")) {
    return null;
  }
  const rootStat = tryStatBigIntPosix(rootPath);
  if (!rootStat) {
    return null;
  }
  let current = path.posix.resolve(targetPath);
  const trailingSegments: string[] = [];
  for (let depth = 0; depth < 128; depth++) {
    const curStat = tryStatBigIntPosix(current);
    if (curStat && curStat.dev === rootStat.dev && curStat.ino === rootStat.ino) {
      return trailingSegments.length > 0 ? trailingSegments.reverse().join("/") : null;
    }
    const base = path.posix.basename(current);
    const parent = path.posix.dirname(current);
    if (parent === current || !base) {
      break;
    }
    trailingSegments.push(base);
    current = parent;
  }
  return null;
}

export function isWslWindowsMountPath(p: string): boolean {
  if (typeof p !== "string") {
    return false;
  }
  return /^\/mnt\/[a-zA-Z](\/|$)/.test(p.trim());
}

/**
 * Verifies that a resolved executable on Linux is a native Linux/POSIX executable and NOT a
 * Windows PE (`magic 0x4d5a` / `WSLInterop`), Windows script (`.exe`/`.bat`/`.cmd`/`.com`/`.ps1`),
 * or `/mnt/<drive>/` DrvFS file that would escape Linux `pgid`/`PR_SET_PDEATHSIG`/`/proc` tracking.
 */
export function verifyLinuxNativeExecutableIdentity(
  canonicalPath: string,
  roleLabel: string
): ValidationResult<void> {
  if (isWslWindowsMountPath(canonicalPath)) {
    return {
      ok: false,
      error: `Refusing to use executable '${canonicalPath}' on Windows mount ('/mnt/<drive>') for ${roleLabel} on Linux host; configure a native Linux executable outside '/mnt/<drive>'`,
    };
  }
  const lowerBase = path.posix.basename(canonicalPath).toLowerCase();
  if (
    lowerBase.endsWith(".exe") ||
    lowerBase.endsWith(".bat") ||
    lowerBase.endsWith(".cmd") ||
    lowerBase.endsWith(".com") ||
    lowerBase.endsWith(".ps1")
  ) {
    return {
      ok: false,
      error: `Refusing to execute Windows/WSLInterop binary '${canonicalPath}' for ${roleLabel} on Linux host (native Linux executable required)`,
    };
  }
  let fd: number | null = null;
  try {
    fd = fs.openSync(canonicalPath, "r");
    const header = Buffer.alloc(2);
    const bytesRead = fs.readSync(fd, header, 0, 2, 0);
    if (bytesRead >= 2 && header[0] === 0x4d && header[1] === 0x5a) {
      return {
        ok: false,
        error: `Refusing to execute Windows PE/WSLInterop binary '${canonicalPath}' for ${roleLabel} on Linux host (MZ header 0x4d5a detected; native Linux ELF/POSIX executable required)`,
      };
    }
  } catch (err) {
    return {
      ok: false,
      error: `Cannot inspect executable header for '${canonicalPath}' (${roleLabel}): ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore close error
      }
    }
  }
  return { ok: true, value: undefined };
}

const WINDOWS_RESERVED_DEVICE_RE = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

/**
 * Returns true if `rawPath` contains control characters, starts with a UNC/device prefix
 * (`\\`, `//`, `\\.\`, `\\?\`), or contains a Windows reserved DOS device segment (`CON`, `NUL`, `COM1`, ...).
 */
export function isDangerousUncOrDevicePath(rawPath: string): boolean {
  if (typeof rawPath !== "string") {
    return true;
  }
  if (/[\0\r\n]/.test(rawPath)) {
    return true;
  }
  const trimmed = rawPath.trim();
  if (trimmed.length === 0) {
    return true;
  }
  if (/^(?:\\\\|\/\/)/.test(trimmed)) {
    return true;
  }
  const segments = trimmed.split(/[\\/]+/);
  for (const seg of segments) {
    if (!seg || seg === "." || seg === "..") {
      continue;
    }
    if (WINDOWS_RESERVED_DEVICE_RE.test(seg)) {
      return true;
    }
  }
  return false;
}

/**
 * Verifies that a resolved executable on Windows is a native Win32 PE `.exe` binary (`MZ` 0x4d5a)
 * and NOT a `.bat`/`.cmd`/`.ps1`/`.vbs`/`.com` wrapper shim (which causes `CreateProcessW` to
 * implicitly invoke `cmd.exe /c` where C-runtime quoting does not neutralize `%` / `&` / `|`)
 * nor a UNC/device path (RT-04).
 */
export function verifyWindowsNativeExecutableIdentity(
  canonicalPath: string,
  roleLabel: string
): ValidationResult<void> {
  if (isDangerousUncOrDevicePath(canonicalPath)) {
    return {
      ok: false,
      error: `Refusing to execute UNC or Windows device path '${canonicalPath}' for ${roleLabel}`,
    };
  }
  const lowerExt = path.win32.extname(canonicalPath).toLowerCase();
  if (lowerExt !== ".exe") {
    return {
      ok: false,
      error: `Refusing to execute non-.exe shim or script '${canonicalPath}' for ${roleLabel} on Windows host (.bat/.cmd/.ps1 wrappers invoke cmd.exe; configure a native .exe PE binary)`,
    };
  }
  let fd: number | null = null;
  try {
    fd = fs.openSync(canonicalPath, "r");
    const header = Buffer.alloc(2);
    const bytesRead = fs.readSync(fd, header, 0, 2, 0);
    if (bytesRead < 2 || header[0] !== 0x4d || header[1] !== 0x5a) {
      return {
        ok: false,
        error: `Refusing to execute non-PE binary '${canonicalPath}' for ${roleLabel} on Windows host (missing MZ 0x4d5a header)`,
      };
    }
  } catch (err) {
    return {
      ok: false,
      error: `Cannot inspect executable header for '${canonicalPath}' (${roleLabel}): ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore close error
      }
    }
  }
  return { ok: true, value: undefined };
}

/**
 * Inspects `<repo>/.git` metadata with zero external processes before launching Git/Checkwash/Prove
 * to block symlinked `.git` / `.git/index` / `.git/config`, UNC/device `gitdir:` pointers, and
 * hostile unpacked `objects/info/alternates` or `http-alternates` entries (RT-01, RT-02).
 */
export function verifyRepositoryGitMetadataSafety(
  canonicalRepositoryRoot: string,
  platform: string = process.platform
): ValidationResult<void> {
  if (!canonicalRepositoryRoot || isDangerousUncOrDevicePath(canonicalRepositoryRoot)) {
    return {
      ok: false,
      error: `Unsafe or invalid repository root path: '${canonicalRepositoryRoot}'`,
    };
  }

  const dotGitPath = path.join(canonicalRepositoryRoot, ".git");
  let dotGitStat: fs.Stats;
  try {
    dotGitStat = fs.lstatSync(dotGitPath);
  } catch {
    // Repository may be bare, in a parent directory, or not yet initialized; let Git report cleanly.
    return { ok: true, value: undefined };
  }

  if (dotGitStat.isSymbolicLink()) {
    return {
      ok: false,
      error: `Refusing to access repository with symbolic-link '.git' entry: '${dotGitPath}'`,
    };
  }

  let resolvedGitDir: string | null = null;
  if (dotGitStat.isDirectory()) {
    resolvedGitDir = dotGitPath;
  } else if (dotGitStat.isFile()) {
    if (dotGitStat.size <= 0 || dotGitStat.size > 4096) {
      return {
        ok: false,
        error: `Invalid '.git' pointer file size (${dotGitStat.size} bytes): '${dotGitPath}'`,
      };
    }
    let rawGitFile = "";
    try {
      rawGitFile = fs.readFileSync(dotGitPath, "utf8").trim();
    } catch (err) {
      return {
        ok: false,
        error: `Cannot read '.git' pointer file '${dotGitPath}': ${String(err)}`,
      };
    }
    if (!rawGitFile.startsWith("gitdir:")) {
      return {
        ok: false,
        error: `Malformed '.git' pointer file (missing 'gitdir:' prefix): '${dotGitPath}'`,
      };
    }
    const rawPtr = rawGitFile.slice("gitdir:".length).trim();
    if (!rawPtr || isDangerousUncOrDevicePath(rawPtr)) {
      return {
        ok: false,
        error: `Refusing unsafe or UNC/device 'gitdir:' target '${rawPtr}' in '${dotGitPath}'`,
      };
    }
    const candidateGitDir = path.resolve(canonicalRepositoryRoot, rawPtr);
    if (isDangerousUncOrDevicePath(candidateGitDir)) {
      return {
        ok: false,
        error: `Refusing unsafe resolved 'gitdir:' path '${candidateGitDir}'`,
      };
    }
    let gdLstat: fs.Stats;
    try {
      gdLstat = fs.lstatSync(candidateGitDir);
    } catch (err) {
      return {
        ok: false,
        error: `Resolved 'gitdir:' target does not exist: '${candidateGitDir}' (${String(err)})`,
      };
    }
    if (gdLstat.isSymbolicLink() || !gdLstat.isDirectory()) {
      return {
        ok: false,
        error: `Refusing symlinked or non-directory 'gitdir:' target: '${candidateGitDir}'`,
      };
    }
    resolvedGitDir = candidateGitDir;
  } else {
    return {
      ok: false,
      error: `Unsupported '.git' filesystem entry type at '${dotGitPath}'`,
    };
  }

  let canonicalGitDir = resolvedGitDir;
  try {
    canonicalGitDir = fs.realpathSync.native(resolvedGitDir);
  } catch (err) {
    return {
      ok: false,
      error: `Cannot canonicalize Git directory '${resolvedGitDir}': ${String(err)}`,
    };
  }
  if (isDangerousUncOrDevicePath(canonicalGitDir)) {
    return {
      ok: false,
      error: `Refusing UNC or device Git directory '${canonicalGitDir}'`,
    };
  }

  if (dotGitStat.isFile()) {
    // A `gitdir:` pointer file can point outside the working tree (worktrees/submodules).
    // Verify target actually looks like a Git metadata dir (regular non-symlink HEAD + objects/ or commondir)
    // so an attacker cannot point `.git` at arbitrary system directories like `/etc` or `C:\Windows\System32`.
    try {
      const headStat = fs.lstatSync(path.join(canonicalGitDir, "HEAD"));
      if (headStat.isSymbolicLink() || !headStat.isFile() || headStat.size <= 0 || headStat.size > 1024) {
        return {
          ok: false,
          error: `Resolved 'gitdir:' target is missing a valid regular 'HEAD' file: '${canonicalGitDir}'`,
        };
      }
      let hasObjectsOrCommondir = false;
      try {
        const objSt = fs.lstatSync(path.join(canonicalGitDir, "objects"));
        if (!objSt.isSymbolicLink() && objSt.isDirectory()) {
          hasObjectsOrCommondir = true;
        }
      } catch {
        // check commondir next
      }
      if (!hasObjectsOrCommondir) {
        try {
          const cdSt = fs.lstatSync(path.join(canonicalGitDir, "commondir"));
          if (!cdSt.isSymbolicLink() && cdSt.isFile() && cdSt.size > 0 && cdSt.size <= 4096) {
            hasObjectsOrCommondir = true;
          }
        } catch {
          // neither exists
        }
      }
      if (!hasObjectsOrCommondir) {
        return {
          ok: false,
          error: `Resolved 'gitdir:' target is not a valid Git metadata directory: '${canonicalGitDir}'`,
        };
      }
    } catch (err) {
      return {
        ok: false,
        error: `Resolved 'gitdir:' target failed Git metadata verification: '${canonicalGitDir}' (${String(err)})`,
      };
    }
  }

  let canonicalCommonDir = canonicalGitDir;
  const commondirFile = path.join(canonicalGitDir, "commondir");
  try {
    const cdStat = fs.lstatSync(commondirFile);
    if (cdStat.isSymbolicLink()) {
      return {
        ok: false,
        error: `Refusing symlinked Git 'commondir' file: '${commondirFile}'`,
      };
    }
    if (cdStat.isFile() && cdStat.size > 0 && cdStat.size <= 4096) {
      const rawCommonRel = fs.readFileSync(commondirFile, "utf8").trim();
      if (!rawCommonRel || isDangerousUncOrDevicePath(rawCommonRel)) {
        return {
          ok: false,
          error: `Refusing unsafe Git 'commondir' target '${rawCommonRel}'`,
        };
      }
      const resolvedCommon = path.resolve(canonicalGitDir, rawCommonRel);
      const commonLstat = fs.lstatSync(resolvedCommon);
      if (commonLstat.isSymbolicLink() || !commonLstat.isDirectory()) {
        return {
          ok: false,
          error: `Refusing symlinked or non-directory Git 'commondir' target '${resolvedCommon}'`,
        };
      }
      canonicalCommonDir = fs.realpathSync.native(resolvedCommon);
      if (isDangerousUncOrDevicePath(canonicalCommonDir)) {
        return {
          ok: false,
          error: `Refusing UNC or device Git common directory '${canonicalCommonDir}'`,
        };
      }
    }
  } catch {
    // commondir is optional (present only in linked worktrees)
  }

  // Reject symlinked index or config files inside gitDir / commonDir
  const sensitiveGitFiles = [
    path.join(canonicalGitDir, "index"),
    path.join(canonicalGitDir, "config"),
    path.join(canonicalCommonDir, "config"),
    path.join(canonicalGitDir, "HEAD"),
  ];
  for (const fPath of sensitiveGitFiles) {
    try {
      const st = fs.lstatSync(fPath);
      if (st.isSymbolicLink()) {
        return {
          ok: false,
          error: `Refusing repository with symbolic-link Git metadata file: '${fPath}'`,
        };
      }
    } catch {
      // Optional file may not exist yet (e.g., unborn index)
    }
  }

  // Validate objects/info/alternates and reject http-alternates across gitDir and commonDir
  const objectDirsToCheck = Array.from(
    new Set([path.join(canonicalGitDir, "objects"), path.join(canonicalCommonDir, "objects")])
  );
  for (const objDir of objectDirsToCheck) {
    try {
      const objStat = fs.lstatSync(objDir);
      if (objStat.isSymbolicLink()) {
        return {
          ok: false,
          error: `Refusing repository with symbolic-link Git objects directory: '${objDir}'`,
        };
      }
    } catch {
      continue;
    }

    const httpAltPath = path.join(objDir, "info", "http-alternates");
    try {
      const httpAltStat = fs.lstatSync(httpAltPath);
      if (httpAltStat.isSymbolicLink() || httpAltStat.size > 0) {
        return {
          ok: false,
          error: `Refusing repository with 'objects/info/http-alternates': '${httpAltPath}'`,
        };
      }
    } catch {
      // Not present
    }

    const altPath = path.join(objDir, "info", "alternates");
    let altStat: fs.Stats | null = null;
    try {
      altStat = fs.lstatSync(altPath);
    } catch {
      altStat = null;
    }
    if (!altStat) {
      continue;
    }
    if (altStat.isSymbolicLink() || !altStat.isFile() || altStat.size > 65_536) {
      return {
        ok: false,
        error: `Refusing symlinked or oversized Git 'objects/info/alternates': '${altPath}'`,
      };
    }
    let altContent = "";
    try {
      altContent = fs.readFileSync(altPath, "utf8");
    } catch (err) {
      return {
        ok: false,
        error: `Cannot read Git 'objects/info/alternates' ('${altPath}'): ${String(err)}`,
      };
    }
    for (const rawLine of altContent.split(/\r?\n/)) {
      const trimmedLine = rawLine.trim();
      if (!trimmedLine || trimmedLine.startsWith("#")) {
        continue;
      }
      if (isDangerousUncOrDevicePath(trimmedLine) || /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmedLine)) {
        return {
          ok: false,
          error: `Refusing unsafe UNC/device/URL entry '${trimmedLine}' in Git 'objects/info/alternates'`,
        };
      }
      const resolvedAlt = path.resolve(objDir, trimmedLine);
      if (isDangerousUncOrDevicePath(resolvedAlt)) {
        return {
          ok: false,
          error: `Refusing unsafe resolved Git alternate object directory '${resolvedAlt}'`,
        };
      }
      let altTargetLstat: fs.Stats;
      try {
        altTargetLstat = fs.lstatSync(resolvedAlt);
      } catch {
        return {
          ok: false,
          error: `Git 'objects/info/alternates' target does not exist: '${resolvedAlt}'`,
        };
      }
      if (altTargetLstat.isSymbolicLink() || !altTargetLstat.isDirectory()) {
        return {
          ok: false,
          error: `Refusing symlinked or non-directory Git alternate object store '${resolvedAlt}'`,
        };
      }
      // Relative alternates in unpacked archives must stay within canonicalRepositoryRoot or canonicalCommonDir
      if (!path.isAbsolute(trimmedLine)) {
        const canonAlt = fs.realpathSync.native(resolvedAlt);
        if (
          !isPathInsideOrEqualPlatform(canonAlt, canonicalRepositoryRoot, platform) &&
          !isPathInsideOrEqualPlatform(canonAlt, canonicalCommonDir, platform)
        ) {
          return {
            ok: false,
            error: `Refusing relative Git 'objects/info/alternates' entry '${trimmedLine}' escaping repository root ('${canonAlt}')`,
          };
        }
      }
    }
  }

  return { ok: true, value: undefined };
}

function isExecutableModeOnPlatform(stat: fs.Stats, platform: string): boolean {
  if (platform === "win32") {
    return true;
  }
  return (stat.mode & 0o111) !== 0;
}

/**
 * Resolves a default executable (e.g., `python.exe`/`python3`, `git.exe`/`git`) from `PATH` ONLY when
 * the user has not configured an explicit machine-scoped path.
 *
 * Security invariants (Rev 3 §7.1, §7.2, B04):
 * - Rejects executable names containing path separators.
 * - Inspects only fully-qualified absolute directory entries in `PATH` (never `.`, empty, or relative entries).
 * - Skips any directory or resolved symlink target inside or equal to `repositoryRootPath` (both raw and canonical).
 * - Skips 0-byte files and non-executable files on POSIX.
 */
export function resolveTrustedExecutableFromPath(params: {
  executableName?: string;
  executableNames?: readonly string[];
  repositoryRootPath: string;
  pathEnv?: string;
  platform?: string;
}): ValidationResult<string> {
  const targetPlatform = params.platform ?? process.platform;
  const isWin = targetPlatform === "win32";
  const rawNames =
    params.executableNames && params.executableNames.length > 0
      ? [...params.executableNames]
      : params.executableName !== undefined
        ? [params.executableName]
        : [];

  if (rawNames.length === 0) {
    return { ok: false, error: "No executable name specified for PATH lookup" };
  }

  const cleanNames: string[] = [];
  for (const n of rawNames) {
    const trimmedName = n.trim();
    if (
      trimmedName.length === 0 ||
      trimmedName.includes("\\") ||
      trimmedName.includes("/") ||
      trimmedName.includes(":")
    ) {
      return { ok: false, error: `Invalid executable name for PATH lookup: '${n}'` };
    }
    cleanNames.push(trimmedName);
  }

  const pathMod = isWin ? path.win32 : path.posix;
  const rawRepoRoot =
    typeof params.repositoryRootPath === "string" && params.repositoryRootPath.trim().length > 0
      ? pathMod.resolve(params.repositoryRootPath.trim())
      : null;
  let canonicalRepoRoot: string | null = null;
  if (rawRepoRoot) {
    const canonRes = resolveCanonicalPath(rawRepoRoot);
    if (canonRes.ok) {
      canonicalRepoRoot = canonRes.value;
    }
  }

  const isInsideTargetRepo = (candidatePath: string): boolean => {
    if (rawRepoRoot && isPathInsideOrEqualPlatform(candidatePath, rawRepoRoot, targetPlatform)) {
      return true;
    }
    if (
      canonicalRepoRoot &&
      isPathInsideOrEqualPlatform(candidatePath, canonicalRepoRoot, targetPlatform)
    ) {
      return true;
    }
    return false;
  };

  const rawPath = params.pathEnv ?? process.env.PATH ?? process.env.Path ?? "";
  const entries = rawPath.split(isWin ? ";" : ":");

  for (const exeName of cleanNames) {
    for (const rawEntry of entries) {
      const cleanedEntry = rawEntry.trim().replace(/^"+|"+$/g, "").trim();
      if (!cleanedEntry || !isFullyQualifiedPlatformPath(cleanedEntry, targetPlatform)) {
        continue;
      }
      if (!isWin && isWslWindowsMountPath(cleanedEntry)) {
        continue;
      }
      if (isInsideTargetRepo(cleanedEntry)) {
        continue;
      }

      const candidatePath = pathMod.join(cleanedEntry, exeName);
      if (isInsideTargetRepo(candidatePath)) {
        continue;
      }

      try {
        const stat = fs.statSync(candidatePath);
        if (
          !stat.isFile() ||
          stat.size <= 0 ||
          !isExecutableModeOnPlatform(stat, targetPlatform)
        ) {
          continue;
        }
        const realCandidate = fs.realpathSync.native(candidatePath);
        const realStat = fs.statSync(realCandidate);
        if (
          !realStat.isFile() ||
          realStat.size <= 0 ||
          !isExecutableModeOnPlatform(realStat, targetPlatform)
        ) {
          continue;
        }
        if (!isWin && !verifyLinuxNativeExecutableIdentity(realCandidate, exeName).ok) {
          continue;
        }
        if (isWin && !verifyWindowsNativeExecutableIdentity(realCandidate, exeName).ok) {
          continue;
        }
        const realDir = pathMod.dirname(realCandidate);
        if (isInsideTargetRepo(realCandidate) || isInsideTargetRepo(realDir)) {
          continue;
        }
        return { ok: true, value: realCandidate };
      } catch {
        continue;
      }
    }
  }

  return {
    ok: false,
    error: `Could not locate a trusted '${cleanNames.join("' or '")}' in system PATH outside target repository`,
  };
}

export function verifyBundledArtifacts(
  extensionRootPath: string,
  targetPlatform: string = process.platform
): ValidationResult<{
  manifest: BundledManifest;
  pyzPath: string;
  pyzSha256: string;
  brokerPath: string;
  brokerSha256: string;
}> {
  const manifestPath = path.join(extensionRootPath, "bundled", "manifest.json");
  let manifest: BundledManifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8")) as BundledManifest;
  } catch (err) {
    return {
      ok: false,
      error: `Cannot read bundled/manifest.json: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (
    !manifest ||
    !manifest.checkwash ||
    manifest.checkwash.version !== EXPECTED_CHECKWASH_VERSION ||
    manifest.checkwash.bytes !== EXPECTED_CHECKWASH_BYTES ||
    manifest.checkwash.sha256.toLowerCase() !== EXPECTED_CHECKWASH_SHA256
  ) {
    return {
      ok: false,
      error: `bundled/manifest.json checkwash entry does not match pinned v${EXPECTED_CHECKWASH_VERSION} contract`,
    };
  }

  const pyzPath = path.join(extensionRootPath, manifest.checkwash.relativePath);
  const pyzCheck = computeFileSha256AndSize(pyzPath);
  if (!pyzCheck.ok) {
    return { ok: false, error: `Bundled checkwash.pyz missing: ${pyzCheck.error}` };
  }
  if (
    pyzCheck.value.bytes !== EXPECTED_CHECKWASH_BYTES ||
    pyzCheck.value.sha256 !== EXPECTED_CHECKWASH_SHA256
  ) {
    return {
      ok: false,
      error: `Bundled checkwash.pyz integrity check failed: got ${pyzCheck.value.bytes} bytes (sha256=${pyzCheck.value.sha256}), expected ${EXPECTED_CHECKWASH_BYTES} bytes (sha256=${EXPECTED_CHECKWASH_SHA256})`,
    };
  }

  let brokerManifestEntry: BrokerArtifactEntry | undefined;
  let brokerLabel = "broker";
  if (targetPlatform === "win32") {
    brokerManifestEntry = manifest.windowsBroker;
    brokerLabel = "checkwash-broker.exe";
  } else if (targetPlatform === "linux") {
    brokerManifestEntry = manifest.linuxBroker;
    brokerLabel = "checkwash-broker-linux-x64";
  } else {
    return {
      ok: false,
      error: `Unsupported platform '${targetPlatform}' for bundled broker verification`,
    };
  }

  if (!brokerManifestEntry || brokerManifestEntry.protocol !== "CWBROKER1") {
    return {
      ok: false,
      error: `bundled/manifest.json broker entry for '${targetPlatform}' is missing or invalid`,
    };
  }

  const brokerPath = path.join(extensionRootPath, brokerManifestEntry.relativePath);
  const brokerCheck = computeFileSha256AndSize(brokerPath);
  if (!brokerCheck.ok) {
    return { ok: false, error: `Bundled ${brokerLabel} missing: ${brokerCheck.error}` };
  }
  if (
    brokerCheck.value.bytes !== brokerManifestEntry.bytes ||
    brokerCheck.value.sha256 !== brokerManifestEntry.sha256.toLowerCase()
  ) {
    return {
      ok: false,
      error: `Bundled ${brokerLabel} integrity check failed: got ${brokerCheck.value.bytes} bytes (sha256=${brokerCheck.value.sha256}), expected ${brokerManifestEntry.bytes} bytes (sha256=${brokerManifestEntry.sha256})`,
    };
  }

  if (targetPlatform === "linux") {
    try {
      const st = fs.statSync(brokerPath);
      if ((st.mode & 0o111) === 0) {
        return {
          ok: false,
          error: `Bundled ${brokerLabel} does not have executable permission (+x): ${brokerPath}`,
        };
      }
      fs.accessSync(brokerPath, fs.constants.X_OK);
    } catch (err) {
      return {
        ok: false,
        error: `Bundled ${brokerLabel} is not executable: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  return {
    ok: true,
    value: {
      manifest,
      pyzPath,
      pyzSha256: pyzCheck.value.sha256,
      brokerPath,
      brokerSha256: brokerCheck.value.sha256,
    },
  };
}

/**
 * Creates a fresh, per-invocation isolated directory in os.tmpdir() without
 * deleting or disturbing any other in-progress run's temporary directory (§7.2, Issue #4).
 */
export function createIsolatedRunDirectory(prefix: string = "checkwash-lens-run-"): string {
  const baseTmp = os.tmpdir();
  fs.mkdirSync(baseTmp, { recursive: true });
  const created = fs.mkdtempSync(path.join(baseTmp, prefix));
  return fs.realpathSync.native(created);
}

const fallbackPosixControlledCwdsByKey = new Map<string, string>();

function isValidOwnedPosixCwd(dirPath: string, uid: number): boolean {
  try {
    const st = fs.lstatSync(dirPath);
    return !st.isSymbolicLink() && st.isDirectory() && st.uid === uid && (st.mode & 0o077) === 0;
  } catch {
    return false;
  }
}

/**
 * Ensures the stable controlled empty working directory exists outside the target repository.
 * On POSIX, scopes by UID, enforces 0700 permissions + non-symlink ownership verification,
 * and falls back to an unguessable 0700 mkdtemp directory if the predictable name was squatted
 * by another local user (RT-03). NEVER deletes existing subdirectories or other runs' temporary data.
 */
export function ensureControlledEmptyDirectory(subName: string = "checkwash-lens-cwd"): string {
  const baseTmp = os.tmpdir();
  fs.mkdirSync(baseTmp, { recursive: true });

  if (typeof process.geteuid === "function") {
    const uid = process.geteuid();
    const scopedName = `${subName}-${uid}`;
    const candidateDir = path.join(baseTmp, scopedName);
    try {
      fs.mkdirSync(candidateDir, { recursive: true, mode: 0o700 });
      const st = fs.lstatSync(candidateDir);
      if (!st.isSymbolicLink() && st.isDirectory() && st.uid === uid) {
        if ((st.mode & 0o077) !== 0) {
          fs.chmodSync(candidateDir, 0o700);
        }
        if (isValidOwnedPosixCwd(candidateDir, uid)) {
          return fs.realpathSync.native(candidateDir);
        }
      }
    } catch {
      // Squatted or inaccessible predictable directory; pivot to unguessable 0700 directory below
    }

    const existingFallback = fallbackPosixControlledCwdsByKey.get(scopedName);
    if (existingFallback && isValidOwnedPosixCwd(existingFallback, uid)) {
      return fs.realpathSync.native(existingFallback);
    }

    const freshFallback = fs.mkdtempSync(path.join(baseTmp, `${scopedName}-`));
    fs.chmodSync(freshFallback, 0o700);
    if (!isValidOwnedPosixCwd(freshFallback, uid)) {
      throw new Error(`Failed to establish 0700 UID-owned working directory at '${freshFallback}'`);
    }
    const canonFallback = fs.realpathSync.native(freshFallback);
    fallbackPosixControlledCwdsByKey.set(scopedName, canonFallback);
    return canonFallback;
  }

  const dir = path.join(baseTmp, subName);
  fs.mkdirSync(dir, { recursive: true });
  const lstat = fs.lstatSync(dir);
  if (lstat.isSymbolicLink() || !lstat.isDirectory()) {
    const freshWinFallback = fs.mkdtempSync(path.join(baseTmp, `${subName}-`));
    return fs.realpathSync.native(freshWinFallback);
  }
  return fs.realpathSync.native(dir);
}

/**
 * Removes an isolated run directory ONLY when owned by the completed invocation
 * and after broker process tree termination has been confirmed.
 */
export function cleanupIsolatedRunDirectory(dirPath: string, cleanupConfirmed: boolean): void {
  if (!cleanupConfirmed || !dirPath) {
    return;
  }
  try {
    fs.rmSync(dirPath, { recursive: true, force: true });
  } catch {
    // Best-effort removal after confirmed process tree exit
  }
}

/**
 * Constructs a clean environment dictionary for static Python / Git / Checkwash execution.
 * Strips all inherited PYTHONPATH, PYTHON*, GIT_* variables, and restricts PATH strictly
 * to the canonical trusted Git directory + minimal OS system directory (§7.2, B03, B04).
 */
export function buildSanitizedStaticEnv(params: {
  canonicalGitDir: string;
  controlledEmptyCwd: string;
  isolatedTempDir?: string;
  inheritedEnv?: NodeJS.ProcessEnv;
  platform?: string;
}): Record<string, string> {
  const targetPlatform = params.platform ?? process.platform;
  const tempTarget = params.isolatedTempDir ?? params.controlledEmptyCwd;

  if (targetPlatform === "linux") {
    const rawDirs = [params.canonicalGitDir, "/usr/bin", "/bin"];
    const seen = new Set<string>();
    const orderedDirs: string[] = [];
    for (const d of rawDirs) {
      const cleaned = d.trim();
      if (!cleaned) continue;
      const norm = path.posix.normalize(cleaned);
      if (!seen.has(norm)) {
        seen.add(norm);
        orderedDirs.push(cleaned);
      }
    }
    return {
      PATH: orderedDirs.join(":"),
      TMPDIR: tempTarget,
      TEMP: tempTarget,
      TMP: tempTarget,
      HOME: tempTarget,
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      PYTHONUTF8: "1",
      PYTHONIOENCODING: "utf-8",
      PYTHONDONTWRITEBYTECODE: "1",
      PYTHONNOUSERSITE: "1",
      GIT_TERMINAL_PROMPT: "0",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_COUNT: "5",
      GIT_CONFIG_KEY_0: "core.fsmonitor",
      GIT_CONFIG_VALUE_0: "false",
      GIT_CONFIG_KEY_1: "core.hooksPath",
      GIT_CONFIG_VALUE_1: params.controlledEmptyCwd,
      GIT_CONFIG_KEY_2: "core.pager",
      GIT_CONFIG_VALUE_2: "cat",
      GIT_CONFIG_KEY_3: "protocol.allow",
      GIT_CONFIG_VALUE_3: "never",
      GIT_CONFIG_KEY_4: "core.sshCommand",
      GIT_CONFIG_VALUE_4: "false",
    };
  }

  const sysRoot = params.inheritedEnv?.SystemRoot || process.env.SystemRoot || "C:\\Windows";
  const system32 = path.win32.join(sysRoot, "System32");
  const comspec = path.win32.join(system32, "cmd.exe");

  // PATH contains ONLY the canonical directory of the trusted git executable and System32.
  const restrictedPath = `${params.canonicalGitDir};${system32}`;

  return {
    SystemRoot: sysRoot,
    WINDIR: sysRoot,
    COMSPEC: comspec,
    PATHEXT: ".COM;.EXE;.BAT;.CMD",
    PATH: restrictedPath,
    TEMP: tempTarget,
    TMP: tempTarget,
    HOME: tempTarget,
    USERPROFILE: tempTarget,
    PYTHONUTF8: "1",
    PYTHONIOENCODING: "utf-8",
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONNOUSERSITE: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "NUL",
    GIT_CONFIG_COUNT: "5",
    GIT_CONFIG_KEY_0: "core.fsmonitor",
    GIT_CONFIG_VALUE_0: "false",
    GIT_CONFIG_KEY_1: "core.hooksPath",
    GIT_CONFIG_VALUE_1: params.controlledEmptyCwd,
    GIT_CONFIG_KEY_2: "core.pager",
    GIT_CONFIG_VALUE_2: "cat",
    GIT_CONFIG_KEY_3: "protocol.allow",
    GIT_CONFIG_VALUE_3: "never",
    GIT_CONFIG_KEY_4: "core.sshCommand",
    GIT_CONFIG_VALUE_4: "false",
    NoDefaultCurrentDirectoryInExePath: "1",
  };
}

function verifyBareGitResolutionPosix(params: {
  callingExecutablePath?: string;
  canonicalGitPath: string;
  controlledEmptyCwd: string;
  sanitizedStaticEnv: Record<string, string>;
}): ValidationResult<string> {
  const { canonicalGitPath, controlledEmptyCwd, sanitizedStaticEnv } = params;

  // 1. Ensure controlledEmptyCwd contains NO 'git' entry
  const cwdGit = path.posix.join(controlledEmptyCwd, "git");
  try {
    const lst = fs.lstatSync(cwdGit);
    if (!lst.isDirectory()) {
      return {
        ok: false,
        error: `Trusted Git identity check failed: controlled working directory '${controlledEmptyCwd}' contains shadowing file '${cwdGit}'`,
      };
    }
  } catch {
    // Does not exist — expected
  }

  // 1b. Ensure calling executable's directory (e.g. Python venv bin/ or Prove directory,
  //     which Python virtualenvs/entrypoints may prepend to PATH) does not contain a
  //     competing 'git' entry whose canonical target differs from canonicalGitPath.
  if (params.callingExecutablePath && params.callingExecutablePath.trim().length > 0) {
    const callerDir = path.posix.dirname(params.callingExecutablePath);
    const colocatedGit = path.posix.join(callerDir, "git");
    let colocatedLstat: fs.Stats | null = null;
    try {
      colocatedLstat = fs.lstatSync(colocatedGit);
    } catch {
      colocatedLstat = null;
    }
    if (colocatedLstat && !colocatedLstat.isDirectory()) {
      const colocatedCanonRes = resolveCanonicalPath(colocatedGit);
      if (
        !colocatedCanonRes.ok ||
        path.posix.basename(canonicalGitPath) !== "git" ||
        colocatedCanonRes.value !== canonicalGitPath
      ) {
        const resolvedLabel = colocatedCanonRes.ok ? colocatedCanonRes.value : colocatedGit;
        return {
          ok: false,
          error: `Trusted Git identity mismatch: colocated 'git' in runtime directory '${callerDir}' resolves to '${resolvedLabel}', which does not match verified Git executable '${canonicalGitPath}'`,
        };
      }
    }
  }

  // 2. Verify PATH is explicitly defined and contains no empty or relative entries
  //    (in POSIX execvp, an empty PATH segment "" or "." resolves against cwd!).
  const rawPath = sanitizedStaticEnv.PATH;
  if (typeof rawPath !== "string" || rawPath.length === 0) {
    return {
      ok: false,
      error: "Trusted Git identity check failed: sanitized environment PATH is empty on POSIX",
    };
  }

  const segments = rawPath.split(":");
  let firstExecvpMatch: string | null = null;

  for (const rawSeg of segments) {
    const seg = rawSeg.trim().replace(/^"+|"+$/g, "").trim();
    if (seg.length === 0 || seg === "." || !seg.startsWith("/")) {
      return {
        ok: false,
        error: `Trusted Git identity check failed: sanitized PATH contains unsafe empty or relative segment '${rawSeg}'`,
      };
    }

    const candidate = path.posix.join(seg, "git");
    let lstat: fs.Stats | null = null;
    try {
      lstat = fs.lstatSync(candidate);
    } catch {
      lstat = null;
    }
    if (!lstat) {
      continue;
    }

    let targetStat: fs.Stats;
    try {
      targetStat = fs.statSync(candidate);
    } catch {
      return {
        ok: false,
        error: `Trusted Git identity check failed: broken symlink '${candidate}' encountered in PATH ahead of verified Git '${canonicalGitPath}'`,
      };
    }

    if (targetStat.isDirectory()) {
      continue;
    }

    if (!targetStat.isFile() || targetStat.size <= 0 || (targetStat.mode & 0o111) === 0) {
      return {
        ok: false,
        error: `Trusted Git identity check failed: non-executable or invalid 'git' entry '${candidate}' encountered in PATH ahead of verified Git '${canonicalGitPath}'`,
      };
    }

    firstExecvpMatch = candidate;
    break;
  }

  if (firstExecvpMatch === null) {
    return {
      ok: false,
      error: `Trusted Git configuration rejected: bare 'git' cannot be resolved in POSIX PATH under sanitized environment (configured Git is '${canonicalGitPath}')`,
    };
  }

  const resolvedBareCanonRes = resolveCanonicalPath(firstExecvpMatch);
  if (!resolvedBareCanonRes.ok) {
    return {
      ok: false,
      error: `Trusted Git identity check failed: cannot canonicalize resolved bare 'git' '${firstExecvpMatch}': ${resolvedBareCanonRes.error}`,
    };
  }

  const resolvedBareGitCanon = resolvedBareCanonRes.value;
  if (
    path.posix.basename(canonicalGitPath) !== "git" ||
    resolvedBareGitCanon !== canonicalGitPath
  ) {
    return {
      ok: false,
      error: `Trusted Git identity mismatch: bare 'git' resolves to '${resolvedBareGitCanon}', which does not match verified Git executable '${canonicalGitPath}'`,
    };
  }

  return { ok: true, value: resolvedBareGitCanon };
}

/**
 * Verifies that when bundled Checkwash (running inside `canonicalPythonPath` with
 * `cwd = controlledEmptyCwd` and `env = sanitizedStaticEnv`) invokes bare `"git"`,
 * the OS resolves `"git"` to the EXACT same canonical executable file as `canonicalGitPath`.
 */
export function verifyBareGitResolutionForStaticEnv(params: {
  canonicalPythonPath: string;
  canonicalGitPath: string;
  controlledEmptyCwd: string;
  sanitizedStaticEnv: Record<string, string>;
  platform?: string;
}): ValidationResult<string> {
  const targetPlatform = params.platform ?? process.platform;
  if (targetPlatform === "linux") {
    return verifyBareGitResolutionPosix({
      callingExecutablePath: params.canonicalPythonPath,
      canonicalGitPath: params.canonicalGitPath,
      controlledEmptyCwd: params.controlledEmptyCwd,
      sanitizedStaticEnv: params.sanitizedStaticEnv,
    });
  }

  const { canonicalPythonPath, canonicalGitPath, controlledEmptyCwd, sanitizedStaticEnv } = params;

  const rawPathext = sanitizedStaticEnv.PATHEXT || ".COM;.EXE;.BAT;.CMD";
  const pathextList = rawPathext
    .split(";")
    .map((ext) => ext.trim())
    .filter((ext) => ext.startsWith(".") && ext.length > 1)
    .map((ext) => ext.toLowerCase());
  if (!pathextList.includes(".exe")) {
    pathextList.push(".exe");
  }

  // 1. Ensure controlledEmptyCwd contains NO git.<ext> entry
  for (const ext of pathextList) {
    const cwdCandidate = path.win32.join(controlledEmptyCwd, `git${ext}`);
    try {
      if (fs.existsSync(cwdCandidate) && !fs.statSync(cwdCandidate).isDirectory()) {
        return {
          ok: false,
          error: `Trusted Git identity check failed: controlled working directory '${controlledEmptyCwd}' contains shadowing file '${cwdCandidate}'`,
        };
      }
    } catch {
      // ignore stat race on non-existent entry
    }
  }

  // 2. Construct exact Windows CreateProcessW(NULL, "git ...") search sequence inside canonicalPythonPath
  const searchDirs: string[] = [];
  const pushDirIfValid = (dir: string | undefined) => {
    if (!dir) return;
    const cleaned = dir.trim().replace(/^"+|"+$/g, "").trim();
    if (cleaned.length > 0) {
      searchDirs.push(cleaned);
    }
  };

  pushDirIfValid(path.win32.dirname(canonicalPythonPath));

  if (sanitizedStaticEnv.NoDefaultCurrentDirectoryInExePath === undefined) {
    pushDirIfValid(controlledEmptyCwd);
  }

  const osSysRoot = process.env.SystemRoot || "C:\\Windows";
  const envSysRoot = sanitizedStaticEnv.SystemRoot || osSysRoot;

  pushDirIfValid(path.win32.join(osSysRoot, "System32"));
  pushDirIfValid(path.win32.join(osSysRoot, "System"));
  pushDirIfValid(osSysRoot);

  if (path.win32.resolve(envSysRoot).toLowerCase() !== path.win32.resolve(osSysRoot).toLowerCase()) {
    pushDirIfValid(path.win32.join(envSysRoot, "System32"));
    pushDirIfValid(path.win32.join(envSysRoot, "System"));
    pushDirIfValid(envSysRoot);
  }

  const rawPath = sanitizedStaticEnv.PATH ?? sanitizedStaticEnv.Path ?? "";
  for (const entry of rawPath.split(";")) {
    pushDirIfValid(entry);
  }

  let firstCreateProcessMatch: string | null = null;

  for (const dir of searchDirs) {
    for (const ext of pathextList) {
      if (ext === ".exe") {
        const exeCandidate = path.win32.join(dir, "git.exe");
        try {
          if (fs.existsSync(exeCandidate) && !fs.statSync(exeCandidate).isDirectory()) {
            firstCreateProcessMatch = exeCandidate;
            break;
          }
        } catch {
          // continue
        }
      } else {
        const otherCandidate = path.win32.join(dir, `git${ext}`);
        try {
          if (fs.existsSync(otherCandidate) && !fs.statSync(otherCandidate).isDirectory()) {
            if (firstCreateProcessMatch === null) {
              return {
                ok: false,
                error: `Trusted Git identity check failed: bare 'git' encounters ambiguous '${otherCandidate}' ahead of verified Git '${canonicalGitPath}'`,
              };
            }
          }
        } catch {
          // continue
        }
      }
    }
    if (firstCreateProcessMatch !== null) {
      break;
    }
  }

  if (firstCreateProcessMatch === null) {
    return {
      ok: false,
      error: `Trusted Git configuration rejected: bare 'git' cannot be resolved in the Windows search order under sanitized environment (configured Git is '${canonicalGitPath}')`,
    };
  }

  let matchStat: fs.Stats;
  try {
    matchStat = fs.statSync(firstCreateProcessMatch);
  } catch (err) {
    return {
      ok: false,
      error: `Trusted Git identity check failed: cannot stat resolved bare 'git' target '${firstCreateProcessMatch}': ${String(err)}`,
    };
  }
  if (!matchStat.isFile() || matchStat.size <= 0) {
    return {
      ok: false,
      error: `Trusted Git identity check failed: bare 'git' resolved to invalid or 0-byte file '${firstCreateProcessMatch}'`,
    };
  }

  const resolvedBareCanonRes = resolveCanonicalPath(firstCreateProcessMatch);
  if (!resolvedBareCanonRes.ok) {
    return {
      ok: false,
      error: `Trusted Git identity check failed: cannot canonicalize resolved bare 'git' '${firstCreateProcessMatch}': ${resolvedBareCanonRes.error}`,
    };
  }

  const resolvedBareGitCanon = resolvedBareCanonRes.value;

  if (
    path.win32.basename(canonicalGitPath).toLowerCase() !== "git.exe" ||
    resolvedBareGitCanon.toLowerCase() !== canonicalGitPath.toLowerCase()
  ) {
    return {
      ok: false,
      error: `Trusted Git identity mismatch: bare 'git' resolves to '${resolvedBareGitCanon}', which does not match verified Git executable '${canonicalGitPath}'`,
    };
  }

  return { ok: true, value: resolvedBareGitCanon };
}

/**
 * Builds the sanitized environment for `checkwash-prove` execution while keeping
 * `canonicalGitDir` at the front of `PATH` ahead of `proveDir`, `hostPyDir`, and `testPyDir`,
 * deduplicating entries case-insensitively on Windows and case-sensitively on Linux.
 */
export function buildSanitizedProveEnv(params: {
  baseStaticEnv: Readonly<Record<string, string>>;
  canonicalGitDir: string;
  proveExecutable: string;
  hostPythonExecutable: string;
  testPythonExecutable?: string;
  platform?: string;
}): Record<string, string> {
  const {
    baseStaticEnv,
    canonicalGitDir,
    proveExecutable,
    hostPythonExecutable,
    testPythonExecutable,
  } = params;
  const targetPlatform = params.platform ?? process.platform;
  const isWin = targetPlatform === "win32";
  const pathMod = isWin ? path.win32 : path.posix;
  const sep = isWin ? ";" : ":";

  const candidateDirs = [
    canonicalGitDir,
    pathMod.dirname(proveExecutable),
    pathMod.dirname(hostPythonExecutable),
    testPythonExecutable ? pathMod.dirname(testPythonExecutable) : "",
    ...(baseStaticEnv.PATH ?? baseStaticEnv.Path ?? "").split(sep),
  ];

  const seen = new Set<string>();
  const orderedDirs: string[] = [];
  for (const rawDir of candidateDirs) {
    const cleaned = rawDir.trim().replace(/^"+|"+$/g, "").trim();
    if (!cleaned) continue;
    const key = isWin ? pathMod.normalize(cleaned).toLowerCase() : pathMod.normalize(cleaned);
    if (!seen.has(key)) {
      seen.add(key);
      orderedDirs.push(cleaned);
    }
  }

  const nextEnv: Record<string, string> = { ...baseStaticEnv };
  delete nextEnv.Path;
  nextEnv.PATH = orderedDirs.join(sep);
  return nextEnv;
}

/**
 * Verifies bare `"git"` resolution across the exact final `cwd`, `env`, and all executables
 * in the launch chain, ensuring neither `PATH` overrides nor Windows `CreateProcessW`
 * loading-executable directory precedence can divert internal bare `"git"` invocations away
 * from `canonicalGitPath`.
 */
export function verifyBareGitResolutionForProcessLaunch(params: {
  callingExecutables: readonly string[];
  canonicalGitPath: string;
  cwd: string;
  env: Record<string, string>;
  platform?: string;
}): ValidationResult<string> {
  const { callingExecutables, canonicalGitPath, cwd, env } = params;
  const targetPlatform = params.platform ?? process.platform;
  const isWin = targetPlatform === "win32";
  const pathMod = isWin ? path.win32 : path.posix;

  if (callingExecutables.length === 0) {
    return {
      ok: false,
      error: "Trusted Git identity check failed: no calling executable specified for process launch",
    };
  }

  let resolvedCanon = canonicalGitPath;
  const checkedDirs = new Set<string>();
  for (const callerExe of callingExecutables) {
    if (!callerExe || callerExe.trim().length === 0) continue;
    const rawDir = pathMod.normalize(pathMod.dirname(callerExe));
    const dirKey = isWin ? rawDir.toLowerCase() : rawDir;
    if (checkedDirs.has(dirKey)) continue;
    checkedDirs.add(dirKey);

    const res = verifyBareGitResolutionForStaticEnv({
      canonicalPythonPath: callerExe,
      canonicalGitPath,
      controlledEmptyCwd: cwd,
      sanitizedStaticEnv: env,
      platform: targetPlatform,
    });
    if (!res.ok) {
      return res;
    }
    resolvedCanon = res.value;
  }

  return { ok: true, value: resolvedCanon };
}

/**
 * Unified admission gate before ANY external process is launched (Rev 3 §7.1, §7.2).
 */
export function verifyLaunchAdmission(
  desc: HostEnvironmentDescriptor
): ValidationResult<VerifiedAdmissionContext> {
  // 1. Workspace Trust Gate (B01)
  if (!desc.isWorkspaceTrusted) {
    return {
      ok: false,
      error: "Restricted Mode: external process execution is disabled in untrusted workspaces",
    };
  }

  // 2 & 3. OS, Architecture, and Physical/Supported Remote Workspace Gate (B02, v0.4.0)
  const hostEnvCheck = verifyWorkspaceHostEnvironment(desc);
  if (!hostEnvCheck.ok) {
    return hostEnvCheck;
  }

  // 4. Canonical Extension & Repository Root
  const extRootRes = resolveCanonicalPath(desc.extensionRootPath);
  if (!extRootRes.ok) {
    return { ok: false, error: `Invalid extension root: ${extRootRes.error}` };
  }
  const repoRootRes = resolveCanonicalPath(desc.repositoryRootPath);
  if (!repoRootRes.ok) {
    return { ok: false, error: `Invalid repository root: ${repoRootRes.error}` };
  }
  const canonicalExtensionRoot = extRootRes.value;
  const canonicalRepositoryRoot = repoRootRes.value;

  try {
    if (!fs.statSync(canonicalRepositoryRoot).isDirectory()) {
      return { ok: false, error: `Repository root is not a directory: ${canonicalRepositoryRoot}` };
    }
  } catch (err) {
    return { ok: false, error: `Cannot stat repository root: ${String(err)}` };
  }

  const repoGitMetaCheck = verifyRepositoryGitMetadataSafety(
    canonicalRepositoryRoot,
    desc.platform
  );
  if (!repoGitMetaCheck.ok) {
    return repoGitMetaCheck;
  }

  // 5. Verify Bundled Artifacts (checkwash.pyz & platform-native CWBROKER1 broker) (B09, B10)
  const bundledRes = verifyBundledArtifacts(canonicalExtensionRoot, desc.platform);
  if (!bundledRes.ok) {
    return bundledRes;
  }

  // 6. Verify Trusted Python Executable Path (§7.2, B04, RT-04)
  const pyRes = resolveCanonicalPath(desc.configuredPythonPath);
  if (!pyRes.ok) {
    return { ok: false, error: `Trusted Python path invalid: ${pyRes.error}` };
  }
  const canonicalPythonPath = pyRes.value;
  try {
    const pyStat = fs.statSync(canonicalPythonPath);
    if (!pyStat.isFile()) {
      return { ok: false, error: `Trusted Python path must be a file, not a directory: ${canonicalPythonPath}` };
    }
    if (!isExecutableModeOnPlatform(pyStat, desc.platform)) {
      return { ok: false, error: `Trusted Python file is not executable: ${canonicalPythonPath}` };
    }
  } catch {
    return { ok: false, error: `Trusted Python executable not found: ${canonicalPythonPath}` };
  }
  if (isPathInsideOrEqualPlatform(canonicalPythonPath, canonicalRepositoryRoot, desc.platform)) {
    return {
      ok: false,
      error: `Refusing to use Python interpreter inside target repository ('${canonicalPythonPath}' is inside '${canonicalRepositoryRoot}')`,
    };
  }
  if (desc.platform === "linux") {
    const pyNativeCheck = verifyLinuxNativeExecutableIdentity(
      canonicalPythonPath,
      "trusted Python interpreter"
    );
    if (!pyNativeCheck.ok) {
      return pyNativeCheck;
    }
  } else if (desc.platform === "win32") {
    const pyWinCheck = verifyWindowsNativeExecutableIdentity(
      canonicalPythonPath,
      "trusted Python interpreter"
    );
    if (!pyWinCheck.ok) {
      return pyWinCheck;
    }
  }

  // 7. Verify Trusted Git Executable Path (§7.2, B04, RT-04)
  const gitRes = resolveCanonicalPath(desc.configuredGitPath);
  if (!gitRes.ok) {
    return { ok: false, error: `Trusted Git path invalid: ${gitRes.error}` };
  }
  const canonicalGitPath = gitRes.value;
  try {
    const gitStat = fs.statSync(canonicalGitPath);
    if (!gitStat.isFile()) {
      return { ok: false, error: `Trusted Git path must be a file, not a directory: ${canonicalGitPath}` };
    }
    if (!isExecutableModeOnPlatform(gitStat, desc.platform)) {
      return { ok: false, error: `Trusted Git file is not executable: ${canonicalGitPath}` };
    }
  } catch {
    return { ok: false, error: `Trusted Git executable not found: ${canonicalGitPath}` };
  }
  const canonicalGitDir = path.dirname(canonicalGitPath);
  if (
    isPathInsideOrEqualPlatform(canonicalGitPath, canonicalRepositoryRoot, desc.platform) ||
    isPathInsideOrEqualPlatform(canonicalGitDir, canonicalRepositoryRoot, desc.platform)
  ) {
    return {
      ok: false,
      error: `Refusing to use Git executable inside target repository ('${canonicalGitPath}' is inside '${canonicalRepositoryRoot}')`,
    };
  }
  if (desc.platform === "linux") {
    const gitNativeCheck = verifyLinuxNativeExecutableIdentity(
      canonicalGitPath,
      "trusted Git executable"
    );
    if (!gitNativeCheck.ok) {
      return gitNativeCheck;
    }
  } else if (desc.platform === "win32") {
    const gitWinCheck = verifyWindowsNativeExecutableIdentity(
      canonicalGitPath,
      "trusted Git executable"
    );
    if (!gitWinCheck.ok) {
      return gitWinCheck;
    }
  }

  // 8. Ensure controlled empty cwd and per-admission isolated temp directory outside repository
  let controlledEmptyCwd: string;
  let isolatedTempDir: string;
  try {
    controlledEmptyCwd = ensureControlledEmptyDirectory("checkwash-lens-static-cwd");
    isolatedTempDir = createIsolatedRunDirectory("checkwash-lens-tmp-");
  } catch (err) {
    return {
      ok: false,
      error: `Failed to initialize isolated working/temporary directory: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (
    isPathInsideOrEqualPlatform(controlledEmptyCwd, canonicalRepositoryRoot, desc.platform) ||
    isPathInsideOrEqualPlatform(isolatedTempDir, canonicalRepositoryRoot, desc.platform)
  ) {
    cleanupIsolatedRunDirectory(isolatedTempDir, true);
    return {
      ok: false,
      error: "Controlled working directory or temporary directory falls inside target repository",
    };
  }

  const sanitizedStaticEnv = buildSanitizedStaticEnv({
    canonicalGitDir,
    controlledEmptyCwd,
    isolatedTempDir,
    inheritedEnv: desc.inheritedEnv,
    platform: desc.platform,
  });

  // 9. Guarantee bare 'git' invoked internally by bundled Checkwash resolves to canonicalGitPath (Issue #10, B04)
  const bareGitCheck = verifyBareGitResolutionForStaticEnv({
    canonicalPythonPath,
    canonicalGitPath,
    controlledEmptyCwd,
    sanitizedStaticEnv,
    platform: desc.platform,
  });
  if (!bareGitCheck.ok) {
    cleanupIsolatedRunDirectory(isolatedTempDir, true);
    return bareGitCheck;
  }

  return {
    ok: true,
    value: {
      canonicalExtensionRoot,
      canonicalRepositoryRoot,
      canonicalPythonPath,
      canonicalGitPath,
      canonicalGitDir,
      bundledPyzPath: bundledRes.value.pyzPath,
      bundledPyzSha256: bundledRes.value.pyzSha256,
      bundledBrokerPath: bundledRes.value.brokerPath,
      bundledBrokerSha256: bundledRes.value.brokerSha256,
      controlledEmptyCwd,
      isolatedTempDir,
      sanitizedStaticEnv,
    },
  };
}
