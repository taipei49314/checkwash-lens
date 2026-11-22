/**
 * runtime/environmentDoctor.ts
 *
 * Read-Only Runtime & Security Environment Doctor for Checkwash Lens.
 *
 * Guarantees:
 * - Zero external process launches in Restricted Mode (`!isWorkspaceTrusted`), virtual/remote
 *   workspaces, unsupported OS/CPU, or when bundled artifact integrity fails.
 * - All external probes in Trusted Mode execute exclusively through `UnifiedProcessRunner`
 *   (`runExclusiveCancelableOperation` -> `verifyLaunchAdmission` -> `checkwash-broker.exe`).
 * - Surfaces `.vscode/settings.json` / `.code-workspace` setting override attempts that are
 *   intentionally ignored by Checkwash Lens's `machine` configuration scope.
 * - Discovers safe candidate executables (`python.exe`, `git.exe`, `checkwash-prove.exe`)
 *   strictly outside the target repository and verifies CPython 3.11+ (`-I -S -B -X utf8`),
 *   bare-`git` Windows search-order identity, and optional `checkwash-prove` v0.1.0 contract.
 */

import * as fs from "fs";
import * as path from "path";
import { PINNED_PROVE_VERSION } from "../core/proveModel";
import {
  buildSanitizedProveEnv,
  cleanupIsolatedRunDirectory,
  EXPECTED_CHECKWASH_VERSION,
  HostEnvironmentDescriptor,
  isFullyQualifiedPlatformPath,
  isPathInsideOrEqualPlatform,
  isWslWindowsMountPath,
  normalizePlatformLookupKey,
  resolveCanonicalOrNormalizedPath,
  resolveCanonicalPath,
  resolveTrustedExecutableFromPath,
  verifyBareGitResolutionForProcessLaunch,
  verifyBundledArtifacts,
  verifyLaunchAdmission,
  verifyLinuxNativeExecutableIdentity,
  verifyWindowsNativeExecutableIdentity,
  verifyWorkspaceHostEnvironment,
} from "./admission";
import { UnifiedProcessRunner } from "./processRunner";

export type DoctorSettingKey =
  | "pythonPath"
  | "gitPath"
  | "provePath"
  | "proveTestPythonPath";

export interface WorkspaceSettingOverrideInspection {
  readonly key: DoctorSettingKey;
  readonly globalValue: string;
  readonly workspaceValue: string;
  readonly workspaceFolderValue: string;
  readonly ignoredCrossOsLocalValue?: string;
}

export interface WorkspaceSettingWarning {
  readonly key: DoctorSettingKey;
  readonly ignoredWorkspaceValue: string;
  readonly activeGlobalValue: string;
  readonly message: string;
}

export type DoctorCheckStatus =
  | "ready"
  | "warning"
  | "error"
  | "skipped"
  | "not_configured";

export interface DoctorCheckItem {
  readonly status: DoctorCheckStatus;
  readonly summary: string;
  readonly canonicalPath?: string | null;
  readonly version?: string | null;
  readonly discoveredCandidatePath?: string | null;
  readonly detail?: string | null;
}

export interface RecommendedUserSettingsPatch {
  pythonPath?: string;
  gitPath?: string;
  provePath?: string;
}

export interface EnvironmentDoctorReport {
  readonly timestamp: string;
  readonly isWorkspaceTrusted: boolean;
  readonly externalProcessesSpawned: boolean;
  readonly overallReadyForStaticScan: boolean;
  readonly overallReadyForProve: boolean;
  readonly repositoryRoot: string | null;
  readonly workspaceSettingsWarnings: readonly WorkspaceSettingWarning[];
  readonly checks: {
    readonly hostCapability: DoctorCheckItem;
    readonly bundledArtifacts: DoctorCheckItem;
    readonly pythonRuntime: DoctorCheckItem;
    readonly gitRuntimeAndBareGit: DoctorCheckItem;
    readonly proveSatellite: DoctorCheckItem;
  };
  readonly recommendedUserSettingsPatch: RecommendedUserSettingsPatch;
  readonly markdownSummary: string;
}

export interface RunEnvironmentDoctorParams {
  readonly processRunner: UnifiedProcessRunner;
  readonly hostDesc: HostEnvironmentDescriptor;
  readonly configuredProvePath?: string;
  readonly configuredProveTestPythonPath?: string;
  readonly settingInspections?: readonly WorkspaceSettingOverrideInspection[];
}

function stripJsoncCommentsAndTrailingCommas(raw: string): string {
  let out = "";
  let inString = false;
  let escaped = false;
  let i = 0;
  while (i < raw.length) {
    const ch = raw[i];
    const next = i + 1 < raw.length ? raw[i + 1] : "";
    if (inString) {
      out += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      i++;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      i++;
      continue;
    }
    if (ch === "/" && next === "/") {
      i += 2;
      while (i < raw.length && raw[i] !== "\n" && raw[i] !== "\r") {
        i++;
      }
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i + 1 < raw.length && !(raw[i] === "*" && raw[i + 1] === "/")) {
        i++;
      }
      i += 2;
      continue;
    }
    out += ch;
    i++;
  }
  return out.replace(/,\s*([}\]])/g, "$1");
}

function readRepoVscodeSettingsOverrides(
  canonicalRepoRoot: string | null
): Partial<Record<DoctorSettingKey, string>> {
  const result: Partial<Record<DoctorSettingKey, string>> = {};
  if (!canonicalRepoRoot) {
    return result;
  }
  try {
    const vscodeDir = path.join(canonicalRepoRoot, ".vscode");
    const settingsFile = path.join(vscodeDir, "settings.json");
    const dirStat = fs.lstatSync(vscodeDir);
    if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
      return result;
    }
    const fileStat = fs.lstatSync(settingsFile);
    if (fileStat.isSymbolicLink() || !fileStat.isFile() || fileStat.size > 262_144) {
      return result;
    }
    const raw = fs.readFileSync(settingsFile, "utf8");
    const parsed = JSON.parse(stripJsoncCommentsAndTrailingCommas(raw)) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return result;
    }
    const obj = parsed as Record<string, unknown>;
    const keys: DoctorSettingKey[] = [
      "pythonPath",
      "gitPath",
      "provePath",
      "proveTestPythonPath",
    ];
    for (const k of keys) {
      const v = obj[`checkwashLens.${k}`];
      if (typeof v === "string" && v.trim().length > 0) {
        result[k] = v.trim();
      }
    }
  } catch {
    // Best-effort read-only inspection; never fail Doctor on malformed .vscode/settings.json
  }
  return result;
}

function collectWorkspaceSettingWarnings(
  inspections: readonly WorkspaceSettingOverrideInspection[] | undefined,
  canonicalRepoRoot: string | null,
  globalSettingMap: ReadonlyMap<DoctorSettingKey, string>
): WorkspaceSettingWarning[] {
  const warnings: WorkspaceSettingWarning[] = [];
  const seenKeys = new Set<DoctorSettingKey>();

  for (const item of inspections ?? []) {
    const wsVal = (item.workspaceValue || "").trim();
    const folderVal = (item.workspaceFolderValue || "").trim();
    const ignored = folderVal || wsVal;
    if (ignored.length > 0) {
      const globalVal = (item.globalValue || "").trim();
      seenKeys.add(item.key);
      warnings.push({
        key: item.key,
        ignoredWorkspaceValue: ignored,
        activeGlobalValue: globalVal,
        message: `Workspace setting 'checkwashLens.${item.key}' = '${ignored}' is ignored by security policy (machine-scoped setting). Active User/Global value: ${globalVal ? `'${globalVal}'` : "(unset — safe PATH fallback)"}.`,
      });
    } else if (item.ignoredCrossOsLocalValue && item.ignoredCrossOsLocalValue.trim().length > 0) {
      const crossVal = item.ignoredCrossOsLocalValue.trim();
      const globalVal = (item.globalValue || "").trim();
      warnings.push({
        key: item.key,
        ignoredWorkspaceValue: crossVal,
        activeGlobalValue: globalVal,
        message: `Local UI User setting 'checkwashLens.${item.key}' = '${crossVal}' targets a different OS and is ignored in this remote workspace host. Active remote value: ${globalVal ? `'${globalVal}'` : "(unset — safe Linux PATH fallback)"}.`,
      });
    }
  }

  // Also inspect `<repo>/.vscode/settings.json` directly because VS Code's configuration registry
  // silently drops `scope: "machine"` keys from `.vscode/settings.json` before `inspect()` returns.
  const fileOverrides = readRepoVscodeSettingsOverrides(canonicalRepoRoot);
  const allKeys: DoctorSettingKey[] = [
    "pythonPath",
    "gitPath",
    "provePath",
    "proveTestPythonPath",
  ];
  for (const key of allKeys) {
    if (seenKeys.has(key)) {
      continue;
    }
    const rawFileVal = fileOverrides[key];
    if (rawFileVal) {
      const globalVal = globalSettingMap.get(key) ?? "";
      warnings.push({
        key,
        ignoredWorkspaceValue: rawFileVal,
        activeGlobalValue: globalVal,
        message: `Workspace '.vscode/settings.json' entry 'checkwashLens.${key}' = '${rawFileVal}' is ignored by security policy (machine-scoped setting). Active User/Global value: ${globalVal ? `'${globalVal}'` : "(unset — safe PATH fallback)"}.`,
      });
    }
  }

  return warnings;
}

function addSafeOutsideRepoCandidate(
  list: string[],
  seenKeys: Set<string>,
  rawCandidatePath: string | undefined,
  canonicalRepoRoot: string,
  platform: string = process.platform
): void {
  if (!rawCandidatePath || rawCandidatePath.trim().length === 0) {
    return;
  }
  const trimmed = rawCandidatePath.trim().replace(/^"+|"+$/g, "").trim();
  if (!isFullyQualifiedPlatformPath(trimmed, platform)) {
    return;
  }
  if (platform === "linux" && isWslWindowsMountPath(trimmed)) {
    return;
  }
  if (isPathInsideOrEqualPlatform(trimmed, canonicalRepoRoot, platform)) {
    return;
  }
  const canonRes = resolveCanonicalPath(trimmed);
  if (!canonRes.ok) {
    return;
  }
  const canon = canonRes.value;
  try {
    const st = fs.statSync(canon);
    if (!st.isFile() || st.size <= 0) {
      return;
    }
    if (platform !== "win32" && (st.mode & 0o111) === 0) {
      return;
    }
  } catch {
    return;
  }
  if (platform === "linux" && !verifyLinuxNativeExecutableIdentity(canon, "candidate executable").ok) {
    return;
  }
  if (platform === "win32" && !verifyWindowsNativeExecutableIdentity(canon, "candidate executable").ok) {
    return;
  }
  const canonDir = path.dirname(canon);
  if (
    isPathInsideOrEqualPlatform(canon, canonicalRepoRoot, platform) ||
    isPathInsideOrEqualPlatform(canonDir, canonicalRepoRoot, platform)
  ) {
    return;
  }
  const key = normalizePlatformLookupKey(canon, platform);
  if (!seenKeys.has(key)) {
    seenKeys.add(key);
    list.push(canon);
  }
}

function discoverPython311PlusInstallCandidates(
  canonicalRepoRoot: string,
  inheritedEnv: NodeJS.ProcessEnv,
  configuredPythonPath: string,
  platform: string = process.platform
): string[] {
  const candidates: string[] = [];
  const seen = new Set<string>();

  addSafeOutsideRepoCandidate(candidates, seen, configuredPythonPath, canonicalRepoRoot, platform);

  const rawPath = inheritedEnv.PATH ?? inheritedEnv.Path ?? "";
  if (platform === "linux") {
    const pyNames = ["python3", "python3.13", "python3.12", "python3.11", "python"];
    const fromPath = resolveTrustedExecutableFromPath({
      executableNames: pyNames,
      repositoryRootPath: canonicalRepoRoot,
      pathEnv: rawPath,
      platform,
    });
    if (fromPath.ok) {
      addSafeOutsideRepoCandidate(candidates, seen, fromPath.value, canonicalRepoRoot, platform);
    }
    const searchDirs = [
      ...rawPath.split(":"),
      "/usr/local/bin",
      "/usr/bin",
      "/bin",
      "/opt/python/bin",
    ];
    for (const rawEntry of searchDirs) {
      const cleaned = rawEntry.trim().replace(/^"+|"+$/g, "").trim();
      if (
        cleaned &&
        isFullyQualifiedPlatformPath(cleaned, platform) &&
        !isWslWindowsMountPath(cleaned)
      ) {
        for (const name of pyNames) {
          addSafeOutsideRepoCandidate(
            candidates,
            seen,
            path.posix.join(cleaned, name),
            canonicalRepoRoot,
            platform
          );
        }
      }
    }
    return candidates;
  }

  const fromPath = resolveTrustedExecutableFromPath({
    executableName: "python.exe",
    repositoryRootPath: canonicalRepoRoot,
    pathEnv: rawPath,
    platform,
  });
  if (fromPath.ok) {
    addSafeOutsideRepoCandidate(candidates, seen, fromPath.value, canonicalRepoRoot, platform);
  }

  // Scan all safe PATH entries for additional python.exe installations
  for (const rawEntry of rawPath.split(";")) {
    const cleaned = rawEntry.trim().replace(/^"+|"+$/g, "").trim();
    if (cleaned && isFullyQualifiedPlatformPath(cleaned, platform)) {
      addSafeOutsideRepoCandidate(
        candidates,
        seen,
        path.win32.join(cleaned, "python.exe"),
        canonicalRepoRoot,
        platform
      );
    }
  }

  // Standard Windows CPython 3.11+ install locations (sorted descending by directory name)
  const baseRoots: string[] = [];
  const localAppData = inheritedEnv.LOCALAPPDATA ?? process.env.LOCALAPPDATA;
  if (localAppData) {
    baseRoots.push(path.win32.join(localAppData, "Programs", "Python"));
  }
  const progFiles = inheritedEnv.ProgramFiles ?? process.env.ProgramFiles ?? "C:\\Program Files";
  baseRoots.push(progFiles);
  const sysDrive = inheritedEnv.SystemDrive ?? process.env.SystemDrive ?? "C:";
  baseRoots.push(`${sysDrive}\\`);

  for (const rootDir of baseRoots) {
    try {
      if (!fs.existsSync(rootDir)) {
        continue;
      }
      const subdirs = fs
        .readdirSync(rootDir, { withFileTypes: true })
        .filter((d) => d.isDirectory() && /^Python3(?:1[1-9]|[2-9]\d)/i.test(d.name))
        .map((d) => d.name)
        .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
      for (const sub of subdirs) {
        addSafeOutsideRepoCandidate(
          candidates,
          seen,
          path.win32.join(rootDir, sub, "python.exe"),
          canonicalRepoRoot,
          platform
        );
      }
    } catch {
      // Ignore inaccessible system directories
    }
  }

  return candidates;
}

function discoverGitInstallCandidates(
  canonicalRepoRoot: string,
  inheritedEnv: NodeJS.ProcessEnv,
  configuredGitPath: string,
  platform: string = process.platform
): string[] {
  const candidates: string[] = [];
  const seen = new Set<string>();

  addSafeOutsideRepoCandidate(candidates, seen, configuredGitPath, canonicalRepoRoot, platform);

  const rawPath = inheritedEnv.PATH ?? inheritedEnv.Path ?? "";
  if (platform === "linux") {
    const fromPath = resolveTrustedExecutableFromPath({
      executableName: "git",
      repositoryRootPath: canonicalRepoRoot,
      pathEnv: rawPath,
      platform,
    });
    if (fromPath.ok) {
      addSafeOutsideRepoCandidate(candidates, seen, fromPath.value, canonicalRepoRoot, platform);
    }
    for (const rawEntry of [...rawPath.split(":"), "/usr/local/bin", "/usr/bin", "/bin"]) {
      const cleaned = rawEntry.trim().replace(/^"+|"+$/g, "").trim();
      if (
        cleaned &&
        isFullyQualifiedPlatformPath(cleaned, platform) &&
        !isWslWindowsMountPath(cleaned)
      ) {
        addSafeOutsideRepoCandidate(
          candidates,
          seen,
          path.posix.join(cleaned, "git"),
          canonicalRepoRoot,
          platform
        );
      }
    }
    return candidates;
  }

  const fromPath = resolveTrustedExecutableFromPath({
    executableName: "git.exe",
    repositoryRootPath: canonicalRepoRoot,
    pathEnv: rawPath,
    platform,
  });
  if (fromPath.ok) {
    addSafeOutsideRepoCandidate(candidates, seen, fromPath.value, canonicalRepoRoot, platform);
  }

  for (const rawEntry of rawPath.split(";")) {
    const cleaned = rawEntry.trim().replace(/^"+|"+$/g, "").trim();
    if (cleaned && isFullyQualifiedPlatformPath(cleaned, platform)) {
      addSafeOutsideRepoCandidate(
        candidates,
        seen,
        path.win32.join(cleaned, "git.exe"),
        canonicalRepoRoot,
        platform
      );
    }
  }

  const progFiles = inheritedEnv.ProgramFiles ?? process.env.ProgramFiles ?? "C:\\Program Files";
  const localAppData = inheritedEnv.LOCALAPPDATA ?? process.env.LOCALAPPDATA;
  const standardGitPaths = [
    path.win32.join(progFiles, "Git", "cmd", "git.exe"),
    path.win32.join(progFiles, "Git", "bin", "git.exe"),
    ...(localAppData
      ? [
          path.win32.join(localAppData, "Programs", "Git", "cmd", "git.exe"),
          path.win32.join(localAppData, "Programs", "Git", "bin", "git.exe"),
        ]
      : []),
  ];
  for (const candidate of standardGitPaths) {
    addSafeOutsideRepoCandidate(candidates, seen, candidate, canonicalRepoRoot, platform);
  }

  return candidates;
}

function parseProveVersionOutput(stdoutText: string): string | null {
  const trimmed = stdoutText.trim();
  const match = /^(?:checkwash-prove\s+)?(\S+)$/i.exec(trimmed);
  return match ? match[1] : null;
}

export function formatEnvironmentDoctorMarkdown(
  report: Omit<EnvironmentDoctorReport, "markdownSummary">
): string {
  const badge = (status: DoctorCheckStatus): string => {
    switch (status) {
      case "ready":
        return "PASS";
      case "warning":
        return "WARN";
      case "not_configured":
        return "OPTIONAL (Not Configured)";
      case "skipped":
        return "SKIPPED";
      case "error":
      default:
        return "ERROR";
    }
  };

  const lines: string[] = [
    "# Checkwash Lens — Environment Doctor Report",
    "",
    `- **Timestamp:** \`${report.timestamp}\``,
    `- **Workspace Trust:** \`${report.isWorkspaceTrusted ? "Trusted" : "Restricted Mode (Untrusted — Zero External Processes Spawned)"}\``,
    `- **Repository Root:** \`${report.repositoryRoot ?? "(none)"}\``,
    `- **Static Checkwash Scan Readiness:** **${report.overallReadyForStaticScan ? "READY" : "NOT READY"}**`,
    `- **Prove v${PINNED_PROVE_VERSION} Satellite Readiness:** **${report.overallReadyForProve ? "READY" : badge(report.checks.proveSatellite.status)}**`,
    "",
    "## Diagnostic Checks",
    "",
  ];

  const renderCheck = (title: string, item: DoctorCheckItem): void => {
    lines.push(`### [${badge(item.status)}] ${title}`);
    lines.push(`- **Summary:** ${item.summary}`);
    if (item.canonicalPath) {
      lines.push(`- **Verified Canonical Path:** \`${item.canonicalPath}\``);
    }
    if (item.version) {
      lines.push(`- **Observed Version:** \`${item.version}\``);
    }
    if (item.discoveredCandidatePath && item.discoveredCandidatePath !== item.canonicalPath) {
      lines.push(`- **Discovered Safe Candidate:** \`${item.discoveredCandidatePath}\``);
    }
    if (item.detail) {
      lines.push(`- **Detail:** ${item.detail}`);
    }
    lines.push("");
  };

  renderCheck("1. Host & Workspace Capability", report.checks.hostCapability);
  renderCheck("2. Bundled Artifacts & Broker Integrity", report.checks.bundledArtifacts);
  renderCheck("3. Trusted CPython 3.11+ Runtime", report.checks.pythonRuntime);
  renderCheck("4. Trusted Git & Bare-`git` Search-Order Identity", report.checks.gitRuntimeAndBareGit);
  renderCheck(`5. Optional Checkwash Prove v${PINNED_PROVE_VERSION} Satellite`, report.checks.proveSatellite);

  if (report.workspaceSettingsWarnings.length > 0) {
    lines.push("## Security Warnings: Ignored Workspace Settings");
    lines.push("");
    for (const w of report.workspaceSettingsWarnings) {
      lines.push(`- \`checkwashLens.${w.key}\`: ${w.message}`);
    }
    lines.push("");
  }

  const patchKeys = Object.keys(report.recommendedUserSettingsPatch) as Array<
    keyof RecommendedUserSettingsPatch
  >;
  if (patchKeys.length > 0) {
    const jsonObj: Record<string, string> = {};
    for (const k of patchKeys) {
      const val = report.recommendedUserSettingsPatch[k];
      if (val) {
        jsonObj[`checkwashLens.${k}`] = val;
      }
    }
    lines.push("## Recommended User Settings (`Global` Scope)");
    lines.push("");
    lines.push(
      "The following verified executable paths outside the target repository can be pinned in VS Code **User Settings** (`Global` scope):"
    );
    lines.push("");
    lines.push("```json");
    lines.push(JSON.stringify(jsonObj, null, 2));
    lines.push("```");
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Runs a read-only diagnostic check of host capabilities, bundled artifacts, workspace setting
 * override attempts, trusted Python/Git runtimes, bare-`git` search-order safety, and optional
 * `checkwash-prove` v0.1.0 satellite readiness.
 */
export async function runEnvironmentDoctor(
  params: RunEnvironmentDoctorParams
): Promise<EnvironmentDoctorReport> {
  const { processRunner, hostDesc } = params;
  const timestamp = new Date().toISOString();
  const inheritedEnv = hostDesc.inheritedEnv ?? process.env;

  const globalSettingMap = new Map<DoctorSettingKey, string>();
  for (const item of params.settingInspections ?? []) {
    globalSettingMap.set(item.key, (item.globalValue || "").trim());
  }

  // -------------------------------------------------------------------------
  // 1. Pure FS / In-Memory Checks (Zero External Processes)
  // -------------------------------------------------------------------------
  let hostCapability: DoctorCheckItem;
  let canonicalRepoRoot: string | null = null;
  let canonicalExtRoot: string | null = null;

  const hostEnvCheck = verifyWorkspaceHostEnvironment(hostDesc);
  if (!hostEnvCheck.ok) {
    hostCapability = {
      status: "error",
      summary: `${hostEnvCheck.error}.`,
    };
  } else {
    const extRes = resolveCanonicalPath(hostDesc.extensionRootPath);
    const repoRes = resolveCanonicalPath(hostDesc.repositoryRootPath);
    if (!extRes.ok) {
      hostCapability = {
        status: "error",
        summary: `Invalid extension root path: ${extRes.error}`,
      };
    } else if (!repoRes.ok) {
      hostCapability = {
        status: "error",
        summary: `No valid local repository folder selected: ${repoRes.error}`,
      };
    } else {
      let isDir = false;
      try {
        isDir = fs.statSync(repoRes.value).isDirectory();
      } catch {
        isDir = false;
      }
      if (!isDir) {
        hostCapability = {
          status: "error",
          summary: `Repository root is not an accessible directory: ${repoRes.value}`,
        };
      } else {
        canonicalExtRoot = extRes.value;
        canonicalRepoRoot = repoRes.value;
        const osLabel = hostDesc.platform === "linux" ? "Linux x64" : "Windows x64";
        const envScopeLabel =
          hostEnvCheck.value.mode === "linux-remote"
            ? `${osLabel} remote workspace ('${hostEnvCheck.value.remoteName}')`
            : `${osLabel} local workspace`;
        hostCapability = hostDesc.isWorkspaceTrusted
          ? {
              status: "ready",
              summary: `${envScopeLabel} verified (Workspace Trust granted).`,
              canonicalPath: canonicalRepoRoot,
            }
          : {
              status: "warning",
              summary:
                "Workspace is in Restricted Mode (Untrusted). Offline report viewing is enabled; all external process launches are disabled.",
              canonicalPath: canonicalRepoRoot,
            };
      }
    }
  }

  const warnings = collectWorkspaceSettingWarnings(
    params.settingInspections,
    canonicalRepoRoot,
    globalSettingMap
  );

  const extRootForArtifacts =
    canonicalExtRoot ?? resolveCanonicalOrNormalizedPath(hostDesc.extensionRootPath);
  const bundledCheck = verifyBundledArtifacts(extRootForArtifacts, hostDesc.platform);
  const brokerDesc =
    hostDesc.platform === "linux"
      ? "Linux Subreaper Broker (CWBROKER1)"
      : "Windows Job Object Broker (CWBROKER1)";
  const bundledArtifacts: DoctorCheckItem = bundledCheck.ok
    ? {
        status: "ready",
        summary: `Verified pinned Checkwash v${EXPECTED_CHECKWASH_VERSION} (.pyz) and ${brokerDesc}.`,
        canonicalPath: bundledCheck.value.pyzPath,
        detail: `pyzSha256=${bundledCheck.value.pyzSha256.slice(0, 16)}..., brokerSha256=${bundledCheck.value.brokerSha256.slice(0, 16)}...`,
      }
    : {
        status: "error",
        summary: `Bundled artifact integrity verification failed: ${bundledCheck.error}`,
      };

  // Gate: NEVER spawn any external process in Restricted Mode or when host/artifact checks fail
  if (
    !hostDesc.isWorkspaceTrusted ||
    hostCapability.status === "error" ||
    !bundledCheck.ok ||
    !canonicalRepoRoot
  ) {
    const skipReason = !hostDesc.isWorkspaceTrusted
      ? "Skipped in Restricted Mode (zero external processes spawned). Grant Workspace Trust to probe Python, Git, and Prove."
      : "Skipped because host capability or bundled artifact check failed.";

    const skippedItem: DoctorCheckItem = {
      status: "skipped",
      summary: skipReason,
    };

    const baseReport: Omit<EnvironmentDoctorReport, "markdownSummary"> = {
      timestamp,
      isWorkspaceTrusted: hostDesc.isWorkspaceTrusted,
      externalProcessesSpawned: false,
      overallReadyForStaticScan: false,
      overallReadyForProve: false,
      repositoryRoot: canonicalRepoRoot,
      workspaceSettingsWarnings: warnings,
      checks: {
        hostCapability,
        bundledArtifacts,
        pythonRuntime: skippedItem,
        gitRuntimeAndBareGit: skippedItem,
        proveSatellite: skippedItem,
      },
      recommendedUserSettingsPatch: {},
    };

    return {
      ...baseReport,
      markdownSummary: formatEnvironmentDoctorMarkdown(baseReport),
    };
  }

  // Check runner health gates before entering exclusive slot
  if (processRunner.hasUnconfirmedCleanup()) {
    const blockedReason = `Execution blocked: previous run cleanup was not confirmed (${processRunner.getUnconfirmedCleanupReason() ?? "unknown"}).`;
    const errItem: DoctorCheckItem = { status: "error", summary: blockedReason };
    const baseReport: Omit<EnvironmentDoctorReport, "markdownSummary"> = {
      timestamp,
      isWorkspaceTrusted: true,
      externalProcessesSpawned: false,
      overallReadyForStaticScan: false,
      overallReadyForProve: false,
      repositoryRoot: canonicalRepoRoot,
      workspaceSettingsWarnings: warnings,
      checks: {
        hostCapability,
        bundledArtifacts,
        pythonRuntime: errItem,
        gitRuntimeAndBareGit: errItem,
        proveSatellite: errItem,
      },
      recommendedUserSettingsPatch: {},
    };
    return {
      ...baseReport,
      markdownSummary: formatEnvironmentDoctorMarkdown(baseReport),
    };
  }

  const brokerDisabled = processRunner.isExecutionDisabledByBrokerFailure();
  if (brokerDisabled.disabled) {
    const disabledReason = `Execution disabled due to broker capability failure: ${brokerDisabled.reason ?? "unknown"}`;
    const errItem: DoctorCheckItem = { status: "error", summary: disabledReason };
    const baseReport: Omit<EnvironmentDoctorReport, "markdownSummary"> = {
      timestamp,
      isWorkspaceTrusted: true,
      externalProcessesSpawned: false,
      overallReadyForStaticScan: false,
      overallReadyForProve: false,
      repositoryRoot: canonicalRepoRoot,
      workspaceSettingsWarnings: warnings,
      checks: {
        hostCapability,
        bundledArtifacts,
        pythonRuntime: errItem,
        gitRuntimeAndBareGit: errItem,
        proveSatellite: errItem,
      },
      recommendedUserSettingsPatch: {},
    };
    return {
      ...baseReport,
      markdownSummary: formatEnvironmentDoctorMarkdown(baseReport),
    };
  }

  const repoRootFixed = canonicalRepoRoot;

  // -------------------------------------------------------------------------
  // 2. Trusted Mode Runtime Probes (Inside Unified Exclusive Cancelable Slot)
  // -------------------------------------------------------------------------
  return processRunner.runExclusiveCancelableOperation(async (abortSignal) => {
    let spawnedAny = false;
    const recommendedPatch: RecommendedUserSettingsPatch = {};

    // First test the exact currently-configured HostEnvironmentDescriptor
    let configuredPairError: string | null = null;
    let verifiedPythonPath: string | null = null;
    let verifiedPythonVersion: string | null = null;
    let verifiedGitPath: string | null = null;
    let verifiedGitVersion: string | null = null;

    const currentAdm = verifyLaunchAdmission(hostDesc);
    if (currentAdm.ok) {
      cleanupIsolatedRunDirectory(currentAdm.value.isolatedTempDir, true);
      spawnedAny = true;
      const probeRes = await processRunner.probeTrustedRuntimeVersions(hostDesc, abortSignal);
      if (probeRes.ok) {
        verifiedPythonPath = probeRes.value.admission.canonicalPythonPath;
        verifiedPythonVersion = probeRes.value.pythonVersion;
        verifiedGitPath = probeRes.value.admission.canonicalGitPath;
        verifiedGitVersion = probeRes.value.gitVersion;
      } else {
        configuredPairError = probeRes.error;
      }
    } else {
      configuredPairError = currentAdm.error;
    }

    // If current pair failed, search safe outside-repo candidate installations
    let discoveredPyPath: string | null = null;
    let discoveredPyVersion: string | null = null;
    let discoveredGitPath: string | null = null;
    let discoveredGitVersion: string | null = null;

    if (!verifiedPythonPath || !verifiedGitPath) {
      const pyCandidates = discoverPython311PlusInstallCandidates(
        repoRootFixed,
        inheritedEnv,
        hostDesc.configuredPythonPath,
        hostDesc.platform
      );
      const gitCandidates = discoverGitInstallCandidates(
        repoRootFixed,
        inheritedEnv,
        hostDesc.configuredGitPath,
        hostDesc.platform
      );

      let attempts = 0;
      outerSearch: for (const pyCand of pyCandidates) {
        for (const gitCand of gitCandidates) {
          if (abortSignal.aborted || attempts >= 8) {
            break outerSearch;
          }
          const candDesc: HostEnvironmentDescriptor = {
            ...hostDesc,
            configuredPythonPath: pyCand,
            configuredGitPath: gitCand,
          };
          const adm = verifyLaunchAdmission(candDesc);
          if (!adm.ok) {
            continue;
          }
          cleanupIsolatedRunDirectory(adm.value.isolatedTempDir, true);
          attempts++;
          spawnedAny = true;
          const probe = await processRunner.probeTrustedRuntimeVersions(candDesc, abortSignal);
          if (probe.ok) {
            discoveredPyPath = probe.value.admission.canonicalPythonPath;
            discoveredPyVersion = probe.value.pythonVersion;
            discoveredGitPath = probe.value.admission.canonicalGitPath;
            discoveredGitVersion = probe.value.gitVersion;
            break outerSearch;
          }
        }
      }
    }

    let pythonRuntime: DoctorCheckItem;
    let gitRuntimeAndBareGit: DoctorCheckItem;

    if (verifiedPythonPath && verifiedGitPath) {
      const globalPy = globalSettingMap.get("pythonPath") ?? "";
      const globalGit = globalSettingMap.get("gitPath") ?? "";
      if (params.settingInspections && globalPy.length === 0) {
        recommendedPatch.pythonPath = verifiedPythonPath;
      }
      if (params.settingInspections && globalGit.length === 0) {
        recommendedPatch.gitPath = verifiedGitPath;
      }

      pythonRuntime = {
        status: "ready",
        summary: `Verified isolated CPython ${verifiedPythonVersion} (-I -S -B -X utf8) outside target repository.`,
        canonicalPath: verifiedPythonPath,
        version: `CPython ${verifiedPythonVersion}`,
      };
      const searchOrderLabel =
        hostDesc.platform === "linux" ? "POSIX PATH" : "Windows CreateProcessW search-order";
      gitRuntimeAndBareGit = {
        status: "ready",
        summary: `Verified Git runtime and bare-'git' ${searchOrderLabel} identity.`,
        canonicalPath: verifiedGitPath,
        version: verifiedGitVersion,
      };
    } else {
      if (discoveredPyPath && discoveredGitPath) {
        recommendedPatch.pythonPath = discoveredPyPath;
        recommendedPatch.gitPath = discoveredGitPath;
      }

      const gitExeLabel = hostDesc.platform === "linux" ? "git" : "git.exe";
      pythonRuntime = {
        status: "error",
        summary: `Current Python runtime check failed: ${configuredPairError ?? "No valid CPython 3.11+ configured"}`,
        discoveredCandidatePath: discoveredPyPath,
        version: discoveredPyVersion ? `Discovered CPython ${discoveredPyVersion}` : null,
        detail: discoveredPyPath
          ? `Environment Doctor discovered a working CPython 3.11+ at '${discoveredPyPath}'. Apply User Settings to repair.`
          : "Install CPython 3.11+ outside the target repository and set 'checkwashLens.pythonPath' in User Settings.",
      };
      gitRuntimeAndBareGit = {
        status: "error",
        summary: `Current Git / bare-'git' identity check failed: ${configuredPairError ?? `No valid ${gitExeLabel} configured`}`,
        discoveredCandidatePath: discoveredGitPath,
        version: discoveredGitVersion,
        detail: discoveredGitPath
          ? `Environment Doctor discovered a verified ${gitExeLabel} at '${discoveredGitPath}'. Apply User Settings to repair.`
          : "Install Git outside the target repository and set 'checkwashLens.gitPath' in User Settings.",
      };
    }

    // -----------------------------------------------------------------------
    // 3. Optional Checkwash Prove v0.1.0 Satellite Check
    // -----------------------------------------------------------------------
    const effectivePyForProve = verifiedPythonPath ?? discoveredPyPath;
    const effectiveGitForProve = verifiedGitPath ?? discoveredGitPath;
    const rawProveConfigured = (params.configuredProvePath ?? "").trim();
    const rawProveTestPy = (params.configuredProveTestPythonPath ?? "").trim();

    let discoveredProveOnPath: string | null = null;
    if (rawProveConfigured.length === 0) {
      const rawPath = inheritedEnv.PATH ?? inheritedEnv.Path ?? "";
      const foundProve = resolveTrustedExecutableFromPath({
        executableName: hostDesc.platform === "win32" ? "checkwash-prove.exe" : "checkwash-prove",
        repositoryRootPath: repoRootFixed,
        pathEnv: rawPath,
        platform: hostDesc.platform,
      });
      if (foundProve.ok) {
        discoveredProveOnPath = foundProve.value;
      }
    }

    const provePathToCheck = rawProveConfigured || discoveredProveOnPath || "";
    let proveSatellite: DoctorCheckItem;

    if (!provePathToCheck) {
      proveSatellite = {
        status: "not_configured",
        summary: `Optional satellite 'checkwashLens.provePath' is not configured (static Checkwash scans do not require Prove).`,
        detail: `To enable manual mutation analysis (--list / Full / Replay), install checkwash-prove v${PINNED_PROVE_VERSION} outside the repository and configure 'checkwashLens.provePath' in User Settings.`,
      };
    } else if (!effectivePyForProve || !effectiveGitForProve) {
      proveSatellite = {
        status: "skipped",
        summary: "Skipped Prove probe until trusted Python and Git runtimes are healthy.",
      };
    } else {
      const canonProveRes = resolveCanonicalPath(provePathToCheck);
      let canonTestPy: string | undefined;
      let testPyError: string | null = null;

      if (rawProveTestPy.length > 0) {
        const tpRes = resolveCanonicalPath(rawProveTestPy);
        if (!tpRes.ok) {
          testPyError = `Invalid 'checkwashLens.proveTestPythonPath': ${tpRes.error}`;
        } else {
          try {
            if (!fs.statSync(tpRes.value).isFile()) {
              testPyError = `'checkwashLens.proveTestPythonPath' is not a regular file: ${tpRes.value}`;
            } else if (isPathInsideOrEqualPlatform(tpRes.value, repoRootFixed, hostDesc.platform)) {
              testPyError = `Refusing 'checkwashLens.proveTestPythonPath' inside target repository: ${tpRes.value}`;
            } else if (hostDesc.platform === "linux") {
              const tpNative = verifyLinuxNativeExecutableIdentity(
                tpRes.value,
                "Prove test Python interpreter"
              );
              if (!tpNative.ok) {
                testPyError = tpNative.error;
              } else {
                canonTestPy = tpRes.value;
              }
            } else if (hostDesc.platform === "win32") {
              const tpWin = verifyWindowsNativeExecutableIdentity(
                tpRes.value,
                "Prove test Python interpreter"
              );
              if (!tpWin.ok) {
                testPyError = tpWin.error;
              } else {
                canonTestPy = tpRes.value;
              }
            } else {
              canonTestPy = tpRes.value;
            }
          } catch {
            testPyError = `Cannot stat 'checkwashLens.proveTestPythonPath': ${tpRes.value}`;
          }
        }
      }

      if (!canonProveRes.ok) {
        proveSatellite = {
          status: "error",
          summary: `Invalid Prove executable path '${provePathToCheck}': ${canonProveRes.error}`,
        };
      } else if (testPyError) {
        proveSatellite = {
          status: "error",
          summary: testPyError,
        };
      } else {
        const canonProve = canonProveRes.value;
        let isFile = false;
        try {
          isFile = fs.statSync(canonProve).isFile();
        } catch {
          isFile = false;
        }
        if (!isFile) {
          proveSatellite = {
            status: "error",
            summary: `Prove path is not an existing regular file: ${canonProve}`,
          };
        } else if (isPathInsideOrEqualPlatform(canonProve, repoRootFixed, hostDesc.platform)) {
          proveSatellite = {
            status: "error",
            summary: `Refusing to execute checkwash-prove inside target repository ('${canonProve}').`,
          };
        } else if (
          hostDesc.platform === "linux" &&
          !verifyLinuxNativeExecutableIdentity(canonProve, "checkwash-prove executable").ok
        ) {
          const proveNative = verifyLinuxNativeExecutableIdentity(
            canonProve,
            "checkwash-prove executable"
          );
          proveSatellite = {
            status: "error",
            summary: proveNative.ok ? "Invalid checkwash-prove binary" : proveNative.error,
          };
        } else if (
          hostDesc.platform === "win32" &&
          !verifyWindowsNativeExecutableIdentity(canonProve, "checkwash-prove executable").ok
        ) {
          const proveWin = verifyWindowsNativeExecutableIdentity(
            canonProve,
            "checkwash-prove executable"
          );
          proveSatellite = {
            status: "error",
            summary: proveWin.ok ? "Invalid checkwash-prove binary" : proveWin.error,
          };
        } else {
          const proveHostDesc: HostEnvironmentDescriptor = {
            ...hostDesc,
            configuredPythonPath: effectivePyForProve,
            configuredGitPath: effectiveGitForProve,
          };
          spawnedAny = true;
          const proveProc = await processRunner.executeGatedProcess({
            hostDesc: proveHostDesc,
            executableSelector: () => canonProve,
            additionalBareGitCallers: (ctx) => [
              ctx.canonicalPythonPath,
              ...(canonTestPy ? [canonTestPy] : []),
            ],
            argsBuilder: () => ["--version"],
            envSelector: (ctx) =>
              buildSanitizedProveEnv({
                baseStaticEnv: ctx.sanitizedStaticEnv,
                canonicalGitDir: ctx.canonicalGitDir,
                proveExecutable: canonProve,
                hostPythonExecutable: ctx.canonicalPythonPath,
                testPythonExecutable: canonTestPy,
                platform: hostDesc.platform,
              }),
            timeoutMs: 10_000,
            abortSignal,
          });

          if (!proveProc.ok) {
            proveSatellite = {
              status: "error",
              summary: `Prove launch / bare-'git' verification failed: ${proveProc.error}`,
              canonicalPath: canonProve,
            };
          } else {
            const { admission, outcome } = proveProc.value;
            const proveEnv = buildSanitizedProveEnv({
              baseStaticEnv: admission.sanitizedStaticEnv,
              canonicalGitDir: admission.canonicalGitDir,
              proveExecutable: canonProve,
              hostPythonExecutable: admission.canonicalPythonPath,
              testPythonExecutable: canonTestPy,
              platform: hostDesc.platform,
            });
            const bareGitProve = verifyBareGitResolutionForProcessLaunch({
              callingExecutables: [
                canonProve,
                admission.canonicalPythonPath,
                ...(canonTestPy ? [canonTestPy] : []),
              ],
              canonicalGitPath: admission.canonicalGitPath,
              cwd: admission.controlledEmptyCwd,
              env: proveEnv,
              platform: hostDesc.platform,
            });

            if (!bareGitProve.ok) {
              proveSatellite = {
                status: "error",
                summary: bareGitProve.error,
                canonicalPath: canonProve,
              };
            } else if (
              outcome.status !== "completed" ||
              outcome.exitCode !== 0 ||
              !outcome.stdoutUtf8Valid ||
              !outcome.cleanupConfirmed
            ) {
              proveSatellite = {
                status: "error",
                summary: `Prove --version failed (status=${outcome.status}, exit=${String(outcome.exitCode)}): ${outcome.stderrText.trim()}`,
                canonicalPath: canonProve,
              };
            } else {
              const observedVer = parseProveVersionOutput(outcome.stdoutText);
              if (observedVer !== PINNED_PROVE_VERSION) {
                proveSatellite = {
                  status: "error",
                  summary: `Prove version mismatch: expected pinned v${PINNED_PROVE_VERSION}, got '${outcome.stdoutText.trim()}'`,
                  canonicalPath: canonProve,
                  version: outcome.stdoutText.trim(),
                };
              } else if (rawProveConfigured.length === 0) {
                recommendedPatch.provePath = canonProve;
                proveSatellite = {
                  status: "warning",
                  summary: `Discovered compatible checkwash-prove v${PINNED_PROVE_VERSION} on PATH, but 'checkwashLens.provePath' is not yet saved in User Settings.`,
                  canonicalPath: canonProve,
                  discoveredCandidatePath: canonProve,
                  version: `checkwash-prove ${observedVer}`,
                  detail: "Apply User Settings to pin 'checkwashLens.provePath' for manual Prove commands.",
                };
              } else {
                proveSatellite = {
                  status: "ready",
                  summary: `Verified pinned checkwash-prove v${PINNED_PROVE_VERSION} and Prove bare-'git' launch environment.`,
                  canonicalPath: canonProve,
                  version: `checkwash-prove ${observedVer}`,
                };
              }
            }
          }
        }
      }
    }

    const overallReadyForStaticScan =
      hostCapability.status === "ready" &&
      bundledArtifacts.status === "ready" &&
      pythonRuntime.status === "ready" &&
      gitRuntimeAndBareGit.status === "ready";

    const overallReadyForProve =
      overallReadyForStaticScan && proveSatellite.status === "ready";

    const baseReport: Omit<EnvironmentDoctorReport, "markdownSummary"> = {
      timestamp,
      isWorkspaceTrusted: true,
      externalProcessesSpawned: spawnedAny,
      overallReadyForStaticScan,
      overallReadyForProve,
      repositoryRoot: repoRootFixed,
      workspaceSettingsWarnings: warnings,
      checks: {
        hostCapability,
        bundledArtifacts,
        pythonRuntime,
        gitRuntimeAndBareGit,
        proveSatellite,
      },
      recommendedUserSettingsPatch: recommendedPatch,
    };

    return {
      ...baseReport,
      markdownSummary: formatEnvironmentDoctorMarkdown(baseReport),
    };
  });
}
