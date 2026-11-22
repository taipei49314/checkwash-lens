/**
 * src/test/testPlatformEnv.ts
 *
 * Shared cross-platform test environment helpers for win32-x64 and linux-x64
 * verification suites. Test-only module (never imported by production code).
 */

import * as cp from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

export const IS_WIN32 = process.platform === "win32";
export const IS_LINUX = process.platform === "linux";
export const ACTIVE_PLATFORM = process.platform;
export const ACTIVE_ARCH = process.arch;
export const ACTIVE_VSIX_TARGET = IS_LINUX ? "linux-x64" : "win32-x64";

function firstExistingExecutable(candidates: string[], fallbackCmdNames: string[]): string {
  for (const c of candidates) {
    if (c && fs.existsSync(c)) {
      return c;
    }
  }
  const pathEnv = process.env.PATH ?? process.env.Path ?? "";
  for (const rawEntry of pathEnv.split(path.delimiter)) {
    const entry = rawEntry.trim().replace(/^"+|"+$/g, "");
    if (!entry) continue;
    for (const name of fallbackCmdNames) {
      const full = path.join(entry, name);
      if (fs.existsSync(full)) {
        return full;
      }
    }
  }
  return candidates[0] ?? fallbackCmdNames[0] ?? "";
}

function getWindowsLocalAppData(): string {
  return process.env.LOCALAPPDATA?.trim() || path.join(os.homedir(), "AppData", "Local");
}

export function resolveTestPythonExe(): string {
  if (process.env.CW_TEST_PYTHON_EXE && process.env.CW_TEST_PYTHON_EXE.trim().length > 0) {
    return process.env.CW_TEST_PYTHON_EXE.trim();
  }
  if (IS_WIN32) {
    const localAppData = getWindowsLocalAppData();
    return firstExistingExecutable(
      [
        path.join(localAppData, "Programs", "Python", "Python311", "python.exe"),
        path.join(localAppData, "Programs", "Python", "Python312", "python.exe"),
      ],
      ["python.exe"]
    );
  }
  return firstExistingExecutable(
    ["/usr/local/bin/python3", "/usr/bin/python3", "/opt/prove-venv/bin/python3"],
    ["python3", "python3.11", "python"]
  );
}

export function resolveTestGitExe(): string {
  if (process.env.CW_TEST_GIT_EXE && process.env.CW_TEST_GIT_EXE.trim().length > 0) {
    return process.env.CW_TEST_GIT_EXE.trim();
  }
  if (IS_WIN32) {
    return firstExistingExecutable(
      ["C:\\Program Files\\Git\\cmd\\git.exe", "C:\\Program Files\\Git\\bin\\git.exe"],
      ["git.exe"]
    );
  }
  return firstExistingExecutable(["/usr/bin/git", "/usr/local/bin/git"], ["git"]);
}

export function resolveTestProveExe(): string {
  if (process.env.CW_TEST_PROVE_EXE && process.env.CW_TEST_PROVE_EXE.trim().length > 0) {
    return process.env.CW_TEST_PROVE_EXE.trim();
  }
  if (IS_WIN32) {
    const localAppData = getWindowsLocalAppData();
    return firstExistingExecutable(
      [
        path.join(os.homedir(), "dev", "checkwash-prove-venv", "Scripts", "checkwash-prove.exe"),
        path.join(localAppData, "Programs", "Python", "Python311", "Scripts", "checkwash-prove.exe"),
      ],
      ["checkwash-prove.exe"]
    );
  }
  return firstExistingExecutable(
    ["/opt/prove-venv/bin/checkwash-prove", "/usr/local/bin/checkwash-prove"],
    ["checkwash-prove"]
  );
}

export function resolveBundledBrokerRelPosix(): string {
  return IS_LINUX ? "bundled/checkwash-broker-linux-x64" : "bundled/checkwash-broker.exe";
}

export function resolveBundledBrokerFilename(): string {
  return IS_LINUX ? "checkwash-broker-linux-x64" : "checkwash-broker.exe";
}

export function resolveBundledBrokerExe(repoRoot: string): string {
  return path.join(repoRoot, "bundled", resolveBundledBrokerFilename());
}

export function resolveTestVscodeExe(): string {
  const envOverride = process.env.CW_TEST_VSCODE_EXE || process.env.CW_TEST_CODE_EXE;
  if (envOverride && envOverride.trim().length > 0) {
    return envOverride.trim();
  }
  if (IS_WIN32) {
    const localAppData = getWindowsLocalAppData();
    return firstExistingExecutable(
      [
        path.join(localAppData, "Programs", "Microsoft VS Code", "Code.exe"),
        "C:\\Program Files\\Microsoft VS Code\\Code.exe",
      ],
      ["Code.exe"]
    );
  }
  return firstExistingExecutable(
    ["/opt/vscode/code", "/usr/share/code/code", "/usr/bin/code"],
    ["code"]
  );
}

export function getPlatformVscodeLaunchArgs(): string[] {
  if (IS_LINUX) {
    return ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"];
  }
  return [];
}

export function resolvePlatformEvidenceDir(repoRoot: string): string {
  if (process.env.CW_EVIDENCE_DIR && process.env.CW_EVIDENCE_DIR.trim().length > 0) {
    return path.resolve(process.env.CW_EVIDENCE_DIR.trim());
  }
  return IS_LINUX ? path.join(repoRoot, "evidence", "linux-x64") : path.join(repoRoot, "evidence");
}

export function getPlatformExecutionMetadata(): {
  evidenceTag: string;
  hostname: string;
  hostMachineHostname: string;
  containerHostname: string | null;
  executionEnvironment: string;
} {
  const actualHostname = os.hostname();
  const hostMachineHostname = process.env.CW_HOST_HOSTNAME?.trim() || actualHostname;
  const evidenceTag = process.env.CW_EVIDENCE_TAG?.trim() || "LOCAL_VERIFICATION";
  return {
    evidenceTag,
    hostname: IS_LINUX
      ? `${hostMachineHostname} (docker-linux:${actualHostname})`
      : actualHostname,
    hostMachineHostname,
    containerHostname: IS_LINUX ? actualHostname : null,
    executionEnvironment: IS_LINUX
      ? `local-docker-linux-x64-on-${hostMachineHostname}`
      : `local-win32-x64-on-${actualHostname}`,
  };
}

export function isPythonExecutableName(exePath: string): boolean {
  const base = path.basename(exePath).toLowerCase();
  return (
    base === "python.exe" ||
    base === "python" ||
    base === "python3" ||
    /^python3\.\d+(\.exe)?$/.test(base)
  );
}

export function isGitExecutableName(exePath: string): boolean {
  const base = path.basename(exePath).toLowerCase();
  return base === "git.exe" || base === "git";
}

export function isProveExecutableName(exePath: string): boolean {
  const base = path.basename(exePath).toLowerCase();
  return base.startsWith("checkwash-prove");
}

export function copyExecutablePreservingMode(srcPath: string, dstPath: string): void {
  fs.copyFileSync(srcPath, dstPath);
  if (!IS_WIN32) {
    fs.chmodSync(dstPath, 0o755);
  }
}

export function writeExecutableDecoyScript(
  filePath: string,
  sentinelPath: string,
  exitCode: number = 99
): void {
  if (IS_WIN32) {
    fs.writeFileSync(
      filePath,
      `@echo off\r\necho DECOY_TRIGGERED > "${sentinelPath}"\r\nexit /b ${exitCode}\r\n`,
      "utf8"
    );
  } else {
    fs.writeFileSync(
      filePath,
      `#!/bin/sh\necho DECOY_TRIGGERED > "${sentinelPath}"\nexit ${exitCode}\n`,
      { encoding: "utf8", mode: 0o755 }
    );
    fs.chmodSync(filePath, 0o755);
  }
}

export function getMinimalBrokerEnv(extra: Record<string, string> = {}): Record<string, string> {
  if (IS_WIN32) {
    return {
      SystemRoot: process.env.SystemRoot || "C:\\Windows",
      PATH: "C:\\Windows\\System32",
      ...extra,
    };
  }
  return {
    PATH: "/usr/local/bin:/usr/bin:/bin",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    TMPDIR: os.tmpdir(),
    ...extra,
  };
}

export function buildDescendantGitIdentityProbeScript(): string {
  if (IS_WIN32) {
    return [
      "import ctypes, ctypes.wintypes, subprocess, hashlib, json, os",
      'p = subprocess.Popen(["git", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)',
      "h = int(p._handle)",
      "buf = ctypes.create_unicode_buffer(32768)",
      "sz = ctypes.wintypes.DWORD(32768)",
      "ok = ctypes.windll.kernel32.QueryFullProcessImageNameW(ctypes.wintypes.HANDLE(h), 0, buf, ctypes.byref(sz))",
      "out, _ = p.communicate()",
      "img = os.path.realpath(buf.value)",
      'sha = hashlib.sha256(open(img, "rb").read()).hexdigest()',
      'print(json.dumps({"ok": bool(ok), "imagePath": img, "sha256": sha, "version": out.decode("utf-8", "replace").strip()}))',
    ].join("; ");
  }
  return [
    "import subprocess, hashlib, json, os",
    'p = subprocess.Popen(["git", "hash-object", "--stdin"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)',
    'img = os.path.realpath(f"/proc/{p.pid}/exe")',
    'p.communicate(b"probe\\n")',
    'ver = subprocess.check_output(["git", "--version"]).decode("utf-8", "replace").strip()',
    'sha = hashlib.sha256(open(img, "rb").read()).hexdigest()',
    'print(json.dumps({"ok": bool(img), "imagePath": img, "sha256": sha, "version": ver}))',
  ].join("; ");
}

export function killProcessTreeBestEffort(pid: number | undefined): void {
  if (!pid || pid <= 0) return;
  try {
    if (IS_WIN32) {
      cp.spawnSync("taskkill.exe", ["/F", "/T", "/PID", String(pid)], {
        windowsHide: true,
        stdio: "ignore",
      });
    } else {
      try {
        process.kill(-pid, "SIGKILL");
      } catch {
        // ignore if not process group leader
      }
      process.kill(pid, "SIGKILL");
    }
  } catch {
    // ignore
  }
}
