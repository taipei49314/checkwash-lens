/**
 * test/v04_wsl_devcontainer_vscode_server_runner.ts
 *
 * v0.4.0 End-to-End Verification Suite:
 *   1. Cross-Platform Remote Host Admission Matrix (`wsl`, `dev-container`, `attached-container` vs
 *      rejected `ssh-remote`, `tunnel`, `codespaces`, virtual workspaces, and cross-OS spoofing).
 *   2. Linux `WSLInterop` (`MZ` `0x4d5a` PE header, `.exe`/`.bat`/`.cmd`, `/mnt/<drive>`) Rejection
 *      and Safe `PATH` Discovery.
 *   3. Cross-OS Machine Settings Isolation (`globalRemoteValue` vs synced local UI `globalLocalValue`
 *      and `Environment Doctor` reporting).
 *   4. POSIX Kernel `(st_dev, st_ino)` Case-Insensitive Mount / Alias Containment & Dynamic VFS
 *      Case-Insensitive Directory Rename Detection (`SNAP-04`).
 *   5. Real `Code.exe` (`1.146.0`) <-> Real `vscode-server-linux-x64` (`1.146.0`) End-to-End Verification
 *      on a Windows 11 host (strictly isolated temp profiles; zero modification to user `~/.vscode` or
 *      `~/.vscode-server`):
 *        - `V04-WSL-B01`: Real WSL2 (`Ubuntu-24.04`) `vscode-server` Restricted Mode (`isTrusted === false`)
 *          with `checkwash-lens-0.4.0-linux-x64.vsix` installed -> `0` child process spawns.
 *        - `V04-WSL-EXT4-E2E`: Real WSL2 (`Ubuntu-24.04`) `vscode-server` Trusted E2E on native `ext4`
 *          (Environment Doctor with Windows `C:\...` `globalLocalValue` isolation, Committed `Block` scan,
 *          `checkwash-rev:` immutable blob, Live Diagnostics & Hover, Staged/Worktree snapshot pre-check,
 *          Context Diet SQL `-- ` secret masking, `cancelActiveScan` `"cancelled"`, and `B08` Remote
 *          Extension Host `SIGKILL` child+grandchild reaping).
 *        - `V04-WSL-DRVFS-MNTC`: Real WSL2 (`Ubuntu-24.04`) `vscode-server` on `/mnt/c/...` (`9p` DrvFS)
 *          proving `/mnt/c/users` vs `/mnt/c/Users` `(st_dev, st_ino)` inside-repo runtime blocking,
 *          `WSLInterop` Windows `.exe`/`MZ` blocking, live diagnostics across case-aliased paths, and
 *          `SNAP-04` case-only rename (`test_calc.py` -> `test_CALC.py`) detection on `9p` DrvFS.
 *        - `V04-DOCKER-DEVCONTAINER-E2E`: Real Docker Linux container (`checkwash-lens-linux-verify:v030`)
 *          running `vscode-server-linux-x64` (`1.146.0`) with `checkwash-lens-0.4.0-linux-x64.vsix`
 *          testing `dev-container` (including real `checkwash-prove v0.1.0` `--list`, Full Prove, and
 *          single-mutant `Replay`) AND `attached-container`.
 *        - `V04-REMOTE-SSH-REJECTED-E2E`: Real `vscode-server-linux-x64` (`1.146.0`) connected via
 *          `ssh-remote` (`vscode.env.remoteName === "ssh-remote"`) -> execution strictly refused (`Not Run`,
 *          `0` broker spawns) while offline report viewing remains functional.
 */

import * as assert from "assert";
import * as cp from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as https from "https";
import * as net from "net";
import * as os from "os";
import * as path from "path";
import * as zlib from "zlib";
import {
  areSameRepositoryPath,
  cleanupIsolatedRunDirectory,
  HostEnvironmentDescriptor,
  isPathInsideOrEqualPlatform,
  isSupportedLinuxRemoteName,
  isWslWindowsMountPath,
  resolveTrustedExecutableFromPath,
  SUPPORTED_LINUX_REMOTE_NAMES,
  tryRelativeInsidePosixInodeRoot,
  verifyLaunchAdmission,
  verifyLinuxNativeExecutableIdentity,
  verifyWorkspaceHostEnvironment,
} from "../runtime/admission";
import { runEnvironmentDoctor } from "../runtime/environmentDoctor";
import { UnifiedProcessRunner } from "../runtime/processRunner";
import { getTotalBrokerSpawnCount, resetTotalBrokerSpawnCountForTests } from "../runtime/windowsBroker";
import {
  ACTIVE_ARCH,
  ACTIVE_PLATFORM,
  getPlatformExecutionMetadata,
  IS_LINUX,
  IS_WIN32,
  killProcessTreeBestEffort,
  resolvePlatformEvidenceDir,
  resolveTestGitExe,
  resolveTestPythonExe,
  resolveTestVscodeExe,
} from "./testPlatformEnv";

const ROOT = path.resolve(__dirname, "..", "..");
const EVIDENCE_DIR = resolvePlatformEvidenceDir(ROOT);
const PYTHON_EXE = resolveTestPythonExe();
const GIT_EXE = resolveTestGitExe();
const PKG_VERSION = (
  JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")) as { version: string }
).version;

interface CaseReceipt {
  id: string;
  title: string;
  status: "PASS" | "FAIL" | "NOT_RUN";
  durationMs: number;
  observations: Record<string, unknown>;
  error?: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sha256File(filePath: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function getGitHeadAndCleanState(): { headSha: string; worktreeClean: boolean } {
  const headSha = cp
    .execFileSync(GIT_EXE, ["-C", ROOT, "rev-parse", "HEAD"], {
      encoding: "utf8",
      windowsHide: true,
    })
    .trim();
  const statusOut = cp
    .execFileSync(GIT_EXE, ["-C", ROOT, "status", "--porcelain"], {
      encoding: "utf8",
      windowsHide: true,
    })
    .trim();
  return { headSha, worktreeClean: statusOut.length === 0 };
}

function makeBaseHostDesc(
  repoRoot: string,
  overrides: Partial<HostEnvironmentDescriptor> = {}
): HostEnvironmentDescriptor {
  return {
    isWorkspaceTrusted: true,
    platform: ACTIVE_PLATFORM,
    arch: ACTIVE_ARCH,
    workspaceScheme: "file",
    isRemote: false,
    remoteName: null,
    isVirtualWorkspace: false,
    extensionRootPath: ROOT,
    repositoryRootPath: repoRoot,
    configuredPythonPath: PYTHON_EXE,
    configuredGitPath: GIT_EXE,
    ...overrides,
  };
}

function initLocalGitRepo(repoDir: string): void {
  fs.mkdirSync(repoDir, { recursive: true });
  const runGit = (args: string[]) => {
    const res = cp.spawnSync(GIT_EXE, ["-C", repoDir, ...args], {
      encoding: "utf8",
      windowsHide: true,
    });
    if (res.status !== 0) {
      throw new Error(`git ${args.join(" ")} failed in ${repoDir}: ${res.stderr}`);
    }
  };
  runGit(["init", "-q"]);
  runGit(["config", "user.name", "Checkwash V04 Test"]);
  runGit(["config", "user.email", "v04@checkwash.local"]);
  fs.writeFileSync(path.join(repoDir, "README.md"), "# v0.4 test\n", "utf8");
  runGit(["add", "."]);
  runGit(["commit", "-q", "-m", "initial"]);
}

function winPathToWslMntPath(winPath: string): string {
  const resolved = path.win32.resolve(winPath);
  const m = /^([a-zA-Z]):\\(.*)$/.exec(resolved);
  if (!m) {
    throw new Error(`Cannot map Windows path '${winPath}' to WSL /mnt/<drive>`);
  }
  const drive = m[1].toLowerCase();
  const rest = m[2].replace(/\\/g, "/");
  return rest.length > 0 ? `/mnt/${drive}/${rest}` : `/mnt/${drive}`;
}

function findFreeTcpPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (!addr || typeof addr === "string") {
        srv.close(() => reject(new Error("Unexpected net.Server address")));
        return;
      }
      const port = addr.port;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

function findVsCodeProductInfo(codeExePath: string): { version: string; commit: string } {
  const codeDir = path.dirname(codeExePath);
  const candidates = [path.join(codeDir, "resources", "app", "product.json")];
  for (const entry of fs.readdirSync(codeDir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      candidates.push(path.join(codeDir, entry.name, "resources", "app", "product.json"));
    }
  }
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      const prod = JSON.parse(fs.readFileSync(p, "utf8")) as {
        version?: string;
        commit?: string;
      };
      if (prod.version && prod.commit) {
        return { version: prod.version, commit: prod.commit };
      }
    }
  }
  throw new Error(`Could not locate VS Code product.json with commit SHA under ${codeDir}`);
}

function downloadHttpsRedirecting(url: string, destPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const visit = (targetUrl: string, redirectsLeft: number) => {
      if (redirectsLeft < 0) {
        reject(new Error(`Too many redirects downloading ${url}`));
        return;
      }
      https
        .get(targetUrl, (res) => {
          const code = res.statusCode ?? 0;
          if ((code === 301 || code === 302 || code === 303 || code === 307 || code === 308) && res.headers.location) {
            res.resume();
            visit(res.headers.location, redirectsLeft - 1);
            return;
          }
          if (code !== 200) {
            res.resume();
            reject(new Error(`HTTP ${code} downloading ${targetUrl}`));
            return;
          }
          const tmpFile = `${destPath}.part-${process.pid}`;
          const out = fs.createWriteStream(tmpFile);
          res.pipe(out);
          out.on("finish", () => {
            out.close(() => {
              fs.renameSync(tmpFile, destPath);
              resolve();
            });
          });
          out.on("error", (err) => {
            try {
              fs.unlinkSync(tmpFile);
            } catch {
              // ignore
            }
            reject(err);
          });
        })
        .on("error", reject);
    };
    visit(url, 5);
  });
}

async function ensureCachedVscodeServerTarball(commit: string): Promise<string> {
  const envTar = process.env.CW_VSCODE_SERVER_TARBALL;
  if (envTar && fs.existsSync(envTar)) {
    return path.resolve(envTar);
  }
  const cacheDir = path.join(os.tmpdir(), "checkwash-vscode-server-cache");
  fs.mkdirSync(cacheDir, { recursive: true });
  const cachedTar = path.join(cacheDir, `vscode-server-linux-x64-${commit}.tar.gz`);
  if (fs.existsSync(cachedTar) && fs.statSync(cachedTar).size > 10_000_000) {
    return cachedTar;
  }
  const downloadUrl = `https://update.code.visualstudio.com/commit:${commit}/server-linux-x64/stable`;
  console.log(`  -> Downloading official vscode-server-linux-x64 (${commit}) to temp cache...`);
  await downloadHttpsRedirecting(downloadUrl, cachedTar);
  return cachedTar;
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function buildMinimalVsixBuffer(files: Array<{ zipPath: string; content: string }>): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;
  for (const item of files) {
    const nameBuf = Buffer.from(item.zipPath, "utf8");
    const rawBuf = Buffer.from(item.content, "utf8");
    const crc = crc32(rawBuf);
    const deflated = zlib.deflateRawSync(rawBuf, { level: 9 });
    const useDeflate = deflated.length < rawBuf.length;
    const method = useDeflate ? 8 : 0;
    const payload = useDeflate ? deflated : rawBuf;

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0x0800, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(((2026 - 1980) << 9) | (1 << 5) | 1, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(payload.length, 18);
    lh.writeUInt32LE(rawBuf.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    localParts.push(lh, nameBuf, payload);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x0800, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(((2026 - 1980) << 9) | (1 << 5) | 1, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(payload.length, 20);
    ch.writeUInt32LE(rawBuf.length, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt32LE(offset, 42);
    centralParts.push(ch, nameBuf);

    offset += lh.length + nameBuf.length + payload.length;
  }
  const cd = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...localParts, cd, eocd]);
}

function createWorkspaceTestDriverVsix(outVsixPath: string): void {
  const pkgJson = JSON.stringify(
    {
      name: "cw-v04-ws-driver",
      publisher: "local-test",
      version: "0.0.1",
      engines: { vscode: "^1.96.0" },
      extensionKind: ["workspace"],
      capabilities: {
        untrustedWorkspaces: {
          supported: true,
        },
      },
      activationEvents: ["*"],
      main: "./index.js",
    },
    null,
    2
  );

  const driverJs = `"use strict";
const cp = require("child_process");
const fs = require("fs");
const path = require("path");
const vscode = require("vscode");

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function writeJsonAtomic(filePath, obj) {
  const tmp = filePath + ".tmp-" + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), "utf8");
  fs.renameSync(tmp, filePath);
}

function isPidAlive(pid) {
  if (!pid || pid <= 0) return false;
  try {
    process.kill(pid, 0);
  } catch (e) {
    if (!(e && e.code === "EPERM")) return false;
  }
  try {
    const st = fs.readFileSync("/proc/" + pid + "/stat", "utf8");
    const idx = st.lastIndexOf(")");
    const ch = idx >= 0 ? st.slice(idx + 1).trim()[0] : "";
    if (ch === "Z" || ch === "X") return false;
  } catch {
    return false;
  }
  return true;
}

async function waitForOperationActive(processRunner, timeoutMs) {
  const start = Date.now();
  while (!processRunner.isOperationActive()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error("Timed out waiting for processRunner.isOperationActive() === true");
    }
    await sleep(5);
  }
}

async function runScenario(cfg) {
  const receipt = {
    ok: false,
    scenario: cfg.scenario,
    extHostPid: process.pid,
    platform: process.platform,
    arch: process.arch,
    execPath: process.execPath,
    vscodeVersion: vscode.version,
    remoteName: vscode.env.remoteName || null,
    isTrusted: vscode.workspace.isTrusted,
    folders: (vscode.workspace.workspaceFolders || []).map((f) => ({
      name: f.name,
      scheme: f.uri.scheme,
      fsPath: f.uri.fsPath,
    })),
  };

  try {
    const ext = vscode.extensions.getExtension("taipei49314.checkwash-lens");
    if (!ext) {
      throw new Error("Installed extension taipei49314.checkwash-lens not found in vscode-server");
    }
    receipt.extensionPath = ext.extensionPath;
    receipt.extensionVersion = ext.packageJSON && ext.packageJSON.version;

    if (cfg.scenario === "wsl_restricted_b01") {
      const spawned = [];
      const origSpawn = cp.ChildProcess.prototype.spawn;
      cp.ChildProcess.prototype.spawn = function(opts) {
        spawned.push(opts && opts.file ? String(opts.file) : "unknown");
        return origSpawn.apply(this, arguments);
      };
      try {
        if (vscode.workspace.isTrusted !== false) {
          throw new Error("Expected Restricted Mode (isTrusted === false), got " + String(vscode.workspace.isTrusted));
        }
        if (vscode.env.remoteName !== "wsl") {
          throw new Error("Expected remoteName === 'wsl', got " + String(vscode.env.remoteName));
        }
        const controller = await ext.activate();
        const scanSnap = await vscode.commands.executeCommand("checkwashLens.scanCommittedRange", "HEAD~1..HEAD");
        const snapPre = await vscode.commands.executeCommand("checkwashLens.scanUncommittedSnapshot", "worktree");
        const docRep = await vscode.commands.executeCommand("checkwashLens.runEnvironmentDoctor", { silentUi: true });
        const offlineSnap = await vscode.commands.executeCommand(
          "checkwashLens.viewOfflineReport",
          vscode.Uri.file(cfg.offlineReportPath)
        );
        if (spawned.length !== 0) {
          throw new Error("Unexpected child process spawn in WSL Restricted Mode: " + JSON.stringify(spawned));
        }
        if (!scanSnap || scanSnap.evaluatedState.state !== "Not Run") {
          throw new Error("Expected scan state Not Run in Restricted Mode");
        }
        if (!snapPre || snapPre.evaluatedState.state !== "Not Run") {
          throw new Error("Expected uncommitted scan state Not Run in Restricted Mode");
        }
        if (!docRep || docRep.externalProcessesSpawned !== false) {
          throw new Error("Expected Doctor externalProcessesSpawned === false in Restricted Mode");
        }
        if (!offlineSnap || !offlineSnap.offlineFindingsPreview) {
          throw new Error("Expected offline report read-only view to work in Restricted Mode");
        }
        receipt.ok = true;
        receipt.spawnedCount = spawned.length;
        receipt.doctorSummary = docRep.checks.hostCapability.summary;
        receipt.offlineReadOnlyWorked = Boolean(offlineSnap.offlineFindingsPreview);
      } finally {
        cp.ChildProcess.prototype.spawn = origSpawn;
      }
      writeJsonAtomic(cfg.receiptPath, receipt);
      return;
    }

    if (cfg.scenario === "wsl_ext4_full_and_b08") {
      if (vscode.env.remoteName !== "wsl" || vscode.workspace.isTrusted !== true) {
        throw new Error("Expected trusted wsl remote workspace, got remote=" + vscode.env.remoteName + " trusted=" + vscode.workspace.isTrusted);
      }
      const controller = await ext.activate();
      controller.selectRepository(cfg.repoDir);
      let pyInspect = vscode.workspace.getConfiguration("checkwashLens").inspect("pythonPath");
      const cfgSyncStart = Date.now();
      while (
        (!pyInspect ||
          (!String(pyInspect.globalValue || "").includes("EvilWindows") &&
            !String(pyInspect.globalLocalValue || "").includes("EvilWindows"))) &&
        Date.now() - cfgSyncStart < 25000
      ) {
        await sleep(50);
        pyInspect = vscode.workspace.getConfiguration("checkwashLens").inspect("pythonPath");
      }

      // 1. Environment Doctor: verify local Windows UI C:\\EvilWindows\\python.exe was isolated and ignored!
      const docRep = await vscode.commands.executeCommand("checkwashLens.runEnvironmentDoctor", { silentUi: true });
      if (!docRep || !docRep.overallReadyForStaticScan) {
        throw new Error("Doctor failed in WSL ext4 workspace: " + JSON.stringify(docRep && docRep.checks));
      }
      if (!String(docRep.checks.hostCapability.summary).includes("remote workspace ('wsl') verified")) {
        throw new Error("Doctor hostCapability did not report WSL remote verification: " + docRep.checks.hostCapability.summary);
      }

      // 2. Open test file & run committed scan -> Block + checkwash-rev: + Diagnostics + Hover
      const testUri = vscode.Uri.file(path.join(cfg.repoDir, "tests", "test_calc.py"));
      const openDoc = await vscode.workspace.openTextDocument(testUri);
      await vscode.window.showTextDocument(openDoc, { preview: false });

      const scanSnap = await vscode.commands.executeCommand(
        "checkwashLens.scanCommittedRange",
        cfg.baseOid + ".." + cfg.headOid
      );
      if (!scanSnap || scanSnap.evaluatedState.state !== "Block") {
        throw new Error("Expected Block verdict in WSL ext4 scan, got " + JSON.stringify(scanSnap && scanSnap.evaluatedState));
      }
      const diags = vscode.languages.getDiagnostics(testUri);
      const cwDiagCount = diags.filter((d) => String(d.source || "").includes("Checkwash")).length;
      if (cwDiagCount < 1) {
        throw new Error("Expected live Checkwash diagnostics in WSL ext4 workspace");
      }
      const finding = scanSnap.enrichedFindings[0];
      const revDoc = await vscode.workspace.openTextDocument(vscode.Uri.parse(finding.preferredRevisionUri));
      if (!revDoc.getText().includes("assert True")) {
        throw new Error("Immutable checkwash-rev: document missing expected blob content");
      }

      // 3. Context Diet SQL '-- api_key' deletion hunk masking
      const diet = controller.prepareContextDietCopy({ mode: "redacted" });
      if (!diet.ok || diet.value.payloadToCopy.includes(cfg.sqlSecret) || !diet.value.payloadToCopy.includes("--- a/db/init.sql")) {
        throw new Error("Context Diet SQL secret masking failed inside WSL vscode-server");
      }

      // 4. Uncommitted snapshot pre-check (worktree)
      fs.writeFileSync(
        path.join(cfg.repoDir, "tests", "test_calc.py"),
        "def test_add():\\n    pass\\n",
        "utf8"
      );
      const wtSnap = await vscode.commands.executeCommand("checkwashLens.scanUncommittedSnapshot", "worktree");
      if (!wtSnap || wtSnap.evaluatedState.state !== "Block") {
        throw new Error("Expected Block on WSL uncommitted worktree snapshot, got " + JSON.stringify(wtSnap && wtSnap.evaluatedState));
      }

      // 5. Real user cancellation via checkwashLens.cancelActiveScan -> strict 'cancelled'
      const wslHostDesc = {
        isWorkspaceTrusted: true,
        platform: "linux",
        arch: "x64",
        workspaceScheme: "file",
        isRemote: true,
        remoteName: "wsl",
        isVirtualWorkspace: false,
        extensionRootPath: ext.extensionPath,
        repositoryRootPath: cfg.repoDir,
        configuredPythonPath: docRep.checks.pythonRuntime.canonicalPath,
        configuredGitPath: docRep.checks.gitRuntimeAndBareGit.canonicalPath,
      };
      const slowOp = controller.getProcessRunner().runExclusiveCancelableOperation((abortSignal) =>
        controller.getProcessRunner().executeGatedProcess({
          hostDesc: wslHostDesc,
          executableSelector: (ctx) => ctx.canonicalPythonPath,
          argsBuilder: () => ["-I", "-S", "-B", "-c", "import time; time.sleep(30)"],
          timeoutMs: 30000,
          abortSignal,
        })
      );
      await waitForOperationActive(controller.getProcessRunner(), 5000);
      await vscode.commands.executeCommand("checkwashLens.cancelActiveScan");
      const slowOut = await slowOp;
      if (!slowOut.ok || slowOut.value.outcome.status !== "cancelled" || !slowOut.value.outcome.cleanupConfirmed || controller.getProcessRunner().hasUnconfirmedCleanup()) {
        throw new Error("WSL cancelActiveScan did not confirm cancelled stop: " + JSON.stringify({ slowOut }));
      }

      // 6. Launch long-running child + grandchild tree inside WSL vscode-server for B08 SIGKILL reaping test!
      const pidFile = path.join(cfg.workDir, "wsl-b08-pids.json");
      const pyTree = [
        "import subprocess, sys, time, json, os, pathlib",
        "ch = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', 'import time; time.sleep(60)'])",
        "tmp_p = " + JSON.stringify(pidFile + ".tmp"),
        "pathlib.Path(tmp_p).write_text(json.dumps({'parentPid': os.getpid(), 'grandchildPid': ch.pid}), encoding='utf-8')",
        "os.replace(tmp_p, " + JSON.stringify(pidFile) + ")",
        "time.sleep(60)"
      ].join("; ");

      void controller.getProcessRunner().runExclusiveCancelableOperation((abortSignal) =>
        controller.getProcessRunner().executeGatedProcess({
          hostDesc: wslHostDesc,
          executableSelector: (ctx) => ctx.canonicalPythonPath,
          argsBuilder: () => ["-I", "-S", "-B", "-c", pyTree],
          timeoutMs: 60000,
          abortSignal,
        })
      );

      const waitPidStart = Date.now();
      while (!fs.existsSync(pidFile)) {
        if (Date.now() - waitPidStart > 10000) {
          throw new Error("Timed out waiting for WSL B08 child+grandchild PIDs");
        }
        await sleep(20);
      }
      const treePids = JSON.parse(fs.readFileSync(pidFile, "utf8"));
      if (!isPidAlive(treePids.parentPid) || !isPidAlive(treePids.grandchildPid)) {
        throw new Error("WSL B08 child/grandchild not alive prior to SIGKILL");
      }

      receipt.ok = true;
      receipt.inspectedPythonPath = pyInspect;
      receipt.doctorHostSummary = docRep.checks.hostCapability.summary;
      receipt.doctorWarnings = docRep.workspaceSettingsWarnings;
      receipt.committedVerdict = scanSnap.evaluatedState.state;
      receipt.cwDiagnosticsCount = cwDiagCount;
      receipt.worktreeSnapshotVerdict = wtSnap.evaluatedState.state;
      receipt.cancelOutcomeStatus = slowOut.value.outcome.status;
      receipt.b08TreePids = {
        extHostPid: process.pid,
        parentPid: treePids.parentPid,
        grandchildPid: treePids.grandchildPid,
      };
      writeJsonAtomic(cfg.receiptPath, receipt);
      // Stay alive waiting for outer orchestrator to SIGKILL extHostPid!
      await sleep(60000);
      return;
    }

    if (cfg.scenario === "wsl_drvfs_mntc") {
      if (vscode.env.remoteName !== "wsl") {
        throw new Error("Expected remoteName === 'wsl'");
      }
      const admMod = require(path.join(ext.extensionPath, "dist", "runtime", "admission.js"));
      const controller = await ext.activate();
      controller.selectRepository(cfg.repoDirUpper);

      // Verify realpathSync.native preserves distinct strings on WSL2 9p DrvFS while sharing (st_dev, st_ino)!
      const realUpper = fs.realpathSync.native(cfg.repoDirUpper);
      const realLower = fs.realpathSync.native(cfg.repoDirLower);
      const sameRepo = admMod.areSameRepositoryPath(cfg.repoDirUpper, cfg.repoDirLower);
      if (!sameRepo) {
        throw new Error("areSameRepositoryPath failed on /mnt/c case-aliased paths: " + realUpper + " vs " + realLower);
      }

      // 1. Inside-repo Python via lowercase /mnt/c/users/... alias MUST be rejected with 0 spawns!
      const docRep = await vscode.commands.executeCommand("checkwashLens.runEnvironmentDoctor", { silentUi: true });
      const insideAliasPy = path.posix.join(cfg.repoDirLower, "evil-bin", "python3");
      const aliasAdm = admMod.verifyLaunchAdmission({
        isWorkspaceTrusted: true,
        platform: "linux",
        arch: "x64",
        workspaceScheme: "file",
        isRemote: true,
        remoteName: "wsl",
        isVirtualWorkspace: false,
        extensionRootPath: ext.extensionPath,
        repositoryRootPath: cfg.repoDirUpper,
        configuredPythonPath: insideAliasPy,
        configuredGitPath: docRep.checks.gitRuntimeAndBareGit.canonicalPath,
      });
      if (aliasAdm.ok || !String(aliasAdm.error).includes("inside target repository")) {
        throw new Error("Expected lowercase /mnt/c/users inside-repo Python to be rejected, got: " + JSON.stringify(aliasAdm));
      }

      // 2. WSLInterop Windows PE ('MZ') binary (both on /mnt/c/*.exe AND copied to /tmp/fake-py without .exe) MUST be rejected!
      const wslExeAdm = admMod.verifyLaunchAdmission({
        isWorkspaceTrusted: true,
        platform: "linux",
        arch: "x64",
        workspaceScheme: "file",
        isRemote: true,
        remoteName: "wsl",
        isVirtualWorkspace: false,
        extensionRootPath: ext.extensionPath,
        repositoryRootPath: cfg.repoDirUpper,
        configuredPythonPath: cfg.mntcExePath,
        configuredGitPath: docRep.checks.gitRuntimeAndBareGit.canonicalPath,
      });
      const tmpMzAdm = admMod.verifyLaunchAdmission({
        isWorkspaceTrusted: true,
        platform: "linux",
        arch: "x64",
        workspaceScheme: "file",
        isRemote: true,
        remoteName: "wsl",
        isVirtualWorkspace: false,
        extensionRootPath: ext.extensionPath,
        repositoryRootPath: cfg.repoDirUpper,
        configuredPythonPath: cfg.ext4MzBinaryPath,
        configuredGitPath: docRep.checks.gitRuntimeAndBareGit.canonicalPath,
      });
      if (wslExeAdm.ok || tmpMzAdm.ok || !String(tmpMzAdm.error).includes("MZ header")) {
        throw new Error("Expected WSLInterop /mnt/c exe and ext4 MZ binary to be rejected: " + JSON.stringify({ wslExeAdm, tmpMzAdm }));
      }

      // 3. Committed scan on /mnt/c DrvFS repository + tryRelativeInsidePosixInodeRoot check
      const relViaAlias = admMod.tryRelativeInsidePosixInodeRoot(
        cfg.repoDirUpper,
        path.posix.join(cfg.repoDirLower, "tests", "test_calc.py")
      );
      if (relViaAlias !== "tests/test_calc.py") {
        throw new Error("Expected tryRelativeInsidePosixInodeRoot -> 'tests/test_calc.py', got: " + String(relViaAlias));
      }

      const scanSnap = await vscode.commands.executeCommand(
        "checkwashLens.scanCommittedRange",
        cfg.baseOid + ".." + cfg.headOid
      );
      if (!scanSnap || scanSnap.evaluatedState.state !== "Block") {
        throw new Error("Expected Block verdict on /mnt/c DrvFS committed scan, got " + JSON.stringify(scanSnap && scanSnap.evaluatedState));
      }

      // 4. SNAP-04 case-only rename on /mnt/c DrvFS (tests/test_good.py -> tests/test_GOOD.py without git mv)
      // On /mnt/c (9p DrvFS) with .git/config ignorecase=true, git ls-files --others hides tests/test_GOOD.py;
      // only detectDirectoryCaseInsensitive via (st_dev, st_ino) stages tests/test_GOOD.py into the snapshot tree!
      const origCaseFile = path.posix.join(cfg.repoDirUpper, "tests", "test_good.py");
      const upperCaseFile = path.posix.join(cfg.repoDirUpper, "tests", "test_GOOD.py");
      const tmpRenameFile = path.posix.join(cfg.repoDirUpper, "tests", "test_good_tmp_rename.py");
      fs.renameSync(origCaseFile, tmpRenameFile);
      fs.writeFileSync(tmpRenameFile, "from calc import mul\\n\\ndef test_keep():\\n    assert True\\n", "utf8");
      fs.renameSync(tmpRenameFile, upperCaseFile);

      const snapRes = await vscode.commands.executeCommand("checkwashLens.scanUncommittedSnapshot", "worktree");
      if (!snapRes || snapRes.evaluatedState.state !== "Block") {
        throw new Error("Expected Block on /mnt/c SNAP-04 case-only rename worktree snapshot, got " + JSON.stringify(snapRes && snapRes.evaluatedState));
      }
      const keptPaths = (snapRes.contextDietResult && snapRes.contextDietResult.keptFilePaths) || [];
      const changedPaths = (snapRes.enrichedFindings || []).map(
        (f) => (f.item && (f.item.resolvedSourcePath || f.item.declaredUnitPath)) || ""
      );
      if (!keptPaths.includes("tests/test_GOOD.py")) {
        throw new Error("Expected case-renamed 'tests/test_GOOD.py' staged in /mnt/c worktree snapshot diff keptFilePaths, got: " + JSON.stringify({ keptPaths, changedPaths }));
      }

      receipt.ok = true;
      receipt.realpathPreservedCaseStrings = realUpper !== realLower;
      receipt.realUpper = realUpper;
      receipt.realLower = realLower;
      receipt.insideRepoLowercaseAliasRejected = !aliasAdm.ok;
      receipt.wslMntcExeRejected = !wslExeAdm.ok;
      receipt.ext4MzHeaderRejected = !tmpMzAdm.ok;
      receipt.committedDrvfsVerdict = scanSnap.evaluatedState.state;
      receipt.snap04KeptFilePaths = keptPaths;
      receipt.snap04CaseRenameFindings = changedPaths;
      writeJsonAtomic(cfg.receiptPath, receipt);
      return;
    }

    if (cfg.scenario === "docker_devcontainer_full") {
      if (vscode.env.remoteName !== cfg.expectedRemoteName) {
        throw new Error("Expected remoteName === " + cfg.expectedRemoteName + ", got " + String(vscode.env.remoteName));
      }
      const controller = await ext.activate();
      controller.selectRepository(cfg.repoDir);

      // Pin provePath in Remote Machine settings via VS Code ConfigurationTarget.Global inside vscode-server!
      await vscode.workspace
        .getConfiguration("checkwashLens")
        .update("provePath", cfg.proveExe, vscode.ConfigurationTarget.Global);
      const inspectedProve = vscode.workspace.getConfiguration("checkwashLens").inspect("provePath");

      const docRep = await vscode.commands.executeCommand("checkwashLens.runEnvironmentDoctor", { silentUi: true });
      if (!docRep || !docRep.overallReadyForStaticScan || !docRep.overallReadyForProve) {
        throw new Error("Expected Doctor static + Prove ready in Docker DevContainer: " + JSON.stringify({ checks: docRep && docRep.checks, inspectedProve }));
      }

      const scanSnap = await vscode.commands.executeCommand(
        "checkwashLens.scanCommittedRange",
        cfg.baseOid + ".." + cfg.headOid
      );
      if (!scanSnap || scanSnap.evaluatedState.state !== "Block") {
        throw new Error("Expected Block in Docker DevContainer committed scan");
      }

      if (cfg.runProveSuite) {
        const hostDesc = {
          isWorkspaceTrusted: true,
          platform: "linux",
          arch: "x64",
          workspaceScheme: "file",
          isRemote: true,
          remoteName: cfg.expectedRemoteName,
          isVirtualWorkspace: false,
          extensionRootPath: ext.extensionPath,
          repositoryRootPath: cfg.repoDir,
          configuredPythonPath: docRep.checks.pythonRuntime.canonicalPath,
          configuredGitPath: docRep.checks.gitRuntimeAndBareGit.canonicalPath,
        };
        const rawRangeSpec = cfg.baseOid + ".." + cfg.headOid;
        // 1) Prove --list
        const listPlan = await controller.prepareProveManualCommandPlan({
          hostDesc,
          configuredProvePath: cfg.proveExe,
          rawRangeSpec,
          entryKind: "list",
        });
        if (!listPlan.ok) {
          throw new Error("Prove list plan failed in DevContainer: " + listPlan.error);
        }
        const listAuth = controller.getProveRunner().issueManualAuthorizationToken({
          plan: listPlan.value,
          userConfirmedExecutionRisk: true,
        });
        const listSnap = await controller.executeAuthorizedProveCommand({
          hostDesc,
          configuredProvePath: cfg.proveExe,
          authorization: listAuth,
          expectedEntryKind: "list",
        });
        if (listSnap.proveOutcome.status !== "Listed") {
          throw new Error("Expected Prove status Listed in DevContainer, got " + JSON.stringify(listSnap.proveOutcome));
        }

        // 2) Full Prove -> Compared with protectionLosses.length >= 1
        const fullPlan = await controller.prepareProveManualCommandPlan({
          hostDesc,
          configuredProvePath: cfg.proveExe,
          rawRangeSpec,
          entryKind: "full",
        });
        if (!fullPlan.ok) {
          throw new Error("Prove full plan failed in DevContainer: " + fullPlan.error);
        }
        const fullAuth = controller.getProveRunner().issueManualAuthorizationToken({
          plan: fullPlan.value,
          userConfirmedExecutionRisk: true,
        });
        const fullSnap = await controller.executeAuthorizedProveCommand({
          hostDesc,
          configuredProvePath: cfg.proveExe,
          authorization: fullAuth,
          expectedEntryKind: "full",
        });
        if (
          fullSnap.proveOutcome.status !== "Compared" ||
          !fullSnap.proveOutcome.record ||
          fullSnap.proveOutcome.record.parsedReport.protectionLosses.length < 1
        ) {
          throw new Error("Expected Compared + protectionLosses >= 1 in DevContainer Full Prove, got " + JSON.stringify(fullSnap.proveOutcome));
        }

        // 3) Single-Mutant Replay
        const lossMutantId = fullSnap.proveOutcome.record.parsedReport.protectionLosses[0].id;
        const replayPlan = await controller.prepareProveReplayCommandPlan({
          hostDesc,
          configuredProvePath: cfg.proveExe,
          recordRunId: fullSnap.proveOutcome.record.runId,
          selectedMutantId: lossMutantId,
        });
        if (!replayPlan.ok) {
          throw new Error("Prove replay plan failed in DevContainer: " + replayPlan.error);
        }
        const replayAuth = controller.getProveRunner().issueManualAuthorizationToken({
          plan: replayPlan.value,
          userConfirmedExecutionRisk: true,
        });
        const replaySnap = await controller.executeAuthorizedProveCommand({
          hostDesc,
          configuredProvePath: cfg.proveExe,
          authorization: replayAuth,
          expectedEntryKind: "replay",
          expectedRecordRunId: fullSnap.proveOutcome.record.runId,
          expectedSelectedMutantId: lossMutantId,
        });
        if (
          replaySnap.proveOutcome.status !== "Compared" ||
          !replaySnap.proveOutcome.record ||
          replaySnap.proveOutcome.record.parsedReport.runCount !== 1 ||
          replaySnap.proveOutcome.record.parsedReport.protectionLosses.length < 1
        ) {
          throw new Error("Expected Compared (runCount=1, protectionLosses>=1) on DevContainer Replay, got " + JSON.stringify(replaySnap.proveOutcome));
        }
        receipt.proveListStatus = listSnap.proveOutcome.status;
        receipt.proveFullStatus = fullSnap.proveOutcome.status;
        receipt.proveProtectionLossesCount = fullSnap.proveOutcome.record.parsedReport.protectionLosses.length;
        receipt.proveReplayMutantId = lossMutantId;
        receipt.proveReplayStatus = replaySnap.proveOutcome.status;
        receipt.proveReplayRunCount = replaySnap.proveOutcome.record.parsedReport.runCount;
      }

      receipt.ok = true;
      receipt.doctorHostSummary = docRep.checks.hostCapability.summary;
      receipt.committedVerdict = scanSnap.evaluatedState.state;
      writeJsonAtomic(cfg.receiptPath, receipt);
      return;
    }

    if (cfg.scenario === "remote_ssh_rejected") {
      if (vscode.env.remoteName !== "ssh-remote") {
        throw new Error("Expected remoteName === 'ssh-remote', got " + String(vscode.env.remoteName));
      }
      const spawned = [];
      const origSpawn = cp.ChildProcess.prototype.spawn;
      cp.ChildProcess.prototype.spawn = function(opts) {
        spawned.push(opts && opts.file ? String(opts.file) : "unknown");
        return origSpawn.apply(this, arguments);
      };
      try {
        const controller = await ext.activate();
        controller.selectRepository(cfg.repoDir);
        const scanSnap = await vscode.commands.executeCommand("checkwashLens.scanCommittedRange", "HEAD~1..HEAD");
        const snapPre = await vscode.commands.executeCommand("checkwashLens.scanUncommittedSnapshot", "worktree");
        const docRep = await vscode.commands.executeCommand("checkwashLens.runEnvironmentDoctor", { silentUi: true });
        const offlineSnap = await vscode.commands.executeCommand(
          "checkwashLens.viewOfflineReport",
          vscode.Uri.file(cfg.offlineReportPath)
        );
        if (spawned.length !== 0) {
          throw new Error("Unexpected process spawn in rejected ssh-remote workspace: " + JSON.stringify(spawned));
        }
        if (
          !scanSnap ||
          scanSnap.evaluatedState.state !== "Error" ||
          !String(scanSnap.evaluatedState.errorReason || "").includes("ssh-remote")
        ) {
          throw new Error("Expected Error mentioning ssh-remote with 0 spawns, got: " + JSON.stringify(scanSnap && scanSnap.evaluatedState));
        }
        if (
          !snapPre ||
          snapPre.evaluatedState.state !== "Error" ||
          !String(snapPre.evaluatedState.errorReason || "").includes("ssh-remote")
        ) {
          throw new Error("Expected Error mentioning ssh-remote for uncommitted snapshot");
        }
        if (!docRep || docRep.checks.hostCapability.status !== "error" || docRep.externalProcessesSpawned !== false) {
          throw new Error("Expected Doctor hostCapability error with 0 spawns in ssh-remote: " + JSON.stringify(docRep));
        }
        if (!offlineSnap || !offlineSnap.offlineFindingsPreview) {
          throw new Error("Expected offline report viewer to remain functional in ssh-remote");
        }
        receipt.ok = true;
        receipt.spawnedCount = spawned.length;
        receipt.rejectedErrorReason = scanSnap.evaluatedState.errorReason;
        receipt.doctorSummary = docRep.checks.hostCapability.summary;
        receipt.offlineReadOnlyWorked = Boolean(offlineSnap.offlineFindingsPreview);
      } finally {
        cp.ChildProcess.prototype.spawn = origSpawn;
      }
      writeJsonAtomic(cfg.receiptPath, receipt);
      return;
    }

    throw new Error("Unknown scenario: " + cfg.scenario);
  } catch (err) {
    receipt.ok = false;
    receipt.error = err && (err.stack || err.message) ? (err.stack || err.message) : String(err);
    writeJsonAtomic(cfg.receiptPath, receipt);
  }
}

exports.activate = function() {
  const cfgPath = process.env.CW_V04_SCENARIO_CONFIG;
  if (!cfgPath || !fs.existsSync(cfgPath)) {
    return;
  }
  const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  setImmediate(() => {
    void runScenario(cfg);
  });
};
`;

  const vsixBuf = buildMinimalVsixBuffer([
    {
      zipPath: "[Content_Types].xml",
      content:
        '<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="json" ContentType="application/json"/><Default Extension="js" ContentType="application/javascript"/><Default Extension="vsixmanifest" ContentType="text/xml"/></Types>',
    },
    {
      zipPath: "extension.vsixmanifest",
      content:
        '<?xml version="1.0" encoding="utf-8"?><PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011"><Metadata><Identity Language="en-US" Id="cw-v04-ws-driver" Version="0.0.1" Publisher="local-test"/><DisplayName>cw-v04-ws-driver</DisplayName><Description>v0.4 vscode-server workspace test driver</Description><Categories>Other</Categories><Properties><Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace"/></Properties></Metadata><Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation><Dependencies/><Assets><Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json"/></Assets></PackageManifest>',
    },
    { zipPath: "extension/package.json", content: pkgJson },
    { zipPath: "extension/index.js", content: driverJs },
  ]);
  fs.writeFileSync(outVsixPath, vsixBuf);
}

function createUiRemoteResolverExtension(uiResolverDir: string): void {
  fs.mkdirSync(uiResolverDir, { recursive: true });
  fs.writeFileSync(
    path.join(uiResolverDir, "package.json"),
    JSON.stringify(
      {
        name: "cw-remote-resolver",
        publisher: "local-test",
        version: "0.0.1",
        engines: { vscode: "^1.96.0" },
        extensionKind: ["ui"],
        capabilities: {
          untrustedWorkspaces: {
            supported: true,
          },
        },
        enabledApiProposals: ["resolvers"],
        activationEvents: [
          "onResolveRemoteAuthority:wsl",
          "onResolveRemoteAuthority:dev-container",
          "onResolveRemoteAuthority:attached-container",
          "onResolveRemoteAuthority:ssh-remote",
        ],
        main: "./index.js",
      },
      null,
      2
    ),
    "utf8"
  );
  fs.writeFileSync(
    path.join(uiResolverDir, "index.js"),
    `"use strict";
const fs = require("fs");
const vscode = require("vscode");
exports.activate = function(context) {
  const cfg = JSON.parse(fs.readFileSync(process.env.CW_REMOTE_RESOLVER_CONFIG, "utf8"));
  for (const scheme of ["wsl", "dev-container", "attached-container", "ssh-remote"]) {
    context.subscriptions.push(
      vscode.workspace.registerRemoteAuthorityResolver(scheme, {
        resolve() {
          return new vscode.ResolvedAuthority("127.0.0.1", cfg.port, cfg.token);
        }
      })
    );
  }
};
`,
    "utf8"
  );
}

async function waitForFileJson<T = Record<string, unknown>>(
  filePath: string,
  timeoutMs: number,
  diagFn?: () => string
): Promise<T> {
  const start = Date.now();
  while (!fs.existsSync(filePath)) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(
        `Timed out after ${timeoutMs}ms waiting for ${filePath}${diagFn ? `\nDiag:\n${diagFn()}` : ""}`
      );
    }
    await sleep(60);
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
}

function launchWinCodeClientToRemote(params: {
  codeExePath: string;
  uiResolverDir: string;
  resolverConfigPath: string;
  userDataDir: string;
  extensionsDir: string;
  folderUri: string;
  trustedWindow: boolean;
  userSettings: Record<string, unknown>;
}): { proc: cp.ChildProcess; getLogs: () => string; shutdown: () => Promise<void> } {
  fs.mkdirSync(path.join(params.userDataDir, "User"), { recursive: true });
  fs.mkdirSync(params.extensionsDir, { recursive: true });
  fs.writeFileSync(
    path.join(params.userDataDir, "User", "settings.json"),
    JSON.stringify(
      {
        "git.enabled": false,
        "git.autoRepositoryDetection": false,
        "extensions.autoUpdate": false,
        "extensions.autoCheckUpdates": false,
        "telemetry.telemetryLevel": "off",
        "update.mode": "none",
        "window.restoreWindows": "none",
        ...params.userSettings,
      },
      null,
      2
    ),
    "utf8"
  );

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    CW_REMOTE_RESOLVER_CONFIG: params.resolverConfigPath,
  };
  delete env.ELECTRON_RUN_AS_NODE;

  const args = [
    "--headless",
    "--disable-gpu",
    "--disable-updates",
    "--skip-welcome",
    "--skip-release-notes",
    ...(params.trustedWindow ? ["--disable-workspace-trust"] : []),
    "--disable-extension=vscode.git",
    "--disable-extension=vscode.git-base",
    "--disable-extension=vscode.github",
    "--disable-extension=vscode.typescript-language-features",
    "--disable-extension=vscode.json-language-features",
    `--user-data-dir=${params.userDataDir}`,
    `--extensions-dir=${params.extensionsDir}`,
    `--extensionDevelopmentPath=${params.uiResolverDir}`,
    "--enable-proposed-api=local-test.cw-remote-resolver",
    `--folder-uri=${params.folderUri}`,
  ];

  const proc = cp.spawn(params.codeExePath, args, {
    env,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let out = "";
  let err = "";
  proc.stdout?.on("data", (d: Buffer) => {
    out += d.toString("utf8");
  });
  proc.stderr?.on("data", (d: Buffer) => {
    err += d.toString("utf8");
  });
  return {
    proc,
    getLogs: () => `Code.exe stdout:\n${out.slice(-1500)}\nCode.exe stderr:\n${err.slice(-1500)}`,
    shutdown: async () => {
      killProcessTreeBestEffort(proc.pid);
      if (proc.exitCode === null) {
        await Promise.race([
          new Promise<void>((resolve) => proc.once("close", () => resolve())),
          sleep(4000),
        ]);
      }
      // Allow Chromium / VS Code `.vscode-shared/sharedStorage/state.vscdb` utility child processes to release SQLite locks
      await sleep(2000);
    },
  };
}

async function main(): Promise<void> {
  console.log("=== Checkwash Lens v0.4.0 WSL2 + Dev Container + vscode-server Verification ===");
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

  const cases: CaseReceipt[] = [];
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-v04-suite-"));

  const caseFilter = (process.env.CW_V04_FILTER || "").trim();
  const runCase = async (
    id: string,
    title: string,
    fn: () => Promise<Record<string, unknown>>
  ): Promise<void> => {
    if (caseFilter && id !== caseFilter) {
      return;
    }
    const start = Date.now();
    try {
      const observations = await fn();
      const durationMs = Date.now() - start;
      cases.push({ id, title, status: "PASS", durationMs, observations });
      console.log(`  [PASS] ${id}: ${title} (${durationMs}ms)`);
    } catch (err) {
      const durationMs = Date.now() - start;
      const msg = err instanceof Error ? err.stack || err.message : String(err);
      cases.push({ id, title, status: "FAIL", durationMs, observations: {}, error: msg });
      console.error(`  [FAIL] ${id}: ${title}\n${msg}`);
    }
  };

  try {
    const unitRepo = path.join(tempRoot, "unit-repo");
    initLocalGitRepo(unitRepo);

    // =========================================================================
    // V04-U01: Remote Host Admission Matrix (Both OSes)
    // =========================================================================
    await runCase(
      "V04-U01",
      "verifyWorkspaceHostEnvironment & verifyLaunchAdmission remote/virtual matrix",
      async () => {
        resetTotalBrokerSpawnCountForTests();

        assert.deepStrictEqual(SUPPORTED_LINUX_REMOTE_NAMES, [
          "wsl",
          "dev-container",
          "attached-container",
        ]);
        assert.strictEqual(isSupportedLinuxRemoteName("wsl"), true);
        assert.strictEqual(isSupportedLinuxRemoteName("  DEV-CONTAINER "), true);
        assert.strictEqual(isSupportedLinuxRemoteName("attached-container"), true);
        assert.strictEqual(isSupportedLinuxRemoteName("ssh-remote"), false);
        assert.strictEqual(isSupportedLinuxRemoteName("tunnel"), false);
        assert.strictEqual(isSupportedLinuxRemoteName("codespaces"), false);
        assert.strictEqual(isSupportedLinuxRemoteName(null), false);

        const rejectedRemotes = ["ssh-remote", "tunnel", "codespaces", "k8s-container", ""];
        for (const rName of rejectedRemotes) {
          const res = verifyLaunchAdmission(
            makeBaseHostDesc(unitRepo, { isRemote: true, remoteName: rName })
          );
          assert.strictEqual(res.ok, false, `Expected remote '${rName}' to be rejected`);
        }

        // Virtual workspace must ALWAYS be rejected even if remoteName === 'wsl'
        const virtualWsl = verifyLaunchAdmission(
          makeBaseHostDesc(unitRepo, {
            isRemote: true,
            remoteName: "wsl",
            isVirtualWorkspace: true,
            workspaceScheme: "vscode-vfs",
          })
        );
        assert.strictEqual(virtualWsl.ok, false);

        // Inconsistent descriptor (isRemote=false with non-empty remoteName) must be rejected
        const inconsistent = verifyWorkspaceHostEnvironment(
          makeBaseHostDesc(unitRepo, { isRemote: false, remoteName: "wsl" })
        );
        assert.strictEqual(inconsistent.ok, false);

        if (IS_LINUX) {
          for (const allowed of SUPPORTED_LINUX_REMOTE_NAMES) {
            const okRes = verifyLaunchAdmission(
              makeBaseHostDesc(unitRepo, { isRemote: true, remoteName: allowed })
            );
            assert.strictEqual(okRes.ok, true, `Expected '${allowed}' to pass on linux/x64`);
            if (okRes.ok) {
              cleanupIsolatedRunDirectory(okRes.value.isolatedTempDir, true);
            }
          }
        } else {
          // On win32/x64, WSL/DevContainer remoteName must be rejected because workspace host must be linux/x64
          for (const r of SUPPORTED_LINUX_REMOTE_NAMES) {
            const winSpoof = verifyLaunchAdmission(
              makeBaseHostDesc(unitRepo, { isRemote: true, remoteName: r })
            );
            assert.strictEqual(winSpoof.ok, false, `Expected '${r}' on win32 host to fail`);
          }
        }

        assert.strictEqual(getTotalBrokerSpawnCount(), 0);
        return {
          supportedRemotes: SUPPORTED_LINUX_REMOTE_NAMES,
          rejectedRemotesTested: rejectedRemotes,
          brokerSpawns: getTotalBrokerSpawnCount(),
        };
      }
    );

    // =========================================================================
    // V04-U02: WSLInterop / Windows PE ('MZ' 0x4d5a) / '/mnt/<drive>' Rejection
    // =========================================================================
    await runCase(
      "V04-U02",
      "Linux WSLInterop ('/mnt/<drive>', '.exe', and 'MZ' 0x4d5a PE header) rejection & safe PATH scan",
      async () => {
        assert.strictEqual(isWslWindowsMountPath("/mnt/c/Windows/System32"), true);
        assert.strictEqual(isWslWindowsMountPath("/mnt/D/tools/python.exe"), true);
        assert.strictEqual(isWslWindowsMountPath("/mnt/c"), true);
        assert.strictEqual(isWslWindowsMountPath("/mnt/custom_linux_vol/bin"), false);
        assert.strictEqual(isWslWindowsMountPath("/usr/bin/python3"), false);

        const binTestDir = path.join(tempRoot, "pe-check");
        fs.mkdirSync(binTestDir, { recursive: true });

        // 1. File with MZ (0x4d 0x5a) PE magic header but NO '.exe' suffix!
        const mzNoExt = path.join(binTestDir, "python3");
        const mzBuf = Buffer.concat([
          Buffer.from([0x4d, 0x5a, 0x90, 0x00]),
          Buffer.from("fake DOS/PE stub"),
        ]);
        fs.writeFileSync(mzNoExt, mzBuf, { mode: 0o755 });

        const mzCheck = verifyLinuxNativeExecutableIdentity(mzNoExt, "Python");
        assert.strictEqual(mzCheck.ok, false);
        assert.ok(mzCheck.error.includes("MZ header 0x4d5a"));

        // 2. File with '.exe' suffix even with POSIX shebang
        const dotExe = path.join(binTestDir, "git.exe");
        fs.writeFileSync(dotExe, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
        const exeCheck = verifyLinuxNativeExecutableIdentity(dotExe, "Git");
        assert.strictEqual(exeCheck.ok, false);

        // 3. Path on '/mnt/c/...'
        const mntCheck = verifyLinuxNativeExecutableIdentity(
          "/mnt/c/Python312/python3",
          "Python"
        );
        assert.strictEqual(mntCheck.ok, false);

        // 4. Native POSIX script / ELF binary passes
        const cleanPosixBinDir = path.join(binTestDir, "native-linux-bin");
        fs.mkdirSync(cleanPosixBinDir, { recursive: true });
        const nativeScript = path.join(cleanPosixBinDir, "python3");
        fs.writeFileSync(nativeScript, "#!/usr/bin/env sh\necho 3.12.3\n", { mode: 0o755 });
        const nativeCheck = verifyLinuxNativeExecutableIdentity(nativeScript, "Python");
        assert.strictEqual(nativeCheck.ok, true);

        if (IS_LINUX) {
          // On Linux, resolveTrustedExecutableFromPath skips '/mnt/c/...' AND skips MZ binary 'python3' in binTestDir,
          // selecting cleanPosixBinDir/python3!
          const syntheticPath = `/mnt/c/Python312:${binTestDir}:${cleanPosixBinDir}`;
          const resolved = resolveTrustedExecutableFromPath({
            executableNames: ["python3"],
            repositoryRootPath: unitRepo,
            pathEnv: syntheticPath,
            platform: "linux",
          });
          assert.strictEqual(resolved.ok, true, resolved.ok ? "" : resolved.error);
          if (resolved.ok) {
            assert.strictEqual(resolved.value, fs.realpathSync.native(nativeScript));
          }
        }

        return {
          mzHeaderRejected: !mzCheck.ok,
          dotExeRejected: !exeCheck.ok,
          mntDriveRejected: !mntCheck.ok,
          nativePosixAccepted: nativeCheck.ok,
        };
      }
    );

    // =========================================================================
    // V04-U03: Cross-OS Machine Settings Warning & Environment Doctor Check
    // =========================================================================
    await runCase(
      "V04-U03",
      "Environment Doctor surfaces ignored cross-OS local UI setting alongside repo poisoning",
      async () => {
        const runner = new UnifiedProcessRunner();
        const docRep = await runEnvironmentDoctor({
          processRunner: runner,
          hostDesc: makeBaseHostDesc(unitRepo, {
            isWorkspaceTrusted: false,
            ...(IS_LINUX ? { isRemote: true, remoteName: "wsl" } : {}),
          }),
          settingInspections: [
            {
              key: "pythonPath",
              globalValue: "",
              workspaceValue: "",
              workspaceFolderValue: "",
              ignoredCrossOsLocalValue: "C:\\Users\\winuser\\Python312\\python.exe",
            },
            {
              key: "gitPath",
              globalValue: "",
              workspaceValue: "./evil/git",
              workspaceFolderValue: "",
            },
          ],
        });
        assert.strictEqual(docRep.externalProcessesSpawned, false);
        assert.strictEqual(docRep.workspaceSettingsWarnings.length, 2);
        assert.ok(
          docRep.workspaceSettingsWarnings.some(
            (w) =>
              w.key === "pythonPath" &&
              w.message.includes("targets a different OS and is ignored in this remote workspace host")
          )
        );
        assert.ok(
          docRep.workspaceSettingsWarnings.some(
            (w) => w.key === "gitPath" && w.message.includes("ignored by security policy")
          )
        );
        return {
          warningsCount: docRep.workspaceSettingsWarnings.length,
          hostSummary: docRep.checks.hostCapability.summary,
        };
      }
    );

    // =========================================================================
    // V04-L01: Linux Native Kernel Inode Containment & Bind/Symlink Alias Check
    // =========================================================================
    if (IS_LINUX) {
      await runCase(
        "V04-L01",
        "POSIX kernel (st_dev, st_ino) directory identity & inside-repository containment",
        async () => {
          const realParent = path.join(tempRoot, "real-mount-parent");
          const aliasParent = path.join(tempRoot, "alias-mount-parent");
          const repoDir = path.join(realParent, "project");
          initLocalGitRepo(repoDir);
          fs.symlinkSync(realParent, aliasParent, "dir");

          const aliasRepoDir = path.join(aliasParent, "project");
          assert.strictEqual(areSameRepositoryPath(repoDir, aliasRepoDir), true);

          // Even an uncanonicalized path via aliasParent/project/sub/python3 is recognized inside repoDir
          const aliasNestedCandidate = path.posix.join(aliasRepoDir, "venv", "bin", "python3");
          assert.strictEqual(
            isPathInsideOrEqualPlatform(aliasNestedCandidate, repoDir, "linux"),
            true
          );

          // Relative path resolution across inode-matching roots
          const subDir = path.join(repoDir, "tests");
          fs.mkdirSync(subDir, { recursive: true });
          const testFile = path.join(subDir, "test_sample.py");
          fs.writeFileSync(testFile, "def test_ok():\n    assert 1 == 1\n", "utf8");

          const rel = tryRelativeInsidePosixInodeRoot(
            repoDir,
            path.posix.join(aliasRepoDir, "tests", "test_sample.py")
          );
          assert.strictEqual(rel, "tests/test_sample.py");

          return {
            sameRepoDetected: true,
            nestedContainmentDetected: true,
            relativeResolved: rel,
          };
        }
      );
    }

    // =========================================================================
    // Real Code.exe <-> Real vscode-server-linux-x64 E2E Suite (Windows Host -> WSL2 + Docker)
    // =========================================================================
    if (IS_WIN32) {
      const codeExe = resolveTestVscodeExe();
      assert.ok(codeExe, "Expected real Windows Code.exe to be installed on the test host");
      const productInfo = findVsCodeProductInfo(codeExe);
      const serverTarballWinPath = await ensureCachedVscodeServerTarball(productInfo.commit);
      const serverTarballSha256 = sha256File(serverTarballWinPath);

      // Ensure fresh 0.4.0 linux-x64 VSIX is built!
      const pkgRun = cp.spawnSync(
        process.execPath,
        [path.join(ROOT, "scripts", "package_vsix.js"), "--target", "linux-x64"],
        { cwd: ROOT, encoding: "utf8", windowsHide: true }
      );
      if (pkgRun.status !== 0) {
        throw new Error(`package_vsix.js --target linux-x64 failed: ${pkgRun.stderr || pkgRun.stdout}`);
      }
      const linuxVsixWinPath = path.join(
        ROOT,
        `checkwash-lens-${PKG_VERSION}-linux-x64.vsix`
      );
      assert.ok(fs.existsSync(linuxVsixWinPath), `Missing ${linuxVsixWinPath}`);
      const linuxVsixSha256 = sha256File(linuxVsixWinPath);

      const wsDriverVsixWinPath = path.join(tempRoot, "cw-v04-ws-driver.vsix");
      createWorkspaceTestDriverVsix(wsDriverVsixWinPath);

      const uiResolverDir = path.join(tempRoot, "ui-remote-resolver");
      createUiRemoteResolverExtension(uiResolverDir);

      // Offline valid JSON v2 report for read-only viewer checks in Restricted / ssh-remote modes
      const offlineJsonContent = fs.readFileSync(
        path.join(ROOT, "fixtures", "phase0", "a01-block.findings.json"),
        "utf8"
      );

      const wslTarballPath = winPathToWslMntPath(serverTarballWinPath);
      const wslLinuxVsixPath = winPathToWslMntPath(linuxVsixWinPath);
      const wslDriverVsixPath = winPathToWslMntPath(wsDriverVsixWinPath);

      const runWslCheck = (bashCmd: string): string => {
        const res = cp.spawnSync("wsl.exe", ["-d", "Ubuntu-24.04", "--", "bash", "-c", bashCmd], {
          encoding: "utf8",
          windowsHide: true,
        });
        if (res.status !== 0) {
          throw new Error(`WSL bash failed (${res.status}): ${res.stderr || res.stdout}`);
        }
        return (res.stdout || "").trim();
      };

      const wslKernel = runWslCheck("uname -srm");
      console.log(
        `  -> Prepared real vscode-server (${productInfo.version}, commit ${productInfo.commit.slice(0, 10)}) + VSIX (${PKG_VERSION}) against WSL2 (${wslKernel}) & Docker`
      );

      // Helper to start foreground WSL2 vscode-server instance in /tmp/cw-v04-wsl-<id>
      const withWslVscodeServer = async <T>(
        instanceId: string,
        setupBashLines: string[],
        scenarioConfig: Record<string, unknown>,
        body: (ctx: {
          port: number;
          token: string;
          resolverConfigPath: string;
          wslBaseDir: string;
          getServerLogs: () => string;
        }) => Promise<T>
      ): Promise<T> => {
        const port = await findFreeTcpPort();
        const token = `tok-${crypto.randomBytes(8).toString("hex")}`;
        const wslBaseDir = `/tmp/cw-v04-wsl-${instanceId}`;
        const hostSideDir = path.join(tempRoot, `wsl-${instanceId}`);
        fs.mkdirSync(hostSideDir, { recursive: true });

        const resolverConfigPath = path.join(hostSideDir, "resolver.json");
        fs.writeFileSync(resolverConfigPath, JSON.stringify({ port, token }), "utf8");

        const scenarioConfigWinPath = path.join(hostSideDir, "scenario.json");
        fs.writeFileSync(scenarioConfigWinPath, JSON.stringify(scenarioConfig, null, 2), "utf8");
        const wslScenarioCfgPath = winPathToWslMntPath(scenarioConfigWinPath);

        const launchScriptWinPath = path.join(hostSideDir, "start_srv.sh");
        const scriptText = [
          "#!/usr/bin/env bash",
          "set -euo pipefail",
          `rm -rf ${wslBaseDir}`,
          `mkdir -p ${wslBaseDir}/srv ${wslBaseDir}/data ${wslBaseDir}/exts ${wslBaseDir}/work`,
          `tar -xzf "${wslTarballPath}" -C ${wslBaseDir}/srv --strip-components=1`,
          ...setupBashLines,
          `${wslBaseDir}/srv/bin/code-server --server-data-dir ${wslBaseDir}/data --extensions-dir ${wslBaseDir}/exts --install-extension "${wslLinuxVsixPath}" --force`,
          `${wslBaseDir}/srv/bin/code-server --server-data-dir ${wslBaseDir}/data --extensions-dir ${wslBaseDir}/exts --install-extension "${wslDriverVsixPath}" --force`,
          `export CW_V04_SCENARIO_CONFIG="${wslScenarioCfgPath}"`,
          `exec ${wslBaseDir}/srv/bin/code-server --host 127.0.0.1 --port ${port} --connection-token ${token} --accept-server-license-terms --telemetry-level off --server-data-dir ${wslBaseDir}/data --extensions-dir ${wslBaseDir}/exts`,
        ].join("\n");
        fs.writeFileSync(launchScriptWinPath, scriptText, "utf8");

        const srvProc = cp.spawn(
          "wsl.exe",
          ["-d", "Ubuntu-24.04", "--", "bash", winPathToWslMntPath(launchScriptWinPath)],
          { stdio: ["ignore", "pipe", "pipe"], windowsHide: true }
        );
        let srvOut = "";
        let srvErr = "";
        srvProc.stdout?.on("data", (d: Buffer) => {
          srvOut += d.toString("utf8");
        });
        srvProc.stderr?.on("data", (d: Buffer) => {
          srvErr += d.toString("utf8");
        });
        const getServerLogs = () =>
          `WSL vscode-server stdout:\n${srvOut.slice(-2000)}\nWSL vscode-server stderr:\n${srvErr.slice(-2000)}`;

        try {
          const listenDeadline = Date.now() + 45_000;
          while (!srvOut.includes("Extension host agent started")) {
            if (srvProc.exitCode !== null) {
              throw new Error(
                `WSL vscode-server exited prematurely (code=${srvProc.exitCode}).\n${getServerLogs()}`
              );
            }
            if (Date.now() > listenDeadline) {
              throw new Error(`Timed out waiting for WSL vscode-server startup.\n${getServerLogs()}`);
            }
            await sleep(80);
          }

          return await body({ port, token, resolverConfigPath, wslBaseDir, getServerLogs });
        } finally {
          killProcessTreeBestEffort(srvProc.pid);
          try {
            cp.spawnSync("wsl.exe", ["-d", "Ubuntu-24.04", "--", "rm", "-rf", wslBaseDir], {
              windowsHide: true,
              timeout: 10_000,
            });
          } catch {
            // best-effort WSL temp cleanup
          }
        }
      };

      // -----------------------------------------------------------------------
      // Case 1: V04-WSL-B01 — Real WSL2 Restricted Mode (isTrusted === false)
      // -----------------------------------------------------------------------
      await runCase(
        "V04-WSL-B01",
        "Real Code.exe <-> WSL2 (Ubuntu-24.04) vscode-server Restricted Mode (isTrusted=false, 0 spawns)",
        async () => {
          const outDir = path.join(tempRoot, "wsl-b01-out");
          fs.mkdirSync(outDir, { recursive: true });
          const receiptWinPath = path.join(outDir, "receipt.json");
          const offlineWinPath = path.join(outDir, "offline.json");
          fs.writeFileSync(offlineWinPath, offlineJsonContent, "utf8");

          const wslRepoDir = "/tmp/cw-v04-wsl-b01/repo";
          return await withWslVscodeServer(
            "b01",
            [
              `mkdir -p ${wslRepoDir}`,
              `cd ${wslRepoDir} && git init -q && git config user.name T && git config user.email t@e.c`,
              `echo "def test_a(): assert 1 == 1" > ${wslRepoDir}/test_a.py`,
              `git add . && git commit -q -m c1`,
              `echo "def test_a(): assert True" > ${wslRepoDir}/test_a.py`,
              `git add . && git commit -q -m c2`,
            ],
            {
              scenario: "wsl_restricted_b01",
              receiptPath: winPathToWslMntPath(receiptWinPath),
              offlineReportPath: winPathToWslMntPath(offlineWinPath),
            },
            async ({ resolverConfigPath, getServerLogs }) => {
              const client = launchWinCodeClientToRemote({
                codeExePath: codeExe,
                uiResolverDir,
                resolverConfigPath,
                userDataDir: path.join(outDir, "win-ud"),
                extensionsDir: path.join(outDir, "win-exts"),
                folderUri: `vscode-remote://wsl+Ubuntu-24.04${wslRepoDir}`,
                trustedWindow: false,
                userSettings: {
                  "security.workspace.trust.enabled": true,
                  "security.workspace.trust.startupPrompt": "never",
                  "security.workspace.trust.banner": "never",
                  "security.workspace.trust.emptyWindow": false,
                },
              });
              try {
                const rec = await waitForFileJson<Record<string, unknown>>(
                  receiptWinPath,
                  45_000,
                  () => `${getServerLogs()}\n${client.getLogs()}`
                );
                assert.strictEqual(rec.ok, true, `WSL B01 failed: ${JSON.stringify(rec)}`);
                assert.strictEqual(rec.remoteName, "wsl");
                assert.strictEqual(rec.isTrusted, false);
                assert.strictEqual(rec.spawnedCount, 0);
                assert.strictEqual(rec.offlineReadOnlyWorked, true);
                return {
                  vscodeVersion: rec.vscodeVersion,
                  wslKernel,
                  serverTarballSha256,
                  linuxVsixSha256,
                  remoteExtHostReceipt: rec,
                };
              } finally {
                await client.shutdown();
              }
            }
          );
        }
      );

      // -----------------------------------------------------------------------
      // Case 2: V04-WSL-EXT4-E2E — Real WSL2 Trusted ext4 E2E + Settings Isolation + Cancel + B08 SIGKILL Reaping
      // -----------------------------------------------------------------------
      await runCase(
        "V04-WSL-EXT4-E2E",
        "Real Code.exe <-> WSL2 vscode-server Trusted ext4 E2E (Doctor C:\\ isolation, Scan, Diet, Cancel, B08 SIGKILL)",
        async () => {
          const outDir = path.join(tempRoot, "wsl-ext4-out");
          fs.mkdirSync(outDir, { recursive: true });
          const receiptWinPath = path.join(outDir, "receipt.json");
          const wslBase = "/tmp/cw-v04-wsl-ext4";
          const wslRepoDir = `${wslBase}/repo`;
          const sqlSecret = "sk-live-WSL998877665544332211SECRET";

          const prepScriptPath = path.join(outDir, "prep_ext4_repo.py");
          fs.writeFileSync(
            prepScriptPath,
            [
              "import json, os, subprocess",
              `repo = ${JSON.stringify(wslRepoDir)}`,
              "os.makedirs(os.path.join(repo, 'tests'), exist_ok=True)",
              "os.makedirs(os.path.join(repo, 'db'), exist_ok=True)",
              "os.makedirs(os.path.join(repo, '.vscode'), exist_ok=True)",
              "subprocess.run(['git', '-C', repo, 'init', '-q'], check=True)",
              "subprocess.run(['git', '-C', repo, 'config', 'user.name', 'WSL E2E'], check=True)",
              "subprocess.run(['git', '-C', repo, 'config', 'user.email', 'wsl@checkwash.local'], check=True)",
              "open(os.path.join(repo, '.vscode', 'settings.json'), 'w').write(json.dumps({'checkwashLens.pythonPath': './evil/python3'}))",
              "open(os.path.join(repo, 'calc.py'), 'w').write('def add(a, b):\\n    return a + b\\n')",
              "open(os.path.join(repo, 'tests', 'test_calc.py'), 'w').write('from calc import add\\n\\ndef test_add():\\n    assert add(2, 3) == 5\\n')",
              `open(os.path.join(repo, 'db', 'init.sql'), 'w').write('-- api_key = "${sqlSecret}"\\nSELECT 1;\\n')`,
              "subprocess.run(['git', '-C', repo, 'add', '.'], check=True)",
              "subprocess.run(['git', '-C', repo, 'commit', '-q', '-m', 'base'], check=True)",
              "base_oid = subprocess.check_output(['git', '-C', repo, 'rev-parse', 'HEAD'], text=True).strip()",
              "open(os.path.join(repo, 'tests', 'test_calc.py'), 'w').write('def test_add():\\n    assert True\\n')",
              "open(os.path.join(repo, 'db', 'init.sql'), 'w').write('SELECT 1;\\n')",
              "subprocess.run(['git', '-C', repo, 'add', '.'], check=True)",
              "subprocess.run(['git', '-C', repo, 'commit', '-q', '-m', 'weaken'], check=True)",
              "head_oid = subprocess.check_output(['git', '-C', repo, 'rev-parse', 'HEAD'], text=True).strip()",
              `open(${JSON.stringify(winPathToWslMntPath(path.join(outDir, "oids.json")))}, 'w').write(json.dumps({'baseOid': base_oid, 'headOid': head_oid}))`,
            ].join("\n"),
            "utf8"
          );

          const fixedScenario = {
            scenario: "wsl_ext4_full_and_b08",
            repoDir: wslRepoDir,
            workDir: `${wslBase}/work`,
            baseOid: "HEAD~1",
            headOid: "HEAD",
            sqlSecret,
            receiptPath: winPathToWslMntPath(receiptWinPath),
          };

          return await withWslVscodeServer(
            "ext4",
            [`python3 "${winPathToWslMntPath(prepScriptPath)}"`],
            fixedScenario,
            async ({ resolverConfigPath, getServerLogs }) => {

              const client = launchWinCodeClientToRemote({
                codeExePath: codeExe,
                uiResolverDir,
                resolverConfigPath,
                userDataDir: path.join(outDir, "win-ud"),
                extensionsDir: path.join(outDir, "win-exts"),
                folderUri: `vscode-remote://wsl+Ubuntu-24.04${wslRepoDir}`,
                trustedWindow: true,
                userSettings: {
                  // Deliberately set a Windows local path in Windows User/settings.json!
                  "checkwashLens.pythonPath": "C:\\EvilWindows\\python.exe",
                },
              });
              try {
                const rec = await waitForFileJson<{
                  ok: boolean;
                  error?: string;
                  b08TreePids: { extHostPid: number; parentPid: number; grandchildPid: number };
                  doctorWarnings: Array<{ key: string; message: string }>;
                }>(receiptWinPath, 60_000, () => `${getServerLogs()}\n${client.getLogs()}`);
                assert.strictEqual(rec.ok, true, `WSL ext4 E2E failed: ${JSON.stringify(rec)}`);

                // Verify both ignored warnings (local Windows UI pythonPath + repo .vscode/settings.json)
                let extraWinLogs = "";
                try {
                  const logsRoot = path.join(outDir, "win-ud", "logs");
                  if (fs.existsSync(logsRoot)) {
                    const collectLogs = (dir: string): string[] => {
                      const res: string[] = [];
                      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
                        const full = path.join(dir, ent.name);
                        if (ent.isDirectory()) res.push(...collectLogs(full));
                        else if (ent.name.endsWith(".log")) {
                          res.push(`--- ${ent.name} ---\n${fs.readFileSync(full, "utf8").slice(-1500)}`);
                        }
                      }
                      return res;
                    };
                    extraWinLogs = collectLogs(logsRoot).join("\n");
                  }
                } catch {}
                assert.ok(
                  rec.doctorWarnings.some(
                    (w) => w.key === "pythonPath" && w.message.includes("C:\\EvilWindows\\python.exe")
                  ),
                  `Expected Doctor warning for ignored Windows globalLocalValue: warnings=${JSON.stringify(rec.doctorWarnings)} inspect=${JSON.stringify((rec as Record<string, unknown>).inspectedPythonPath)}\nWIN_LOGS:\n${extraWinLogs}`
                );

                // Now execute real B08 SIGKILL against the WSL2 vscode-server Remote Extension Host PID!
                const { extHostPid, parentPid, grandchildPid } = rec.b08TreePids;
                runWslCheck(`kill -9 ${extHostPid}`);

                const reapDeadline = Date.now() + 8_000;
                let aliveCheck = "alive";
                while (Date.now() < reapDeadline) {
                  aliveCheck = runWslCheck(
                    `python3 -c "import os; alive=[p for p in (${parentPid}, ${grandchildPid}) if os.path.exists(f'/proc/{p}') and 'Z' not in open(f'/proc/{p}/stat').read().split(')')[-1][:5]]; print('dead' if not alive else f'alive:{alive}')"`
                  );
                  if (aliveCheck === "dead") {
                    break;
                  }
                  await sleep(80);
                }
                assert.strictEqual(
                  aliveCheck,
                  "dead",
                  `Expected WSL2 brokered child+grandchild (${parentPid}, ${grandchildPid}) to be reaped after SIGKILL of extHostPid=${extHostPid}, got ${aliveCheck}`
                );

                return {
                  remoteExtHostReceipt: rec,
                  b08SigkillReapResult: aliveCheck,
                };
              } finally {
                await client.shutdown();
              }
            }
          );
        }
      );

      // -----------------------------------------------------------------------
      // Case 3: V04-WSL-DRVFS-MNTC — Real WSL2 on '/mnt/c/...' (9p DrvFS)
      // -----------------------------------------------------------------------
      await runCase(
        "V04-WSL-DRVFS-MNTC",
        "Real Code.exe <-> WSL2 vscode-server on /mnt/c (9p DrvFS): case-alias B04 block, WSLInterop MZ block, SNAP-04 case rename",
        async () => {
          const outDir = path.join(tempRoot, "wsl-drvfs-out");
          const winDrvfsRepo = path.join(outDir, "DrvFsRepo");
          fs.mkdirSync(path.join(winDrvfsRepo, "tests"), { recursive: true });
          fs.mkdirSync(path.join(winDrvfsRepo, "evil-bin"), { recursive: true });

          // Initialize repository on Windows C:\... (mounted in WSL2 at /mnt/c/Users/...)
          initLocalGitRepo(winDrvfsRepo);
          fs.writeFileSync(
            path.join(winDrvfsRepo, "calc.py"),
            "def mul(a, b):\n    return a * b\n",
            "utf8"
          );
          fs.writeFileSync(
            path.join(winDrvfsRepo, "tests", "test_calc.py"),
            "from calc import mul\n\ndef test_mul():\n    assert mul(3, 4) == 12\n",
            "utf8"
          );
          fs.writeFileSync(
            path.join(winDrvfsRepo, "tests", "test_good.py"),
            "from calc import mul\n\ndef test_keep():\n    assert mul(2, 5) == 10\n",
            "utf8"
          );
          fs.writeFileSync(
            path.join(winDrvfsRepo, "evil-bin", "python3"),
            "#!/bin/sh\necho PWNED\n",
            "utf8"
          );
          cp.execFileSync(GIT_EXE, ["-C", winDrvfsRepo, "add", "."], { windowsHide: true });
          cp.execFileSync(GIT_EXE, ["-C", winDrvfsRepo, "commit", "-q", "-m", "base-drvfs"], {
            windowsHide: true,
          });
          const baseOid = cp
            .execFileSync(GIT_EXE, ["-C", winDrvfsRepo, "rev-parse", "HEAD"], {
              encoding: "utf8",
              windowsHide: true,
            })
            .trim();

          fs.writeFileSync(
            path.join(winDrvfsRepo, "tests", "test_calc.py"),
            "def test_mul():\n    assert True\n",
            "utf8"
          );
          cp.execFileSync(GIT_EXE, ["-C", winDrvfsRepo, "add", "."], { windowsHide: true });
          cp.execFileSync(GIT_EXE, ["-C", winDrvfsRepo, "commit", "-q", "-m", "weaken-drvfs"], {
            windowsHide: true,
          });
          const headOid = cp
            .execFileSync(GIT_EXE, ["-C", winDrvfsRepo, "rev-parse", "HEAD"], {
              encoding: "utf8",
              windowsHide: true,
            })
            .trim();

          // Real Windows PE binary on /mnt/c + copied into WSL ext4 /tmp without '.exe'
          const mntcExeWin = path.join(ROOT, "bundled", "checkwash-broker.exe");
          const wslMntcExe = winPathToWslMntPath(mntcExeWin);
          const repoDirUpper = winPathToWslMntPath(winDrvfsRepo);
          // Toggle casing of path segments (e.g. /mnt/c/Users/.../DrvFsRepo -> /mnt/c/users/.../drvfsrepo)
          const repoDirLower = `/mnt/c/${repoDirUpper.slice("/mnt/c/".length).toLowerCase()}`;
          assert.notStrictEqual(repoDirUpper, repoDirLower);

          const receiptWinPath = path.join(outDir, "receipt.json");
          const ext4MzBinaryPath = "/tmp/cw-v04-wsl-drvfs/work/fake-linux-python3";

          return await withWslVscodeServer(
            "drvfs",
            [
              `cp "${wslMntcExe}" "${ext4MzBinaryPath}"`,
              `chmod 755 "${ext4MzBinaryPath}"`,
            ],
            {
              scenario: "wsl_drvfs_mntc",
              repoDirUpper,
              repoDirLower,
              baseOid,
              headOid,
              mntcExePath: wslMntcExe,
              ext4MzBinaryPath,
              receiptPath: winPathToWslMntPath(receiptWinPath),
            },
            async ({ resolverConfigPath, getServerLogs }) => {
              const client = launchWinCodeClientToRemote({
                codeExePath: codeExe,
                uiResolverDir,
                resolverConfigPath,
                userDataDir: path.join(outDir, "win-ud"),
                extensionsDir: path.join(outDir, "win-exts"),
                folderUri: `vscode-remote://wsl+Ubuntu-24.04${repoDirUpper}`,
                trustedWindow: true,
                userSettings: {},
              });
              try {
                const rec = await waitForFileJson<Record<string, unknown>>(
                  receiptWinPath,
                  60_000,
                  () => `${getServerLogs()}\n${client.getLogs()}`
                );
                assert.strictEqual(rec.ok, true, `WSL DrvFS E2E failed: ${JSON.stringify(rec)}`);
                assert.strictEqual(rec.realpathPreservedCaseStrings, true);
                assert.strictEqual(rec.insideRepoLowercaseAliasRejected, true);
                assert.strictEqual(rec.wslMntcExeRejected, true);
                assert.strictEqual(rec.ext4MzHeaderRejected, true);
                assert.strictEqual(rec.committedDrvfsVerdict, "Block");
                return rec;
              } finally {
                await client.shutdown();
              }
            }
          );
        }
      );

      // -----------------------------------------------------------------------
      // Helper to run real vscode-server inside Docker Linux container (checkwash-lens-linux-verify:v030)
      // -----------------------------------------------------------------------
      const withDockerVscodeServer = async <T>(
        instanceId: string,
        scenarioConfigBuilder: (containerOutDir: string) => Record<string, unknown>,
        remoteSettingsJson: Record<string, unknown>,
        body: (ctx: {
          port: number;
          token: string;
          resolverConfigPath: string;
          containerRepoDir: string;
          hostOutDir: string;
          getServerLogs: () => string;
        }) => Promise<T>
      ): Promise<T> => {
        const port = await findFreeTcpPort();
        const token = `dctok-${crypto.randomBytes(8).toString("hex")}`;
        const hostOutDir = path.join(tempRoot, `docker-${instanceId}`);
        fs.mkdirSync(hostOutDir, { recursive: true });

        const resolverConfigPath = path.join(hostOutDir, "resolver.json");
        fs.writeFileSync(resolverConfigPath, JSON.stringify({ port, token }), "utf8");

        const containerRepoDir = `/tmp/cw-v04-dc-${instanceId}/repo`;
        const scenarioCfg = scenarioConfigBuilder("/cw-host-out");
        fs.writeFileSync(
          path.join(hostOutDir, "scenario.json"),
          JSON.stringify(scenarioCfg, null, 2),
          "utf8"
        );
        fs.writeFileSync(
          path.join(hostOutDir, "machine-settings.json"),
          JSON.stringify(remoteSettingsJson, null, 2),
          "utf8"
        );
        fs.writeFileSync(path.join(hostOutDir, "offline.json"), offlineJsonContent, "utf8");
        fs.copyFileSync(linuxVsixWinPath, path.join(hostOutDir, "checkwash-lens.vsix"));
        fs.copyFileSync(wsDriverVsixWinPath, path.join(hostOutDir, "ws-driver.vsix"));

        const startSh = [
          "#!/usr/bin/env bash",
          "set -euo pipefail",
          `BASE=/tmp/cw-v04-dc-${instanceId}`,
          "mkdir -p $BASE/srv $BASE/data/Machine $BASE/exts $BASE/repo/src $BASE/repo/tests",
          "cp /cw-host-out/machine-settings.json $BASE/data/Machine/settings.json",
          "tar -xzf /vscode-srv.tar.gz -C $BASE/srv --strip-components=1",
          "cd $BASE/repo",
          "git init -q && git config user.name DC && git config user.email dc@checkwash.local",
          "touch src/__init__.py",
          "cat > src/pricing.py << 'EOF'",
          "def discount(price: int) -> int:",
          "    if price >= 100:",
          "        return price - 20",
          "    return price",
          "EOF",
          "cat > tests/test_pricing.py << 'EOF'",
          "from src.pricing import discount",
          "",
          "def test_discount():",
          "    assert discount(100) == 80",
          "    assert discount(120) == 100",
          "    assert discount(50) == 50",
          "EOF",
          "git add . && git commit -q -m base",
          "cat > tests/test_pricing.py << 'EOF'",
          "from src.pricing import discount",
          "",
          "def test_discount():",
          "    assert discount(120) is not None",
          "EOF",
          "git add . && git commit -q -m weaken",
          "$BASE/srv/bin/code-server --server-data-dir $BASE/data --extensions-dir $BASE/exts --install-extension /cw-host-out/checkwash-lens.vsix --force",
          "$BASE/srv/bin/code-server --server-data-dir $BASE/data --extensions-dir $BASE/exts --install-extension /cw-host-out/ws-driver.vsix --force",
          "export CW_V04_SCENARIO_CONFIG=/cw-host-out/scenario.json",
          `exec $BASE/srv/bin/code-server --host 0.0.0.0 --port ${port} --connection-token ${token} --accept-server-license-terms --telemetry-level off --server-data-dir $BASE/data --extensions-dir $BASE/exts`,
        ].join("\n");
        fs.writeFileSync(path.join(hostOutDir, "start_dc.sh"), startSh, "utf8");

        const containerName = `cw-v04-srv-${instanceId}-${process.pid}`;
        const dockerProc = cp.spawn(
          "docker",
          [
            "run",
            "--rm",
            "--name",
            containerName,
            "-p",
            `127.0.0.1:${port}:${port}`,
            "-v",
            `${serverTarballWinPath}:/vscode-srv.tar.gz:ro`,
            "-v",
            `${hostOutDir}:/cw-host-out`,
            "checkwash-lens-linux-verify:v030",
            "bash",
            "/cw-host-out/start_dc.sh",
          ],
          { stdio: ["ignore", "pipe", "pipe"], windowsHide: true }
        );
        let dOut = "";
        let dErr = "";
        dockerProc.stdout?.on("data", (d: Buffer) => {
          dOut += d.toString("utf8");
        });
        dockerProc.stderr?.on("data", (d: Buffer) => {
          dErr += d.toString("utf8");
        });
        const getServerLogs = () =>
          `Docker vscode-server stdout:\n${dOut.slice(-2000)}\nDocker vscode-server stderr:\n${dErr.slice(-2000)}`;

        try {
          const deadline = Date.now() + 50_000;
          while (!dOut.includes("Extension host agent started")) {
            if (dockerProc.exitCode !== null) {
              throw new Error(
                `Docker vscode-server exited early (code=${dockerProc.exitCode}).\n${getServerLogs()}`
              );
            }
            if (Date.now() > deadline) {
              throw new Error(`Timed out waiting for Docker vscode-server.\n${getServerLogs()}`);
            }
            await sleep(80);
          }

          return await body({
            port,
            token,
            resolverConfigPath,
            containerRepoDir,
            hostOutDir,
            getServerLogs,
          });
        } finally {
          try {
            cp.spawnSync("docker", ["rm", "-f", containerName], {
              windowsHide: true,
              timeout: 15_000,
            });
          } catch {
            // ignore
          }
          killProcessTreeBestEffort(dockerProc.pid);
        }
      };

      // -----------------------------------------------------------------------
      // Case 4: V04-DOCKER-DEVCONTAINER-E2E — Real Docker Container ('dev-container' + Prove v0.1.0 + 'attached-container')
      // -----------------------------------------------------------------------
      await runCase(
        "V04-DOCKER-DEVCONTAINER-E2E",
        "Real Code.exe <-> Docker Linux Container vscode-server ('dev-container' + Prove v0.1.0 List/Full/Replay + 'attached-container')",
        async () => {
          const dcContainerRepo = "/tmp/cw-v04-dc-devc/repo";
          const dcReceipt = await withDockerVscodeServer(
            "devc",
            (cOut) => ({
              scenario: "docker_devcontainer_full",
              expectedRemoteName: "dev-container",
              repoDir: dcContainerRepo,
              baseOid: "HEAD~1",
              headOid: "HEAD",
              proveExe: "/opt/prove-venv/bin/checkwash-prove",
              runProveSuite: true,
              receiptPath: `${cOut}/receipt-devc.json`,
            }),
            {
              "checkwashLens.provePath": "/opt/prove-venv/bin/checkwash-prove",
            },
            async ({ resolverConfigPath, containerRepoDir, hostOutDir, getServerLogs }) => {
              const client = launchWinCodeClientToRemote({
                codeExePath: codeExe,
                uiResolverDir,
                resolverConfigPath,
                userDataDir: path.join(hostOutDir, "win-ud"),
                extensionsDir: path.join(hostOutDir, "win-exts"),
                folderUri: `vscode-remote://dev-container+cwv04docker${containerRepoDir}`,
                trustedWindow: true,
                userSettings: {
                  "checkwashLens.pythonPath": "C:\\WindowsHostPath\\python.exe",
                },
              });
              try {
                const rec = await waitForFileJson<Record<string, unknown>>(
                  path.join(hostOutDir, "receipt-devc.json"),
                  75_000,
                  () => `${getServerLogs()}\n${client.getLogs()}`
                );
                assert.strictEqual(rec.ok, true, `DevContainer E2E failed: ${JSON.stringify(rec)}`);
                assert.strictEqual(rec.remoteName, "dev-container");
                assert.strictEqual(rec.committedVerdict, "Block");
                assert.strictEqual(rec.proveListStatus, "Listed");
                assert.strictEqual(rec.proveFullStatus, "Compared");
                assert.ok(Number(rec.proveProtectionLossesCount) >= 1);
                assert.strictEqual(rec.proveReplayStatus, "Compared");
                assert.strictEqual(rec.proveReplayRunCount, 1);
                return rec;
              } finally {
                await client.shutdown();
              }
            }
          );

          const acContainerRepo = "/tmp/cw-v04-dc-attc/repo";
          const acReceipt = await withDockerVscodeServer(
            "attc",
            (cOut) => ({
              scenario: "docker_devcontainer_full",
              expectedRemoteName: "attached-container",
              repoDir: acContainerRepo,
              baseOid: "HEAD~1",
              headOid: "HEAD",
              proveExe: "/opt/prove-venv/bin/checkwash-prove",
              runProveSuite: false,
              receiptPath: `${cOut}/receipt-attc.json`,
            }),
            {
              "checkwashLens.provePath": "/opt/prove-venv/bin/checkwash-prove",
            },
            async ({ resolverConfigPath, containerRepoDir, hostOutDir, getServerLogs }) => {
              const client = launchWinCodeClientToRemote({
                codeExePath: codeExe,
                uiResolverDir,
                resolverConfigPath,
                userDataDir: path.join(hostOutDir, "win-ud"),
                extensionsDir: path.join(hostOutDir, "win-exts"),
                folderUri: `vscode-remote://attached-container+cwv04docker${containerRepoDir}`,
                trustedWindow: true,
                userSettings: {},
              });
              try {
                const rec = await waitForFileJson<Record<string, unknown>>(
                  path.join(hostOutDir, "receipt-attc.json"),
                  60_000,
                  () => `${getServerLogs()}\n${client.getLogs()}`
                );
                assert.strictEqual(rec.ok, true, `Attached Container failed: ${JSON.stringify(rec)}`);
                assert.strictEqual(rec.remoteName, "attached-container");
                assert.strictEqual(rec.committedVerdict, "Block");
                return rec;
              } finally {
                await client.shutdown();
              }
            }
          );

          return {
            devContainerReceipt: dcReceipt,
            attachedContainerReceipt: acReceipt,
          };
        }
      );

      // -----------------------------------------------------------------------
      // Case 5: V04-REMOTE-SSH-REJECTED-E2E — Real vscode-server with 'ssh-remote' Refused (0 spawns)
      // -----------------------------------------------------------------------
      await runCase(
        "V04-REMOTE-SSH-REJECTED-E2E",
        "Real Code.exe <-> Linux vscode-server connected as 'ssh-remote' -> strictly refused (Not Run, 0 spawns)",
        async () => {
          const sshRepoDir = "/tmp/cw-v04-dc-ssh/repo";
          return await withDockerVscodeServer(
            "ssh",
            (cOut) => ({
              scenario: "remote_ssh_rejected",
              repoDir: sshRepoDir,
              offlineReportPath: `${cOut}/offline.json`,
              receiptPath: `${cOut}/receipt-ssh.json`,
            }),
            {},
            async ({ resolverConfigPath, containerRepoDir, hostOutDir, getServerLogs }) => {
              const client = launchWinCodeClientToRemote({
                codeExePath: codeExe,
                uiResolverDir,
                resolverConfigPath,
                userDataDir: path.join(hostOutDir, "win-ud"),
                extensionsDir: path.join(hostOutDir, "win-exts"),
                folderUri: `vscode-remote://ssh-remote+blockedhost${containerRepoDir}`,
                trustedWindow: true,
                userSettings: {},
              });
              try {
                const rec = await waitForFileJson<Record<string, unknown>>(
                  path.join(hostOutDir, "receipt-ssh.json"),
                  60_000,
                  () => `${getServerLogs()}\n${client.getLogs()}`
                );
                assert.strictEqual(rec.ok, true, `SSH rejection E2E failed: ${JSON.stringify(rec)}`);
                assert.strictEqual(rec.remoteName, "ssh-remote");
                assert.strictEqual(rec.spawnedCount, 0);
                assert.strictEqual(rec.offlineReadOnlyWorked, true);
                return rec;
              } finally {
                await client.shutdown();
              }
            }
          );
        }
      );
    }

    const failedCases = cases.filter((c) => c.status === "FAIL");
    const { headSha, worktreeClean } = getGitHeadAndCleanState();
    const receipt = {
      suite: "v04-wsl-devcontainer-vscode-server",
      extensionVersion: PKG_VERSION,
      generatedAt: new Date().toISOString(),
      ...getPlatformExecutionMetadata(),
      sourceSha: headSha,
      worktreeClean,
      scope: IS_WIN32
        ? "Windows 11 UI Host + Real WSL2 (Ubuntu-24.04) vscode-server + Real Docker Linux Container vscode-server + Cross-OS Admission/Mount/PE Invariants"
        : "Linux x64 Container Native Kernel Inode Containment + WSLInterop/PE/Mount/Remote Admission Invariants",
      notRunEnvironments: [
        "NOT_RUN: Remote - SSH ('ssh-remote') execution support (intentionally rejected by policy; negative rejection verified E2E)",
        "NOT_RUN: Dev Tunnels ('tunnel') / GitHub Codespaces ('codespaces') / Virtual Workspaces ('vscode-vfs')",
        "NOT_RUN: Windows 10 x64 / macOS / ARM64 (linux-arm64, win32-arm64)",
      ],
      totalCases: cases.length,
      passedCases: cases.filter((c) => c.status === "PASS").length,
      failedCases: failedCases.length,
      exitCode: failedCases.length === 0 ? 0 : 1,
      cases,
    };

    const outPath = path.join(EVIDENCE_DIR, "v04-wsl-devcontainer-vscode-server-results.json");
    fs.writeFileSync(outPath, JSON.stringify(receipt, null, 2) + "\n", "utf8");
    console.log(`=== Wrote v0.4.0 receipt to ${outPath} (passed=${receipt.passedCases}/${receipt.totalCases}) ===`);

    if (failedCases.length > 0) {
      process.exitCode = 1;
    }
  } finally {
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch {
      // best-effort temp cleanup
    }
  }
}

void main().catch((err) => {
  console.error(err);
  process.exit(1);
});
