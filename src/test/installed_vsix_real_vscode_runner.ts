/**
 * installed_vsix_real_vscode_runner.ts
 *
 * End-to-End Verification of the Built Production VSIX (`checkwash-lens-0.1.0-win32-x64.vsix`)
 * Installed into Isolated Desktop VS Code (`Code.exe`) Profiles:
 *
 *   1. VSIX Archive & Installed Payload Audit:
 *      - Verifies exact SHA-256 and byte size of `checkwash-lens-0.1.0-win32-x64.vsix`,
 *        bundled `checkwash.pyz` (`v0.13.1`), and `checkwash-broker.exe`.
 *      - Installs the `.vsix` into isolated `--extensions-dir` via VS Code's own CLI (`cli.js --install-extension`),
 *        never passing `--extensionDevelopmentPath=<checkwash-lens>`.
 *
 *   2. Session 1 — Real B01 Restricted Mode (`vscode.workspace.isTrusted === false`):
 *      - Launches real Desktop VS Code (`Code.exe`) with Workspace Trust ENABLED (no `--disable-workspace-trust`)
 *        on an untrusted temporary Git repository.
 *      - Verifies `taipei49314.checkwash-lens` has NOT yet activated (`ext.isActive === false`), attaches BOTH
 *        an out-of-process NT Kernel Job Object + IOCP process-creation monitor (`AssignProcessToJobObject` +
 *        `JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.TotalProcesses` + `JOB_OBJECT_MSG_NEW_PROCESS`) to the Extension
 *        Host PID (`process.pid`) AND synchronous in-process `child_process` hooks BEFORE calling `ext.activate()`.
 *      - Exercises activation, `scanCommittedRange`, `runProveList`, `runProveFull`, `replayMutant`,
 *        `copyContextDietDiff`, `cancelActiveScan`, editor open/edit/save events, configuration inspection
 *        (with poisoned `.vscode/settings.json`), and direct probe/plan entrypoints.
 *      - Proves ZERO child processes were created in the Extension Host process tree across activation and all
 *        tested Restricted Mode operations (backed by a live positive control on Session 2), while
 *        `checkwashLens.viewOfflineReport` still renders Checkwash JSON v2 and Prove v0.1.0 reports read-only.
 *
 *   3. Session 2 — Trusted Installed VSIX End-to-End Flow (+ Kernel Monitor Positive Control):
 *      - Launches real Desktop VS Code (`Code.exe`) in an isolated Trusted profile with the `.vsix` installed,
 *        attaching the same NT Kernel Job Object + IOCP monitor to confirm positive detection of short-lived
 *        broker/git/python child processes (`kernelSpawnedChildCount > 0`).
 *      - Verifies `scanCommittedRange` (`Block` verdict, real `vscode.languages.getDiagnostics`,
 *        `checkwash-rev:` immutable document provider, Hover provider, and Context Diet SQL `-- ` secret masking),
 *        true `"cancelled"` semantics via `checkwashLens.cancelActiveScan` across static scan, multi-process
 *        child+grandchild tree (`inFlightOutcomeStatus === "cancelled"`, never `"timed_out"`), Prove preflight,
 *        and Prove execution (subsequent scan unblocked), plus read-only `viewOfflineReport`.
 */

import * as assert from "assert";
import * as cp from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  ACTIVE_VSIX_TARGET,
  getPlatformExecutionMetadata,
  getPlatformVscodeLaunchArgs,
  IS_WIN32,
  killProcessTreeBestEffort,
  resolveBundledBrokerFilename,
  resolvePlatformEvidenceDir,
  resolveTestGitExe,
  resolveTestProveExe,
  resolveTestPythonExe,
  resolveTestVscodeExe,
} from "./testPlatformEnv";

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const FIXTURES_DIR = path.join(REPO_ROOT, "fixtures", "phase0");
const EVIDENCE_DIR = resolvePlatformEvidenceDir(REPO_ROOT);
const RESULTS_FILE = path.join(EVIDENCE_DIR, "installed-vsix-real-vscode-results.json");
const PKG_JSON = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8")) as {
  name: string;
  version: string;
};
const VSIX_PATH = path.join(
  REPO_ROOT,
  `${PKG_JSON.name}-${PKG_JSON.version}-${ACTIVE_VSIX_TARGET}.vsix`
);
const BUNDLED_MANIFEST_PATH = path.join(REPO_ROOT, "bundled", "manifest.json");
const CSC_EXE = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe";

const CODE_EXE = resolveTestVscodeExe();
const PYTHON_EXE = resolveTestPythonExe();
const GIT_EXE = resolveTestGitExe();
const PROVE_EXE = resolveTestProveExe();

function sha256Buffer(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function sha256File(filePath: string): string {
  return sha256Buffer(fs.readFileSync(filePath));
}

function sleepOuter(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isPidAliveOuter(pid: number | undefined | null): boolean {
  if (!pid || pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
  } catch (err: unknown) {
    if (!(err && typeof err === "object" && (err as { code?: string }).code === "EPERM")) {
      return false;
    }
  }
  if (!IS_WIN32) {
    try {
      const statText = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
      const closeParen = statText.lastIndexOf(")");
      const stateChar = closeParen >= 0 ? statText.slice(closeParen + 1).trim()[0] : "";
      if (stateChar === "Z" || stateChar === "X") {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

function forceKillProcessTree(pid: number | undefined | null): void {
  if (!pid || pid <= 0) {
    return;
  }
  killProcessTreeBestEffort(pid);
}

function runGitSync(repoDir: string, args: string[]): string {
  const res = cp.spawnSync(GIT_EXE, ["-C", repoDir, ...args], {
    encoding: "utf8",
    windowsHide: true,
  });
  if (res.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed in ${repoDir}: ${res.stderr}`);
  }
  return (res.stdout || "").trim();
}

function readZipEntryNames(zipBuf: Buffer): string[] {
  let eocdOffset = -1;
  for (let i = zipBuf.length - 22; i >= Math.max(0, zipBuf.length - 65557); i--) {
    if (zipBuf.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw new Error("Invalid VSIX archive: EOCD signature not found");
  }
  const totalEntries = zipBuf.readUInt16LE(eocdOffset + 10);
  const cdOffset = zipBuf.readUInt32LE(eocdOffset + 16);
  const names: string[] = [];
  let cursor = cdOffset;
  for (let i = 0; i < totalEntries; i++) {
    if (zipBuf.readUInt32LE(cursor) !== 0x02014b50) {
      throw new Error(`Invalid Central Directory header at offset ${cursor}`);
    }
    const nameLen = zipBuf.readUInt16LE(cursor + 28);
    const extraLen = zipBuf.readUInt16LE(cursor + 30);
    const commentLen = zipBuf.readUInt16LE(cursor + 32);
    const name = zipBuf.subarray(cursor + 46, cursor + 46 + nameLen).toString("utf8");
    names.push(name);
    cursor += 46 + nameLen + extraLen + commentLen;
  }
  return names;
}

function findVsCodeCliJs(codeExePath: string): string {
  const codeDir = path.dirname(codeExePath);
  const directCandidate = path.join(codeDir, "resources", "app", "out", "cli.js");
  if (fs.existsSync(directCandidate)) {
    return directCandidate;
  }
  for (const entry of fs.readdirSync(codeDir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      const subCandidate = path.join(codeDir, entry.name, "resources", "app", "out", "cli.js");
      if (fs.existsSync(subCandidate)) {
        return subCandidate;
      }
    }
  }
  throw new Error(`Could not locate VS Code resources/app/out/cli.js under ${codeDir}`);
}

function installVsixIntoIsolatedProfile(params: {
  codeExePath: string;
  cliJsPath: string;
  vsixPath: string;
  extensionsDir: string;
  userDataDir: string;
}): { installExitCode: number | null; installStdout: string; installStderr: string; installedExtDir: string } {
  fs.mkdirSync(params.extensionsDir, { recursive: true });
  fs.mkdirSync(path.join(params.userDataDir, "User"), { recursive: true });

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ELECTRON_RUN_AS_NODE: "1",
  };
  const res = cp.spawnSync(
    params.codeExePath,
    [
      params.cliJsPath,
      "--install-extension",
      params.vsixPath,
      "--extensions-dir",
      params.extensionsDir,
      "--user-data-dir",
      params.userDataDir,
      "--force",
    ],
    {
      encoding: "utf8",
      env,
      timeout: 60_000,
      windowsHide: true,
    }
  );
  if (res.status !== 0) {
    throw new Error(
      `Failed to install VSIX (exit=${res.status}): stdout=${res.stdout}\nstderr=${res.stderr}`
    );
  }

  const subdirs = fs
    .readdirSync(params.extensionsDir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && d.name.toLowerCase().startsWith("taipei49314.checkwash-lens-"));
  assert.strictEqual(
    subdirs.length,
    1,
    `Expected exactly 1 installed checkwash-lens folder in ${params.extensionsDir}, found: ${subdirs.map((d) => d.name).join(", ")}`
  );

  return {
    installExitCode: res.status,
    installStdout: (res.stdout || "").trim(),
    installStderr: (res.stderr || "").trim(),
    installedExtDir: path.join(params.extensionsDir, subdirs[0].name),
  };
}

/**
 * Compiles a 64-bit native Win32 NT Kernel Job Object + I/O Completion Port process-creation monitor
 * (`AssignProcessToJobObject` + `JOBOBJECT_BASIC_ACCOUNTING_INFORMATION` + `JOB_OBJECT_MSG_NEW_PROCESS`).
 *
 * Unlike user-mode snapshot polling (`CreateToolhelp32Snapshot`), kernel Job Object accounting (`TotalProcesses`)
 * and IOCP `JOB_OBJECT_MSG_NEW_PROCESS` packets are recorded synchronously inside the Windows kernel on every
 * child/descendant process creation regardless of how short-lived (`<1ms`) the process is.
 * Intentionally sets NO `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` limit so releasing the handle never perturbs VS Code.
 */
function compileDescendantProcessMonitorExe(outDir: string): string {
  if (!IS_WIN32) {
    const cPath = path.join(outDir, "ExtHostProcMonitor.c");
    const binPath = path.join(outDir, "ExtHostProcMonitor");
    const cSource = `
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_O_TRACEFORK
#define PTRACE_O_TRACEFORK 0x00000002
#endif
#ifndef PTRACE_O_TRACEVFORK
#define PTRACE_O_TRACEVFORK 0x00000004
#endif
#ifndef PTRACE_O_TRACECLONE
#define PTRACE_O_TRACECLONE 0x00000008
#endif
#ifndef PTRACE_O_TRACEEXEC
#define PTRACE_O_TRACEEXEC 0x00000010
#endif
#ifndef PTRACE_EVENT_FORK
#define PTRACE_EVENT_FORK 1
#endif
#ifndef PTRACE_EVENT_VFORK
#define PTRACE_EVENT_VFORK 2
#endif
#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif
#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC 4
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define MAX_TRACKED 4096

typedef struct {
  pid_t pid;
  char imagePath[1024];
} SpawnEvent;

static pid_t rootThreads[MAX_TRACKED];
static int rootThreadCount = 0;

static pid_t countedChildren[MAX_TRACKED];
static int countedChildCount = 0;

static pid_t pendingExecChildren[MAX_TRACKED];
static int pendingExecCount = 0;

static SpawnEvent events[MAX_TRACKED];
static int eventCount = 0;

static int containsPid(const pid_t *arr, int count, pid_t p) {
  for (int i = 0; i < count; i++) {
    if (arr[i] == p) return 1;
  }
  return 0;
}

static void addPidUnique(pid_t *arr, int *count, pid_t p) {
  if (p <= 0 || *count >= MAX_TRACKED) return;
  if (!containsPid(arr, *count, p)) {
    arr[*count] = p;
    (*count)++;
  }
}

static void removePid(pid_t *arr, int *count, pid_t p) {
  for (int i = 0; i < *count; i++) {
    if (arr[i] == p) {
      arr[i] = arr[*count - 1];
      (*count)--;
      return;
    }
  }
}

static int isTaskOfRoot(pid_t rootPid, pid_t candidateTid) {
  if (candidateTid == rootPid) return 1;
  if (containsPid(rootThreads, rootThreadCount, candidateTid)) return 1;
  char pathBuf[128];
  snprintf(pathBuf, sizeof(pathBuf), "/proc/%d/task/%d", (int)rootPid, (int)candidateTid);
  if (access(pathBuf, F_OK) == 0) {
    addPidUnique(rootThreads, &rootThreadCount, candidateTid);
    return 1;
  }
  return 0;
}

static void readProcExe(pid_t pid, char *outBuf, size_t cap) {
  char linkPath[128];
  snprintf(linkPath, sizeof(linkPath), "/proc/%d/exe", (int)pid);
  ssize_t n = readlink(linkPath, outBuf, cap - 1);
  if (n > 0) {
    outBuf[n] = '\\0';
  } else {
    outBuf[0] = '\\0';
  }
}

static void writeJsonEscaped(FILE *f, const char *s) {
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p == '\\\\') fputs("\\\\\\\\", f);
    else if (*p == '"') fputs("\\\\\\"", f);
    else if (*p == '\\n' || *p == '\\r') fputc(' ', f);
    else if (*p >= 0x20) fputc(*p, f);
  }
}

static int writeErrorJson(const char *outPath, int code, int errNum, const char *msg) {
  FILE *f = fopen(outPath, "wb");
  if (f) {
    fprintf(f, "{\\"kernelJobAssigned\\":false,\\"errorCode\\":%d,\\"errno\\":%d,\\"error\\":\\"", code, errNum);
    writeJsonEscaped(f, msg);
    fprintf(f, "\\"}");
    fclose(f);
  }
  return code;
}

static uint64_t monotonicMs(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static void recordExecEvent(pid_t pid, const char *img) {
  if (eventCount >= MAX_TRACKED) return;
  events[eventCount].pid = pid;
  snprintf(events[eventCount].imagePath, sizeof(events[eventCount].imagePath), "%s", img ? img : "");
  eventCount++;
}

static void drainWaitEvents(pid_t rootPid, int *exitedChildCount) {
  for (;;) {
    int status = 0;
    pid_t wpid = waitpid(-1, &status, __WALL | WNOHANG);
    if (wpid <= 0) {
      break;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      if (containsPid(rootThreads, rootThreadCount, wpid)) {
        removePid(rootThreads, &rootThreadCount, wpid);
      } else if (containsPid(countedChildren, countedChildCount, wpid)) {
        (*exitedChildCount)++;
        removePid(pendingExecChildren, &pendingExecCount, wpid);
      }
      continue;
    }

    if (!WIFSTOPPED(status)) {
      continue;
    }

    int stopSig = WSTOPSIG(status);
    unsigned int event = ((unsigned int)status) >> 16;

    if (isTaskOfRoot(rootPid, wpid)) {
      if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
        unsigned long newPidUl = 0;
        if (ptrace(PTRACE_GETEVENTMSG, wpid, NULL, &newPidUl) == 0 && newPidUl > 0) {
          pid_t newPid = (pid_t)newPidUl;
          if (!isTaskOfRoot(rootPid, newPid)) {
            addPidUnique(countedChildren, &countedChildCount, newPid);
            addPidUnique(pendingExecChildren, &pendingExecCount, newPid);
          }
        }
      }
      int deliverSig = (event == 0) ? stopSig : 0;
      ptrace(PTRACE_CONT, wpid, NULL, (void *)(uintptr_t)deliverSig);
    } else {
      addPidUnique(countedChildren, &countedChildCount, wpid);
      if (event == PTRACE_EVENT_EXEC) {
        char img[1024];
        readProcExe(wpid, img, sizeof(img));
        recordExecEvent(wpid, img);
        removePid(pendingExecChildren, &pendingExecCount, wpid);
        ptrace(PTRACE_DETACH, wpid, NULL, 0);
      } else {
        addPidUnique(pendingExecChildren, &pendingExecCount, wpid);
        int deliverSig = (event == 0) ? stopSig : 0;
        ptrace(PTRACE_CONT, wpid, NULL, (void *)(uintptr_t)deliverSig);
      }
    }
  }
}

static void detachTracee(pid_t tid) {
  if (tid <= 0) return;
  if (ptrace(PTRACE_INTERRUPT, tid, NULL, NULL) != 0) {
    return;
  }
  uint64_t start = monotonicMs();
  while (monotonicMs() - start < 250) {
    int st = 0;
    pid_t r = waitpid(tid, &st, __WALL | WNOHANG);
    if (r == tid) {
      if (WIFSTOPPED(st)) {
        unsigned int ev = ((unsigned int)st) >> 16;
        int sig = (ev == 0) ? WSTOPSIG(st) : 0;
        if (ptrace(PTRACE_DETACH, tid, NULL, (void *)(uintptr_t)sig) == 0) {
          return;
        }
      } else if (WIFEXITED(st) || WIFSIGNALED(st)) {
        return;
      }
    } else if (r < 0 && errno == ECHILD) {
      return;
    }
    usleep(2000);
  }
}

int main(int argc, char **argv) {
  if (argc < 5) return 2;
  pid_t rootPid = (pid_t)atoi(argv[1]);
  const char *ackPath = argv[2];
  const char *stopPath = argv[3];
  const char *outJsonPath = argv[4];

  unsigned long seizeOpts =
    PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;

  char taskDirBuf[128];
  snprintf(taskDirBuf, sizeof(taskDirBuf), "/proc/%d/task", (int)rootPid);
  int rootAttached = 0;

  for (int pass = 0; pass < 4; pass++) {
    DIR *d = opendir(taskDirBuf);
    if (!d) {
      return writeErrorJson(outJsonPath, 10, errno, "opendir(/proc/rootPid/task) failed");
    }
    int newlyAttached = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
      if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
      pid_t tid = (pid_t)atoi(ent->d_name);
      if (tid <= 0 || containsPid(rootThreads, rootThreadCount, tid)) continue;
      if (ptrace(PTRACE_SEIZE, tid, NULL, (void *)(uintptr_t)seizeOpts) == 0) {
        addPidUnique(rootThreads, &rootThreadCount, tid);
        if (tid == rootPid) rootAttached = 1;
        newlyAttached++;
      } else if (tid == rootPid && !rootAttached) {
        int savedErr = errno;
        closedir(d);
        return writeErrorJson(outJsonPath, 14, savedErr, "ptrace(PTRACE_SEIZE) failed on rootPid");
      }
    }
    closedir(d);
    if (newlyAttached == 0) break;
  }

  if (!rootAttached) {
    return writeErrorJson(outJsonPath, 14, ESRCH, "rootPid was not attached by PTRACE_SEIZE");
  }

  FILE *ackF = fopen(ackPath, "wb");
  if (ackF) {
    fwrite("ready", 1, 5, ackF);
    fclose(ackF);
  }

  int exitedChildCount = 0;
  uint64_t deadline = monotonicMs() + 85000ULL;
  while (monotonicMs() < deadline) {
    drainWaitEvents(rootPid, &exitedChildCount);
    if (access(stopPath, F_OK) == 0) {
      drainWaitEvents(rootPid, &exitedChildCount);
      break;
    }
    usleep(1000);
  }

  for (int i = 0; i < pendingExecCount; i++) {
    detachTracee(pendingExecChildren[i]);
  }
  for (int i = 0; i < rootThreadCount; i++) {
    detachTracee(rootThreads[i]);
  }

  FILE *outF = fopen(outJsonPath, "wb");
  if (!outF) return 17;
  fprintf(outF, "{");
  fprintf(outF, "\\"rootPid\\":%d,", (int)rootPid);
  fprintf(outF, "\\"observationMechanism\\":\\"linux-kernel-ptrace-seize-fork-clone-exec-monitor\\",");
  fprintf(outF, "\\"observationScope\\":\\"Extension Host process tree (extHostPid) from pre-activation handshake until monitor stop\\",");
  fprintf(outF, "\\"kernelJobAssigned\\":true,");
  fprintf(outF, "\\"rootPidAssignedEventObserved\\":true,");
  fprintf(outF, "\\"initialTotalProcesses\\":1,");
  fprintf(outF, "\\"finalTotalProcesses\\":%d,", 1 + countedChildCount);
  fprintf(outF, "\\"kernelSpawnedChildCount\\":%d,", countedChildCount);
  fprintf(outF, "\\"iocpExitedChildCount\\":%d,", exitedChildCount);
  fprintf(outF, "\\"iocpNewProcessEvents\\":[");
  for (int i = 0; i < eventCount; i++) {
    if (i > 0) fputc(',', outF);
    fprintf(outF, "{\\"pid\\":%d,\\"imagePath\\":\\"", (int)events[i].pid);
    writeJsonEscaped(outF, events[i].imagePath);
    fprintf(outF, "\\"}");
  }
  fprintf(outF, "]}");
  fclose(outF);
  return 0;
}
`;
    fs.writeFileSync(cPath, cSource, "utf8");
    const res = cp.spawnSync("gcc", ["-O2", "-Wall", "-Wextra", "-o", binPath, cPath], {
      encoding: "utf8",
    });
    if (res.status !== 0) {
      throw new Error(`gcc failed compiling ExtHostProcMonitor: ${res.stdout}\n${res.stderr}`);
    }
    fs.chmodSync(binPath, 0o755);
    return binPath;
  }

  assert.strictEqual(fs.existsSync(CSC_EXE), true, `csc.exe required at ${CSC_EXE}`);
  const csPath = path.join(outDir, "ExtHostProcMonitor.cs");
  const exePath = path.join(outDir, "ExtHostProcMonitor.exe");
  const csSource = `
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

class Program {
  const uint PROCESS_TERMINATE = 0x0001;
  const uint PROCESS_SET_QUOTA = 0x0100;
  const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
  const int JobObjectBasicAccountingInformation = 1;
  const int JobObjectAssociateCompletionPortInformation = 7;
  const uint JOB_OBJECT_MSG_NEW_PROCESS = 6;
  const uint JOB_OBJECT_MSG_EXIT_PROCESS = 7;
  const uint JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS = 8;

  [StructLayout(LayoutKind.Sequential)]
  struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
    public long TotalUserTime;
    public long TotalKernelTime;
    public long ThisPeriodTotalUserTime;
    public long ThisPeriodTotalKernelTime;
    public uint TotalPageFaultCount;
    public uint TotalProcesses;
    public uint ActiveProcesses;
    public uint TotalTerminatedProcesses;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
    public IntPtr CompletionKey;
    public IntPtr CompletionPort;
  }

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr CreateIoCompletionPort(
    IntPtr FileHandle,
    IntPtr ExistingCompletionPort,
    UIntPtr CompletionKey,
    uint NumberOfConcurrentThreads
  );

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool SetInformationJobObject(
    IntPtr hJob,
    int JobObjectInfoClass,
    ref JOBOBJECT_ASSOCIATE_COMPLETION_PORT lpJobObjectInfo,
    uint cbJobObjectInfoLength
  );

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool QueryInformationJobObject(
    IntPtr hJob,
    int JobObjectInfoClass,
    out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION lpJobObjectInfo,
    uint cbJobObjectInfoLength,
    out uint lpReturnLength
  );

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool GetQueuedCompletionStatus(
    IntPtr CompletionPort,
    out uint lpNumberOfBytesTransferred,
    out UIntPtr lpCompletionKey,
    out IntPtr lpOverlapped,
    uint dwMilliseconds
  );

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool CloseHandle(IntPtr hObject);

  static string EscapeJson(string s) {
    if (s == null) return "";
    return s.Replace("\\\\", "\\\\\\\\").Replace("\\"", "\\\\\\"").Replace("\\r", "").Replace("\\n", " ");
  }

  static string GetImagePath(uint pid) {
    IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
    if (h == IntPtr.Zero) return "";
    try {
      StringBuilder sb = new StringBuilder(32768);
      uint sz = (uint)sb.Capacity;
      if (QueryFullProcessImageNameW(h, 0, sb, ref sz)) {
        return sb.ToString();
      }
      return "";
    } finally {
      CloseHandle(h);
    }
  }

  static void DrainCompletionPackets(
    IntPtr hIocp,
    uint rootPid,
    uint waitMs,
    ref bool rootPidAssignedEventObserved,
    ref int iocpExitedChildCount,
    List<string> iocpNewProcessJsonItems
  ) {
    uint msgId;
    UIntPtr compKey;
    IntPtr overlapped;
    if (!GetQueuedCompletionStatus(hIocp, out msgId, out compKey, out overlapped, waitMs)) {
      return;
    }
    do {
      uint pid = (uint)overlapped.ToInt64();
      if (msgId == JOB_OBJECT_MSG_NEW_PROCESS) {
        if (pid == rootPid) {
          rootPidAssignedEventObserved = true;
        } else {
          string img = EscapeJson(GetImagePath(pid));
          iocpNewProcessJsonItems.Add("{\\"pid\\":" + pid + ",\\"imagePath\\":\\"" + img + "\\"}");
        }
      } else if (msgId == JOB_OBJECT_MSG_EXIT_PROCESS || msgId == JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS) {
        if (pid != rootPid) {
          iocpExitedChildCount++;
        }
      }
    } while (GetQueuedCompletionStatus(hIocp, out msgId, out compKey, out overlapped, 0));
  }

  static int WriteErrorAndExit(string outJsonPath, int code, string reason) {
    string json = "{\\"kernelJobAssigned\\":false,\\"errorCode\\":" + code + ",\\"win32LastError\\":" + Marshal.GetLastWin32Error() + ",\\"error\\":\\"" + EscapeJson(reason) + "\\"}";
    File.WriteAllText(outJsonPath, json, new UTF8Encoding(false));
    return code;
  }

  static int Main(string[] args) {
    uint rootPid = uint.Parse(args[0]);
    string ackPath = args[1];
    string stopPath = args[2];
    string outJsonPath = args[3];

    IntPtr hRoot = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, rootPid);
    if (hRoot == IntPtr.Zero) {
      return WriteErrorAndExit(outJsonPath, 10, "OpenProcess failed for rootPid " + rootPid);
    }

    IntPtr hJob = IntPtr.Zero;
    IntPtr hIocp = IntPtr.Zero;
    try {
      hJob = CreateJobObjectW(IntPtr.Zero, null);
      if (hJob == IntPtr.Zero) {
        return WriteErrorAndExit(outJsonPath, 11, "CreateJobObjectW failed");
      }

      hIocp = CreateIoCompletionPort(new IntPtr(-1), IntPtr.Zero, UIntPtr.Zero, 1);
      if (hIocp == IntPtr.Zero) {
        return WriteErrorAndExit(outJsonPath, 12, "CreateIoCompletionPort failed");
      }

      JOBOBJECT_ASSOCIATE_COMPLETION_PORT assoc = new JOBOBJECT_ASSOCIATE_COMPLETION_PORT();
      assoc.CompletionKey = new IntPtr(1);
      assoc.CompletionPort = hIocp;
      if (!SetInformationJobObject(
        hJob,
        JobObjectAssociateCompletionPortInformation,
        ref assoc,
        (uint)Marshal.SizeOf(typeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT))
      )) {
        return WriteErrorAndExit(outJsonPath, 13, "SetInformationJobObject(AssociateCompletionPort) failed");
      }

      if (!AssignProcessToJobObject(hJob, hRoot)) {
        return WriteErrorAndExit(outJsonPath, 14, "AssignProcessToJobObject failed");
      }

      JOBOBJECT_BASIC_ACCOUNTING_INFORMATION initAcc;
      uint retLen;
      if (!QueryInformationJobObject(
        hJob,
        JobObjectBasicAccountingInformation,
        out initAcc,
        (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)),
        out retLen
      )) {
        return WriteErrorAndExit(outJsonPath, 15, "Initial QueryInformationJobObject failed");
      }

      bool rootPidAssignedEventObserved = false;
      int iocpExitedChildCount = 0;
      List<string> iocpNewProcessJsonItems = new List<string>();

      DrainCompletionPackets(
        hIocp,
        rootPid,
        0,
        ref rootPidAssignedEventObserved,
        ref iocpExitedChildCount,
        iocpNewProcessJsonItems
      );

      // Signal ACK only AFTER Kernel Job Object + IOCP are bound and baseline accounting is captured
      File.WriteAllText(ackPath, "ready", new UTF8Encoding(false));

      DateTime deadline = DateTime.UtcNow.AddSeconds(65);
      while (!File.Exists(stopPath) && DateTime.UtcNow < deadline) {
        DrainCompletionPackets(
          hIocp,
          rootPid,
          40,
          ref rootPidAssignedEventObserved,
          ref iocpExitedChildCount,
          iocpNewProcessJsonItems
        );
      }

      JOBOBJECT_BASIC_ACCOUNTING_INFORMATION finalAcc;
      if (!QueryInformationJobObject(
        hJob,
        JobObjectBasicAccountingInformation,
        out finalAcc,
        (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)),
        out retLen
      )) {
        return WriteErrorAndExit(outJsonPath, 16, "Final QueryInformationJobObject failed");
      }

      DrainCompletionPackets(
        hIocp,
        rootPid,
        0,
        ref rootPidAssignedEventObserved,
        ref iocpExitedChildCount,
        iocpNewProcessJsonItems
      );

      int initialTotal = (int)initAcc.TotalProcesses;
      int finalTotal = (int)finalAcc.TotalProcesses;
      int spawnedChildren = finalTotal - initialTotal;

      StringBuilder outSb = new StringBuilder();
      outSb.Append("{");
      outSb.Append("\\"rootPid\\":" + rootPid + ",");
      outSb.Append("\\"observationMechanism\\":\\"win32-nt-kernel-job-object-accounting-and-iocp\\",");
      outSb.Append("\\"observationScope\\":\\"Extension Host process tree (extHostPid) from pre-activation handshake until monitor stop\\",");
      outSb.Append("\\"kernelJobAssigned\\":true,");
      outSb.Append("\\"rootPidAssignedEventObserved\\":" + (rootPidAssignedEventObserved ? "true" : "false") + ",");
      outSb.Append("\\"initialTotalProcesses\\":" + initialTotal + ",");
      outSb.Append("\\"finalTotalProcesses\\":" + finalTotal + ",");
      outSb.Append("\\"kernelSpawnedChildCount\\":" + spawnedChildren + ",");
      outSb.Append("\\"iocpExitedChildCount\\":" + iocpExitedChildCount + ",");
      outSb.Append("\\"iocpNewProcessEvents\\":[");
      for (int i = 0; i < iocpNewProcessJsonItems.Count; i++) {
        if (i > 0) outSb.Append(",");
        outSb.Append(iocpNewProcessJsonItems[i]);
      }
      outSb.Append("]}");
      File.WriteAllText(outJsonPath, outSb.ToString(), new UTF8Encoding(false));
      return 0;
    } finally {
      if (hIocp != IntPtr.Zero) CloseHandle(hIocp);
      if (hJob != IntPtr.Zero) CloseHandle(hJob);
      if (hRoot != IntPtr.Zero) CloseHandle(hRoot);
    }
  }
}
`;
  fs.writeFileSync(csPath, csSource, "utf8");
  const res = cp.spawnSync(
    CSC_EXE,
    ["/nologo", "/platform:x64", "/target:exe", `/out:${exePath}`, csPath],
    {
      encoding: "utf8",
      windowsHide: true,
    }
  );
  if (res.status !== 0) {
    throw new Error(`csc.exe failed compiling ExtHostProcMonitor: ${res.stdout}\n${res.stderr}`);
  }
  return exePath;
}

/**
 * On Linux with Yama LSM (`kernel.yama.ptrace_scope = 1`), an unprivileged sibling process
 * (`ExtHostProcMonitor`) cannot call `ptrace(PTRACE_SEIZE, extHostPid)` unless the tracee
 * (`extHostPid`) calls `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)`.
 *
 * Compiles a tiny header-free N-API shared library (`allow_ptracer.node`) loaded synchronously
 * in-process via `process.dlopen` inside the test driver BEFORE `taipei49314.checkwash-lens`
 * activates and BEFORE writing `handshakePath` (spawning zero child processes and requiring zero root privileges).
 */
function compileLinuxAllowPtracerAddon(outDir: string): string | null {
  if (IS_WIN32) {
    return null;
  }
  const cPath = path.join(outDir, "allow_ptracer.c");
  const nodeAddonPath = path.join(outDir, "allow_ptracer.node");
  const cSource = `
#include <sys/prctl.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

__attribute__((constructor))
static void cw_test_allow_yama_ptracer(void) {
  (void)prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
}

__attribute__((visibility("default")))
void *napi_register_module_v1(void *env, void *exports) {
  (void)env;
  return exports;
}
`;
  fs.writeFileSync(cPath, cSource, "utf8");
  const res = cp.spawnSync(
    "gcc",
    ["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-o", nodeAddonPath, cPath],
    { encoding: "utf8" }
  );
  if (res.status !== 0) {
    throw new Error(
      `gcc failed compiling allow_ptracer.node: ${res.stdout}\n${res.stderr}`
    );
  }
  return nodeAddonPath;
}

function createTestGitRepoWithWeakeningAndSqlSecret(parentDir: string, name: string): {
  repoDir: string;
  baseOid: string;
  headOid: string;
  sqlSecret: string;
  addedPat: string;
} {
  const repoDir = path.join(parentDir, name);
  fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
  fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });
  fs.mkdirSync(path.join(repoDir, "db"), { recursive: true });

  runGitSync(repoDir, ["init"]);
  runGitSync(repoDir, ["config", "user.email", "vsix-verify@example.local"]);
  runGitSync(repoDir, ["config", "user.name", "VSIX Verifier"]);

  const sqlSecret = "SECRET123456_VSIX_SQL_CREDENTIAL";
  const addedPat = "ghp_9876543210ZYXWVUTSRQPONMLKJIHGFEDCBA12";

  fs.writeFileSync(
    path.join(repoDir, "src", "calc.py"),
    "def compute(x: int) -> int:\n    return x - 20\n",
    "utf8"
  );
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_calc.py"),
    "from src.calc import compute\n\ndef test_compute():\n    assert compute(100) == 80\n",
    "utf8"
  );
  fs.writeFileSync(
    path.join(repoDir, "db", "init.sql"),
    `-- bootstrap\n-- api_key = "${sqlSecret}"\nSELECT 1;\n`,
    "utf8"
  );
  // Poison workspace settings inside the repo to verify both Restricted Mode and Trusted Mode ignore repo settings
  fs.mkdirSync(path.join(repoDir, ".vscode"), { recursive: true });
  fs.writeFileSync(
    path.join(repoDir, ".vscode", "settings.json"),
    JSON.stringify(
      {
        "checkwashLens.pythonPath": path.join(repoDir, "evil-python.exe"),
        "checkwashLens.gitPath": path.join(repoDir, "evil-git.exe"),
        "checkwashLens.provePath": path.join(repoDir, "evil-prove.exe"),
      },
      null,
      2
    ),
    "utf8"
  );

  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "base commit"]);
  const baseOid = runGitSync(repoDir, ["rev-parse", "HEAD"]);

  fs.writeFileSync(
    path.join(repoDir, "tests", "test_calc.py"),
    "import time\nfrom src.calc import compute\n\ndef test_compute():\n    time.sleep(1)\n    _ = compute(100)\n    assert True\n",
    "utf8"
  );
  fs.writeFileSync(
    path.join(repoDir, "db", "init.sql"),
    `-- bootstrap\n++ token = "${addedPat}"\nSELECT 1;\n`,
    "utf8"
  );
  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "head commit with weakened test and sql comment diff"]);
  const headOid = runGitSync(repoDir, ["rev-parse", "HEAD"]);

  return { repoDir, baseOid, headOid, sqlSecret, addedPat };
}

/**
 * Creates a tiny, zero-dependency driver extension (`test-driver`) whose sole purpose is to supply
 * `--extensionDevelopmentPath` + `--extensionTestsPath` so `taipei49314.checkwash-lens` itself is loaded
 * strictly as an installed VSIX extension from `--extensions-dir`!
 */
function createDriverExtensionDir(tempRoot: string): {
  driverDir: string;
  restrictedRunnerJs: string;
  trustedRunnerJs: string;
  reloadRunnerJs: string;
  crashRunnerJs: string;
} {
  const driverDir = path.join(tempRoot, "vsix-test-driver-ext");
  fs.mkdirSync(driverDir, { recursive: true });
  fs.writeFileSync(
    path.join(driverDir, "package.json"),
    JSON.stringify(
      {
        name: "vsix-test-driver",
        publisher: "local-test",
        version: "0.0.1",
        engines: { vscode: "^1.96.0" },
        activationEvents: ["*"],
        main: "./index.js",
        capabilities: {
          untrustedWorkspaces: { supported: true },
          virtualWorkspaces: { supported: true },
        },
      },
      null,
      2
    ),
    "utf8"
  );
  fs.writeFileSync(
    path.join(driverDir, "index.js"),
    `"use strict";
exports.activate = function() {
  if (process.env.CW_VSIX_B08_RELOAD_CONFIG) {
    void require("./run_b08_reload.js").run().catch(function(err) {
      try {
        const fs = require("fs");
        const cfg = JSON.parse(fs.readFileSync(process.env.CW_VSIX_B08_RELOAD_CONFIG, "utf8"));
        fs.writeFileSync(
          cfg.phase2ReceiptPath,
          JSON.stringify(
            {
              ok: false,
              phase: fs.existsSync(cfg.phase1HandshakePath) ? "phase2" : "phase1",
              pid: process.pid,
              error: err && (err.stack || err.message) ? (err.stack || err.message) : String(err)
            },
            null,
            2
          ),
          "utf8"
        );
      } catch {}
    });
  } else if (process.env.CW_VSIX_B08_CRASH_CONFIG) {
    void require("./run_b08_crash.js").run().catch(function(err) {
      try {
        const fs = require("fs");
        const cfg = JSON.parse(fs.readFileSync(process.env.CW_VSIX_B08_CRASH_CONFIG, "utf8"));
        if (cfg.crashErrorPath) {
          fs.writeFileSync(
            cfg.crashErrorPath,
            JSON.stringify(
              {
                ok: false,
                pid: process.pid,
                error: err && (err.stack || err.message) ? (err.stack || err.message) : String(err)
              },
              null,
              2
            ),
            "utf8"
          );
        }
      } catch {}
    });
  }
};
exports.deactivate = function() {};
`,
    "utf8"
  );

  // -------------------------------------------------------------------------
  // Session 1 Driver Script: Real Restricted Mode (`workspace.isTrusted === false`)
  // -------------------------------------------------------------------------
  const restrictedRunnerJs = path.join(driverDir, "run_restricted_b01.js");
  fs.writeFileSync(
    restrictedRunnerJs,
    `"use strict";
const cp = require("child_process");
const fs = require("fs");
const path = require("path");
const vscode = require("vscode");

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function findNodeById(nodes, id) {
  for (const n of nodes || []) {
    if (n.id === id) return n;
    const sub = findNodeById(n.children, id);
    if (sub) return sub;
  }
  return null;
}

function collectCommandsInTree(nodes) {
  const cmds = [];
  for (const n of nodes || []) {
    if (n.command) cmds.push(n.command.commandId);
    cmds.push(...collectCommandsInTree(n.children));
  }
  return cmds;
}

exports.run = async function run() {
  const cfg = JSON.parse(fs.readFileSync(process.env.CW_VSIX_DRIVER_CONFIG, "utf8"));
  const receipt = { ok: false, extHostPid: process.pid };

  // 0. Inspect Checkwash Lens BEFORE activation and install synchronous child_process hooks
  const ext = vscode.extensions.getExtension("taipei49314.checkwash-lens");
  if (!ext) {
    throw new Error("Installed extension taipei49314.checkwash-lens not found in Extension Host");
  }
  const wasActiveBeforeMonitorAttach = Boolean(ext.isActive);

  const nodeChildProcessCalls = [];
  const origProtoSpawn = cp.ChildProcess.prototype.spawn;
  const origSpawnSync = cp.spawnSync;
  const origExecSync = cp.execSync;
  const origExecFileSync = cp.execFileSync;

  cp.ChildProcess.prototype.spawn = function patchedSpawn(options) {
    nodeChildProcessCalls.push({
      method: "ChildProcess.prototype.spawn",
      file: options && options.file ? String(options.file) : ""
    });
    return origProtoSpawn.apply(this, arguments);
  };
  cp.spawnSync = function patchedSpawnSync(file) {
    nodeChildProcessCalls.push({ method: "spawnSync", file: String(file || "") });
    return origSpawnSync.apply(this, arguments);
  };
  cp.execSync = function patchedExecSync(cmd) {
    nodeChildProcessCalls.push({ method: "execSync", file: String(cmd || "") });
    return origExecSync.apply(this, arguments);
  };
  cp.execFileSync = function patchedExecFileSync(file) {
    nodeChildProcessCalls.push({ method: "execFileSync", file: String(file || "") });
    return origExecFileSync.apply(this, arguments);
  };

  try {
    if (wasActiveBeforeMonitorAttach !== false) {
      throw new Error("Expected checkwash-lens to be inactive prior to Kernel Job Object monitor attach, got ext.isActive=" + String(ext.isActive));
    }

    // 1. Handshake with outer kernel process monitor BEFORE activating Checkwash Lens
    if (cfg.allowPtracerNodePath) {
      process.dlopen({ exports: {} }, cfg.allowPtracerNodePath);
    }
    fs.writeFileSync(cfg.handshakePath, JSON.stringify({ extHostPid: process.pid }), "utf8");
    const waitStart = Date.now();
    while (!fs.existsSync(cfg.monitorAckPath)) {
      if (Date.now() - waitStart > 15000) {
        throw new Error("Timed out waiting for outer process monitor ACK");
      }
      await sleep(15);
    }

    // 2. Verify real Restricted Mode is active (workspace.isTrusted === false)
    if (vscode.workspace.isTrusted !== false) {
      throw new Error("Expected vscode.workspace.isTrusted === false in real Restricted Mode, got: " + String(vscode.workspace.isTrusted));
    }

    // 3. Verify Checkwash Lens is installed from VSIX inside extensionsDir and activates cleanly
    const canonExtPath = fs.realpathSync.native(ext.extensionPath);
    const canonExtensionsRoot = fs.realpathSync.native(cfg.extensionsDir);
    const normExtPath = process.platform === "win32" ? canonExtPath.toLowerCase() : canonExtPath;
    const normRootPath = process.platform === "win32" ? canonExtensionsRoot.toLowerCase() : canonExtensionsRoot;
    if (!normExtPath.startsWith(normRootPath + path.sep)) {
      throw new Error("Extension did not load from installed VSIX dir: " + canonExtPath);
    }

    const controller = await ext.activate();
    if (!ext.isActive || !controller) {
      throw new Error("Extension failed to activate or did not return controller in Restricted Mode");
    }

    const initialSnap = controller.getViewSnapshot();
    if (initialSnap.evaluatedState.state !== "Not Run") {
      throw new Error("Expected initial state Not Run, got: " + initialSnap.evaluatedState.state);
    }

    // 4. Exercise execution commands in Restricted Mode -> ALL must refuse without spawning processes
    const scanSnap = await vscode.commands.executeCommand(
      "checkwashLens.scanCommittedRange",
      "HEAD~1..HEAD"
    );
    if (!scanSnap || scanSnap.evaluatedState.state !== "Not Run" ||
        !String(scanSnap.evaluatedState.notRunReason || "").includes("Restricted Mode")) {
      throw new Error("scanCommittedRange in Restricted Mode did not return Restricted Mode Not Run state: " + JSON.stringify(scanSnap && scanSnap.evaluatedState));
    }

    const proveListRes = await vscode.commands.executeCommand("checkwashLens.runProveList", "HEAD~1..HEAD");
    const proveFullRes = await vscode.commands.executeCommand("checkwashLens.runProveFull", "HEAD~1..HEAD");
    const replayRes = await vscode.commands.executeCommand("checkwashLens.replayMutant", 1, "src/calc.py:2:4:SDL:1");
    const copyDietRes = await vscode.commands.executeCommand("checkwashLens.copyContextDietDiff");
    const cancelRes = await vscode.commands.executeCommand("checkwashLens.cancelActiveScan");
    const stagedPreSnap = await vscode.commands.executeCommand("checkwashLens.scanUncommittedSnapshot", "staged");
    const worktreePreSnap = await vscode.commands.executeCommand("checkwashLens.scanUncommittedSnapshot", "worktree");
    const doctorRestricted = await vscode.commands.executeCommand("checkwashLens.runEnvironmentDoctor", { silentUi: true });
    if (proveListRes !== null || proveFullRes !== null || replayRes !== null || copyDietRes !== null) {
      throw new Error("Prove/Replay/ContextDiet commands must return null in Restricted Mode");
    }
    if (
      !stagedPreSnap || stagedPreSnap.evaluatedState.state !== "Not Run" ||
      !worktreePreSnap || worktreePreSnap.evaluatedState.state !== "Not Run" ||
      !doctorRestricted || doctorRestricted.isWorkspaceTrusted !== false ||
      doctorRestricted.externalProcessesSpawned !== false ||
      doctorRestricted.workspaceSettingsWarnings.length < 2
    ) {
      throw new Error("Snapshot pre-check or Environment Doctor behaved unexpectedly in Restricted Mode: " + JSON.stringify({ stagedPreSnap, worktreePreSnap, doctorRestricted }));
    }

    // 5. Exercise editor open/edit/save events & configuration change event in Restricted Mode
    const testDocUri = vscode.Uri.file(path.join(cfg.repoDir, "tests", "test_calc.py"));
    const doc = await vscode.workspace.openTextDocument(testDocUri);
    await vscode.window.showTextDocument(doc, { preview: false });
    const edit = new vscode.WorkspaceEdit();
    edit.insert(testDocUri, new vscode.Position(0, 0), "# untrusted edit\\n");
    await vscode.workspace.applyEdit(edit);
    await doc.save();

    await vscode.workspace.getConfiguration("files").update("eol", "\\n", vscode.ConfigurationTarget.Global);

    // 6. Exercise direct runtime probe, Git range resolution, and Prove/Replay plan entrypoints
    const untrustedHostDesc = {
      isWorkspaceTrusted: vscode.workspace.isTrusted,
      platform: process.platform,
      arch: process.arch,
      workspaceScheme: "file",
      isRemote: false,
      isVirtualWorkspace: false,
      extensionRootPath: ext.extensionPath,
      repositoryRootPath: cfg.repoDir,
      configuredPythonPath: cfg.pythonExe,
      configuredGitPath: cfg.gitExe
    };
    const probeRes = await controller.getProcessRunner().probeTrustedRuntimeVersions(untrustedHostDesc);
    const rangeRes = await controller.getProcessRunner().resolveAndPinCommittedRange(untrustedHostDesc, "HEAD~1..HEAD");
    const manualPlanRes = await controller.prepareProveManualCommandPlan({
      hostDesc: untrustedHostDesc,
      configuredProvePath: cfg.proveExe,
      rawRangeSpec: "HEAD~1..HEAD",
      entryKind: "list"
    });
    const replayPlanRes = await controller.prepareProveReplayCommandPlan({
      hostDesc: untrustedHostDesc,
      configuredProvePath: cfg.proveExe,
      recordRunId: 1,
      selectedMutantId: "src/calc.py:2:4:SDL:1"
    });
    if (probeRes.ok || rangeRes.ok || manualPlanRes.ok || replayPlanRes.ok) {
      throw new Error("Direct probes/plans must fail closed in Restricted Mode");
    }

    // 7. Verify Offline Report Read-Only Viewing STILL WORKS in Restricted Mode!
    const offlineCwSnap = await vscode.commands.executeCommand(
      "checkwashLens.viewOfflineReport",
      vscode.Uri.file(cfg.offlineCheckwashReportPath)
    );
    const offlineCwRoot = findNodeById(offlineCwSnap && offlineCwSnap.treeNodes, "offline_checkwash_root");
    if (!offlineCwRoot || offlineCwSnap.evaluatedState.state !== "Not Run") {
      throw new Error("Offline Checkwash v2 report failed to render read-only in Restricted Mode");
    }

    const offlineProveSnap = await vscode.commands.executeCommand(
      "checkwashLens.viewOfflineReport",
      vscode.Uri.file(cfg.offlineProveReportPath)
    );
    const proveRoot = findNodeById(offlineProveSnap && offlineProveSnap.treeNodes, "prove_root");
    const proveScope = findNodeById(offlineProveSnap && offlineProveSnap.treeNodes, "prove_scope_summary");
    const proveClarify = findNodeById(offlineProveSnap && offlineProveSnap.treeNodes, "prove_group_needs_clarification");
    const treeCmds = collectCommandsInTree(offlineProveSnap && offlineProveSnap.treeNodes);
    if (!proveRoot || !proveScope || !proveClarify || treeCmds.includes("checkwashLens.replayMutant")) {
      throw new Error("Offline Prove report failed read-only rendering or exposed Replay command in Restricted Mode");
    }

    if (nodeChildProcessCalls.length !== 0) {
      throw new Error("Extension Host invoked child_process in Restricted Mode: " + JSON.stringify(nodeChildProcessCalls));
    }

    await sleep(50);
    fs.writeFileSync(cfg.stopMonitorPath, "stop", "utf8");

    Object.assign(receipt, {
      ok: true,
      vscodeVersion: vscode.version,
      isWorkspaceTrusted: vscode.workspace.isTrusted,
      extensionId: ext.id,
      wasActiveBeforeMonitorAttach,
      nodeChildProcessHookInstalledPreActivation: true,
      nodeChildProcessCallsCount: nodeChildProcessCalls.length,
      nodeChildProcessCalls,
      zeroProcessObservationScope:
        "Extension Host process tree (extHostPid) from prior to checkwash-lens activation (ext.isActive=false) through activation and all tested Restricted Mode commands, workspace events, probes, and offline report views",
      extensionActive: ext.isActive,
      extensionPath: canonExtPath,
      loadedFromInstalledVsix: true,
      scanStateInRestrictedMode: scanSnap.evaluatedState.state,
      scanNotRunReason: scanSnap.evaluatedState.notRunReason,
      probesBlocked: !probeRes.ok && !rangeRes.ok && !manualPlanRes.ok && !replayPlanRes.ok,
      offlineCheckwashReadOnlyRendered: Boolean(offlineCwRoot),
      offlineProveReadOnlyRendered: Boolean(proveRoot && proveScope && proveClarify),
      offlineProveTreeCommands: treeCmds,
      restrictedDoctorWarningsCount: doctorRestricted.workspaceSettingsWarnings.length,
      restrictedSnapshotStates: [stagedPreSnap.evaluatedState.state, worktreePreSnap.evaluatedState.state],
      cancelSnapState: cancelRes && cancelRes.evaluatedState && cancelRes.evaluatedState.state
    });
    fs.writeFileSync(cfg.receiptPath, JSON.stringify(receipt, null, 2), "utf8");
  } catch (err) {
    try { fs.writeFileSync(cfg.stopMonitorPath, "stop", "utf8"); } catch {}
    receipt.ok = false;
    receipt.error = err && (err.stack || err.message) ? (err.stack || err.message) : String(err);
    fs.writeFileSync(cfg.receiptPath, JSON.stringify(receipt, null, 2), "utf8");
    throw err;
  } finally {
    cp.ChildProcess.prototype.spawn = origProtoSpawn;
    cp.spawnSync = origSpawnSync;
    cp.execSync = origExecSync;
    cp.execFileSync = origExecFileSync;
  }
};
`,
    "utf8"
  );

  // -------------------------------------------------------------------------
  // Session 2 Driver Script: Trusted Workspace End-to-End Installed VSIX Verification
  // -------------------------------------------------------------------------
  const trustedRunnerJs = path.join(driverDir, "run_trusted_vsix.js");
  fs.writeFileSync(
    trustedRunnerJs,
    `"use strict";
const fs = require("fs");
const path = require("path");
const vscode = require("vscode");

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function isPidAlive(pid) {
  if (!pid || pid <= 0) return false;
  try {
    process.kill(pid, 0);
  } catch (e) {
    if (!(e && e.code === "EPERM")) return false;
  }
  if (process.platform !== "win32") {
    try {
      const st = fs.readFileSync("/proc/" + pid + "/stat", "utf8");
      const idx = st.lastIndexOf(")");
      const stateCh = idx >= 0 ? st.slice(idx + 1).trim()[0] : "";
      if (stateCh === "Z" || stateCh === "X") return false;
    } catch {
      return false;
    }
  }
  return true;
}

async function waitForOperationActive(processRunner, timeoutMs) {
  const start = Date.now();
  while (!processRunner.isOperationActive()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error("Timed out waiting for UnifiedProcessRunner.isOperationActive() === true");
    }
    await sleep(2);
  }
}

function findNodeById(nodes, id) {
  for (const n of nodes || []) {
    if (n.id === id) return n;
    const sub = findNodeById(n.children, id);
    if (sub) return sub;
  }
  return null;
}

function collectCommandsInTree(nodes) {
  const cmds = [];
  for (const n of nodes || []) {
    if (n.command) cmds.push(n.command.commandId);
    cmds.push(...collectCommandsInTree(n.children));
  }
  return cmds;
}

exports.run = async function run() {
  const cfg = JSON.parse(fs.readFileSync(process.env.CW_VSIX_DRIVER_CONFIG, "utf8"));
  const receipt = { ok: false, extHostPid: process.pid };
  try {
    // 0. Handshake with outer kernel process monitor (Positive Control for Session 1 B01!)
    if (cfg.allowPtracerNodePath) {
      process.dlopen({ exports: {} }, cfg.allowPtracerNodePath);
    }
    fs.writeFileSync(cfg.handshakePath, JSON.stringify({ extHostPid: process.pid }), "utf8");
    const waitMonitorStart = Date.now();
    while (!fs.existsSync(cfg.monitorAckPath)) {
      if (Date.now() - waitMonitorStart > 15000) {
        throw new Error("Timed out waiting for Session 2 process monitor ACK");
      }
      await sleep(15);
    }

    if (vscode.workspace.isTrusted !== true) {
      throw new Error("Expected vscode.workspace.isTrusted === true in Trusted session, got: " + String(vscode.workspace.isTrusted));
    }

    const ext = vscode.extensions.getExtension("taipei49314.checkwash-lens");
    if (!ext) {
      throw new Error("Installed extension taipei49314.checkwash-lens not found in Trusted session");
    }
    const canonExtPath = fs.realpathSync.native(ext.extensionPath);
    const canonExtensionsRoot = fs.realpathSync.native(cfg.extensionsDir);
    const normExtPath = process.platform === "win32" ? canonExtPath.toLowerCase() : canonExtPath;
    const normRootPath = process.platform === "win32" ? canonExtensionsRoot.toLowerCase() : canonExtensionsRoot;
    if (!normExtPath.startsWith(normRootPath + path.sep)) {
      throw new Error("Extension did not load from installed VSIX dir: " + canonExtPath);
    }

    const controller = await ext.activate();
    if (!ext.isActive || !controller) {
      throw new Error("Extension failed to activate in Trusted session");
    }

    controller.selectRepository(cfg.repoDir);
    const testFileUri = vscode.Uri.file(path.join(cfg.repoDir, "tests", "test_calc.py"));
    const openTestDoc = await vscode.workspace.openTextDocument(testFileUri);
    await vscode.window.showTextDocument(openTestDoc, { preview: false });

    // 1. Run real committed-range scan via installed VSIX command
    const scanSnap = await vscode.commands.executeCommand(
      "checkwashLens.scanCommittedRange",
      cfg.baseOid + ".." + cfg.headOid
    );
    if (!scanSnap || scanSnap.evaluatedState.state !== "Block") {
      throw new Error("Expected scan state Block in Trusted VSIX session, got: " + JSON.stringify(scanSnap && scanSnap.evaluatedState));
    }

    // 2. Verify real VS Code Diagnostics, immutable checkwash-rev: document, Hover, and Context Diet SQL masking
    const diags = vscode.languages.getDiagnostics(testFileUri);
    const cwDiags = diags.filter((d) => String(d.source || "").includes("Checkwash"));
    const fgDiags = diags.filter((d) => String(d.source || "").includes("Fast Guard"));
    if (cwDiags.length < 1 || fgDiags.length < 1) {
      throw new Error("Expected both Checkwash and Fast Guard diagnostics, got cw=" + cwDiags.length + " fg=" + fgDiags.length);
    }

    const headFinding = scanSnap.enrichedFindings.find((f) => f.item.evidenceSide === "head") || scanSnap.enrichedFindings[0];
    const revDoc = await vscode.workspace.openTextDocument(vscode.Uri.parse(headFinding.preferredRevisionUri));
    if (!revDoc.getText().includes("assert True")) {
      throw new Error("Immutable checkwash-rev: document did not contain expected head blob");
    }

    const hovers = await vscode.commands.executeCommand(
      "vscode.executeHoverProvider",
      testFileUri,
      new vscode.Position(cwDiags[0].range.start.line, 4)
    );
    if (!hovers || hovers.length === 0) {
      throw new Error("Expected Hover result on Checkwash diagnostic line");
    }

    const dietPrep = controller.prepareContextDietCopy({ mode: "redacted" });
    if (!dietPrep.ok) {
      throw new Error("prepareContextDietCopy(redacted) failed: " + dietPrep.error);
    }
    if (dietPrep.value.payloadToCopy.includes(cfg.sqlSecret) ||
        dietPrep.value.payloadToCopy.includes(cfg.addedPat) ||
        !dietPrep.value.payloadToCopy.includes("--- a/db/init.sql") ||
        !dietPrep.value.payloadToCopy.includes("+++ b/db/init.sql")) {
      throw new Error("Context Diet redacted payload failed secret masking or header preservation");
    }

    // 3. Active Cancellation & Process-Tree Cleanup with strict "cancelled" semantics (NEVER "timed_out")
    const trustedHostDesc = {
      isWorkspaceTrusted: true,
      platform: process.platform,
      arch: process.arch,
      workspaceScheme: "file",
      isRemote: false,
      isVirtualWorkspace: false,
      extensionRootPath: ext.extensionPath,
      repositoryRootPath: cfg.repoDir,
      configuredPythonPath: cfg.pythonExe,
      configuredGitPath: cfg.gitExe
    };

    // 3A. Cancel a real user-triggered checkwashLens.scanCommittedRange command mid-flight
    const realScanCancelPromise = vscode.commands.executeCommand(
      "checkwashLens.scanCommittedRange",
      cfg.baseOid + ".." + cfg.headOid
    );
    await waitForOperationActive(controller.getProcessRunner(), 5000);
    await vscode.commands.executeCommand("checkwashLens.cancelActiveScan");
    const cancelledScanSnap = await realScanCancelPromise;
    const cancelReason = String(
      (cancelledScanSnap &&
        cancelledScanSnap.evaluatedState &&
        cancelledScanSnap.evaluatedState.notRunReason) ||
        ""
    );
    if (
      !cancelledScanSnap ||
      cancelledScanSnap.evaluatedState.state !== "Not Run" ||
      (cancelReason !== "Scan cancelled by user and confirmed stopped" &&
        cancelReason !== "Scan was cancelled by user and process tree termination was confirmed") ||
      controller.getProcessRunner().hasUnconfirmedCleanup()
    ) {
      throw new Error(
        "Real scanCommittedRange cancellation did not produce confirmed user-cancelled Not Run state: " +
          JSON.stringify(cancelledScanSnap && cancelledScanSnap.evaluatedState)
      );
    }

    // 3B. Cancel a multi-level child + grandchild process tree inside runExclusiveCancelableOperation
    //     and assert outcome.status === "cancelled" (NEVER "timed_out")
    const pidFile = path.join(cfg.tempDir, "cancel-tree-pids.json");
    const pyTreeScript = [
      "import subprocess, sys, time, json, os, pathlib",
      "child = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', 'import time; time.sleep(30)'])",
      "tmp_p = " + JSON.stringify(pidFile + ".tmp"),
      "pathlib.Path(tmp_p).write_text(json.dumps({'parentPid': os.getpid(), 'grandchildPid': child.pid}), encoding='utf-8')",
      "os.replace(tmp_p, " + JSON.stringify(pidFile) + ")",
      "time.sleep(30)"
    ].join("; ");

    const inFlightPromise = controller
      .getProcessRunner()
      .runExclusiveCancelableOperation((abortSignal) =>
        controller.getProcessRunner().executeGatedProcess({
          hostDesc: trustedHostDesc,
          executableSelector: (ctx) => ctx.canonicalPythonPath,
          argsBuilder: () => ["-I", "-S", "-B", "-c", pyTreeScript],
          timeoutMs: 30000,
          abortSignal
        })
      );

    const waitPidStart = Date.now();
    while (!fs.existsSync(pidFile)) {
      if (Date.now() - waitPidStart > 10000) {
        throw new Error("Timed out waiting for in-flight child/grandchild PID file");
      }
      await sleep(25);
    }
    const spawnedPids = JSON.parse(fs.readFileSync(pidFile, "utf8"));
    const aliveBeforeCancel = isPidAlive(spawnedPids.parentPid) && isPidAlive(spawnedPids.grandchildPid);
    if (!aliveBeforeCancel) {
      throw new Error("Expected child and grandchild PIDs to be alive prior to cancelActiveScan");
    }

    const cancelStartMs = Date.now();
    const cancelSnap = await vscode.commands.executeCommand("checkwashLens.cancelActiveScan");
    const inFlightRes = await inFlightPromise;
    const cancelElapsedMs = Date.now() - cancelStartMs;

    await sleep(100);
    const parentAliveAfter = isPidAlive(spawnedPids.parentPid);
    const grandchildAliveAfter = isPidAlive(spawnedPids.grandchildPid);
    if (parentAliveAfter || grandchildAliveAfter) {
      throw new Error("Process tree survived cancelActiveScan: parent=" + parentAliveAfter + " grandchild=" + grandchildAliveAfter);
    }
    if (!inFlightRes.ok) {
      throw new Error("Expected broker outcome on cancelActiveScan, got error: " + inFlightRes.error);
    }
    if (inFlightRes.value.outcome.status !== "cancelled") {
      throw new Error(
        "Expected inFlightOutcomeStatus === 'cancelled' (not timed_out!), got: " +
          JSON.stringify(inFlightRes.value.outcome)
      );
    }
    if (
      inFlightRes.value.outcome.cleanupConfirmed !== true ||
      inFlightRes.value.outcome.activeProcessesRemaining !== 0 ||
      controller.getProcessRunner().hasUnconfirmedCleanup()
    ) {
      throw new Error("Expected cleanupConfirmed === true and 0 active processes remaining on real broker cancellation");
    }
    if (cancelElapsedMs >= 10000) {
      throw new Error("Cancellation took unexpectedly long (" + cancelElapsedMs + "ms), indicating timeout fallback instead of immediate cancel");
    }

    // 3C. Cancel Prove preflight AND Prove full execution via checkwashLens.cancelActiveScan
    const provePreflightPromise = controller.prepareProveManualCommandPlan({
      hostDesc: trustedHostDesc,
      configuredProvePath: cfg.proveExe,
      rawRangeSpec: cfg.baseOid + ".." + cfg.headOid,
      entryKind: "list"
    });
    await waitForOperationActive(controller.getProcessRunner(), 5000);
    await vscode.commands.executeCommand("checkwashLens.cancelActiveScan");
    const provePreflightRes = await provePreflightPromise;
    const postPreflightCancelSnap = controller.getViewSnapshot();
    if (
      provePreflightRes.ok ||
      provePreflightRes.cancelled !== true ||
      postPreflightCancelSnap.proveOutcome.status !== "Not Run / Cancelled" ||
      controller.getProcessRunner().hasUnconfirmedCleanup()
    ) {
      throw new Error(
        "Prove preflight cancellation did not settle as clean Not Run / Cancelled: " +
          JSON.stringify({ provePreflightRes, proveOutcome: postPreflightCancelSnap.proveOutcome })
      );
    }

    const fullPlanRes = await controller.prepareProveManualCommandPlan({
      hostDesc: trustedHostDesc,
      configuredProvePath: cfg.proveExe,
      rawRangeSpec: cfg.baseOid + ".." + cfg.headOid,
      entryKind: "full"
    });
    if (!fullPlanRes.ok) {
      throw new Error("Failed to prepare full Prove plan for cancellation test: " + fullPlanRes.error);
    }
    const fullAuth = controller.getProveRunner().issueManualAuthorizationToken({
      plan: fullPlanRes.value,
      userConfirmedExecutionRisk: true
    });
    const proveExecPromise = controller.executeAuthorizedProveCommand({
      hostDesc: trustedHostDesc,
      configuredProvePath: cfg.proveExe,
      authorization: fullAuth,
      expectedEntryKind: "full"
    });
    await waitForOperationActive(controller.getProcessRunner(), 5000);
    await sleep(150);
    await vscode.commands.executeCommand("checkwashLens.cancelActiveScan");
    const proveExecCancelSnap = await proveExecPromise;
    if (
      proveExecCancelSnap.proveOutcome.status !== "Not Run / Cancelled" ||
      proveExecCancelSnap.proveOutcome.errorReason !== null ||
      controller.getProcessRunner().hasUnconfirmedCleanup()
    ) {
      throw new Error(
        "Prove full execution cancellation did not settle as clean Not Run / Cancelled: " +
          JSON.stringify(proveExecCancelSnap.proveOutcome)
      );
    }

    // 3D. Follow-up scan after confirmed cancellations must succeed cleanly and restore Block verdict!
    const postCancelScanSnap = await vscode.commands.executeCommand(
      "checkwashLens.scanCommittedRange",
      cfg.baseOid + ".." + cfg.headOid
    );
    if (!postCancelScanSnap || postCancelScanSnap.evaluatedState.state !== "Block") {
      throw new Error("Follow-up scan after confirmed cancelActiveScan did not succeed with Block");
    }

    // 4. Offline Prove Report Read-Only Viewing (clarification + losses + notes, static verdict unpolluted!)
    const offlineProveSnap = await vscode.commands.executeCommand(
      "checkwashLens.viewOfflineReport",
      vscode.Uri.file(cfg.offlineProveReportPath)
    );
    const scopeNode = findNodeById(offlineProveSnap.treeNodes, "prove_scope_summary");
    const statusNode = findNodeById(offlineProveSnap.treeNodes, "prove_raw_status");
    const clarifyGroup = findNodeById(offlineProveSnap.treeNodes, "prove_group_needs_clarification");
    const lossesGroup = findNodeById(offlineProveSnap.treeNodes, "prove_group_protection_losses");
    const treeCmds = collectCommandsInTree(offlineProveSnap.treeNodes);
    if (!scopeNode || !statusNode || !clarifyGroup || !lossesGroup) {
      throw new Error("Offline Prove report missing scope/status/clarification/losses nodes in Trusted VSIX session");
    }
    if (treeCmds.includes("checkwashLens.replayMutant")) {
      throw new Error("Offline Prove report must NOT expose checkwashLens.replayMutant command");
    }
    if (offlineProveSnap.evaluatedState.state !== "Block") {
      throw new Error("Viewing offline Prove report polluted static Checkwash verdict: " + offlineProveSnap.evaluatedState.state);
    }

    // 5. v0.2.0 Environment Doctor + Uncommitted Staged/Worktree Snapshot Pre-Check in Installed VSIX
    const doctorTrusted = await vscode.commands.executeCommand(
      "checkwashLens.runEnvironmentDoctor",
      { silentUi: true }
    );
    if (
      !doctorTrusted ||
      doctorTrusted.overallReadyForStaticScan !== true ||
      doctorTrusted.overallReadyForProve !== true ||
      doctorTrusted.workspaceSettingsWarnings.length !== 3
    ) {
      throw new Error("Environment Doctor in Trusted VSIX returned unexpected report: " + JSON.stringify(doctorTrusted));
    }
    const doctorVirtualDoc = await vscode.workspace.openTextDocument(
      vscode.Uri.parse("checkwash-doctor:/Environment-Doctor-Report.md")
    );
    if (!doctorVirtualDoc.getText().includes("Ignored Workspace Settings")) {
      throw new Error("checkwash-doctor: virtual document did not render Environment Doctor report");
    }

    const countLooseObjects = (dir) => {
      let total = 0;
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        if (ent.isDirectory() && ent.name !== "pack" && ent.name !== "info") {
          total += fs.readdirSync(path.join(dir, ent.name)).length;
        }
      }
      return total;
    };
    const objectsDir = path.join(cfg.repoDir, ".git", "objects");
    const looseBefore = countLooseObjects(objectsDir);
    const untrackedConftest = path.join(cfg.repoDir, "tests", "conftest.py");
    fs.writeFileSync(
      untrackedConftest,
      'import pytest\\n\\n@pytest.fixture(autouse=True)\\ndef _skip_all():\\n    pytest.skip("wip")\\n',
      "utf8"
    );
    try {
      const stagedPre = await vscode.commands.executeCommand("checkwashLens.scanUncommittedSnapshot", "staged");
      const worktreePre = await vscode.commands.executeCommand("checkwashLens.scanUncommittedSnapshot", "worktree");
      const looseAfter = countLooseObjects(objectsDir);
      if (
        !stagedPre || stagedPre.evaluatedState.state !== "Not Run" ||
        stagedPre.evaluatedState.scanScope !== "staged-precheck" ||
        !worktreePre || worktreePre.evaluatedState.state !== "Block" ||
        worktreePre.evaluatedState.scanScope !== "worktree-precheck" ||
        !String(worktreePre.statusBar && worktreePre.statusBar.text || "").includes("[Worktree Pre-Check]: Block") ||
        looseAfter !== looseBefore
      ) {
        throw new Error("Uncommitted Snapshot Pre-Check failed in Trusted VSIX: " + JSON.stringify({
          stagedPre: stagedPre && stagedPre.evaluatedState,
          worktreePre: worktreePre && worktreePre.evaluatedState,
          looseBefore,
          looseAfter
        }));
      }
    } finally {
      fs.rmSync(untrackedConftest, { force: true });
    }

    await sleep(50);
    fs.writeFileSync(cfg.stopMonitorPath, "stop", "utf8");

    Object.assign(receipt, {
      ok: true,
      vscodeVersion: vscode.version,
      isWorkspaceTrusted: vscode.workspace.isTrusted,
      extensionId: ext.id,
      extensionPath: canonExtPath,
      loadedFromInstalledVsix: true,
      scanVerdict: scanSnap.evaluatedState.state,
      checkwashDiagnosticsCount: cwDiags.length,
      fastGuardDiagnosticsCount: fgDiags.length,
      immutableRevScheme: revDoc.uri.scheme,
      contextDietMaskedSqlAndPat: true,
      environmentDoctor: {
        readyForStaticScan: doctorTrusted.overallReadyForStaticScan,
        readyForProve: doctorTrusted.overallReadyForProve,
        ignoredWorkspaceWarnings: doctorTrusted.workspaceSettingsWarnings.length,
        virtualDocScheme: doctorVirtualDoc.uri.scheme
      },
      uncommittedSnapshotPreCheck: {
        stagedCleanState: "Not Run",
        worktreeUntrackedConftestState: "Block",
        zeroGitLooseObjectsAdded: true
      },
      cancellationCleanup: {
        realScanCommandCancelledState: cancelledScanSnap.evaluatedState.state,
        realScanCommandCancelledReason: cancelledScanSnap.evaluatedState.notRunReason,
        spawnedPids,
        aliveBeforeCancel,
        parentAliveAfter,
        grandchildAliveAfter,
        inFlightOutcomeStatus: inFlightRes.value.outcome.status,
        inFlightCleanupConfirmed: inFlightRes.value.outcome.cleanupConfirmed,
        inFlightActiveProcessesRemaining: inFlightRes.value.outcome.activeProcessesRemaining,
        cancelElapsedMs,
        provePreflightCancelled: provePreflightRes.cancelled === true,
        provePreflightCancelledOutcomeStatus: postPreflightCancelSnap.proveOutcome.status,
        proveExecutionCancelledOutcomeStatus: proveExecCancelSnap.proveOutcome.status,
        postCancelFollowupVerdict: postCancelScanSnap.evaluatedState.state,
        cancelCommandEvaluatedState: cancelSnap && cancelSnap.evaluatedState && cancelSnap.evaluatedState.state
      },
      offlineProvePresentation: {
        scopeLabel: scopeNode.label,
        rawStatusLabel: statusNode.label,
        clarificationCount: clarifyGroup.children.length,
        protectionLossesCount: lossesGroup.children.length,
        replayExposed: false,
        staticVerdictPreserved: offlineProveSnap.evaluatedState.state
      }
    });
    fs.writeFileSync(cfg.receiptPath, JSON.stringify(receipt, null, 2), "utf8");
  } catch (err) {
    try { fs.writeFileSync(cfg.stopMonitorPath, "stop", "utf8"); } catch {}
    receipt.ok = false;
    receipt.error = err && (err.stack || err.message) ? (err.stack || err.message) : String(err);
    fs.writeFileSync(cfg.receiptPath, JSON.stringify(receipt, null, 2), "utf8");
    throw err;
  }
};
`,
    "utf8"
  );

  // -------------------------------------------------------------------------
  // Session 3 Driver Script: Real Desktop B08-A (`workbench.action.reloadWindow` Mid-Flight)
  // -------------------------------------------------------------------------
  const reloadRunnerJs = path.join(driverDir, "run_b08_reload.js");
  fs.writeFileSync(
    reloadRunnerJs,
    `"use strict";
const fs = require("fs");
const path = require("path");
const vscode = require("vscode");

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function isPidAlive(pid) {
  if (!pid || pid <= 0) return false;
  try {
    process.kill(pid, 0);
  } catch (e) {
    if (!(e && e.code === "EPERM")) return false;
  }
  if (process.platform !== "win32") {
    try {
      const st = fs.readFileSync("/proc/" + pid + "/stat", "utf8");
      const idx = st.lastIndexOf(")");
      const stateCh = idx >= 0 ? st.slice(idx + 1).trim()[0] : "";
      if (stateCh === "Z" || stateCh === "X") return false;
    } catch {
      return false;
    }
  }
  return true;
}

let phase2RunningInThisProcess = false;

async function runPostReloadPhase2(cfg) {
  if (phase2RunningInThisProcess) return;
  if (!fs.existsSync(cfg.phase1HandshakePath)) return;
  const hs1 = JSON.parse(fs.readFileSync(cfg.phase1HandshakePath, "utf8"));
  if (hs1.extHostPid1 === process.pid) return;
  phase2RunningInThisProcess = true;

  const receipt = { ok: false, extHostPid1: hs1.extHostPid1, extHostPid2: process.pid };
  try {
    const ext = vscode.extensions.getExtension("taipei49314.checkwash-lens");
    if (!ext) {
      throw new Error("checkwash-lens missing after workbench.action.reloadWindow");
    }
    const controller = await ext.activate();
    controller.selectRepository(cfg.repoDir);
    const postSnap = await vscode.commands.executeCommand(
      "checkwashLens.scanCommittedRange",
      cfg.baseOid + ".." + cfg.headOid
    );
    if (!postSnap || postSnap.evaluatedState.state !== "Block") {
      throw new Error("Post-reload scan failed to recover with Block verdict: " + JSON.stringify(postSnap && postSnap.evaluatedState));
    }
    Object.assign(receipt, {
      ok: true,
      vscodeVersion: vscode.version,
      postReloadScanVerdict: postSnap.evaluatedState.state,
      hasUnconfirmedCleanupAfterReload: controller.getProcessRunner().hasUnconfirmedCleanup()
    });
    fs.writeFileSync(cfg.phase2ReceiptPath, JSON.stringify(receipt, null, 2), "utf8");
  } catch (err) {
    receipt.ok = false;
    receipt.error = err && (err.stack || err.message) ? (err.stack || err.message) : String(err);
    fs.writeFileSync(cfg.phase2ReceiptPath, JSON.stringify(receipt, null, 2), "utf8");
    throw err;
  }
}

exports.maybeRunPostReloadPhase2 = async function maybeRunPostReloadPhase2() {
  if (!process.env.CW_VSIX_B08_RELOAD_CONFIG) return;
  const cfg = JSON.parse(fs.readFileSync(process.env.CW_VSIX_B08_RELOAD_CONFIG, "utf8"));
  await runPostReloadPhase2(cfg);
};

exports.run = async function run() {
  const cfg = JSON.parse(fs.readFileSync(process.env.CW_VSIX_B08_RELOAD_CONFIG, "utf8"));
  if (fs.existsSync(cfg.phase1HandshakePath)) {
    await runPostReloadPhase2(cfg);
    return;
  }

  const ext = vscode.extensions.getExtension("taipei49314.checkwash-lens");
  if (!ext) {
    throw new Error("Installed extension taipei49314.checkwash-lens not found in B08-A reload session");
  }
  const controller = await ext.activate();
  controller.selectRepository(cfg.repoDir);

  const pidFile = path.join(cfg.tempDir, "b08-reload-tree-pids.json");
  const pyTreeScript = [
    "import subprocess, sys, time, json, os, pathlib",
    "child = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', 'import time; time.sleep(45)'])",
    "tmp_p = " + JSON.stringify(pidFile + ".tmp"),
    "pathlib.Path(tmp_p).write_text(json.dumps({'parentPid': os.getpid(), 'grandchildPid': child.pid}), encoding='utf-8')",
    "os.replace(tmp_p, " + JSON.stringify(pidFile) + ")",
    "time.sleep(45)"
  ].join("; ");

  const trustedHostDesc = {
    isWorkspaceTrusted: true,
    platform: process.platform,
    arch: process.arch,
    workspaceScheme: "file",
    isRemote: false,
    isVirtualWorkspace: false,
    extensionRootPath: ext.extensionPath,
    repositoryRootPath: cfg.repoDir,
    configuredPythonPath: cfg.pythonExe,
    configuredGitPath: cfg.gitExe
  };

  // Start long-running child + grandchild tree inside brokered runner
  void controller.getProcessRunner().runExclusiveCancelableOperation((abortSignal) =>
    controller.getProcessRunner().executeGatedProcess({
      hostDesc: trustedHostDesc,
      executableSelector: (ctx) => ctx.canonicalPythonPath,
      argsBuilder: () => ["-I", "-S", "-B", "-c", pyTreeScript],
      timeoutMs: 45000,
      abortSignal
    })
  );

  const waitStart = Date.now();
  while (!fs.existsSync(pidFile)) {
    if (Date.now() - waitStart > 12000) {
      throw new Error("Timed out waiting for B08-A child/grandchild PID file");
    }
    await sleep(25);
  }
  const pids = JSON.parse(fs.readFileSync(pidFile, "utf8"));
  if (!isPidAlive(pids.parentPid) || !isPidAlive(pids.grandchildPid)) {
    throw new Error("Expected B08-A parentPid and grandchildPid to be alive before Reload Window");
  }

  fs.writeFileSync(
    cfg.phase1HandshakePath,
    JSON.stringify({
      extHostPid1: process.pid,
      parentPid: pids.parentPid,
      grandchildPid: pids.grandchildPid
    }),
    "utf8"
  );

  const ackStart = Date.now();
  while (!fs.existsSync(cfg.proceedReloadAckPath)) {
    if (Date.now() - ackStart > 15000) {
      throw new Error("Timed out waiting for outer harness reload ACK");
    }
    await sleep(20);
  }

  // Trigger real VS Code Desktop Reload Window while brokered child+grandchild tree is active!
  void vscode.commands.executeCommand("workbench.action.reloadWindow");

  // Keep promise pending so --extensionTestsPath does not exit Code.exe before window reloads
  await sleep(30000);
};
`,
    "utf8"
  );

  // -------------------------------------------------------------------------
  // Session 4 Driver Script: Real Desktop B08-B (Extension Host Forced Hard Crash Mid-Flight)
  // -------------------------------------------------------------------------
  const crashRunnerJs = path.join(driverDir, "run_b08_crash.js");
  fs.writeFileSync(
    crashRunnerJs,
    `"use strict";
const fs = require("fs");
const path = require("path");
const vscode = require("vscode");

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function isPidAlive(pid) {
  if (!pid || pid <= 0) return false;
  try {
    process.kill(pid, 0);
  } catch (e) {
    if (!(e && e.code === "EPERM")) return false;
  }
  if (process.platform !== "win32") {
    try {
      const st = fs.readFileSync("/proc/" + pid + "/stat", "utf8");
      const idx = st.lastIndexOf(")");
      const stateCh = idx >= 0 ? st.slice(idx + 1).trim()[0] : "";
      if (stateCh === "Z" || stateCh === "X") return false;
    } catch {
      return false;
    }
  }
  return true;
}

exports.run = async function run() {
  const cfg = JSON.parse(fs.readFileSync(process.env.CW_VSIX_B08_CRASH_CONFIG, "utf8"));
  const ext = vscode.extensions.getExtension("taipei49314.checkwash-lens");
  if (!ext) {
    throw new Error("Installed extension taipei49314.checkwash-lens not found in B08-B crash session");
  }
  const controller = await ext.activate();
  controller.selectRepository(cfg.repoDir);

  const pidFile = path.join(cfg.tempDir, "b08-crash-tree-pids.json");
  const pyTreeScript = [
    "import subprocess, sys, time, json, os, pathlib",
    "child = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', 'import time; time.sleep(45)'])",
    "tmp_p = " + JSON.stringify(pidFile + ".tmp"),
    "pathlib.Path(tmp_p).write_text(json.dumps({'parentPid': os.getpid(), 'grandchildPid': child.pid}), encoding='utf-8')",
    "os.replace(tmp_p, " + JSON.stringify(pidFile) + ")",
    "time.sleep(45)"
  ].join("; ");

  const trustedHostDesc = {
    isWorkspaceTrusted: true,
    platform: process.platform,
    arch: process.arch,
    workspaceScheme: "file",
    isRemote: false,
    isVirtualWorkspace: false,
    extensionRootPath: ext.extensionPath,
    repositoryRootPath: cfg.repoDir,
    configuredPythonPath: cfg.pythonExe,
    configuredGitPath: cfg.gitExe
  };

  void controller.getProcessRunner().runExclusiveCancelableOperation((abortSignal) =>
    controller.getProcessRunner().executeGatedProcess({
      hostDesc: trustedHostDesc,
      executableSelector: (ctx) => ctx.canonicalPythonPath,
      argsBuilder: () => ["-I", "-S", "-B", "-c", pyTreeScript],
      timeoutMs: 45000,
      abortSignal
    })
  );

  const waitStart = Date.now();
  while (!fs.existsSync(pidFile)) {
    if (Date.now() - waitStart > 12000) {
      throw new Error("Timed out waiting for B08-B child/grandchild PID file");
    }
    await sleep(25);
  }
  const pids = JSON.parse(fs.readFileSync(pidFile, "utf8"));
  if (!isPidAlive(pids.parentPid) || !isPidAlive(pids.grandchildPid)) {
    throw new Error("Expected B08-B parentPid and grandchildPid to be alive before Extension Host crash");
  }

  fs.writeFileSync(
    cfg.crashHandshakePath,
    JSON.stringify({
      extHostPid: process.pid,
      parentPid: pids.parentPid,
      grandchildPid: pids.grandchildPid
    }),
    "utf8"
  );

  // Outer harness will TerminateProcess(process.pid) while this promise is pending (zero JS deactivate)
  await sleep(60000);
};
`,
    "utf8"
  );

  return { driverDir, restrictedRunnerJs, trustedRunnerJs, reloadRunnerJs, crashRunnerJs };
}

async function main(): Promise<void> {
  console.log("=== Installed VSIX & Real VS Code Desktop Verification (B01 Restricted + Trusted E2E) ===");
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

  assert.strictEqual(fs.existsSync(CODE_EXE), true, `VS Code Desktop not found at ${CODE_EXE}`);
  assert.strictEqual(
    fs.existsSync(VSIX_PATH),
    true,
    `Built VSIX not found at ${VSIX_PATH} — run scripts/package_vsix.js first`
  );

  const cliJsPath = findVsCodeCliJs(CODE_EXE);
  const bundledManifest = JSON.parse(fs.readFileSync(BUNDLED_MANIFEST_PATH, "utf8"));
  const vsixBuf = fs.readFileSync(VSIX_PATH);
  const vsixSha256 = sha256Buffer(vsixBuf);
  const vsixBytes = vsixBuf.length;
  const vsixEntries = readZipEntryNames(vsixBuf);

  const activeBrokerFilename = resolveBundledBrokerFilename();
  const otherPlatformBrokerFilename = IS_WIN32
    ? "checkwash-broker-linux-x64"
    : "checkwash-broker.exe";

  // Verify VSIX entry hygiene (target-specific bundled broker + zero leaked test/evidence/other-OS artifacts)
  for (const requiredEntry of [
    "[Content_Types].xml",
    "extension.vsixmanifest",
    "extension/package.json",
    "extension/media/icon.png",
    "extension/media/checkwash-activity.svg",
    "extension/dist/extension.js",
    "extension/bundled/checkwash.pyz",
    `extension/bundled/${activeBrokerFilename}`,
    "extension/bundled/manifest.json",
  ]) {
    assert.strictEqual(
      vsixEntries.includes(requiredEntry),
      true,
      `VSIX missing required entry: ${requiredEntry}`
    );
  }
  assert.strictEqual(
    vsixEntries.includes(`extension/bundled/${otherPlatformBrokerFilename}`),
    false,
    `Platform-specific VSIX (${ACTIVE_VSIX_TARGET}) must NOT contain ${otherPlatformBrokerFilename}`
  );
  for (const entry of vsixEntries) {
    assert.strictEqual(
      entry.startsWith("extension/dist/test/") ||
        entry.startsWith("extension/src/") ||
        entry.startsWith("extension/fixtures/") ||
        entry.startsWith("extension/evidence/"),
      false,
      `Forbidden non-production entry leaked into VSIX: ${entry}`
    );
  }

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-installed-vsix-verify-"));
  try {
    const monitorExe = compileDescendantProcessMonitorExe(tempRoot);
    const allowPtracerNodePath = compileLinuxAllowPtracerAddon(tempRoot);
    const {
      driverDir,
      restrictedRunnerJs,
      trustedRunnerJs,
    } = createDriverExtensionDir(tempRoot);
    const s1TargetRepo = createTestGitRepoWithWeakeningAndSqlSecret(
      tempRoot,
      "target-repo-s1-restricted"
    );
    const { repoDir, baseOid, headOid, sqlSecret, addedPat } =
      createTestGitRepoWithWeakeningAndSqlSecret(tempRoot, "target-repo-s2-trusted");

    const offlineCheckwashReportPath = path.join(FIXTURES_DIR, "a01-block.findings.json");
    const offlineProveReportPath = path.join(
      FIXTURES_DIR,
      "prove-real-clarification-coexisting.json"
    );

    // =========================================================================
    // Session 1: Real B01 Restricted Mode (`workspace.isTrusted === false`)
    // =========================================================================
    console.log("  -> Session 1: Installing VSIX & launching real VS Code in Restricted Mode (B01)...");
    const s1UserDataDir = path.join(tempRoot, "s1-restricted-user-data");
    const s1ExtensionsDir = path.join(tempRoot, "s1-restricted-extensions");
    const s1Install = installVsixIntoIsolatedProfile({
      codeExePath: CODE_EXE,
      cliJsPath,
      vsixPath: VSIX_PATH,
      extensionsDir: s1ExtensionsDir,
      userDataDir: s1UserDataDir,
    });

    // Verify extracted VSIX bundled binary hashes & POSIX executable permissions match manifest
    assert.strictEqual(
      sha256File(path.join(s1Install.installedExtDir, "bundled", "checkwash.pyz")),
      bundledManifest.checkwash.sha256
    );
    const extractedBrokerPath = path.join(
      s1Install.installedExtDir,
      "bundled",
      activeBrokerFilename
    );
    assert.strictEqual(
      sha256File(extractedBrokerPath),
      IS_WIN32 ? bundledManifest.windowsBroker.sha256 : bundledManifest.linuxBroker.sha256
    );
    if (!IS_WIN32) {
      const brokerMode = fs.statSync(extractedBrokerPath).mode;
      assert.strictEqual(
        (brokerMode & 0o111) !== 0,
        true,
        `Installed Linux broker must retain executable permission bits after VSIX extraction, got mode=0o${(brokerMode & 0o777).toString(8)}`
      );
    }

    // Enable real Workspace Trust (`isTrusted === false` for untrusted `repoDir`) AND configure
    // valid machine runtime paths to prove Restricted Mode blocks execution even when paths exist!
    fs.writeFileSync(
      path.join(s1UserDataDir, "User", "settings.json"),
      JSON.stringify(
        {
          "security.workspace.trust.enabled": true,
          "security.workspace.trust.startupPrompt": "never",
          "security.workspace.trust.banner": "never",
          "security.workspace.trust.emptyWindow": false,
          "git.enabled": false,
          "git.autoRepositoryDetection": false,
          "npm.autoDetect": "off",
          "task.autoDetect": "off",
          "typescript.tsserver.enable": false,
          "extensions.autoUpdate": false,
          "extensions.autoCheckUpdates": false,
          "telemetry.telemetryLevel": "off",
          "update.mode": "none",
          "window.restoreWindows": "none",
          "checkwashLens.pythonPath": PYTHON_EXE,
          "checkwashLens.gitPath": GIT_EXE,
          "checkwashLens.provePath": PROVE_EXE,
        },
        null,
        2
      ),
      "utf8"
    );

    const s1HandshakePath = path.join(tempRoot, "s1-handshake.json");
    const s1MonitorAckPath = path.join(tempRoot, "s1-monitor-ack.txt");
    const s1StopMonitorPath = path.join(tempRoot, "s1-monitor-stop.txt");
    const s1MonitorOutPath = path.join(tempRoot, "s1-monitor-out.json");
    const s1ReceiptPath = path.join(tempRoot, "s1-restricted-receipt.json");
    const s1DriverConfigPath = path.join(tempRoot, "s1-driver-config.json");

    fs.writeFileSync(
      s1DriverConfigPath,
      JSON.stringify(
        {
          extensionsDir: s1ExtensionsDir,
          repoDir: s1TargetRepo.repoDir,
          pythonExe: PYTHON_EXE,
          gitExe: GIT_EXE,
          proveExe: PROVE_EXE,
          offlineCheckwashReportPath,
          offlineProveReportPath,
          handshakePath: s1HandshakePath,
          monitorAckPath: s1MonitorAckPath,
          stopMonitorPath: s1StopMonitorPath,
          receiptPath: s1ReceiptPath,
          allowPtracerNodePath,
        },
        null,
        2
      ),
      "utf8"
    );

    const s1Env: NodeJS.ProcessEnv = {
      ...process.env,
      CW_VSIX_DRIVER_CONFIG: s1DriverConfigPath,
    };
    delete s1Env.ELECTRON_RUN_AS_NODE;

    // IMPORTANT: NO `--disable-workspace-trust` and NO `--disable-extensions`!
    // Built-in noisy extensions (`vscode.git`, `vscode.typescript-language-features`, etc.) are disabled
    // individually via `--disable-extension=...` so our installed VSIX loads normally in Restricted Mode.
    const s1Args = [
      "--headless",
      ...getPlatformVscodeLaunchArgs(),
      "--disable-gpu",
      "--disable-updates",
      "--skip-welcome",
      "--skip-release-notes",
      "--disable-extension=vscode.git",
      "--disable-extension=vscode.git-base",
      "--disable-extension=vscode.github",
      "--disable-extension=vscode.typescript-language-features",
      "--disable-extension=vscode.json-language-features",
      `--user-data-dir=${s1UserDataDir}`,
      `--extensions-dir=${s1ExtensionsDir}`,
      `--extensionDevelopmentPath=${driverDir}`,
      `--extensionTestsPath=${restrictedRunnerJs}`,
      s1TargetRepo.repoDir,
    ];

    const s1CodeProc = cp.spawn(CODE_EXE, s1Args, {
      cwd: tempRoot,
      env: s1Env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let s1Stdout = "";
    let s1Stderr = "";
    s1CodeProc.stdout.on("data", (d: Buffer) => {
      s1Stdout += d.toString("utf8");
    });
    s1CodeProc.stderr.on("data", (d: Buffer) => {
      s1Stderr += d.toString("utf8");
    });

    let monitorProc: cp.ChildProcess | null = null;
    const s1ExitCode = await new Promise<number | null>((resolve, reject) => {
      const timeout = setTimeout(() => {
        s1CodeProc.kill();
        reject(new Error(`Session 1 VS Code timed out. stderr=${s1Stderr}`));
      }, 75_000);

      const pollHandshake = setInterval(() => {
        if (!monitorProc && fs.existsSync(s1HandshakePath)) {
          clearInterval(pollHandshake);
          const hs = JSON.parse(fs.readFileSync(s1HandshakePath, "utf8")) as { extHostPid: number };
          monitorProc = cp.spawn(
            monitorExe,
            [String(hs.extHostPid), s1MonitorAckPath, s1StopMonitorPath, s1MonitorOutPath],
            { stdio: "ignore", windowsHide: true }
          );
        }
      }, 15);

      s1CodeProc.on("close", (code) => {
        clearInterval(pollHandshake);
        clearTimeout(timeout);
        try {
          fs.writeFileSync(s1StopMonitorPath, "stop", "utf8");
        } catch {
          // Ignore
        }
        resolve(code);
      });
    });

    let s1MonitorExitCode: number | null = null;
    if (monitorProc) {
      s1MonitorExitCode = await new Promise<number | null>((resolve) => {
        if ((monitorProc as cp.ChildProcess).exitCode !== null) {
          resolve((monitorProc as cp.ChildProcess).exitCode);
          return;
        }
        (monitorProc as cp.ChildProcess).once("close", (c) => resolve(c));
      });
    }

    const s1MonitorDiag = fs.existsSync(s1MonitorOutPath)
      ? fs.readFileSync(s1MonitorOutPath, "utf8")
      : "<no monitor out>";
    assert.strictEqual(
      fs.existsSync(s1ReceiptPath),
      true,
      `Session 1 Restricted Mode did not produce receipt (exit=${s1ExitCode}, monitorExit=${s1MonitorExitCode}, monitorOut=${s1MonitorDiag}, stdout=${s1Stdout}, stderr=${s1Stderr})`
    );
    const s1Receipt = JSON.parse(fs.readFileSync(s1ReceiptPath, "utf8"));
    assert.strictEqual(
      s1Receipt.ok,
      true,
      `Session 1 Restricted Mode failed: ${JSON.stringify(s1Receipt)} (exit=${s1ExitCode}, monitorExit=${s1MonitorExitCode}, monitorOut=${s1MonitorDiag})`
    );
    assert.strictEqual(s1ExitCode, 0);
    assert.strictEqual(s1MonitorExitCode, 0, `Session 1 Kernel Job Object monitor exited with ${s1MonitorExitCode}`);
    assert.strictEqual(s1Receipt.isWorkspaceTrusted, false);
    assert.strictEqual(s1Receipt.wasActiveBeforeMonitorAttach, false);
    assert.strictEqual(s1Receipt.nodeChildProcessHookInstalledPreActivation, true);
    assert.strictEqual(s1Receipt.nodeChildProcessCallsCount, 0);
    assert.strictEqual(s1Receipt.extensionActive, true);
    assert.strictEqual(s1Receipt.loadedFromInstalledVsix, true);

    interface KernelMonitorObservation {
      rootPid: number;
      observationMechanism: string;
      observationScope: string;
      kernelJobAssigned: boolean;
      rootPidAssignedEventObserved: boolean;
      initialTotalProcesses: number;
      finalTotalProcesses: number;
      kernelSpawnedChildCount: number;
      iocpExitedChildCount: number;
      iocpNewProcessEvents: Array<{ pid: number; imagePath: string }>;
    }

    const s1MonitorObs = JSON.parse(
      fs.readFileSync(s1MonitorOutPath, "utf8")
    ) as KernelMonitorObservation;
    assert.strictEqual(
      s1MonitorObs.kernelJobAssigned,
      true,
      `Session 1 Kernel Job Object failed to attach: ${JSON.stringify(s1MonitorObs)}`
    );
    assert.strictEqual(
      s1MonitorObs.rootPidAssignedEventObserved,
      true,
      `Session 1 IOCP did not observe rootPid assignment packet: ${JSON.stringify(s1MonitorObs)}`
    );
    assert.strictEqual(
      s1MonitorObs.kernelSpawnedChildCount,
      0,
      `Expected 0 kernel-accounted child processes in Restricted Mode, got: ${JSON.stringify(s1MonitorObs)}`
    );
    assert.strictEqual(
      s1MonitorObs.iocpNewProcessEvents.length,
      0,
      `Expected 0 IOCP JOB_OBJECT_MSG_NEW_PROCESS child events in Restricted Mode, got: ${JSON.stringify(s1MonitorObs)}`
    );
    console.log(
      `  [PASS] Session 1 (Real B01 Restricted Mode): isTrusted=false, wasActivePreAttach=false, nodeCpCalls=0, kernelSpawnedChildCount=${s1MonitorObs.kernelSpawnedChildCount}, iocpChildEvents=0`
    );

    // =========================================================================
    // Session 2: Trusted Workspace End-to-End Flow on Installed VSIX (+ Monitor Positive Control)
    // =========================================================================
    console.log("  -> Session 2: Installing VSIX & running Trusted E2E flow (Scan + Diet + Cancel + Offline + Monitor Positive Control)...");
    const s2UserDataDir = path.join(tempRoot, "s2-trusted-user-data");
    const s2ExtensionsDir = path.join(tempRoot, "s2-trusted-extensions");
    const s2TempWorkDir = path.join(tempRoot, "s2-work");
    fs.mkdirSync(s2TempWorkDir, { recursive: true });

    const s2Install = installVsixIntoIsolatedProfile({
      codeExePath: CODE_EXE,
      cliJsPath,
      vsixPath: VSIX_PATH,
      extensionsDir: s2ExtensionsDir,
      userDataDir: s2UserDataDir,
    });

    fs.writeFileSync(
      path.join(s2UserDataDir, "User", "settings.json"),
      JSON.stringify(
        {
          "security.workspace.trust.enabled": false,
          "git.enabled": false,
          "git.autoRepositoryDetection": false,
          "extensions.autoUpdate": false,
          "extensions.autoCheckUpdates": false,
          "telemetry.telemetryLevel": "off",
          "update.mode": "none",
          "window.restoreWindows": "none",
          "checkwashLens.pythonPath": PYTHON_EXE,
          "checkwashLens.gitPath": GIT_EXE,
          "checkwashLens.provePath": PROVE_EXE,
        },
        null,
        2
      ),
      "utf8"
    );

    const s2HandshakePath = path.join(tempRoot, "s2-handshake.json");
    const s2MonitorAckPath = path.join(tempRoot, "s2-monitor-ack.txt");
    const s2StopMonitorPath = path.join(tempRoot, "s2-monitor-stop.txt");
    const s2MonitorOutPath = path.join(tempRoot, "s2-monitor-out.json");
    const s2ReceiptPath = path.join(tempRoot, "s2-trusted-receipt.json");
    const s2DriverConfigPath = path.join(tempRoot, "s2-driver-config.json");
    fs.writeFileSync(
      s2DriverConfigPath,
      JSON.stringify(
        {
          extensionsDir: s2ExtensionsDir,
          tempDir: s2TempWorkDir,
          repoDir,
          baseOid,
          headOid,
          sqlSecret,
          addedPat,
          pythonExe: PYTHON_EXE,
          gitExe: GIT_EXE,
          proveExe: PROVE_EXE,
          offlineProveReportPath,
          handshakePath: s2HandshakePath,
          monitorAckPath: s2MonitorAckPath,
          stopMonitorPath: s2StopMonitorPath,
          receiptPath: s2ReceiptPath,
          allowPtracerNodePath,
        },
        null,
        2
      ),
      "utf8"
    );

    const s2Env: NodeJS.ProcessEnv = {
      ...process.env,
      CW_VSIX_DRIVER_CONFIG: s2DriverConfigPath,
    };
    delete s2Env.ELECTRON_RUN_AS_NODE;

    const s2Args = [
      "--headless",
      ...getPlatformVscodeLaunchArgs(),
      "--disable-gpu",
      "--disable-updates",
      "--skip-welcome",
      "--skip-release-notes",
      "--disable-workspace-trust",
      "--disable-extension=vscode.git",
      "--disable-extension=vscode.git-base",
      "--disable-extension=vscode.github",
      "--disable-extension=vscode.typescript-language-features",
      `--user-data-dir=${s2UserDataDir}`,
      `--extensions-dir=${s2ExtensionsDir}`,
      `--extensionDevelopmentPath=${driverDir}`,
      `--extensionTestsPath=${trustedRunnerJs}`,
      repoDir,
    ];

    const s2CodeProc = cp.spawn(CODE_EXE, s2Args, {
      cwd: tempRoot,
      env: s2Env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let s2Stdout = "";
    let s2Stderr = "";
    s2CodeProc.stdout.on("data", (d: Buffer) => {
      s2Stdout += d.toString("utf8");
    });
    s2CodeProc.stderr.on("data", (d: Buffer) => {
      s2Stderr += d.toString("utf8");
    });

    let s2MonitorProc: cp.ChildProcess | null = null;
    const s2ExitCode = await new Promise<number | null>((resolve, reject) => {
      const timeout = setTimeout(() => {
        s2CodeProc.kill();
        reject(new Error(`Session 2 VS Code timed out. stderr=${s2Stderr}`));
      }, 95_000);

      const pollHandshake = setInterval(() => {
        if (!s2MonitorProc && fs.existsSync(s2HandshakePath)) {
          clearInterval(pollHandshake);
          const hs = JSON.parse(fs.readFileSync(s2HandshakePath, "utf8")) as { extHostPid: number };
          s2MonitorProc = cp.spawn(
            monitorExe,
            [String(hs.extHostPid), s2MonitorAckPath, s2StopMonitorPath, s2MonitorOutPath],
            { stdio: "ignore", windowsHide: true }
          );
        }
      }, 15);

      s2CodeProc.on("close", (code) => {
        clearInterval(pollHandshake);
        clearTimeout(timeout);
        try {
          fs.writeFileSync(s2StopMonitorPath, "stop", "utf8");
        } catch {
          // Ignore
        }
        resolve(code);
      });
    });

    let s2MonitorExitCode: number | null = null;
    if (s2MonitorProc) {
      s2MonitorExitCode = await new Promise<number | null>((resolve) => {
        if ((s2MonitorProc as cp.ChildProcess).exitCode !== null) {
          resolve((s2MonitorProc as cp.ChildProcess).exitCode);
          return;
        }
        (s2MonitorProc as cp.ChildProcess).once("close", (c) => resolve(c));
      });
    }

    const s2MonitorDiag = fs.existsSync(s2MonitorOutPath)
      ? fs.readFileSync(s2MonitorOutPath, "utf8")
      : "<no monitor out>";
    assert.strictEqual(
      fs.existsSync(s2ReceiptPath),
      true,
      `Session 2 Trusted VSIX did not write receipt (exit=${s2ExitCode}, monitorExit=${s2MonitorExitCode}, monitorOut=${s2MonitorDiag}, stdout=${s2Stdout}, stderr=${s2Stderr})`
    );
    const s2Receipt = JSON.parse(fs.readFileSync(s2ReceiptPath, "utf8"));
    assert.strictEqual(
      s2Receipt.ok,
      true,
      `Session 2 Trusted VSIX failed: ${JSON.stringify(s2Receipt)} (exit=${s2ExitCode}, monitorExit=${s2MonitorExitCode}, monitorOut=${s2MonitorDiag})`
    );
    assert.strictEqual(s2ExitCode, 0);
    assert.strictEqual(s2MonitorExitCode, 0, `Session 2 Kernel Job Object monitor exited with ${s2MonitorExitCode}`);

    // Outer strict verification of true "cancelled" semantics (never "timed_out")
    assert.strictEqual(
      s2Receipt.cancellationCleanup.inFlightOutcomeStatus,
      "cancelled",
      `Expected Session 2 inFlightOutcomeStatus === 'cancelled', got: ${JSON.stringify(s2Receipt.cancellationCleanup)}`
    );
    assert.strictEqual(s2Receipt.cancellationCleanup.inFlightCleanupConfirmed, true);
    assert.strictEqual(s2Receipt.cancellationCleanup.inFlightActiveProcessesRemaining, 0);
    assert.strictEqual(s2Receipt.cancellationCleanup.provePreflightCancelled, true);
    assert.strictEqual(
      s2Receipt.cancellationCleanup.provePreflightCancelledOutcomeStatus,
      "Not Run / Cancelled"
    );
    assert.strictEqual(
      s2Receipt.cancellationCleanup.proveExecutionCancelledOutcomeStatus,
      "Not Run / Cancelled"
    );

    // Outer strict verification of Positive Control for the Kernel Job Object + IOCP sensor
    const s2MonitorObs = JSON.parse(
      fs.readFileSync(s2MonitorOutPath, "utf8")
    ) as KernelMonitorObservation;
    assert.strictEqual(s2MonitorObs.kernelJobAssigned, true);
    assert.strictEqual(s2MonitorObs.rootPidAssignedEventObserved, true);
    assert.strictEqual(
      s2MonitorObs.kernelSpawnedChildCount > 0,
      true,
      `Positive control failed: expected Trusted Session 2 kernelSpawnedChildCount > 0, got: ${JSON.stringify(s2MonitorObs)}`
    );
    assert.strictEqual(
      s2MonitorObs.iocpNewProcessEvents.length > 0,
      true,
      `Positive control failed: expected Trusted Session 2 iocpNewProcessEvents.length > 0, got: ${JSON.stringify(s2MonitorObs)}`
    );
    const s2ObservedBroker = s2MonitorObs.iocpNewProcessEvents.some((ev) =>
      ev.imagePath.toLowerCase().includes(activeBrokerFilename.toLowerCase())
    );
    assert.strictEqual(
      s2ObservedBroker,
      true,
      `Positive control failed: expected monitor events to include ${activeBrokerFilename}, got: ${JSON.stringify(s2MonitorObs.iocpNewProcessEvents)}`
    );

    console.log(
      `  [PASS] Session 2 (Trusted Installed VSIX + Positive Control): scan=${s2Receipt.scanVerdict}, inFlightOutcomeStatus=${s2Receipt.cancellationCleanup.inFlightOutcomeStatus}, provePreflightCancel=true, proveExecCancel=true, kernelSpawnedChildCount=${s2MonitorObs.kernelSpawnedChildCount}`
    );

    // =========================================================================
    // Session 3: Real Desktop B08-A (`workbench.action.reloadWindow` During Active Run)
    // =========================================================================
    console.log("  -> Session 3: Installing VSIX & verifying real Desktop B08-A (workbench.action.reloadWindow during active child+grandchild run)...");
    const s3UserDataDir = path.join(tempRoot, "s3-reload-user-data");
    const s3ExtensionsDir = path.join(tempRoot, "s3-reload-extensions");
    const s3TempWorkDir = path.join(tempRoot, "s3-work");
    fs.mkdirSync(s3TempWorkDir, { recursive: true });

    const s3Install = installVsixIntoIsolatedProfile({
      codeExePath: CODE_EXE,
      cliJsPath,
      vsixPath: VSIX_PATH,
      extensionsDir: s3ExtensionsDir,
      userDataDir: s3UserDataDir,
    });

    fs.writeFileSync(
      path.join(s3UserDataDir, "User", "settings.json"),
      JSON.stringify(
        {
          "security.workspace.trust.enabled": false,
          "git.enabled": false,
          "git.autoRepositoryDetection": false,
          "extensions.autoUpdate": false,
          "extensions.autoCheckUpdates": false,
          "telemetry.telemetryLevel": "off",
          "update.mode": "none",
          "window.restoreWindows": "none",
          "checkwashLens.pythonPath": PYTHON_EXE,
          "checkwashLens.gitPath": GIT_EXE,
        },
        null,
        2
      ),
      "utf8"
    );

    const s3Phase1HandshakePath = path.join(tempRoot, "s3-phase1-handshake.json");
    const s3ProceedReloadAckPath = path.join(tempRoot, "s3-proceed-reload-ack.txt");
    const s3Phase2ReceiptPath = path.join(tempRoot, "s3-phase2-receipt.json");
    const s3ConfigPath = path.join(tempRoot, "s3-reload-config.json");
    fs.writeFileSync(
      s3ConfigPath,
      JSON.stringify(
        {
          tempDir: s3TempWorkDir,
          repoDir,
          baseOid,
          headOid,
          pythonExe: PYTHON_EXE,
          gitExe: GIT_EXE,
          phase1HandshakePath: s3Phase1HandshakePath,
          proceedReloadAckPath: s3ProceedReloadAckPath,
          phase2ReceiptPath: s3Phase2ReceiptPath,
        },
        null,
        2
      ),
      "utf8"
    );

    const s3Env: NodeJS.ProcessEnv = {
      ...process.env,
      CW_VSIX_B08_RELOAD_CONFIG: s3ConfigPath,
    };
    delete s3Env.ELECTRON_RUN_AS_NODE;

    // Normal VS Code Desktop window mode (NO `--extensionTestsPath`) so `workbench.action.reloadWindow`
    // reloads the window in-place and spawns a fresh Extension Host (`extHostPid2`) rather than exiting Code.exe.
    const s3Args = [
      "--headless",
      ...getPlatformVscodeLaunchArgs(),
      "--disable-gpu",
      "--disable-updates",
      "--skip-welcome",
      "--skip-release-notes",
      "--disable-workspace-trust",
      "--disable-extension=vscode.git",
      "--disable-extension=vscode.git-base",
      "--disable-extension=vscode.github",
      "--disable-extension=vscode.typescript-language-features",
      `--user-data-dir=${s3UserDataDir}`,
      `--extensions-dir=${s3ExtensionsDir}`,
      `--extensionDevelopmentPath=${driverDir}`,
      repoDir,
    ];

    const s3CodeProc = cp.spawn(CODE_EXE, s3Args, {
      cwd: tempRoot,
      env: s3Env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      detached: !IS_WIN32,
    });
    let s3Stderr = "";
    s3CodeProc.stderr.on("data", (d: Buffer) => {
      s3Stderr += d.toString("utf8");
    });

    let s3ReloadReapLatencyMs = -1;
    let s3MainCodeAliveAfterTreeReap = false;
    let s3Hs1: { extHostPid1: number; parentPid: number; grandchildPid: number } | null = null;
    let s3Phase2Receipt: Record<string, unknown> | null = null;

    try {
      const s3WaitHsStart = Date.now();
      while (!fs.existsSync(s3Phase1HandshakePath)) {
        if (fs.existsSync(s3Phase2ReceiptPath)) {
          throw new Error(
            `Session 3 Phase 1 failed inside Extension Host: ${fs.readFileSync(s3Phase2ReceiptPath, "utf8")}`
          );
        }
        if (s3CodeProc.exitCode !== null) {
          throw new Error(`Session 3 Code.exe exited prematurely (${s3CodeProc.exitCode}): ${s3Stderr}`);
        }
        if (Date.now() - s3WaitHsStart > 35_000) {
          throw new Error(`Timed out waiting for Session 3 Phase 1 handshake: ${s3Stderr}`);
        }
        await sleepOuter(25);
      }

      s3Hs1 = JSON.parse(fs.readFileSync(s3Phase1HandshakePath, "utf8")) as {
        extHostPid1: number;
        parentPid: number;
        grandchildPid: number;
      };
      assert.strictEqual(isPidAliveOuter(s3CodeProc.pid), true, "Expected Session 3 main Code.exe alive");
      assert.strictEqual(isPidAliveOuter(s3Hs1.extHostPid1), true, "Expected Session 3 extHostPid1 alive");
      assert.strictEqual(isPidAliveOuter(s3Hs1.parentPid), true, "Expected Session 3 parentPid alive before Reload Window");
      assert.strictEqual(isPidAliveOuter(s3Hs1.grandchildPid), true, "Expected Session 3 grandchildPid alive before Reload Window");

      const reloadStartMs = Date.now();
      fs.writeFileSync(s3ProceedReloadAckPath, "reload", "utf8");

      // Poll until both parentPid AND grandchildPid are reaped by broker on Reload Window
      while (isPidAliveOuter(s3Hs1.parentPid) || isPidAliveOuter(s3Hs1.grandchildPid)) {
        if (Date.now() - reloadStartMs > 15_000) {
          throw new Error(
            `B08-A FAILURE: Brokered child/grandchild survived workbench.action.reloadWindow >15s! parentAlive=${isPidAliveOuter(s3Hs1.parentPid)}, grandchildAlive=${isPidAliveOuter(s3Hs1.grandchildPid)}`
          );
        }
        await sleepOuter(25);
      }
      s3ReloadReapLatencyMs = Date.now() - reloadStartMs;
      s3MainCodeAliveAfterTreeReap = isPidAliveOuter(s3CodeProc.pid);
      assert.strictEqual(
        s3MainCodeAliveAfterTreeReap,
        true,
        `Expected main Code.exe window process to stay alive across workbench.action.reloadWindow (exitCode=${s3CodeProc.exitCode})`
      );

      // Wait for reloaded Extension Host (extHostPid2) to complete post-reload scan recovery
      const waitPhase2Start = Date.now();
      while (!fs.existsSync(s3Phase2ReceiptPath)) {
        if (s3CodeProc.exitCode !== null) {
          throw new Error(
            `Session 3 Code.exe exited unexpectedly during post-reload Phase 2 (${s3CodeProc.exitCode}): ${s3Stderr}`
          );
        }
        if (Date.now() - waitPhase2Start > 30_000) {
          throw new Error(`Timed out waiting for Session 3 post-reload Phase 2 receipt: ${s3Stderr}`);
        }
        await sleepOuter(30);
      }
      s3Phase2Receipt = JSON.parse(fs.readFileSync(s3Phase2ReceiptPath, "utf8")) as Record<string, unknown>;
      assert.strictEqual(s3Phase2Receipt.ok, true, `Session 3 post-reload Phase 2 failed: ${JSON.stringify(s3Phase2Receipt)}`);
      assert.notStrictEqual(
        s3Phase2Receipt.extHostPid2,
        s3Hs1.extHostPid1,
        "Expected workbench.action.reloadWindow to spawn a fresh Extension Host PID"
      );
      assert.strictEqual(s3Phase2Receipt.postReloadScanVerdict, "Block");
      assert.strictEqual(s3Phase2Receipt.hasUnconfirmedCleanupAfterReload, false);
    } finally {
      forceKillProcessTree(s3CodeProc.pid);
      await sleepOuter(150);
    }

    console.log(
      `  [PASS] Session 3 (Real Desktop B08-A Reload Window): extHostPid1=${s3Hs1.extHostPid1} -> extHostPid2=${String(s3Phase2Receipt.extHostPid2)}, parent+grandchild reaped in ${s3ReloadReapLatencyMs}ms, postReloadScan=${String(s3Phase2Receipt.postReloadScanVerdict)}`
    );

    // =========================================================================
    // Session 4: Real Desktop B08-B (Extension Host Forced Hard Crash `TerminateProcess` / `SIGKILL`)
    // =========================================================================
    console.log(
      `  -> Session 4: Installing VSIX & verifying real Desktop B08-B (Extension Host forced crash ${IS_WIN32 ? "TerminateProcess" : "SIGKILL"} during active child+grandchild run)...`
    );
    const s4UserDataDir = path.join(tempRoot, "s4-crash-user-data");
    const s4ExtensionsDir = path.join(tempRoot, "s4-crash-extensions");
    const s4TempWorkDir = path.join(tempRoot, "s4-work");
    fs.mkdirSync(s4TempWorkDir, { recursive: true });

    const s4Install = installVsixIntoIsolatedProfile({
      codeExePath: CODE_EXE,
      cliJsPath,
      vsixPath: VSIX_PATH,
      extensionsDir: s4ExtensionsDir,
      userDataDir: s4UserDataDir,
    });

    fs.writeFileSync(
      path.join(s4UserDataDir, "User", "settings.json"),
      JSON.stringify(
        {
          "security.workspace.trust.enabled": false,
          "git.enabled": false,
          "git.autoRepositoryDetection": false,
          "extensions.autoUpdate": false,
          "extensions.autoCheckUpdates": false,
          "telemetry.telemetryLevel": "off",
          "update.mode": "none",
          "window.restoreWindows": "none",
          "checkwashLens.pythonPath": PYTHON_EXE,
          "checkwashLens.gitPath": GIT_EXE,
        },
        null,
        2
      ),
      "utf8"
    );

    const s4CrashHandshakePath = path.join(tempRoot, "s4-crash-handshake.json");
    const s4CrashErrorPath = path.join(tempRoot, "s4-crash-error.json");
    const s4ConfigPath = path.join(tempRoot, "s4-crash-config.json");
    fs.writeFileSync(
      s4ConfigPath,
      JSON.stringify(
        {
          tempDir: s4TempWorkDir,
          repoDir,
          pythonExe: PYTHON_EXE,
          gitExe: GIT_EXE,
          crashHandshakePath: s4CrashHandshakePath,
          crashErrorPath: s4CrashErrorPath,
        },
        null,
        2
      ),
      "utf8"
    );

    const s4Env: NodeJS.ProcessEnv = {
      ...process.env,
      CW_VSIX_B08_CRASH_CONFIG: s4ConfigPath,
    };
    delete s4Env.ELECTRON_RUN_AS_NODE;

    // Normal VS Code Desktop window mode (NO `--extensionTestsPath`) so main Code.exe stays open
    // when Extension Host crashes abruptly via Win32 TerminateProcess.
    const s4Args = [
      "--headless",
      ...getPlatformVscodeLaunchArgs(),
      "--disable-gpu",
      "--disable-updates",
      "--skip-welcome",
      "--skip-release-notes",
      "--disable-workspace-trust",
      "--disable-extension=vscode.git",
      "--disable-extension=vscode.git-base",
      "--disable-extension=vscode.github",
      "--disable-extension=vscode.typescript-language-features",
      `--user-data-dir=${s4UserDataDir}`,
      `--extensions-dir=${s4ExtensionsDir}`,
      `--extensionDevelopmentPath=${driverDir}`,
      repoDir,
    ];

    const s4CodeProc = cp.spawn(CODE_EXE, s4Args, {
      cwd: tempRoot,
      env: s4Env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      detached: !IS_WIN32,
    });
    let s4Stderr = "";
    s4CodeProc.stderr.on("data", (d: Buffer) => {
      s4Stderr += d.toString("utf8");
    });

    let s4CrashReapLatencyMs = -1;
    let s4MainCodeAliveAfterExtHostCrash = false;
    let s4Hs: { extHostPid: number; parentPid: number; grandchildPid: number } | null = null;

    try {
      const waitS4Start = Date.now();
      while (!fs.existsSync(s4CrashHandshakePath)) {
        if (fs.existsSync(s4CrashErrorPath)) {
          throw new Error(
            `Session 4 failed inside Extension Host: ${fs.readFileSync(s4CrashErrorPath, "utf8")}`
          );
        }
        if (s4CodeProc.exitCode !== null) {
          throw new Error(`Session 4 Code.exe exited prematurely (${s4CodeProc.exitCode}): ${s4Stderr}`);
        }
        if (Date.now() - waitS4Start > 35_000) {
          throw new Error(`Timed out waiting for Session 4 crash handshake: ${s4Stderr}`);
        }
        await sleepOuter(25);
      }

      s4Hs = JSON.parse(fs.readFileSync(s4CrashHandshakePath, "utf8")) as {
        extHostPid: number;
        parentPid: number;
        grandchildPid: number;
      };
      assert.notStrictEqual(s4CodeProc.pid, s4Hs.extHostPid, "Main Code.exe PID must differ from Extension Host PID");
      assert.strictEqual(isPidAliveOuter(s4CodeProc.pid), true);
      assert.strictEqual(isPidAliveOuter(s4Hs.extHostPid), true);
      assert.strictEqual(isPidAliveOuter(s4Hs.parentPid), true);
      assert.strictEqual(isPidAliveOuter(s4Hs.grandchildPid), true);

      // Abrupt hard kill on Extension Host ONLY (Win32 TerminateProcess / POSIX SIGKILL — zero JS deactivate()!)
      const crashKillStartMs = Date.now();
      if (IS_WIN32) {
        process.kill(s4Hs.extHostPid);
      } else {
        process.kill(s4Hs.extHostPid, "SIGKILL");
      }

      while (
        isPidAliveOuter(s4Hs.extHostPid) ||
        isPidAliveOuter(s4Hs.parentPid) ||
        isPidAliveOuter(s4Hs.grandchildPid)
      ) {
        if (Date.now() - crashKillStartMs > 10_000) {
          throw new Error(
            `B08-B FAILURE: Brokered child/grandchild survived abrupt Extension Host TerminateProcess! extHost=${isPidAliveOuter(s4Hs.extHostPid)}, parent=${isPidAliveOuter(s4Hs.parentPid)}, grandchild=${isPidAliveOuter(s4Hs.grandchildPid)}`
          );
        }
        await sleepOuter(20);
      }
      s4CrashReapLatencyMs = Date.now() - crashKillStartMs;
      s4MainCodeAliveAfterExtHostCrash = isPidAliveOuter(s4CodeProc.pid);
      assert.strictEqual(
        s4MainCodeAliveAfterExtHostCrash,
        true,
        `Expected main Code.exe window process to stay alive when Extension Host crashes via TerminateProcess (exitCode=${s4CodeProc.exitCode})`
      );
    } finally {
      forceKillProcessTree(s4CodeProc.pid);
      await sleepOuter(150);
    }

    console.log(
      `  [PASS] Session 4 (Real Desktop B08-B Extension Host Hard Crash): extHostPid=${s4Hs.extHostPid} killed via ${IS_WIN32 ? "TerminateProcess" : "SIGKILL"}, parent+grandchild reaped in ${s4CrashReapLatencyMs}ms (mainCodeAlive=${s4MainCodeAliveAfterExtHostCrash})`
    );

    // =========================================================================
    // Write Authoritative Installed VSIX, Real B01, & Real Desktop B08 Receipt
    // =========================================================================
    const probeOut = (exe: string, args: string[]): string => {
      const r = cp.spawnSync(exe, args, { encoding: "utf8", windowsHide: true });
      return ((r.stdout || "") + (r.stderr || "")).trim();
    };
    const sourceSha = runGitSync(REPO_ROOT, ["rev-parse", "HEAD"]);
    const statusPorcelain = runGitSync(REPO_ROOT, ["status", "--porcelain"]);

    const summary = {
      suite:
        "Installed VSIX & Real VS Code Desktop Verification (B01 Restricted Mode + Trusted E2E + Real B08 Reload Window & Extension Host Crash)",
      testLayer: "installed-vsix-in-isolated-real-vscode-desktop",
      executionTag: process.env.CW_EVIDENCE_TAG?.trim() || "LOCAL_VERIFICATION",
      ...getPlatformExecutionMetadata(),
      nodeVersion: process.version,
      vscodeDesktopVersion: s1Receipt.vscodeVersion,
      pythonVersion: probeOut(PYTHON_EXE, ["--version"]),
      gitVersion: probeOut(GIT_EXE, ["--version"]),
      proveVersion: probeOut(PROVE_EXE, ["--version"]),
      sourceSha,
      worktreeClean: statusPorcelain.length === 0,
      worktreeStatusSummary: statusPorcelain ? statusPorcelain.split("\n") : [],
      timestamp: new Date().toISOString(),
      exitCode: 0,
      artifacts: {
        vsixFile: path.basename(VSIX_PATH),
        vsixPath: VSIX_PATH,
        vsixTarget: ACTIVE_VSIX_TARGET,
        vsixBytes,
        vsixSha256,
        vsixEntryCount: vsixEntries.length,
        vsixEntries,
        checkwashPyzSha256: bundledManifest.checkwash.sha256,
        activeBrokerFilename,
        activeBrokerSha256: IS_WIN32
          ? bundledManifest.windowsBroker.sha256
          : bundledManifest.linuxBroker.sha256,
        windowsBrokerSha256: bundledManifest.windowsBroker?.sha256 ?? null,
        linuxBrokerSha256: bundledManifest.linuxBroker?.sha256 ?? null,
        proveGeneratorSha256: bundledManifest.proveAdapter.generatorSha256,
      },
      fixtureCommits: {
        baseOid,
        headOid,
      },
      session1RealRestrictedModeB01: {
        installStdout: s1Install.installStdout,
        vscodeExitCode: s1ExitCode,
        receipt: s1Receipt,
        kernelProcessMonitor: s1MonitorObs,
      },
      session2TrustedInstalledVsix: {
        installStdout: s2Install.installStdout,
        vscodeExitCode: s2ExitCode,
        receipt: s2Receipt,
        kernelProcessMonitorPositiveControl: s2MonitorObs,
      },
      session3RealDesktopB08ReloadWindow: {
        installStdout: s3Install.installStdout,
        mainCodePid: s3CodeProc.pid,
        mainCodeAliveAfterTreeReap: s3MainCodeAliveAfterTreeReap,
        extHostPidBeforeReload: s3Hs1.extHostPid1,
        extHostPidAfterReload: s3Phase2Receipt.extHostPid2,
        spawnedParentPid: s3Hs1.parentPid,
        spawnedGrandchildPid: s3Hs1.grandchildPid,
        parentAliveAfterReload: false,
        grandchildAliveAfterReload: false,
        reloadTreeReapLatencyMs: s3ReloadReapLatencyMs,
        postReloadReceipt: s3Phase2Receipt,
      },
      session4RealDesktopB08ExtHostCrash: {
        installStdout: s4Install.installStdout,
        mainCodePid: s4CodeProc.pid,
        mainCodeAliveAfterExtHostCrash: s4MainCodeAliveAfterExtHostCrash,
        crashedExtHostPid: s4Hs.extHostPid,
        crashMechanism: IS_WIN32
          ? "Win32 TerminateProcess on Extension Host PID (zero JS deactivate)"
          : "POSIX SIGKILL on Extension Host PID (zero JS deactivate)",
        spawnedParentPid: s4Hs.parentPid,
        spawnedGrandchildPid: s4Hs.grandchildPid,
        parentAliveAfterCrash: false,
        grandchildAliveAfterCrash: false,
        crashTreeReapLatencyMs: s4CrashReapLatencyMs,
      },
      notRunBoundaries: {
        windows10x64:
          "NOT_RUN：尚未於 Windows 10 x64 實機或等效環境執行驗收",
        unsupportedPlatformsAndWorkspaces:
          "NOT_RUN：macOS、ARM64（Windows/Linux）、Remote SSH / Dev Containers / WSL 延伸宿主與 Virtual Workspaces 不在目前 win32-x64 / linux-x64 支援矩陣內",
        otherIdes:
          "NOT_RUN：Cursor / Windsurf / Antigravity IDE 相容性未執行",
      },
    };

    fs.writeFileSync(RESULTS_FILE, JSON.stringify(summary, null, 2), "utf8");
    console.log(`\nWrote Installed VSIX & Real B01 receipt to: ${RESULTS_FILE}`);
  } finally {
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch {
      // Ignore transient Windows log lock during VS Code shutdown
    }
  }
}

void main().catch((err) => {
  console.error("FATAL error in installed_vsix_real_vscode_runner:", err);
  process.exit(1);
});
