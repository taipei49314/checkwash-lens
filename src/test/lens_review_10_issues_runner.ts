/**
 * lens_review_10_issues_runner.ts
 *
 * Dedicated Regression Suite for the 10 Checkwash Lens Engineering Review Issues:
 *   #1 [P1] Context Diet hunk masking (deleted `-- ...` SQL comments & added `++ ...` lines through clipboard)
 *   #2 [P1] Unconfirmed cleanup prioritized across all cancel/timeout paths (`stopped=false`, `Error`, blocks follow-ups)
 *   #3 [P1] Prove authorization bound to immutable prepared plan (`list`, `full`, `replay`)
 *   #4 [P2] Prove non-zero exit preserved as `Execution error` (read-only diagnostic, Replay blocked, static verdict clean)
 *   #5 [P2] Checkwash JSON v2 valid empty-string `unit: ""` accepted without false positioning
 *   #6 [P2] Prove `list_only=true` early returns classified consistently with `full` mode (never falsely `Listed`)
 *   #7 [P2] Prove `needs_clarification` schema (`test`, `reason`, `also_fails_in_new`, `detail`) & plain-data UI
 *   #8 [P2] Prove UI scope (`generatedCount`, `runCount`, `skippedOverCapCount`), `rawStatusText`, `notes`, and 0-loss disclaimer
 *   #9 [P2] Windows broker `stdin` async write/error handling & single-settlement races without relaxing production hash checks
 *  #10 [P2] Verified Git vs Checkwash internal bare `git` canonical executable identity enforcement
 */

import * as assert from "assert";
import * as cp from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import Module = require("module");

import { validateFindingsJsonV2, validateCheckwashSarif } from "../core/checkwashSchema";
import {
  classifyProveReport,
  NO_CONFIRMED_LOSS_FIXED_MESSAGE,
  validateProveReportJson,
} from "../core/proveModel";
import { joinCheckwashJsonAndSarif, PINNED_CHECKWASH_BUILD_COMMIT, PINNED_CHECKWASH_PYZ_SHA256, PINNED_CHECKWASH_VERSION } from "../core/reportJoiner";
import { PinnedScanIdentity } from "../core/sourceIdentity";
import { authorizeClipboardCopy, buildContextDietDiff } from "../engine/contextDiet";
import { CheckwashEngineRunner } from "../engine/checkwashRunner";
import { RevisionProvider } from "../source/revisionProvider";
import {
  buildSanitizedProveEnv,
  HostEnvironmentDescriptor,
  verifyBareGitResolutionForProcessLaunch,
  verifyBareGitResolutionForStaticEnv,
  verifyBundledArtifacts,
  verifyLaunchAdmission,
} from "../runtime/admission";
import { UnifiedProcessRunner } from "../runtime/processRunner";
import {
  BrokerLaunchOutcome,
  executeViaWindowsBroker,
  getTotalBrokerSpawnCount,
  resetTotalBrokerSpawnCountForTests,
} from "../runtime/windowsBroker";
import { PROVE_EXECUTION_RISK_WARNING } from "../satellite/proveRunner";
import { CheckwashLensController, ControllerViewSnapshot } from "../ui/commands";
import { buildLiveDiagnosticsPlan } from "../ui/diagnostics";
import { buildCheckwashTreeModel, CheckwashTreeNode } from "../ui/treeView";
import {
  ACTIVE_ARCH,
  ACTIVE_PLATFORM,
  copyExecutablePreservingMode,
  getMinimalBrokerEnv,
  getPlatformExecutionMetadata,
  IS_WIN32,
  isGitExecutableName,
  isProveExecutableName,
  isPythonExecutableName,
  resolveBundledBrokerExe,
  resolveBundledBrokerFilename,
  resolvePlatformEvidenceDir,
  resolveTestGitExe,
  resolveTestProveExe,
  resolveTestPythonExe,
  writeExecutableDecoyScript,
} from "./testPlatformEnv";

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const FIXTURES_DIR = path.join(REPO_ROOT, "fixtures", "phase0");
const EVIDENCE_DIR = resolvePlatformEvidenceDir(REPO_ROOT);
const RESULTS_FILE = path.join(EVIDENCE_DIR, "lens-review-10-issues-results.json");
const BROKER_EXE = resolveBundledBrokerExe(REPO_ROOT);
const CSC_EXE = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe";

const PYTHON_EXE = resolveTestPythonExe();
const GIT_EXE = resolveTestGitExe();
const PROVE_EXE = resolveTestProveExe();

interface IssueRegressionResult {
  issueNumber: number;
  id: string;
  severity: "P1" | "P2";
  title: string;
  passed: boolean;
  durationMs: number;
  assertionsCount: number;
  details: Record<string, unknown>;
  error?: string;
}

function sha256File(filePath: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function findNodeById(nodes: CheckwashTreeNode[], id: string): CheckwashTreeNode | null {
  for (const n of nodes) {
    if (n.id === id) return n;
    const found = findNodeById(n.children, id);
    if (found) return found;
  }
  return null;
}

function collectAllNodes(nodes: CheckwashTreeNode[]): CheckwashTreeNode[] {
  const out: CheckwashTreeNode[] = [];
  for (const n of nodes) {
    out.push(n);
    out.push(...collectAllNodes(n.children));
  }
  return out;
}

function makeHostDesc(
  repoRoot: string,
  overrides: Partial<HostEnvironmentDescriptor> = {}
): HostEnvironmentDescriptor {
  return {
    isWorkspaceTrusted: true,
    platform: ACTIVE_PLATFORM,
    arch: ACTIVE_ARCH,
    workspaceScheme: "file",
    isRemote: false,
    isVirtualWorkspace: false,
    extensionRootPath: REPO_ROOT,
    repositoryRootPath: repoRoot,
    configuredPythonPath: PYTHON_EXE,
    configuredGitPath: GIT_EXE,
    ...overrides,
  };
}

function runGitSync(repo: string, args: string[]): string {
  const out = cp.spawnSync(GIT_EXE, ["-C", repo, ...args], {
    encoding: "utf8",
    windowsHide: true,
  });
  if (out.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed in ${repo}: ${out.stderr}`);
  }
  return (out.stdout || "").trim();
}

function createTempGitRepo(parentDir: string, name: string): string {
  const repoDir = path.join(parentDir, name);
  fs.mkdirSync(repoDir, { recursive: true });
  runGitSync(repoDir, ["init"]);
  runGitSync(repoDir, ["config", "user.name", "Lens Review Regression"]);
  runGitSync(repoDir, ["config", "user.email", "regression@example.local"]);
  return fs.realpathSync.native(repoDir);
}

// ============================================================================
// Lightweight Extension Command Harness (for Clipboard & Modal End-to-End Tests)
// ============================================================================

interface MiniVscodeHarnessState {
  isTrusted: boolean;
  workspaceFolderPath: string;
  clipboardText: string;
  machineSettings: Record<string, unknown>;
  shownErrors: string[];
  shownWarnings: string[];
  shownInfos: string[];
  modalHandler: (
    message: string,
    options: { modal?: boolean },
    buttons: string[]
  ) => Promise<string | undefined>;
}

function withMockedVscodeExtension<T>(
  initialState: MiniVscodeHarnessState,
  fn: (
    vscodeApi: {
      executeCommand: <R = unknown>(cmd: string, ...args: unknown[]) => Promise<R>;
      getTreeItemForNode: (node: CheckwashTreeNode) => Record<string, unknown>;
      deactivate: () => Promise<void>;
    },
    state: MiniVscodeHarnessState,
    controller: CheckwashLensController
  ) => Promise<T>
): Promise<T> {
  const registeredCommands = new Map<string, (...args: unknown[]) => unknown>();
  let capturedTreeProvider: { getTreeItem: (el: CheckwashTreeNode) => Record<string, unknown> } | null = null;

  class SimpleEventEmitter<E> {
    private listeners: Array<(e: E) => void> = [];
    public event = (listener: (e: E) => void) => {
      this.listeners.push(listener);
      return {
        dispose: () => {
          this.listeners = this.listeners.filter((l) => l !== listener);
        },
      };
    };
    public fire(data: E): void {
      for (const l of [...this.listeners]) l(data);
    }
    public dispose(): void {
      this.listeners = [];
    }
  }

  class MockTreeItem {
    public id?: string;
    public description?: string;
    public tooltip?: unknown;
    public command?: unknown;
    constructor(public label: string, public collapsibleState: number) {}
  }

  const makeUri = (fsPath: string) => {
    const slashNormalized = fsPath.replace(/\\/g, "/");
    const uriPath = slashNormalized.startsWith("/") ? slashNormalized : `/${slashNormalized}`;
    return {
      scheme: "file",
      authority: "",
      path: uriPath,
      query: "",
      fragment: "",
      fsPath,
      toString: () => `file://${uriPath}`,
    };
  };

  const mockVscode: Record<string, unknown> = {
    EventEmitter: SimpleEventEmitter,
    TreeItem: MockTreeItem,
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    StatusBarAlignment: { Left: 1, Right: 2 },
    ThemeColor: class {
      constructor(public id: string) {}
    },
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    Range: class {
      constructor(
        public startLine: number,
        public startChar: number,
        public endLine: number,
        public endChar: number
      ) {}
    },
    Diagnostic: class {
      public source?: string;
      public code?: string;
      constructor(public range: unknown, public message: string, public severity: number) {}
    },
    ProgressLocation: { Notification: 15 },
    Uri: {
      file: makeUri,
      parse: (raw: string) => ({
        scheme: raw.split(":")[0] || "file",
        authority: "",
        path: raw,
        query: "",
        fragment: "",
        fsPath: raw,
        toString: () => raw,
      }),
    },
    env: {
      remoteName: undefined,
      clipboard: {
        writeText: async (txt: string) => {
          initialState.clipboardText = txt;
        },
        readText: async () => initialState.clipboardText,
      },
    },
    workspace: {
      get isTrusted() {
        return initialState.isTrusted;
      },
      get workspaceFolders() {
        return initialState.workspaceFolderPath
          ? [{ uri: makeUri(initialState.workspaceFolderPath), name: "repo", index: 0 }]
          : [];
      },
      textDocuments: [],
      getConfiguration: (section?: string) => ({
        inspect: <V>(key: string) => {
          const fullKey = section ? `${section}.${key}` : key;
          const val = initialState.machineSettings[fullKey] as V | undefined;
          return {
            key: fullKey,
            globalValue: val,
          };
        },
      }),
      registerTextDocumentContentProvider: () => ({ dispose: () => {} }),
      onDidChangeTextDocument: () => ({ dispose: () => {} }),
      onDidOpenTextDocument: () => ({ dispose: () => {} }),
      onDidSaveTextDocument: () => ({ dispose: () => {} }),
      onDidCloseTextDocument: () => ({ dispose: () => {} }),
      onDidGrantWorkspaceTrust: () => ({ dispose: () => {} }),
      onDidChangeWorkspaceFolders: () => ({ dispose: () => {} }),
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
        command: "",
        backgroundColor: undefined,
        show: () => {},
        dispose: () => {},
      }),
      createTreeView: (_id: string, opts: { treeDataProvider: typeof capturedTreeProvider }) => {
        capturedTreeProvider = opts.treeDataProvider;
        return { dispose: () => {} };
      },
      showErrorMessage: async (msg: string) => {
        initialState.shownErrors.push(msg);
        return undefined;
      },
      showInformationMessage: async (msg: string) => {
        initialState.shownInfos.push(msg);
        return undefined;
      },
      showWarningMessage: async (
        msg: string,
        optsOrBtn?: { modal?: boolean } | string,
        ...btns: string[]
      ) => {
        initialState.shownWarnings.push(msg);
        if (typeof optsOrBtn === "object" && optsOrBtn !== null) {
          return initialState.modalHandler(msg, optsOrBtn, btns);
        }
        const allBtns = typeof optsOrBtn === "string" ? [optsOrBtn, ...btns] : btns;
        return initialState.modalHandler(msg, {}, allBtns);
      },
      withProgress: async <R>(
        _opts: unknown,
        task: (
          progress: { report: () => void },
          token: { onCancellationRequested: () => { dispose: () => void } }
        ) => Promise<R>
      ) =>
        task(
          { report: () => {} },
          { onCancellationRequested: () => ({ dispose: () => {} }) }
        ),
    },
    commands: {
      registerCommand: (id: string, handler: (...args: unknown[]) => unknown) => {
        registeredCommands.set(id, handler);
        return { dispose: () => registeredCommands.delete(id) };
      },
      executeCommand: async <R = unknown>(id: string, ...args: unknown[]): Promise<R> => {
        const handler = registeredCommands.get(id);
        if (!handler) {
          throw new Error(`Command not registered: ${id}`);
        }
        return (await handler(...args)) as R;
      },
    },
  };

  const origLoad = (Module as unknown as { _load: (...args: unknown[]) => unknown })._load;
  (Module as unknown as { _load: (...args: unknown[]) => unknown })._load = function (
    ...args: unknown[]
  ) {
    if (args[0] === "vscode") {
      return mockVscode;
    }
    return origLoad.apply(this, args);
  };

  const extJsPath = require.resolve("../extension");
  delete require.cache[extJsPath];

  return (async () => {
    try {
      const extMod = require("../extension") as typeof import("../extension");
      const subscriptions: Array<{ dispose: () => void }> = [];
      const controller = extMod.activate({
        extensionPath: REPO_ROOT,
        subscriptions,
      } as unknown as import("vscode").ExtensionContext);

      return await fn(
        {
          executeCommand: <R = unknown>(cmd: string, ...args: unknown[]) =>
            (mockVscode.commands as { executeCommand: <X>(c: string, ...a: unknown[]) => Promise<X> }).executeCommand<R>(
              cmd,
              ...args
            ),
          getTreeItemForNode: (node: CheckwashTreeNode) => {
            if (!capturedTreeProvider) {
              throw new Error("TreeDataProvider was not captured");
            }
            return capturedTreeProvider.getTreeItem(node);
          },
          deactivate: () => extMod.deactivate(),
        },
        initialState,
        controller
      );
    } finally {
      (Module as unknown as { _load: (...args: unknown[]) => unknown })._load = origLoad;
      delete require.cache[extJsPath];
    }
  })();
}

// ============================================================================
// Issue #1 [P1]: Context Diet hunk masking through clipboard payload
// ============================================================================
async function testIssue1ContextDietHunkMasking(tempRoot: string): Promise<{
  assertions: number;
  details: Record<string, unknown>;
}> {
  let assertions = 0;
  const sqlSecret = "SECRET123456_SQL_PROD_KEY";
  const addedPat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

  // 1. Direct unit check: deleted `-- api_key = "..."`, added `++ token = "..."`, and normal file headers
  const syntheticUnifiedDiff = [
    "diff --git a/db/migrations/001_init.sql b/db/migrations/001_init.sql",
    "index 1111111..2222222 100644",
    "--- a/db/migrations/001_init.sql",
    "+++ b/db/migrations/001_init.sql",
    "@@ -1,4 +1,4 @@",
    " CREATE TABLE accounts (id INT PRIMARY KEY);",
    `--- api_key = "${sqlSecret}"`,
    `+++ token = "${addedPat}"`,
    " SELECT 1;",
    "",
  ].join("\n");

  const directDiet = buildContextDietDiff({
    repositoryRoot: REPO_ROOT,
    effectiveBaseOid: "1".repeat(40),
    effectiveHeadOid: "2".repeat(40),
    changedFiles: [{ status: "M", oldPath: null, newPath: "db/migrations/001_init.sql" }],
    rawUnifiedDiff: syntheticUnifiedDiff,
  });
  assert.strictEqual(
    directDiet.redactedFormattedPayload.includes(sqlSecret),
    false,
    "Redacted diff must NOT contain deleted SQL `--` comment credential"
  );
  assert.strictEqual(
    directDiet.redactedFormattedPayload.includes(addedPat),
    false,
    "Redacted diff must NOT contain added `++` source line PAT"
  );
  assert.strictEqual(
    directDiet.redactedFormattedPayload.includes("--- a/db/migrations/001_init.sql") &&
      directDiet.redactedFormattedPayload.includes("+++ b/db/migrations/001_init.sql"),
    true,
    "Normal file headers `--- a/...` and `+++ b/...` must remain intact"
  );
  assert.strictEqual(
    directDiet.redactedFormattedPayload.includes("--- api_key =") &&
      directDiet.redactedFormattedPayload.includes("[REDACTED:credential_assignment]"),
    true,
    "Diff deletion marker `-` + `-- ` SQL prefix must be preserved while credential value is masked"
  );
  assert.strictEqual(
    directDiet.redactedFormattedPayload.includes("+++ token =") &&
      directDiet.redactedFormattedPayload.includes("[REDACTED:github_token]"),
    true,
    "Diff addition marker `+` + `++ ` prefix must be preserved while GitHub PAT is masked"
  );
  assert.strictEqual(
    directDiet.sensitiveFindings.length >= 2,
    true,
    "Sensitive findings must be generated for both deleted `-- ` line and added `++ ` line"
  );
  const defaultRedactedAuth = authorizeClipboardCopy({
    dietResult: directDiet,
    mode: "redacted",
  });
  if (!defaultRedactedAuth.ok) assert.fail(defaultRedactedAuth.error);
  assert.strictEqual(defaultRedactedAuth.value.payloadToCopy.includes(sqlSecret), false);
  assert.strictEqual(defaultRedactedAuth.value.payloadToCopy.includes(addedPat), false);
  assertions += 8;

  // 2. End-to-end Git repo -> scanCommittedRange -> copyContextDietDiff -> clipboard verification
  const repoDir = createTempGitRepo(tempRoot, "issue1-sql-diet-repo");
  fs.mkdirSync(path.join(repoDir, "db"), { recursive: true });
  fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });

  fs.writeFileSync(
    path.join(repoDir, "db", "config.sql"),
    [
      "-- Database bootstrap",
      `-- api_key = "${sqlSecret}"`,
      "SELECT 1;",
      "",
    ].join("\n"),
    "utf8"
  );
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_db.py"),
    "def test_ok():\n    assert 1 + 1 == 2\n",
    "utf8"
  );
  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "base with sql comment secret"]);
  const baseOid = runGitSync(repoDir, ["rev-parse", "HEAD"]);

  fs.writeFileSync(
    path.join(repoDir, "db", "config.sql"),
    [
      "-- Database bootstrap",
      `++ token = "${addedPat}"`,
      "SELECT 1;",
      "",
    ].join("\n"),
    "utf8"
  );
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_db.py"),
    "def test_ok():\n    assert 1 + 1 == 2\n    assert 2 + 2 == 4\n",
    "utf8"
  );
  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "delete sql comment secret and add ++ token"]);
  const headOid = runGitSync(repoDir, ["rev-parse", "HEAD"]);

  // Verify ALSO when there are no sensitive findings on a separate commit? No: here sensitive findings DO trigger warning modal,
  // AND let's test BOTH:
  //   (a) After warning modal -> user chooses `"Copy Redacted Payload (Recommended)"` -> clipboard redacted, zero raw secret.
  //   (b) Direct default redacted payload (`controller.getViewSnapshot().contextDietResult!.redactedClipboardText` AND
  //       `copyContextDietDiff` default redacted path when modal returns `"Copy Redacted Payload (Recommended)"` PLUS
  //       testing when `sensitiveFindings` is empty on a clean diff vs default redacted payload property).
  // Wait: let's check `extension.ts` for `copyContextDietDiff`! When `hasHighRiskContent` is true, `copyContextDietDiff`
  // opens the modal with `"Copy Redacted Payload (Recommended)"` and `"Copy Unredacted Raw Diff"`; when `hasHighRiskContent`
  // is false, `copyContextDietDiff` copies `diet.redactedClipboardText` directly by default!
  // Because our fix makes `hasHighRiskContent === true` for `-- api_key = "SECRET..."` (previously `sensitiveFindings` was EMPTY
  // so `hasHighRiskContent` was FALSE and the default path copied the raw secret without even warning!!), BOTH the default
  // `diet.redactedClipboardText` AND the post-warning `"Copy Redacted Payload (Recommended)"` clipboard payload now mask the secret!

  const harnessState: MiniVscodeHarnessState = {
    isTrusted: true,
    workspaceFolderPath: repoDir,
    clipboardText: "",
    machineSettings: {
      "checkwashLens.pythonPath": PYTHON_EXE,
      "checkwashLens.gitPath": GIT_EXE,
    },
    shownErrors: [],
    shownWarnings: [],
    shownInfos: [],
    modalHandler: async (_msg, _opts, buttons) =>
      buttons.find((b) => b.includes("Redacted")),
  };

  await withMockedVscodeExtension(harnessState, async (api, state, controller) => {
    const snap = await api.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanCommittedRange",
      `${baseOid}..${headOid}`
    );
    assert.strictEqual(snap.evaluatedState.state, "Pass");
    const diet = controller.getViewSnapshot().contextDietResult;
    assert.ok(diet !== null, "contextDietResult must be populated after scan");
    assert.strictEqual(diet!.hasSensitiveData, true, "Sensitive content flag must be true");
    assert.strictEqual(diet!.sensitiveFindings.length >= 2, true);

    // Verify default redacted payload property & controller prepareContextDietCopy({ mode: "redacted" }) directly
    assert.strictEqual(diet!.redactedFormattedPayload.includes(sqlSecret), false);
    assert.strictEqual(diet!.redactedFormattedPayload.includes(addedPat), false);
    const defaultPrep = controller.prepareContextDietCopy({ mode: "redacted" });
    if (!defaultPrep.ok) assert.fail(defaultPrep.error);
    assert.strictEqual(defaultPrep.value.payloadToCopy.includes(sqlSecret), false);
    assert.strictEqual(defaultPrep.value.payloadToCopy.includes(addedPat), false);
    assertions += 8;

    // Verify warning modal -> select Redacted -> clipboard text
    state.clipboardText = "";
    const copyRes = await api.executeCommand<{ payloadToCopy: string; modeUsed: string }>(
      "checkwashLens.copyContextDietDiff"
    );
    assert.ok(copyRes !== null);
    assert.strictEqual(copyRes.modeUsed, "redacted");
    assert.strictEqual(state.shownWarnings.length >= 1, true, "Sensitive content warning modal must fire");
    assert.strictEqual(state.clipboardText.length > 0, true);
    assert.strictEqual(
      state.clipboardText.includes(sqlSecret),
      false,
      "Clipboard after selecting Redacted must NOT contain SQL secret"
    );
    assert.strictEqual(
      state.clipboardText.includes(addedPat),
      false,
      "Clipboard after selecting Redacted must NOT contain PAT"
    );
    assert.strictEqual(
      state.clipboardText.includes("--- a/db/config.sql") &&
        state.clipboardText.includes("+++ b/db/config.sql"),
      true,
      "Clipboard must preserve file headers"
    );
    assertions += 7;

    await api.deactivate();
  });

  return {
    assertions,
    details: {
      sensitiveFindingsDetected: directDiet.sensitiveFindings.map((f) => f.kind),
      clipboardContainedRawSqlSecret: false,
      clipboardContainedRawPat: false,
      fileHeadersPreserved: true,
    },
  };
}

// ============================================================================
// Issue #2 [P1]: Unconfirmed cleanup prioritized across all cancel/timeout stages
// ============================================================================
async function testIssue2UnconfirmedCleanupAcrossStages(tempRoot: string): Promise<{
  assertions: number;
  details: Record<string, unknown>;
}> {
  let assertions = 0;
  const repoDir = createTempGitRepo(tempRoot, "issue2-cleanup-stages-repo");
  fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
  fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });
  fs.writeFileSync(path.join(repoDir, "src", "x.py"), "def f(a):\n    return a + 1\n", "utf8");
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_x.py"),
    "from src.x import f\ndef test_f():\n    assert f(1) == 2\n",
    "utf8"
  );
  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "base"]);
  const baseOid = runGitSync(repoDir, ["rev-parse", "HEAD"]);

  fs.writeFileSync(
    path.join(repoDir, "tests", "test_x.py"),
    "from src.x import f\ndef test_f():\n    assert f(1) == 2\n    assert f(2) == 3\n",
    "utf8"
  );
  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "head"]);
  const headOid = runGitSync(repoDir, ["rev-parse", "HEAD"]);

  type CancelStage = "runtime_probe" | "git_range_resolution" | "analysis" | "post_processing";
  const stages: CancelStage[] = [
    "runtime_probe",
    "git_range_resolution",
    "analysis",
    "post_processing",
  ];

  const isMatchingStageCall = (stage: CancelStage, exe: string, args: string[]): boolean => {
    if (stage === "runtime_probe") {
      return (
        isPythonExecutableName(exe) &&
        args.some((a) => a.includes("platform.python_version()"))
      );
    }
    if (stage === "git_range_resolution") {
      return isGitExecutableName(exe) && args.includes("rev-parse");
    }
    if (stage === "analysis") {
      return isPythonExecutableName(exe) && args.some((a) => a.endsWith("checkwash.pyz"));
    }
    // post_processing: git diff --unified=3 or git cat-file blob in CheckwashEngineRunner
    return isGitExecutableName(exe) && (args.includes("diff") || args.includes("cat-file"));
  };

  const matrixSummary: Array<Record<string, unknown>> = [];

  for (const stage of stages) {
    for (const cleanupConfirmed of [true, false]) {
      const harnessState: MiniVscodeHarnessState = {
        isTrusted: true,
        workspaceFolderPath: repoDir,
        clipboardText: "",
        machineSettings: {
          "checkwashLens.pythonPath": PYTHON_EXE,
          "checkwashLens.gitPath": GIT_EXE,
        },
        shownErrors: [],
        shownWarnings: [],
        shownInfos: [],
        modalHandler: async (_m, _o, btns) => btns[0],
      };

      await withMockedVscodeExtension(harnessState, async (api, state, controller) => {
        const procRunner = controller.getProcessRunner();
        let intercepted = false;
        let stageEnteredResolve!: () => void;
        const stageEntered = new Promise<void>((r) => {
          stageEnteredResolve = r;
        });

        procRunner.setCustomBrokerExecutorForTests(async (req, abortSignal) => {
          if (!intercepted && isMatchingStageCall(stage, req.executable, req.args)) {
            intercepted = true;
            stageEnteredResolve();
            if (abortSignal && !abortSignal.aborted) {
              await new Promise<void>((r) =>
                abortSignal.addEventListener("abort", () => r(), { once: true })
              );
            }
            return {
              status: "cancelled",
              exitCode: null,
              childPid: 42420,
              stdoutRaw: Buffer.alloc(0),
              stderrRaw: Buffer.alloc(0),
              stdoutUtf8Valid: true,
              stderrUtf8Valid: true,
              stdoutText: "",
              stderrText: "",
              cleanupConfirmed,
              activeProcessesRemaining: cleanupConfirmed ? 0 : 1,
              brokerErrorDetail: cleanupConfirmed
                ? undefined
                : `Unconfirmed cleanup during ${stage}`,
            };
          }
          return executeViaWindowsBroker(req, abortSignal);
        });

        const scanPromise = api.executeCommand<ControllerViewSnapshot>(
          "checkwashLens.scanCommittedRange",
          `${baseOid}..${headOid}`
        );
        await stageEntered;
        await api.executeCommand("checkwashLens.cancelActiveScan");
        const finalSnap = await scanPromise;
        procRunner.setCustomBrokerExecutorForTests(null);

        if (!cleanupConfirmed) {
          assert.strictEqual(
            finalSnap.evaluatedState.state,
            "Error",
            `Stage '${stage}' with cleanupConfirmed=false must end in Error`
          );
          assert.strictEqual(
            (finalSnap.evaluatedState.errorReason ?? "").includes("confirmed stopped"),
            false,
            `Stage '${stage}' with cleanupConfirmed=false must NEVER claim confirmed stopped`
          );
          assert.strictEqual(
            state.shownInfos.some((m) => m.includes("confirmed stopped")),
            false,
            `Extension UI must NOT show 'confirmed stopped' info toast on cleanup failure (${stage})`
          );
          assert.strictEqual(
            state.shownErrors.length >= 1,
            true,
            `Extension UI must surface error toast on cleanup failure (${stage})`
          );

          // Verify next scan and Prove preflight are BOTH blocked!
          const followupScan = await controller.scanCommittedRange(
            makeHostDesc(repoDir),
            `${baseOid}..${headOid}`
          );
          assert.strictEqual(
            followupScan.evaluatedState.state,
            "Error",
            `Follow-up scan after unconfirmed cleanup in '${stage}' must be blocked`
          );
          const followupProve = await controller.prepareProveManualCommandPlan({
            hostDesc: makeHostDesc(repoDir),
            configuredProvePath: PROVE_EXE,
            rawRangeSpec: `${baseOid}..${headOid}`,
            entryKind: "list",
          });
          assert.strictEqual(followupProve.ok, false, "Prove preflight must also be blocked");
          assertions += 6;
        } else {
          assert.strictEqual(
            finalSnap.evaluatedState.state,
            "Not Run",
            `Stage '${stage}' with cleanupConfirmed=true must end in Not Run`
          );
          assert.strictEqual(
            (finalSnap.evaluatedState.notRunReason ?? "").includes("confirmed stopped"),
            true,
            `Stage '${stage}' with cleanupConfirmed=true must confirm normal stop`
          );

          // Verify next scan succeeds cleanly!
          const followupScan = await controller.scanCommittedRange(
            makeHostDesc(repoDir),
            `${baseOid}..${headOid}`
          );
          assert.strictEqual(
            followupScan.evaluatedState.state,
            "Pass",
            `Follow-up scan after confirmed stop in '${stage}' must run normally`
          );
          assertions += 3;
        }

        matrixSummary.push({
          stage,
          cleanupConfirmed,
          finalState: finalSnap.evaluatedState.state,
        });

        await api.deactivate();
      });
    }
  }

  // Additional required case: Timeout + cleanup failure occurring simultaneously
  const timeoutCleanupRunner = new UnifiedProcessRunner();
  timeoutCleanupRunner.setCustomBrokerExecutorForTests(async (req, abortSignal) => {
    if (isPythonExecutableName(req.executable) && req.args.some((a) => a.endsWith("checkwash.pyz"))) {
      return {
        status: "timed_out",
        exitCode: null,
        childPid: 51515,
        stdoutRaw: Buffer.alloc(0),
        stderrRaw: Buffer.alloc(0),
        stdoutUtf8Valid: true,
        stderrUtf8Valid: true,
        stdoutText: "",
        stderrText: "",
        cleanupConfirmed: false,
        activeProcessesRemaining: 2,
        brokerErrorDetail: "Job Object still has 2 active processes after timeout",
      };
    }
    return executeViaWindowsBroker(req, abortSignal);
  });

  const timeoutAndUnconfirmedEval = await timeoutCleanupRunner.runCommittedCheckwashScan(
    makeHostDesc(repoDir),
    `${baseOid}..${headOid}`
  );
  assert.strictEqual(timeoutAndUnconfirmedEval.state, "Error");
  assert.strictEqual(
    (timeoutAndUnconfirmedEval.errorReason ?? "").includes("not confirmed") &&
      (timeoutAndUnconfirmedEval.errorReason ?? "").includes("timeout"),
    true,
    `Expected both unconfirmed cleanup and timeout in errorReason, got: ${timeoutAndUnconfirmedEval.errorReason}`
  );
  assert.strictEqual(
    (timeoutAndUnconfirmedEval.errorReason ?? "").includes("confirmed stopped"),
    false
  );
  const blockedAfterTimeoutCleanup = await timeoutCleanupRunner.runCommittedCheckwashScan(
    makeHostDesc(repoDir),
    `${baseOid}..${headOid}`
  );
  assert.strictEqual(blockedAfterTimeoutCleanup.state, "Error");
  assertions += 4;

  // Additional Re-Review Case: Prove preflight (`prepareProveManualCommandPlan`) cancelled via
  // `cancelActiveRunAndConfirmStop` across `cleanupConfirmed=true` vs `cleanupConfirmed=false`!
  for (const cleanupConfirmed of [true, false] as const) {
    const pfRunner = new UnifiedProcessRunner();
    const pfCtrl = new CheckwashLensController(pfRunner);
    let enteredPreflightResolve!: () => void;
    const enteredPreflight = new Promise<void>((r) => {
      enteredPreflightResolve = r;
    });

    pfRunner.setCustomBrokerExecutorForTests(async (req, abortSignal) => {
      if (isProveExecutableName(req.executable) && req.args.includes("--version")) {
        enteredPreflightResolve();
        await new Promise<void>((resolve) => {
          if (abortSignal?.aborted) {
            resolve();
            return;
          }
          abortSignal?.addEventListener("abort", () => resolve(), { once: true });
        });
        return {
          status: "cancelled",
          exitCode: null,
          childPid: 23456,
          stdoutRaw: Buffer.alloc(0),
          stderrRaw: Buffer.from("cancelled prove preflight", "utf8"),
          stdoutUtf8Valid: true,
          stderrUtf8Valid: true,
          stdoutText: "",
          stderrText: "cancelled prove preflight",
          cleanupConfirmed,
          activeProcessesRemaining: cleanupConfirmed ? 0 : 1,
          brokerErrorDetail: cleanupConfirmed ? undefined : "Simulated surviving preflight child",
        };
      }
      return executeViaWindowsBroker(req, abortSignal);
    });

    const pfPromise = pfCtrl.prepareProveManualCommandPlan({
      hostDesc: makeHostDesc(repoDir),
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: `${baseOid}..${headOid}`,
      entryKind: "list",
    });
    await enteredPreflight;
    assert.strictEqual(pfRunner.isOperationActive(), true, "Prove preflight must occupy active exclusive slot");

    const stopRes = await pfRunner.cancelActiveRunAndConfirmStop();
    const pfRes = await pfPromise;
    const pfSnap = pfCtrl.getViewSnapshot();

    assert.strictEqual(pfRes.ok, false);
    if (cleanupConfirmed) {
      assert.strictEqual(stopRes.stopped, true);
      assert.strictEqual(stopRes.cleanupConfirmed, true);
      assert.strictEqual(!pfRes.ok && pfRes.cancelled, true);
      assert.strictEqual(pfSnap.proveOutcome.status, "Not Run / Cancelled");
    } else {
      assert.strictEqual(stopRes.stopped, false);
      assert.strictEqual(stopRes.cleanupConfirmed, false);
      assert.strictEqual(!pfRes.ok && Boolean(pfRes.cancelled), false);
      assert.strictEqual(pfSnap.proveOutcome.status, "Execution error");
      assert.strictEqual(
        (pfSnap.proveOutcome.errorReason ?? "").includes("confirmed stopped"),
        false
      );
      const blockedFollowupPf = await pfCtrl.prepareProveManualCommandPlan({
        hostDesc: makeHostDesc(repoDir),
        configuredProvePath: PROVE_EXE,
        rawRangeSpec: `${baseOid}..${headOid}`,
        entryKind: "list",
      });
      assert.strictEqual(blockedFollowupPf.ok, false);
    }
    assertions += 7;
  }

  return {
    assertions,
    details: {
      matrixCasesVerified: matrixSummary.length,
      matrixSummary,
      provePreflightCancelMatrixVerified: true,
      timeoutPlusCleanupFailureError: timeoutAndUnconfirmedEval.errorReason,
    },
  };
}

// ============================================================================
// Issue #3 [P1]: Prove authorization bound to immutable execution plan
// ============================================================================
async function testIssue3ProvePlanBoundAuthorization(tempRoot: string): Promise<{
  assertions: number;
  details: Record<string, unknown>;
}> {
  let assertions = 0;

  // Create two repos (repoA and repoB). In repoA, place a sentinel in test_ sentinel check so we ALSO prove
  // preflight (`prepareProveManualCommandPlan`) NEVER executes any project tests!
  const testExecSentinel = path.join(tempRoot, "issue3-pytest-executed-sentinel.txt");
  const repoA = createTempGitRepo(tempRoot, "issue3-repo-a");
  fs.mkdirSync(path.join(repoA, "src"), { recursive: true });
  fs.mkdirSync(path.join(repoA, "tests"), { recursive: true });
  fs.writeFileSync(
    path.join(repoA, "src", "calc.py"),
    "def inc(x: int) -> int:\n    if x < 0:\n        raise ValueError('neg')\n    return x + 1\n",
    "utf8"
  );
  fs.writeFileSync(
    path.join(repoA, "tests", "test_calc.py"),
    [
      "import pathlib, pytest",
      "from src.calc import inc",
      `pathlib.Path(${JSON.stringify(testExecSentinel)}).write_text("RAN_TESTS", encoding="utf-8")`,
      "def test_inc():",
      "    assert inc(1) == 2",
      "    with pytest.raises(ValueError):",
      "        inc(-1)",
      "",
    ].join("\n"),
    "utf8"
  );
  runGitSync(repoA, ["add", "."]);
  runGitSync(repoA, ["commit", "-m", "c1 base"]);
  const c1Oid = runGitSync(repoA, ["rev-parse", "HEAD"]);

  fs.writeFileSync(
    path.join(repoA, "tests", "test_calc.py"),
    [
      "import pathlib",
      "from src.calc import inc",
      `pathlib.Path(${JSON.stringify(testExecSentinel)}).write_text("RAN_TESTS", encoding="utf-8")`,
      "def test_inc():",
      "    assert inc(1) == 2",
      "",
    ].join("\n"),
    "utf8"
  );
  runGitSync(repoA, ["add", "."]);
  runGitSync(repoA, ["commit", "-m", "c2 weakened"]);
  const c2Oid = runGitSync(repoA, ["rev-parse", "HEAD"]);

  const repoB = createTempGitRepo(tempRoot, "issue3-repo-b");
  fs.writeFileSync(path.join(repoB, "README.md"), "# Repo B\n", "utf8");
  runGitSync(repoB, ["add", "."]);
  runGitSync(repoB, ["commit", "-m", "repoB init"]);

  const validListFixtureRaw = fs.readFileSync(
    path.join(FIXTURES_DIR, "a12-prove-list.json"),
    "utf8"
  );

  // 1. Extension-level modal test:
  //    (a) Preflight prepares plan with `HEAD~1..HEAD` -> resolves `c1Oid..c2Oid`, spawns ZERO project tests!
  //    (b) While modal is open, branch `HEAD` advances to `c3Oid`! User confirms -> executes pinned `c1Oid..c2Oid`, NOT `c3Oid`!
  //    (c) Replay modal: while Replay modal is open, branch moves again -> Replay still executes pinned `c1Oid..c2Oid` + pinned mutant ID!
  //    (d) While modal is open, `provePath` / `pythonPath` runtime setting changes -> execution rejected, 0 Prove runs!
  //    (e) Cancelling modal -> plan invalidated, 0 Prove runs!
  //    (f) Untrusted workspace -> rejected before preflight/modal, 0 spawns!
  let c3Oid = "";
  const capturedProveArgvs: string[][] = [];

  const harnessState: MiniVscodeHarnessState = {
    isTrusted: true,
    workspaceFolderPath: repoA,
    clipboardText: "",
    machineSettings: {
      "checkwashLens.pythonPath": PYTHON_EXE,
      "checkwashLens.gitPath": GIT_EXE,
      "checkwashLens.provePath": PROVE_EXE,
    },
    shownErrors: [],
    shownWarnings: [],
    shownInfos: [],
    modalHandler: async () => undefined,
  };

  await withMockedVscodeExtension(harnessState, async (api, state, controller) => {
    const procRunner = controller.getProcessRunner();
    procRunner.setCustomBrokerExecutorForTests(async (req, sig) => {
      if (isProveExecutableName(req.executable) && !req.args.includes("--version")) {
        capturedProveArgvs.push([...req.args]);
        return {
          status: "completed",
          exitCode: 0,
          childPid: 30001,
          stdoutRaw: Buffer.from(validListFixtureRaw, "utf8"),
          stderrRaw: Buffer.alloc(0),
          stdoutUtf8Valid: true,
          stderrUtf8Valid: true,
          stdoutText: validListFixtureRaw,
          stderrText: "",
          cleanupConfirmed: true,
          activeProcessesRemaining: 0,
        };
      }
      return executeViaWindowsBroker(req, sig);
    });

    // (a) Cancel modal -> verify preflight did NOT execute project tests, modal showed pinned OIDs & limits, and 0 Prove runs launched
    let modalMessageSeen = "";
    state.modalHandler = async (msg) => {
      modalMessageSeen = msg;
      assert.strictEqual(
        fs.existsSync(testExecSentinel),
        false,
        "Preflight must NOT execute project tests before confirmation"
      );
      return undefined; // Cancel
    };
    const cancelledRes = await api.executeCommand("checkwashLens.runProveList", "HEAD~1..HEAD");
    assert.strictEqual(cancelledRes, null);
    assert.strictEqual(capturedProveArgvs.length, 0);
    assert.strictEqual(modalMessageSeen.includes(`${c1Oid}..${c2Oid}`), true, "Modal must show pinned OIDs");
    assert.strictEqual(modalMessageSeen.includes(PROVE_EXECUTION_RISK_WARNING), true);
    assertions += 5;

    // (b) Move branch HEAD during open confirmation modal -> must execute confirmed pinned `c1Oid..c2Oid`!
    state.modalHandler = async (_msg, _opts, buttons) => {
      fs.writeFileSync(path.join(repoA, "README.md"), "moved head while modal open\n", "utf8");
      runGitSync(repoA, ["add", "README.md"]);
      runGitSync(repoA, ["commit", "-m", "c3 moved head"]);
      c3Oid = runGitSync(repoA, ["rev-parse", "HEAD"]);
      return buttons[0];
    };
    const listSnap = await api.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.runProveList",
      "HEAD~1..HEAD"
    );
    assert.strictEqual(listSnap.proveOutcome.status, "Listed");
    assert.strictEqual(capturedProveArgvs.length, 1);
    assert.strictEqual(
      capturedProveArgvs[0].includes(`${c1Oid}..${c2Oid}`),
      true,
      `Expected Prove argv to use pinned ${c1Oid}..${c2Oid} despite branch move to ${c3Oid}, got ${JSON.stringify(capturedProveArgvs[0])}`
    );
    assert.strictEqual(capturedProveArgvs[0].includes(`${c2Oid}..${c3Oid}`), false);
    assertions += 4;

    // (c) Replay modal: verify Replay confirmation modal binds mutant ID & pinned OIDs, and rejects runtime change mid-modal
    const listRunId = listSnap.proveOutcome.record!.runId;
    const candidateId = listSnap.proveOutcome.record!.parsedReport.candidates[0].id;

    // Create a copy of checkwash-prove (or python setting change) to simulate runtime change while modal is open
    const altProveCopy = path.join(
      tempRoot,
      IS_WIN32 ? "checkwash-prove-copy.exe" : "checkwash-prove-copy"
    );
    copyExecutablePreservingMode(PROVE_EXE, altProveCopy);

    state.modalHandler = async (msg, _opts, buttons) => {
      assert.strictEqual(msg.includes(candidateId), true, "Replay modal must show mutant ID");
      // Change configured provePath while modal is open!
      state.machineSettings["checkwashLens.provePath"] = altProveCopy;
      return buttons[0];
    };
    const runsBeforeRuntimeSwap = capturedProveArgvs.length;
    const runtimeChangedSnap = await api.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.replayMutant",
      listRunId,
      candidateId
    );
    assert.strictEqual(
      runtimeChangedSnap.proveOutcome.status,
      "Execution error",
      "Changing runtime path while modal is open must invalidate the plan"
    );
    assert.strictEqual(
      capturedProveArgvs.length,
      runsBeforeRuntimeSwap,
      "Invalidated plan after runtime change must spawn 0 Prove runs"
    );
    assertions += 3;

    // Restore provePath and verify valid Replay executes pinned OIDs + mutant ID
    state.machineSettings["checkwashLens.provePath"] = PROVE_EXE;
    state.modalHandler = async (_msg, _opts, buttons) => buttons[0];
    const validReplaySnap = await api.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.replayMutant",
      listRunId,
      candidateId
    );
    assert.strictEqual(validReplaySnap.proveOutcome.record?.entryKind, "replay");
    assert.strictEqual(capturedProveArgvs.length, runsBeforeRuntimeSwap + 1);
    const replayArgv = capturedProveArgvs[capturedProveArgvs.length - 1];
    assert.strictEqual(replayArgv.includes(`${c1Oid}..${c2Oid}`), true);
    assert.strictEqual(replayArgv.includes(candidateId), true);
    assertions += 4;

    // (d) Flip Workspace Trust to false while modal is open -> rejected with 0 Prove runs!
    state.modalHandler = async (_msg, _opts, buttons) => {
      state.isTrusted = false;
      return buttons[0];
    };
    const runsBeforeTrustDrop = capturedProveArgvs.length;
    const trustDroppedSnap = await api.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.runProveFull",
      `${c1Oid}..${c2Oid}`
    );
    assert.strictEqual(trustDroppedSnap.proveOutcome.status, "Execution error");
    assert.strictEqual(capturedProveArgvs.length, runsBeforeTrustDrop);
    assertions += 2;

    // And when already untrusted before command: rejected immediately with 0 broker spawns!
    resetTotalBrokerSpawnCountForTests();
    const untrustedListRes = await api.executeCommand(
      "checkwashLens.runProveList",
      `${c1Oid}..${c2Oid}`
    );
    assert.strictEqual(untrustedListRes, null);
    assert.strictEqual(getTotalBrokerSpawnCount(), 0);
    assertions += 2;

    // 2. Direct ProveSatelliteRunner checks: token reuse, limit/option mismatch, cross-mode, cross-repository
    state.isTrusted = true;
    const proveRunner = controller.getProveRunner();
    const planRes = await proveRunner.prepareManualProvePlan({
      hostDesc: makeHostDesc(repoA),
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: `${c1Oid}..${c2Oid}`,
      entryKind: "full",
      options: { maxMutants: 10, workers: 1 },
      wallClockBudgetMs: 120_000,
    });
    if (!planRes.ok) assert.fail(planRes.error);
    const authToken = proveRunner.issueManualAuthorizationToken({
      plan: planRes.value,
      userConfirmedExecutionRisk: true,
    });

    // Cross-mode (`list` expected against `full` token) -> rejected AND consumes token/plan!
    const crossModeOut = await proveRunner.executeAuthorizedProvePlan({
      hostDesc: makeHostDesc(repoA),
      configuredProvePath: PROVE_EXE,
      authorization: authToken,
      expectedEntryKind: "list",
    });
    assert.strictEqual(crossModeOut.status, "Execution error");

    // Token reuse after consumption -> rejected!
    const reusedOut = await proveRunner.executeAuthorizedProvePlan({
      hostDesc: makeHostDesc(repoA),
      configuredProvePath: PROVE_EXE,
      authorization: authToken,
      expectedEntryKind: "full",
    });
    assert.strictEqual(reusedOut.status, "Execution error");
    assert.strictEqual((reusedOut.errorReason ?? "").includes("already consumed"), true);

    // Cross-repository (`repoB` passed at execution time for `repoA` plan) -> rejected!
    const planCrossRepo = await proveRunner.prepareManualProvePlan({
      hostDesc: makeHostDesc(repoA),
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: `${c1Oid}..${c2Oid}`,
      entryKind: "full",
    });
    if (!planCrossRepo.ok) throw new Error(planCrossRepo.error);
    const tokenCrossRepo = proveRunner.issueManualAuthorizationToken({
      plan: planCrossRepo.value,
      userConfirmedExecutionRisk: true,
    });
    const crossRepoOut = await proveRunner.executeAuthorizedProvePlan({
      hostDesc: makeHostDesc(repoB),
      configuredProvePath: PROVE_EXE,
      authorization: tokenCrossRepo,
    });
    assert.strictEqual(crossRepoOut.status, "Execution error");

    // Resource limit / option change (`maxMutants` changed from 10 to 25 or `wallClockBudgetMs` changed) -> rejected!
    const planLimits = await proveRunner.prepareManualProvePlan({
      hostDesc: makeHostDesc(repoA),
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: `${c1Oid}..${c2Oid}`,
      entryKind: "full",
      options: { maxMutants: 10 },
      wallClockBudgetMs: 120_000,
    });
    if (!planLimits.ok) throw new Error(planLimits.error);
    const tokenLimits = proveRunner.issueManualAuthorizationToken({
      plan: planLimits.value,
      userConfirmedExecutionRisk: true,
    });
    const limitChangedOut = await proveRunner.executeAuthorizedProvePlan({
      hostDesc: makeHostDesc(repoA),
      configuredProvePath: PROVE_EXE,
      authorization: tokenLimits,
      expectedOptions: { maxMutants: 25 },
      expectedWallClockBudgetMs: 60_000,
    });
    assert.strictEqual(limitChangedOut.status, "Execution error");
    assertions += 6;

    // Additional Re-Review Case A: Cancelling `checkwashLens.runProveList` DURING preflight via
    // `checkwashLens.cancelActiveScan` cancels cleanly (`Not Run / Cancelled`), opens 0 modals, and shows 0 error toasts!
    let preflightEnteredResolve!: () => void;
    const preflightEntered = new Promise<void>((r) => {
      preflightEnteredResolve = r;
    });
    let modalOpenedOnCancelledPreflight = false;
    harnessState.modalHandler = async () => {
      modalOpenedOnCancelledPreflight = true;
      return "Confirm & Run Prove --list";
    };
    harnessState.shownErrors.length = 0;

    procRunner.setCustomBrokerExecutorForTests(async (req, sig) => {
      if (isProveExecutableName(req.executable) && req.args.includes("--version")) {
        preflightEnteredResolve();
        await new Promise<void>((resolve) => {
          if (sig?.aborted) {
            resolve();
            return;
          }
          sig?.addEventListener("abort", () => resolve(), { once: true });
        });
        return {
          status: "cancelled",
          exitCode: null,
          childPid: 24567,
          stdoutRaw: Buffer.alloc(0),
          stderrRaw: Buffer.alloc(0),
          stdoutUtf8Valid: true,
          stderrUtf8Valid: true,
          stdoutText: "",
          stderrText: "",
          cleanupConfirmed: true,
          activeProcessesRemaining: 0,
        };
      }
      return executeViaWindowsBroker(req, sig);
    });

    const listDuringPreflightPromise = api.executeCommand(
      "checkwashLens.runProveList",
      `${c1Oid}..${c2Oid}`
    );
    await preflightEntered;
    await api.executeCommand("checkwashLens.cancelActiveScan");
    const listPreflightCancelledRes = await listDuringPreflightPromise;
    assert.strictEqual(listPreflightCancelledRes, null);
    assert.strictEqual(modalOpenedOnCancelledPreflight, false, "Cancelled preflight must NEVER open modal");
    assert.strictEqual(harnessState.shownErrors.length, 0, "Cleanly cancelled preflight must NOT show error toast");
    assert.strictEqual(controller.getViewSnapshot().proveOutcome.status, "Not Run / Cancelled");
    procRunner.setCustomBrokerExecutorForTests(null);
    assertions += 4;

    // Additional Re-Review Case B: Post-confirmation `git` dropped into `proveDir` (without altering
    // `checkwash-prove`'s own SHA-256!) MUST invalidate the plan at execution time!
    const customProveDir = path.join(tempRoot, "issue3-post-confirm-prove-dir");
    fs.mkdirSync(customProveDir, { recursive: true });
    const customProveExe = path.join(
      customProveDir,
      IS_WIN32 ? "checkwash-prove.exe" : "checkwash-prove"
    );
    copyExecutablePreservingMode(PROVE_EXE, customProveExe);

    const planBeforeGitDrop = await proveRunner.prepareManualProvePlan({
      hostDesc: makeHostDesc(repoA),
      configuredProvePath: customProveExe,
      rawRangeSpec: `${c1Oid}..${c2Oid}`,
      entryKind: "list",
    });
    assert.strictEqual(planBeforeGitDrop.ok, true, "Clean customProveDir should prepare plan when prove --version works");
    if (planBeforeGitDrop.ok) {
      const tokGitDrop = proveRunner.issueManualAuthorizationToken({
        plan: planBeforeGitDrop.value,
        userConfirmedExecutionRisk: true,
      });
      // Drop a rogue `git` into `customProveDir` AFTER confirmation!
      copyExecutablePreservingMode(
        GIT_EXE,
        path.join(customProveDir, IS_WIN32 ? "git.exe" : "git")
      );
      const droppedGitOut = await proveRunner.executeAuthorizedProvePlan({
        hostDesc: makeHostDesc(repoA),
        configuredProvePath: customProveExe,
        authorization: tokGitDrop,
        expectedEntryKind: "list",
      });
      assert.strictEqual(droppedGitOut.status, "Execution error");
      assert.strictEqual(
        (droppedGitOut.errorReason ?? "").includes("Trusted Git identity mismatch"),
        true,
        `Expected Trusted Git identity mismatch on post-confirm git drop, got: ${droppedGitOut.errorReason}`
      );
      assertions += 3;
    }

    procRunner.setCustomBrokerExecutorForTests(null);
    await api.deactivate();
  });

  return {
    assertions,
    details: {
      preflightRanZeroProjectTests: true,
      pinnedRangeExecutedDespiteBranchMove: `${c1Oid}..${c2Oid}`,
      runtimeChangeRejected: true,
      limitChangeRejected: true,
      tokenReuseRejected: true,
      crossRepoAndCrossModeRejected: true,
      untrustedBlockedWithZeroSpawns: true,
    },
  };
}

// ============================================================================
// Issue #4 [P2]: Prove non-zero exit preserved as Execution error
// ============================================================================
async function testIssue4ProveNonZeroExitHandling(tempRoot: string): Promise<{
  assertions: number;
  details: Record<string, unknown>;
}> {
  let assertions = 0;
  const repoDir = createTempGitRepo(tempRoot, "issue4-prove-exit-repo");
  fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
  fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });
  fs.writeFileSync(path.join(repoDir, "src", "m.py"), "def f(x):\n    return x + 1\n", "utf8");
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_m.py"),
    "from src.m import f\ndef test_f():\n    assert f(1) == 2\n",
    "utf8"
  );
  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "base"]);
  const baseOid = runGitSync(repoDir, ["rev-parse", "HEAD"]);
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_m.py"),
    "from src.m import f\ndef test_f():\n    assert f(1) == 2\n    assert f(2) == 3\n",
    "utf8"
  );
  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "head"]);
  const headOid = runGitSync(repoDir, ["rev-parse", "HEAD"]);

  const validLossReportRaw = fs.readFileSync(
    path.join(FIXTURES_DIR, "a11-prove-protection-loss.json"),
    "utf8"
  );
  const firstMutantId = JSON.parse(validLossReportRaw).protection_losses[0].id as string;

  const controller = new CheckwashLensController();
  const procRunner = controller.getProcessRunner();

  // First run a real static scan so `evaluatedState` is `Pass` — verify Prove errors NEVER pollute static verdict!
  const initialScanSnap = await controller.scanCommittedRange(
    makeHostDesc(repoDir),
    `${baseOid}..${headOid}`
  );
  assert.strictEqual(initialScanSnap.evaluatedState.state, "Pass");
  assertions++;

  const runSimulatedProve = async (mockOutcome: Partial<BrokerLaunchOutcome>): Promise<ControllerViewSnapshot> => {
    procRunner.setCustomBrokerExecutorForTests(async (req, sig) => {
      if (isProveExecutableName(req.executable) && !req.args.includes("--version")) {
        const outStr = mockOutcome.stdoutText ?? validLossReportRaw;
        const errStr = mockOutcome.stderrText ?? "";
        return {
          status: "completed",
          exitCode: 0,
          childPid: 31000,
          stdoutRaw: Buffer.from(outStr, "utf8"),
          stderrRaw: Buffer.from(errStr, "utf8"),
          stdoutUtf8Valid: true,
          stderrUtf8Valid: true,
          stdoutText: outStr,
          stderrText: errStr,
          cleanupConfirmed: true,
          activeProcessesRemaining: 0,
          ...mockOutcome,
        };
      }
      return executeViaWindowsBroker(req, sig);
    });
    try {
      const planRes = await controller.prepareProveManualCommandPlan({
        hostDesc: makeHostDesc(repoDir),
        configuredProvePath: PROVE_EXE,
        rawRangeSpec: `${baseOid}..${headOid}`,
        entryKind: "full",
      });
      if (!planRes.ok) throw new Error(planRes.error);
      const auth = controller.getProveRunner().issueManualAuthorizationToken({
        plan: planRes.value,
        userConfirmedExecutionRisk: true,
      });
      return await controller.executeAuthorizedProveCommand({
        hostDesc: makeHostDesc(repoDir),
        configuredProvePath: PROVE_EXE,
        authorization: auth,
      });
    } finally {
      procRunner.setCustomBrokerExecutorForTests(null);
    }
  };

  // 1. Valid JSON + exit 0 -> Compared, raw exitCode === 0, Replay allowed
  const exit0Snap = await runSimulatedProve({ exitCode: 0 });
  assert.strictEqual(exit0Snap.proveOutcome.status, "Compared");
  assert.strictEqual(exit0Snap.proveOutcome.record?.exitCode, 0);
  assert.ok(controller.getProveRunner().getTrustedRecord(exit0Snap.proveOutcome.record!.runId));
  const exit0PlGroup = findNodeById(exit0Snap.treeNodes, "prove_group_protection_losses");
  assert.strictEqual(exit0PlGroup?.children[0].command?.commandId, "checkwashLens.replayMutant");
  assertions += 4;

  // 2. Valid JSON + non-zero exits 1, 2, 120 -> raw exitCode preserved, status === "Execution error",
  //    diagnostic record kept read-only, Replay blocked in TreeView AND in prepareProveReplayCommandPlan,
  //    static `evaluatedState` still `Pass`!
  for (const nonZeroCode of [1, 2, 120]) {
    const snap = await runSimulatedProve({
      exitCode: nonZeroCode,
      stderrText: `simulated exit ${nonZeroCode}`,
    });
    assert.strictEqual(snap.proveOutcome.status, "Execution error");
    assert.strictEqual(
      snap.proveOutcome.record?.exitCode,
      nonZeroCode,
      `Raw exit code ${nonZeroCode} must NOT be rewritten to 0`
    );
    assert.strictEqual(
      (snap.proveOutcome.errorReason ?? "").includes(String(nonZeroCode)),
      true
    );
    assert.strictEqual(
      controller.getProveRunner().getTrustedRecord(snap.proveOutcome.record!.runId),
      undefined,
      `Non-zero exit ${nonZeroCode} record must NOT enter trustedRecordsById`
    );

    const errNode = findNodeById(snap.treeNodes, "prove_error_reason");
    assert.ok(errNode !== null, "TreeView must show prove_error_reason");
    const plGroup = findNodeById(snap.treeNodes, "prove_group_protection_losses");
    assert.ok(plGroup !== null, "Valid JSON remains visible for read-only diagnostics");
    assert.strictEqual(
      plGroup!.children.every((c) => c.command === undefined),
      true,
      `All Replay commands must be disabled for exit ${nonZeroCode}`
    );

    const replayPlanAttempt = await controller.prepareProveReplayCommandPlan({
      hostDesc: makeHostDesc(repoDir),
      configuredProvePath: PROVE_EXE,
      recordRunId: snap.proveOutcome.record!.runId,
      selectedMutantId: firstMutantId,
    });
    assert.strictEqual(replayPlanAttempt.ok, false, "Replay preflight must reject non-zero exit record");
    assert.strictEqual(
      controller.getViewSnapshot().evaluatedState.state,
      "Pass",
      "Static Checkwash verdict must remain unpolluted"
    );
    assertions += 9;
  }

  // 3. Empty stdout, invalid JSON, signal/null exit, and confirmed cancellation
  const emptyStdoutSnap = await runSimulatedProve({ exitCode: 0, stdoutText: "   " });
  assert.strictEqual(emptyStdoutSnap.proveOutcome.status, "Execution error");
  assert.strictEqual(emptyStdoutSnap.proveOutcome.record, null);

  const invalidJsonSnap = await runSimulatedProve({ exitCode: 0, stdoutText: "{broken-json" });
  assert.strictEqual(invalidJsonSnap.proveOutcome.status, "Execution error");
  assert.strictEqual(invalidJsonSnap.proveOutcome.record, null);

  const signalKilledSnap = await runSimulatedProve({
    status: "broker_error",
    exitCode: null,
    stderrText: "terminated by signal",
  });
  assert.strictEqual(signalKilledSnap.proveOutcome.status, "Execution error");
  assert.strictEqual(signalKilledSnap.proveOutcome.record, null);

  const cancelledSnap = await runSimulatedProve({
    status: "cancelled",
    exitCode: null,
    stdoutText: "",
  });
  assert.strictEqual(cancelledSnap.proveOutcome.status, "Not Run / Cancelled");
  assert.strictEqual(cancelledSnap.proveOutcome.record, null);
  assert.strictEqual(cancelledSnap.evaluatedState.state, "Pass");
  assertions += 9;

  return {
    assertions,
    details: {
      exitCodesTestedWithValidJson: [0, 1, 2, 120],
      emptyStdoutAndInvalidJsonTested: true,
      signalAndCancelledTested: true,
      staticVerdictUnpolluted: true,
    },
  };
}

// ============================================================================
// Issue #5 [P2]: JSON v2 valid empty-string `unit: ""` accepted cleanly
// ============================================================================
async function testIssue5EmptyUnitStringAccepted(tempRoot: string): Promise<{
  assertions: number;
  details: Record<string, unknown>;
}> {
  let assertions = 0;

  // 1. Real pinned Checkwash v0.13.1 empty-title JS fixture (`it("", ...)`)
  const jsFindingsRaw = fs.readFileSync(
    path.join(FIXTURES_DIR, "a02-empty-unit-js.findings.json"),
    "utf8"
  );
  const jsSarifRaw = fs.readFileSync(
    path.join(FIXTURES_DIR, "a02-empty-unit-js.sarif.json"),
    "utf8"
  );
  const jsReceipt = JSON.parse(
    fs.readFileSync(path.join(FIXTURES_DIR, "a02-empty-unit-js-receipt.json"), "utf8")
  );

  const valJson = validateFindingsJsonV2(jsFindingsRaw);
  const valSarif = validateCheckwashSarif(jsSarifRaw);
  assert.strictEqual(valJson.ok, true, "Real empty-unit JS findings JSON v2 must validate");
  assert.strictEqual(valSarif.ok, true, "Real empty-unit JS SARIF 2.1.0 must validate");
  if (!valJson.ok || !valSarif.ok) throw new Error("Unreachable");
  assert.strictEqual(valJson.value.verdict, "block");
  assert.strictEqual(valJson.value.findings.some((f) => f.unit === ""), true);
  assertions += 4;

  const scanIdentity: PinnedScanIdentity = {
    scanId: 501,
    repositoryRoot: jsReceipt.jsonInvocation.repositoryRoot,
    rawRangeSpec: jsReceipt.jsonInvocation.rawRangeSpec,
    rangeMode: "two-dot",
    leftRef: jsReceipt.jsBase,
    rightRef: jsReceipt.jsHead,
    resolvedLeftOid: jsReceipt.jsBase,
    resolvedRightOid: jsReceipt.jsHead,
    effectiveBaseOid: jsReceipt.jsBase,
    effectiveHeadOid: jsReceipt.jsHead,
    checkwashVersion: PINNED_CHECKWASH_VERSION,
    checkwashPyzSha256: PINNED_CHECKWASH_PYZ_SHA256,
    checkwashBuildCommit: PINNED_CHECKWASH_BUILD_COMMIT,
    pythonExecutable: PYTHON_EXE,
    pythonVersion: "Python 3.11.9",
    gitExecutable: GIT_EXE,
    gitVersion: "git version 2.55.0.windows.3",
    controlledCwd: jsReceipt.jsonInvocation.cwd,
  };

  const joined = joinCheckwashJsonAndSarif({
    jsonIdentity: scanIdentity,
    sarifIdentity: scanIdentity,
    jsonDoc: valJson.value,
    sarifDoc: valSarif.value,
  });
  if (!joined.ok) assert.fail(joined.error);
  const emptyUnitItems = joined.value.items.filter((i) => i.finding.unit === "");
  assert.strictEqual(emptyUnitItems.length >= 1, true);
  // Positioning comes strictly from SARIF region.startLine (line >= 4 in math.test.js, NOT line 1 / indexOf("") == 0!)
  for (const item of emptyUnitItems) {
    if (item.startLine1Based !== null) {
      assert.strictEqual(
        item.startLine1Based >= 4,
        true,
        `Empty unit must NOT match line 1 via empty-string search; got startLine1Based=${item.startLine1Based}`
      );
    }
  }
  assertions += 3;

  // Also check when SARIF has NO region on an empty-unit finding -> `startLine1Based === null` and 0 false live diagnostics!
  const sarifWithoutRegion = JSON.parse(jsSarifRaw);
  for (const r of sarifWithoutRegion.runs[0].results) {
    delete r.locations[0].physicalLocation.region;
  }
  const valNoReg = validateCheckwashSarif(JSON.stringify(sarifWithoutRegion));
  if (!valNoReg.ok) throw new Error(valNoReg.error);
  const joinedNoReg = joinCheckwashJsonAndSarif({
    jsonIdentity: scanIdentity,
    sarifIdentity: scanIdentity,
    jsonDoc: valJson.value,
    sarifDoc: valNoReg.value,
  });
  if (!joinedNoReg.ok) throw new Error(joinedNoReg.error);
  assert.strictEqual(joinedNoReg.value.items.every((i) => i.startLine1Based === null), true);
  const diagPlan = buildLiveDiagnosticsPlan(
    joinedNoReg.value.items.map((item) => ({
      item,
      headRevisionUri: null,
      baseRevisionUri: null,
      preferredRevisionUri: null,
      revealLine1Based: null,
      liveProjectionAllowed: false,
      liveVscodeLine0Based: null,
      liveProjectionReason: "File-level finding without SARIF region",
    })),
    []
  );
  assert.strictEqual(diagPlan.checkwashByFile.size, 0, "Missing region + empty unit must never invent line 1 diagnostic");
  assertions += 2;

  // 2. Test `unit: null`, normal string `"test_valid"`, and invalid types (`123`, `true`, `{}`, `[]`, missing `unit`)
  const cloneFindingDoc = (unitVal: unknown, omitKey: boolean = false): string => {
    const doc = JSON.parse(jsFindingsRaw);
    if (omitKey) {
      delete doc.findings[0].unit;
    } else {
      doc.findings[0].unit = unitVal;
    }
    return JSON.stringify(doc);
  };
  assert.strictEqual(validateFindingsJsonV2(cloneFindingDoc(null)).ok, true);
  assert.strictEqual(validateFindingsJsonV2(cloneFindingDoc("describe > non-empty title")).ok, true);
  for (const badUnit of [123, true, false, {}, ["a"]]) {
    assert.strictEqual(
      validateFindingsJsonV2(cloneFindingDoc(badUnit)).ok,
      false,
      `Invalid unit type ${JSON.stringify(badUnit)} must be rejected`
    );
    assertions++;
  }
  assert.strictEqual(validateFindingsJsonV2(cloneFindingDoc(undefined, true)).ok, false);
  assertions += 3;

  // 3. Live end-to-end `CheckwashLensController.runScanCommand` on a real Git repo with `it("", ...)` weakening
  const jsRepo = createTempGitRepo(tempRoot, "issue5-live-js-repo");
  fs.mkdirSync(path.join(jsRepo, "tests"), { recursive: true });
  fs.writeFileSync(
    path.join(jsRepo, "tests", "empty_title.test.js"),
    'describe("suite", () => {\n  it("", () => {\n    expect(2 + 2).toBe(4);\n  });\n});\n',
    "utf8"
  );
  runGitSync(jsRepo, ["add", "."]);
  runGitSync(jsRepo, ["commit", "-m", "base"]);
  const liveBase = runGitSync(jsRepo, ["rev-parse", "HEAD"]);
  fs.writeFileSync(
    path.join(jsRepo, "tests", "empty_title.test.js"),
    'describe("suite", () => {\n  it("", () => {\n    expect(true).toBe(true);\n  });\n});\n',
    "utf8"
  );
  runGitSync(jsRepo, ["add", "."]);
  runGitSync(jsRepo, ["commit", "-m", "head"]);
  const liveHead = runGitSync(jsRepo, ["rev-parse", "HEAD"]);

  const liveCtrl = new CheckwashLensController();
  const liveSnap = await liveCtrl.scanCommittedRange(
    makeHostDesc(jsRepo),
    `${liveBase}..${liveHead}`
  );
  assert.strictEqual(liveSnap.evaluatedState.state, "Block", "Live scan on empty-title JS test must preserve Block verdict");
  assert.strictEqual(
    liveSnap.evaluatedState.joinedReport?.items.some((i) => i.finding.unit === ""),
    true
  );
  assertions += 2;

  return {
    assertions,
    details: {
      emptyUnitFindingCount: emptyUnitItems.length,
      liveJsRepoVerdict: liveSnap.evaluatedState.state,
      invalidUnitTypesRejected: ["number", "boolean", "object", "array", "undefined"],
    },
  };
}

// ============================================================================
// Issue #6 [P2]: `list_only=true` early returns vs completed `Listed` & `full`
// ============================================================================
async function testIssue6ListOnlyClassificationParity(tempRoot: string): Promise<{
  assertions: number;
  details: Record<string, unknown>;
}> {
  let assertions = 0;

  const repoDir = createTempGitRepo(tempRoot, "issue6-list-parity-repo");
  fs.writeFileSync(path.join(repoDir, "README.md"), "init\n", "utf8");
  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "c1"]);
  const c1 = runGitSync(repoDir, ["rev-parse", "HEAD"]);
  fs.writeFileSync(path.join(repoDir, "README.md"), "init2\n", "utf8");
  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "c2"]);
  const c2 = runGitSync(repoDir, ["rev-parse", "HEAD"]);

  // Build synthetic trace-failure pair derived from real collection-failure report (where traced run fails)
  const listCollRaw = fs.readFileSync(path.join(FIXTURES_DIR, "prove-real-list-collection-fail.json"), "utf8");
  const fullCollRaw = fs.readFileSync(path.join(FIXTURES_DIR, "prove-real-full-collection-fail.json"), "utf8");
  const listTraceObj = JSON.parse(listCollRaw);
  listTraceObj.status =
    "the traced run of the old tests did not finish (pytest exit timeout), so no product line is known; raise --suite-timeout if it timed out";
  const fullTraceObj = JSON.parse(fullCollRaw);
  fullTraceObj.status = listTraceObj.status;

  const pairs: Array<{
    name: string;
    listRaw: string;
    fullRaw: string;
    expectedListStatus: string;
    expectedFullStatus: string;
    expectedReason: string | null;
    expectListCandidatesAndReplay: boolean;
  }> = [
    {
      name: "completed_enumeration_vs_compared",
      listRaw: fs.readFileSync(path.join(FIXTURES_DIR, "a12-prove-list.json"), "utf8"),
      fullRaw: fs.readFileSync(path.join(FIXTURES_DIR, "a11-prove-protection-loss.json"), "utf8"),
      expectedListStatus: "Listed",
      expectedFullStatus: "Compared",
      expectedReason: null,
      expectListCandidatesAndReplay: true,
    },
    {
      name: "no_changed_tests_nothing_to_compare",
      listRaw: fs.readFileSync(path.join(FIXTURES_DIR, "prove-real-list-nothing.json"), "utf8"),
      fullRaw: fs.readFileSync(path.join(FIXTURES_DIR, "a12-prove-nothing.json"), "utf8"),
      expectedListStatus: "Nothing to compare",
      expectedFullStatus: "Nothing to compare",
      expectedReason: null,
      expectListCandidatesAndReplay: false,
    },
    {
      name: "no_mutants",
      listRaw: fs.readFileSync(path.join(FIXTURES_DIR, "prove-real-list-no-mutants.json"), "utf8"),
      fullRaw: fs.readFileSync(path.join(FIXTURES_DIR, "prove-real-full-no-mutants.json"), "utf8"),
      expectedListStatus: "Not compared",
      expectedFullStatus: "Not compared",
      expectedReason: "no_mutants",
      expectListCandidatesAndReplay: false,
    },
    {
      name: "clean_run_failed",
      listRaw: fs.readFileSync(path.join(FIXTURES_DIR, "prove-real-list-clean-fail.json"), "utf8"),
      fullRaw: fs.readFileSync(path.join(FIXTURES_DIR, "prove-real-full-clean-fail.json"), "utf8"),
      expectedListStatus: "Not compared",
      expectedFullStatus: "Not compared",
      expectedReason: "collection_clean_or_trace",
      expectListCandidatesAndReplay: false,
    },
    {
      name: "collection_failed",
      listRaw: listCollRaw,
      fullRaw: fullCollRaw,
      expectedListStatus: "Not compared",
      expectedFullStatus: "Not compared",
      expectedReason: "collection_clean_or_trace",
      expectListCandidatesAndReplay: false,
    },
    {
      name: "trace_failed",
      listRaw: JSON.stringify(listTraceObj),
      fullRaw: JSON.stringify(fullTraceObj),
      expectedListStatus: "Not compared",
      expectedFullStatus: "Not compared",
      expectedReason: "collection_clean_or_trace",
      expectListCandidatesAndReplay: false,
    },
  ];

  const runControllerWithReport = async (
    entryKind: "list" | "full",
    reportJson: string
  ): Promise<{ snap: ControllerViewSnapshot; controller: CheckwashLensController }> => {
    const controller = new CheckwashLensController();
    controller.getProcessRunner().setCustomBrokerExecutorForTests(async (req, sig) => {
      if (isProveExecutableName(req.executable) && !req.args.includes("--version")) {
        return {
          status: "completed",
          exitCode: 0,
          childPid: 32000,
          stdoutRaw: Buffer.from(reportJson, "utf8"),
          stderrRaw: Buffer.alloc(0),
          stdoutUtf8Valid: true,
          stderrUtf8Valid: true,
          stdoutText: reportJson,
          stderrText: "",
          cleanupConfirmed: true,
          activeProcessesRemaining: 0,
        };
      }
      return executeViaWindowsBroker(req, sig);
    });
    const planRes = await controller.prepareProveManualCommandPlan({
      hostDesc: makeHostDesc(repoDir),
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: `${c1}..${c2}`,
      entryKind,
    });
    if (!planRes.ok) throw new Error(planRes.error);
    const auth = controller.getProveRunner().issueManualAuthorizationToken({
      plan: planRes.value,
      userConfirmedExecutionRisk: true,
    });
    const snap = await controller.executeAuthorizedProveCommand({
      hostDesc: makeHostDesc(repoDir),
      configuredProvePath: PROVE_EXE,
      authorization: auth,
    });
    controller.getProcessRunner().setCustomBrokerExecutorForTests(null);
    return { snap, controller };
  };

  for (const p of pairs) {
    const { snap: listSnap, controller: listCtrl } = await runControllerWithReport("list", p.listRaw);
    const { snap: fullSnap } = await runControllerWithReport("full", p.fullRaw);

    assert.strictEqual(
      listSnap.proveOutcome.status,
      p.expectedListStatus,
      `[${p.name}] list status mismatch: got ${listSnap.proveOutcome.status}, expected ${p.expectedListStatus}`
    );
    assert.strictEqual(
      fullSnap.proveOutcome.status,
      p.expectedFullStatus,
      `[${p.name}] full status mismatch`
    );
    assert.strictEqual(
      listSnap.proveOutcome.record?.parsedReport.notComparedReason,
      p.expectedReason,
      `[${p.name}] list notComparedReason mismatch`
    );
    assert.strictEqual(
      fullSnap.proveOutcome.record?.parsedReport.notComparedReason,
      p.expectedReason,
      `[${p.name}] full notComparedReason mismatch`
    );

    const proveRoot = findNodeById(listSnap.treeNodes, "prove_root")!;
    const allListNodes = collectAllNodes([proveRoot]);
    const listReplayNodes = allListNodes.filter(
      (n) => n.command?.commandId === "checkwashLens.replayMutant"
    );

    if (p.expectListCandidatesAndReplay) {
      assert.strictEqual(
        listSnap.proveOutcome.record!.parsedReport.candidates.length > 0,
        true
      );
      assert.strictEqual(listReplayNodes.length > 0, true);
    } else {
      assert.strictEqual(
        listSnap.proveOutcome.record!.parsedReport.candidates.length,
        0,
        `[${p.name}] early-return list must have 0 candidates`
      );
      assert.strictEqual(
        listReplayNodes.length,
        0,
        `[${p.name}] early-return list must expose 0 Replay commands`
      );
      // Even a direct replay preflight attempt with a fabricated mutant ID must be rejected!
      const badReplay = await listCtrl.prepareProveReplayCommandPlan({
        hostDesc: makeHostDesc(repoDir),
        configuredProvePath: PROVE_EXE,
        recordRunId: listSnap.proveOutcome.record!.runId,
        selectedMutantId: "src/calc.py:1:1:SDL:1",
      });
      assert.strictEqual(badReplay.ok, false);
    }
    assertions += 7;
  }

  return {
    assertions,
    details: {
      scenariosVerified: pairs.map((p) => p.name),
    },
  };
}

// ============================================================================
// Issue #7 [P2]: `needs_clarification` upstream schema & plain-data UI
// ============================================================================
async function testIssue7NeedsClarificationSchemaAndUi(): Promise<{
  assertions: number;
  details: Record<string, unknown>;
}> {
  let assertions = 0;

  const realCoexistingRaw = fs.readFileSync(
    path.join(FIXTURES_DIR, "prove-real-clarification-coexisting.json"),
    "utf8"
  );
  const valRes = validateProveReportJson(realCoexistingRaw);
  if (!valRes.ok) assert.fail(valRes.error);

  const firstNc = valRes.value.needs_clarification[0];
  assert.strictEqual(firstNc.test.includes("test_legacy_promo_behavior"), true);
  assert.strictEqual(firstNc.reason.length > 0, true);
  assert.strictEqual(typeof firstNc.also_fails_in_new, "boolean");
  assert.strictEqual(firstNc.detail.includes("assert 15 == 999"), true);
  assertions += 5;

  // Unknown optional field on `needs_clarification` item must remain compatible
  const withUnknownOpt = JSON.parse(realCoexistingRaw);
  withUnknownOpt.needs_clarification[0].future_upstream_hint = "compatible_extra_field";
  const valUnknown = validateProveReportJson(JSON.stringify(withUnknownOpt));
  assert.strictEqual(valUnknown.ok, true, "Unknown optional field on needs_clarification must be tolerated");

  // Legacy synthetic `{ path, status, why }` missing required `test`/`reason`/`also_fails_in_new`/`detail` must fail
  const legacySynthetic = JSON.parse(realCoexistingRaw);
  legacySynthetic.needs_clarification = [
    { path: "src/calc.py", status: "untraced_change", why: "synthetic" },
  ];
  assert.strictEqual(validateProveReportJson(JSON.stringify(legacySynthetic)).ok, false);
  assertions += 2;

  // Inspect TreeView presentation when clarification coexists with protection_losses & unconfirmed_losses
  // (using a trusted session record so `canReplay` is TRUE for losses, proving `needs_clarification` STILL gets ZERO commands!)
  const controller = new CheckwashLensController();
  const proveRunner = controller.getProveRunner();
  const parsed = classifyProveReport(valRes.value);
  const treeNodes = buildCheckwashTreeModel({
    evaluatedState: controller.getViewSnapshot().evaluatedState,
    enrichedFindings: [],
    fastGuardResult: null,
    proveOutcome: {
      status: parsed.status,
      errorReason: null,
      record: {
        runId: 77,
        entryKind: "full",
        adapterVersion: "0.1.0",
        isImportedExternalReport: false,
        repositoryRoot: REPO_ROOT,
        rawRangeSpec: "HEAD~1..HEAD",
        effectiveBaseOid: "a".repeat(40),
        effectiveHeadOid: "b".repeat(40),
        fromMergeBase: false,
        runtimeIdentity: {
          proveExecutable: PROVE_EXE,
          proveExecutableSha256: "1".repeat(64),
          proveVersion: "0.1.0",
          hostPythonExecutable: PYTHON_EXE,
          hostPythonVersion: "Python 3.11.9",
          testPythonExecutable: PYTHON_EXE,
          testPythonVersion: "Python 3.11.9",
          testPythonSha256: "2".repeat(64),
          catalogueVersion: "v0.5-m2",
          catalogueGeneratorSha256:
            "67096f7340a281585aaeaf801ae0ac29c4eb1a777c358ee973f02058cc7f4e14",
        },
        argv: [],
        effectiveOptions: {
          workers: 1,
          maxMutants: 25,
          timeoutSeconds: 30,
          suiteTimeoutSeconds: 120,
          importRoot: null,
          strictWarnings: false,
          listOnly: false,
          keep: false,
          onlyMutantId: null,
        },
        rawReportSha256: "3".repeat(64),
        parsedReport: parsed,
        exitCode: 0,
        cleanupConfirmed: true,
      },
    },
  });

  const plGroup = findNodeById(treeNodes, "prove_group_protection_losses");
  const ulGroup = findNodeById(treeNodes, "prove_group_unconfirmed_losses");
  const ncGroup = findNodeById(treeNodes, "prove_group_needs_clarification");
  assert.ok(plGroup !== null && plGroup.children.length > 0, "protection_losses group must coexist");
  assert.ok(ulGroup !== null && ulGroup.children.length > 0, "unconfirmed_losses group must coexist");
  assert.ok(ncGroup !== null && ncGroup.children.length > 0, "needs_clarification group must coexist");

  const ncItem = ncGroup!.children[0];
  assert.strictEqual(ncItem.label.includes(firstNc.test), true, "Test name must be visible in label");
  assert.strictEqual(ncItem.label.includes(firstNc.reason), true, "Reason must be visible in label");
  assert.strictEqual(
    (ncItem.description ?? "").includes(`also_fails_in_new=${firstNc.also_fails_in_new}`),
    true
  );
  assert.strictEqual(
    (ncItem.tooltip ?? "").includes(firstNc.detail) &&
      ncItem.children.some((c) => c.label.includes("assert 15 == 999")),
    true,
    "Detail must be visible in tooltip and expandable detail children"
  );

  // Verify ALL nodes under `prove_group_needs_clarification` are strictly plain data (`command === undefined`)
  const allNcNodes = collectAllNodes([ncGroup!]);
  assert.strictEqual(
    allNcNodes.every((n) => n.command === undefined),
    true,
    "Clarification items and detail lines must NEVER carry any command or Replay capability"
  );
  assert.strictEqual(proveRunner.getTrustedRecord(77), undefined);
  assertions += 9;

  return {
    assertions,
    details: {
      clarificationTestName: firstNc.test,
      clarificationReason: firstNc.reason,
      alsoFailsInNew: firstNc.also_fails_in_new,
      coexistingLossesCount: parsed.protectionLosses.length,
      coexistingUnconfirmedCount: parsed.unconfirmedLosses.length,
    },
  };
}

// ============================================================================
// Issue #8 [P2]: Prove UI scope, cap warnings, rawStatusText, and notes
// ============================================================================
async function testIssue8ProveUiScopeAndNotes(): Promise<{
  assertions: number;
  details: Record<string, unknown>;
}> {
  let assertions = 0;

  const baseZeroLossRaw = fs.readFileSync(
    path.join(FIXTURES_DIR, "a11-prove-zero-loss.json"),
    "utf8"
  );
  const capZeroRaw = fs.readFileSync(
    path.join(FIXTURES_DIR, "a12-prove-cap-zero.json"),
    "utf8"
  );

  const harnessState: MiniVscodeHarnessState = {
    isTrusted: true,
    workspaceFolderPath: REPO_ROOT,
    clipboardText: "",
    machineSettings: {},
    shownErrors: [],
    shownWarnings: [],
    shownInfos: [],
    modalHandler: async () => undefined,
  };

  await withMockedVscodeExtension(harnessState, async (api, _state, controller) => {
    // Case A & C & D: Partial mutants skipped over cap (`generated=59, run=10, skipped_over_cap=49`),
    // 0 confirmed protection losses, multi-line `status`, and multi-line + special-character `notes`!
    const specialNote1 =
      "Multi-line note line 1: [click](command:checkwashLens.runProveFull) `backticks` $ENV <tag> & \"quotes\"\nLine 2: C:\\path\\with\\backslashes & 中文說明\nLine 3: --workers 2 interference warning";
    const multiLineStatus = "done (summary line 1)\ndetail status line 2: cap reached";

    const docCustom = JSON.parse(baseZeroLossRaw);
    docCustom.status = multiLineStatus;
    docCustom.notes = [...docCustom.notes, specialNote1];

    const tmpCustomFile = path.join(os.tmpdir(), `cw-issue8-${Date.now()}.json`);
    const tmpCapZeroFile = path.join(os.tmpdir(), `cw-issue8-cap0-${Date.now()}.json`);
    try {
      fs.writeFileSync(tmpCustomFile, JSON.stringify(docCustom), "utf8");
      fs.writeFileSync(tmpCapZeroFile, capZeroRaw, "utf8");

      const viewRes = controller.viewOfflineReportFileReadOnly(tmpCustomFile);
      assert.strictEqual(viewRes.ok, true);
      const snap = controller.getViewSnapshot();

      const scopeNode = findNodeById(snap.treeNodes, "prove_scope_summary");
      assert.ok(scopeNode !== null, "prove_scope_summary must be rendered");
      assert.strictEqual(
        scopeNode!.label,
        "Scope: generated=59, run=10, skipped_over_cap=49"
      );
      assert.strictEqual(
        (scopeNode!.description ?? "").includes("Cap-limited scope") &&
          (scopeNode!.description ?? "").includes("49 of 59"),
        true,
        `Expected cap-limited scope warning in description, got: ${scopeNode!.description}`
      );

      const rawStatusNode = findNodeById(snap.treeNodes, "prove_raw_status");
      assert.ok(rawStatusNode !== null, "prove_raw_status must be rendered");
      assert.strictEqual(rawStatusNode!.label, "Upstream Status: done (summary line 1)");
      assert.strictEqual(rawStatusNode!.tooltip, multiLineStatus);
      assert.strictEqual(rawStatusNode!.children.length, 2);
      assert.strictEqual(rawStatusNode!.children[1].label, "detail status line 2: cap reached");

      const zeroLossNode = findNodeById(snap.treeNodes, "prove_zero_loss_disclaimer");
      assert.ok(zeroLossNode !== null, "Zero-confirmed-loss disclaimer must be retained");
      assert.strictEqual(zeroLossNode!.label, NO_CONFIRMED_LOSS_FIXED_MESSAGE);

      const notesGroup = findNodeById(snap.treeNodes, "prove_group_notes");
      assert.ok(notesGroup !== null, "prove_group_notes must be rendered");
      assert.strictEqual(notesGroup!.children.length, 2);
      const multilineNoteNode = notesGroup!.children[1];
      assert.strictEqual(multilineNoteNode.tooltip, specialNote1);
      assert.strictEqual(multilineNoteNode.children.length, 3);
      assert.strictEqual(
        multilineNoteNode.children[0].label.includes("[click](command:checkwashLens.runProveFull)"),
        true,
        "Special characters and markdown-like syntax must remain literal plain text"
      );
      assert.strictEqual(
        multilineNoteNode.children[1].label.includes("中文說明"),
        true
      );

      // Verify VS Code TreeDataProvider.getTreeItem produces plain string tooltip (NOT MarkdownString) and NO command!
      for (const n of collectAllNodes([scopeNode!, rawStatusNode!, notesGroup!])) {
        assert.strictEqual(n.command, undefined);
        const treeItem = api.getTreeItemForNode(n);
        assert.strictEqual(treeItem.command, undefined);
        if (treeItem.tooltip !== undefined) {
          assert.strictEqual(typeof treeItem.tooltip, "string", "Tooltip must be plain string, never MarkdownString");
        }
      }
      assertions += 18;

      // Case B: Zero executed (`--max-mutants 0` -> `generated=59, run=0, skipped_over_cap=59`)
      const viewCapZero = controller.viewOfflineReportFileReadOnly(tmpCapZeroFile);
      assert.strictEqual(viewCapZero.ok, true);
      const snapCapZero = controller.getViewSnapshot();
      const capZeroScope = findNodeById(snapCapZero.treeNodes, "prove_scope_summary");
      assert.ok(capZeroScope !== null);
      assert.strictEqual(
        capZeroScope!.label,
        "Scope: generated=59, run=0, skipped_over_cap=59"
      );
      assert.strictEqual(
        (capZeroScope!.description ?? "").includes("0 executed"),
        true,
        `Expected zero-executed scope disclosure, got: ${capZeroScope!.description}`
      );
      const capZeroStatus = findNodeById(snapCapZero.treeNodes, "prove_raw_status");
      assert.strictEqual(
        capZeroStatus?.label.includes("no mutant was run (--max-mutants 0)"),
        true
      );
      assertions += 5;
    } finally {
      fs.rmSync(tmpCustomFile, { force: true });
      fs.rmSync(tmpCapZeroFile, { force: true });
      await api.deactivate();
    }
  });

  return {
    assertions,
    details: {
      partialCapSkippedVerified: true,
      zeroExecutedVerified: true,
      zeroLossWithNotesVerified: true,
      multilineAndSpecialCharNotesPlainData: true,
    },
  };
}

// ============================================================================
// Issue #9 [P2]: Broker stdin async write/error & close/abort races
// ============================================================================
async function testIssue9BrokerStdinAsyncRaces(tempRoot: string): Promise<{
  assertions: number;
  details: Record<string, unknown>;
}> {
  let assertions = 0;

  // Guard against any uncaughtException / unhandledRejection (such as unhandled 'error' on proc.stdin!)
  const uncaughtErrors: unknown[] = [];
  const onUncaught = (err: unknown) => uncaughtErrors.push(err);
  const onUnhandledRejection = (reason: unknown) => uncaughtErrors.push(reason);
  process.on("uncaughtException", onUncaught);
  process.on("unhandledRejection", onUnhandledRejection);

  try {
    // Compile a tiny native helper executable in `tempRoot` (C# via `csc.exe` on Windows; C via `gcc` on Linux)
    // ONLY for direct `executeViaWindowsBroker` pipe-race stimulation; verify production `verifyBundledArtifacts`
    // STILL rejects it if substituted into an extension root!
    const stubEarlyExitExe = path.join(
      tempRoot,
      IS_WIN32 ? "stub-early-exit-broker.exe" : "stub-early-exit-broker"
    );
    const stubExitOnCancelExe = path.join(
      tempRoot,
      IS_WIN32 ? "stub-exit-on-cancel-broker.exe" : "stub-exit-on-cancel-broker"
    );
    const readyFlagPath = path.join(tempRoot, "stub-cancel-ready.flag");

    if (IS_WIN32) {
      assert.strictEqual(fs.existsSync(CSC_EXE), true, "Built-in Windows csc.exe required for pipe-race stub");
      const stubCsPath = path.join(tempRoot, "StubBroker.cs");
      fs.writeFileSync(
        stubCsPath,
        [
          "using System;",
          "using System.IO;",
          "using System.Threading;",
          "class Program {",
          "  static int Main() {",
          "    string mode = Environment.GetEnvironmentVariable(\"CW_STUB_BROKER_MODE\") ?? \"early\";",
          "    if (mode == \"early\") {",
          "      return 77;",
          "    }",
          "    string line = Console.In.ReadLine();",
          "    string flag = Environment.GetEnvironmentVariable(\"CW_STUB_READY_FILE\");",
          "    if (!string.IsNullOrEmpty(flag)) File.WriteAllText(flag, \"READY\");",
          "    Thread.Sleep(40);",
          "    Console.Error.WriteLine(\"exiting during cancel without json\");",
          "    return 88;",
          "  }",
          "}",
        ].join("\n"),
        "utf8"
      );

      const compileEarly = cp.spawnSync(
        CSC_EXE,
        ["/nologo", "/target:exe", `/out:${stubEarlyExitExe}`, stubCsPath],
        { encoding: "utf8", windowsHide: true }
      );
      assert.strictEqual(compileEarly.status, 0, `csc compile failed: ${compileEarly.stdout}\n${compileEarly.stderr}`);
    } else {
      const stubCPath = path.join(tempRoot, "StubBroker.c");
      fs.writeFileSync(
        stubCPath,
        [
          "#include <stdio.h>",
          "#include <stdlib.h>",
          "#include <string.h>",
          "#include <unistd.h>",
          "int main(void) {",
          "  const char *mode = getenv(\"CW_STUB_BROKER_MODE\");",
          "  if (!mode || strcmp(mode, \"early\") == 0) {",
          "    return 77;",
          "  }",
          "  char buf[4096];",
          "  if (fgets(buf, sizeof(buf), stdin) == NULL) {}",
          "  const char *flag = getenv(\"CW_STUB_READY_FILE\");",
          "  if (flag && flag[0] != '\\0') {",
          "    FILE *f = fopen(flag, \"wb\");",
          "    if (f) { fwrite(\"READY\", 1, 5, f); fclose(f); }",
          "  }",
          "  usleep(40000);",
          "  fprintf(stderr, \"exiting during cancel without json\\n\");",
          "  fflush(stderr);",
          "  return 88;",
          "}",
        ].join("\n"),
        "utf8"
      );

      const compileEarly = cp.spawnSync(
        "gcc",
        ["-O2", "-o", stubEarlyExitExe, stubCPath],
        { encoding: "utf8" }
      );
      assert.strictEqual(compileEarly.status, 0, `gcc compile failed: ${compileEarly.stdout}\n${compileEarly.stderr}`);
      fs.chmodSync(stubEarlyExitExe, 0o755);
    }
    copyExecutablePreservingMode(stubEarlyExitExe, stubExitOnCancelExe);
    assertions += 2;

    // Prove production hash & admission checks are NOT weakened: substituting `stubEarlyExitExe` as the active
    // bundled broker in a fake extension root MUST be rejected by `verifyBundledArtifacts` and `verifyLaunchAdmission`!
    const fakeExtRoot = path.join(tempRoot, "issue9-fake-ext-root");
    fs.mkdirSync(path.join(fakeExtRoot, "bundled"), { recursive: true });
    for (const entry of fs.readdirSync(path.join(REPO_ROOT, "bundled"))) {
      copyExecutablePreservingMode(
        path.join(REPO_ROOT, "bundled", entry),
        path.join(fakeExtRoot, "bundled", entry)
      );
    }
    copyExecutablePreservingMode(
      stubEarlyExitExe,
      path.join(fakeExtRoot, "bundled", resolveBundledBrokerFilename())
    );

    const fakeRepo = createTempGitRepo(tempRoot, "issue9-repo");
    assert.strictEqual(verifyBundledArtifacts(REPO_ROOT).ok, true, "Production bundled broker hash must pass");
    assert.strictEqual(verifyBundledArtifacts(fakeExtRoot).ok, false, "Stub broker must fail production hash check");
    assert.strictEqual(
      verifyLaunchAdmission(makeHostDesc(fakeRepo, { extensionRootPath: fakeExtRoot })).ok,
      false,
      "verifyLaunchAdmission must reject unpinned broker binary"
    );
    assertions += 3;

    // 1. Broker exits BEFORE large request finishes writing to `stdin` (triggers async EPIPE/EOF on request write!)
    const hugeArg = "A".repeat(512 * 1024); // > OS anonymous pipe buffer (4KB-64KB), guaranteeing partial/blocked write -> EPIPE!
    process.env.CW_STUB_BROKER_MODE = "early";
    const earlyExitOutcome = await executeViaWindowsBroker({
      brokerExecutablePath: stubEarlyExitExe,
      executable: PYTHON_EXE,
      args: ["-c", "pass", hugeArg],
      cwd: tempRoot,
      env: getMinimalBrokerEnv(),
      timeoutMs: 10_000,
      maxStdoutBytes: 1024 * 1024,
      maxStderrBytes: 1024 * 1024,
    });
    assert.strictEqual(earlyExitOutcome.status, "broker_error");
    assert.strictEqual(
      earlyExitOutcome.cleanupConfirmed,
      false,
      "Must NOT assume child stopped when request write / broker fails"
    );
    assert.strictEqual(
      (earlyExitOutcome.brokerErrorDetail ?? "").includes("77") ||
        (earlyExitOutcome.brokerErrorDetail ?? "").toLowerCase().includes("stdin"),
      true,
      `Expected exit code 77 / stdin detail, got: ${earlyExitOutcome.brokerErrorDetail}`
    );
    assertions += 3;

    // 2. Broker receives request and exits right as `CANCEL\n` is written to `stdin`
    process.env.CW_STUB_BROKER_MODE = "cancel_exit";
    process.env.CW_STUB_READY_FILE = readyFlagPath;
    fs.rmSync(readyFlagPath, { force: true });
    const cancelAbort = new AbortController();
    const cancelRacePromise = executeViaWindowsBroker(
      {
        brokerExecutablePath: stubExitOnCancelExe,
        executable: PYTHON_EXE,
        args: ["--version"],
        cwd: tempRoot,
        env: getMinimalBrokerEnv(),
        timeoutMs: 10_000,
        maxStdoutBytes: 1024 * 1024,
        maxStderrBytes: 1024 * 1024,
      },
      cancelAbort.signal
    );
    for (let i = 0; i < 50; i++) {
      if (fs.existsSync(readyFlagPath)) break;
      await new Promise((r) => setTimeout(r, 10));
    }
    // Hammer abort right around broker exit (40ms window)
    await new Promise((r) => setTimeout(r, 38));
    cancelAbort.abort();
    const cancelExitOutcome = await cancelRacePromise;
    assert.strictEqual(cancelExitOutcome.status, "broker_error");
    assert.strictEqual(cancelExitOutcome.cleanupConfirmed, false);
    assert.strictEqual(
      (cancelExitOutcome.brokerErrorDetail ?? "").includes("88"),
      true,
      `Expected raw exit 88 preserved, got: ${cancelExitOutcome.brokerErrorDetail}`
    );
    assertions += 3;

    // 3. Spawn error (`ENOENT`) + `abort` race & real broker rapid close/abort race
    delete process.env.CW_STUB_BROKER_MODE;
    delete process.env.CW_STUB_READY_FILE;

    const enoentAbort = new AbortController();
    const enoentPromise = executeViaWindowsBroker(
      {
        brokerExecutablePath: path.join(tempRoot, IS_WIN32 ? "does-not-exist-broker.exe" : "does-not-exist-broker"),
        executable: PYTHON_EXE,
        args: ["--version"],
        cwd: tempRoot,
        env: getMinimalBrokerEnv(),
        timeoutMs: 5_000,
        maxStdoutBytes: 65536,
        maxStderrBytes: 65536,
      },
      enoentAbort.signal
    );
    enoentAbort.abort();
    const enoentOutcome = await enoentPromise;
    assert.strictEqual(enoentOutcome.status, "broker_error");
    assert.strictEqual(enoentOutcome.cleanupConfirmed, false);

    for (let i = 0; i < 10; i++) {
      const raceCtrl = new AbortController();
      setTimeout(() => raceCtrl.abort(), i * 8);
      const realRaceOut = await executeViaWindowsBroker(
        {
          brokerExecutablePath: BROKER_EXE,
          executable: PYTHON_EXE,
          args: ["-I", "-S", "-B", "-c", "print('ok')"],
          cwd: tempRoot,
          env: getMinimalBrokerEnv(),
          timeoutMs: 10_000,
          maxStdoutBytes: 65536,
          maxStderrBytes: 65536,
        },
        raceCtrl.signal
      );
      assert.strictEqual(
        realRaceOut.status === "completed" || realRaceOut.status === "cancelled",
        true,
        `Unexpected status in real broker close/abort race: ${realRaceOut.status} (${realRaceOut.brokerErrorDetail})`
      );
      assert.strictEqual(realRaceOut.cleanupConfirmed, true);
    }

    // Give libuv event loop a turn to flush any late stream callbacks
    await new Promise((r) => setTimeout(r, 100));
    assert.strictEqual(
      uncaughtErrors.length,
      0,
      `Must have ZERO uncaught stream/async exceptions, got: ${JSON.stringify(uncaughtErrors)}`
    );
    assertions += 23;

    return {
      assertions,
      details: {
        earlyExitBeforeRequestWriteDetail: earlyExitOutcome.brokerErrorDetail,
        exitDuringCancelWriteDetail: cancelExitOutcome.brokerErrorDetail,
        spawnErrorAbortRaceDetail: enoentOutcome.brokerErrorDetail,
        uncaughtAsyncErrors: uncaughtErrors.length,
        productionBrokerHashStillEnforced: true,
      },
    };
  } finally {
    delete process.env.CW_STUB_BROKER_MODE;
    delete process.env.CW_STUB_READY_FILE;
    process.off("uncaughtException", onUncaught);
    process.off("unhandledRejection", onUnhandledRejection);
  }
}

// ============================================================================
// Issue #10 [P2]: Verified Git vs Checkwash bare `git` canonical identity
// ============================================================================
async function testIssue10BareGitCanonicalIdentity(tempRoot: string): Promise<{
  assertions: number;
  details: Record<string, unknown>;
}> {
  let assertions = 0;
  const repoDir = createTempGitRepo(tempRoot, "issue10-git-identity-repo");
  fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
  fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });
  fs.writeFileSync(path.join(repoDir, "src", "v.py"), "def v():\n    return 1\n", "utf8");
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_v.py"),
    "from src.v import v\ndef test_v():\n    assert v() == 1\n",
    "utf8"
  );
  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "base"]);
  const baseOid = runGitSync(repoDir, ["rev-parse", "HEAD"]);
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_v.py"),
    "from src.v import v\ndef test_v():\n    assert v() == 1\n    assert v() > 0\n",
    "utf8"
  );
  runGitSync(repoDir, ["add", "."]);
  runGitSync(repoDir, ["commit", "-m", "head"]);
  const headOid = runGitSync(repoDir, ["rev-parse", "HEAD"]);

  resetTotalBrokerSpawnCountForTests();

  // 1. `git-new` configured in a directory that ALSO has `git` (same dir, same version string!) -> BLOCKED!
  const dualGitDir = path.join(tempRoot, "issue10-dual-git");
  fs.mkdirSync(dualGitDir, { recursive: true });
  const gitNewPath = path.join(dualGitDir, IS_WIN32 ? "git-new.exe" : "git-new");
  const gitSiblingPath = path.join(dualGitDir, IS_WIN32 ? "git.exe" : "git");
  copyExecutablePreservingMode(GIT_EXE, gitNewPath);
  copyExecutablePreservingMode(GIT_EXE, gitSiblingPath);

  const sharedProcForIssue10 = new UnifiedProcessRunner();
  const engineRunner = new CheckwashEngineRunner(
    sharedProcForIssue10,
    new RevisionProvider(sharedProcForIssue10)
  );
  const dualScan = await engineRunner.executeStaticScan(
    makeHostDesc(repoDir, { configuredGitPath: gitNewPath }),
    `${baseOid}..${headOid}`
  );
  assert.strictEqual(dualScan.evaluatedState.state, "Error");
  assert.strictEqual(
    (dualScan.evaluatedState.errorReason ?? "").includes("Trusted Git identity mismatch"),
    true
  );
  assert.strictEqual(getTotalBrokerSpawnCount(), 0, "Must block before spawning any process");
  assertions += 3;

  // 2. `git-new` configured alone where bare `git` either cannot resolve or resolves to system `git` -> BLOCKED!
  const loneGitDir = path.join(tempRoot, "issue10-lone-git");
  fs.mkdirSync(loneGitDir, { recursive: true });
  const loneGitNew = path.join(loneGitDir, IS_WIN32 ? "git-new.exe" : "git-new");
  copyExecutablePreservingMode(GIT_EXE, loneGitNew);

  const loneScan = await engineRunner.executeStaticScan(
    makeHostDesc(repoDir, { configuredGitPath: loneGitNew }),
    `${baseOid}..${headOid}`
  );
  assert.strictEqual(loneScan.evaluatedState.state, "Error");
  const loneErr = loneScan.evaluatedState.errorReason ?? "";
  assert.strictEqual(
    loneErr.includes("bare 'git' cannot be resolved") ||
      loneErr.includes("Trusted Git identity mismatch"),
    true,
    `Expected bare-git unresolved or mismatch error, got: ${loneErr}`
  );
  // Also explicitly verify isolated PATH without any `git` yields `bare 'git' cannot be resolved`:
  const isolatedNoBareRes = verifyBareGitResolutionForStaticEnv({
    canonicalPythonPath: PYTHON_EXE,
    canonicalGitPath: loneGitNew,
    controlledEmptyCwd: loneGitDir,
    sanitizedStaticEnv: IS_WIN32
      ? {
          SystemRoot: loneGitDir,
          PATHEXT: ".COM;.EXE;.BAT;.CMD",
          PATH: loneGitDir,
          NoDefaultCurrentDirectoryInExePath: "1",
        }
      : {
          PATH: loneGitDir,
        },
  });
  assert.strictEqual(isolatedNoBareRes.ok, false);
  if (!isolatedNoBareRes.ok) {
    assert.strictEqual(isolatedNoBareRes.error.includes("bare 'git' cannot be resolved"), true);
  }
  assert.strictEqual(getTotalBrokerSpawnCount(), 0);
  assertions += 4;

  // 3. Another `git` exists earlier in OS search order or runtime directory:
  //    3a: `<pythonDir>/git` (colocated next to Python executable)
  const fakePyDir = path.join(tempRoot, "issue10-py-dir-with-shadow-git");
  fs.mkdirSync(fakePyDir, { recursive: true });
  const fakePyExe = path.join(fakePyDir, IS_WIN32 ? "python.exe" : "python3");
  const shadowGitInPyDir = path.join(fakePyDir, IS_WIN32 ? "git.exe" : "git");
  copyExecutablePreservingMode(PYTHON_EXE, fakePyExe);
  copyExecutablePreservingMode(GIT_EXE, shadowGitInPyDir);

  const pyShadowAdm = verifyLaunchAdmission(
    makeHostDesc(repoDir, {
      configuredPythonPath: fakePyExe,
      configuredGitPath: GIT_EXE,
    })
  );
  assert.strictEqual(pyShadowAdm.ok, false, "git next to python must be blocked as search-order/colocated shadow");
  if (!pyShadowAdm.ok) {
    assert.strictEqual(pyShadowAdm.error.includes("Trusted Git identity mismatch"), true);
  }

  //    3b: `<SystemRoot>\System32\git.exe` on Windows; earlier POSIX `PATH` shadow & unsafe relative `PATH` segment on Linux
  if (IS_WIN32) {
    const fakeSysRoot = path.join(tempRoot, "issue10-fake-sysroot");
    fs.mkdirSync(path.join(fakeSysRoot, "System32"), { recursive: true });
    copyExecutablePreservingMode(GIT_EXE, path.join(fakeSysRoot, "System32", "git.exe"));
    const sys32ShadowScan = await engineRunner.executeStaticScan(
      makeHostDesc(repoDir, {
        configuredGitPath: GIT_EXE,
        inheritedEnv: { ...process.env, SystemRoot: fakeSysRoot },
      }),
      `${baseOid}..${headOid}`
    );
    assert.strictEqual(sys32ShadowScan.evaluatedState.state, "Error");
    assert.strictEqual(getTotalBrokerSpawnCount(), 0);
  } else {
    const posixShadowDir = path.join(tempRoot, "issue10-posix-shadow-dir");
    fs.mkdirSync(posixShadowDir, { recursive: true });
    copyExecutablePreservingMode(GIT_EXE, path.join(posixShadowDir, "git"));
    const posixShadowRes = verifyBareGitResolutionForStaticEnv({
      canonicalPythonPath: PYTHON_EXE,
      canonicalGitPath: GIT_EXE,
      controlledEmptyCwd: tempRoot,
      sanitizedStaticEnv: {
        PATH: `${posixShadowDir}:${path.dirname(GIT_EXE)}:/usr/bin:/bin`,
      },
    });
    assert.strictEqual(posixShadowRes.ok, false);
    const relativeSegRes = verifyBareGitResolutionForStaticEnv({
      canonicalPythonPath: PYTHON_EXE,
      canonicalGitPath: GIT_EXE,
      controlledEmptyCwd: tempRoot,
      sanitizedStaticEnv: {
        PATH: `:${path.dirname(GIT_EXE)}:/usr/bin`,
      },
    });
    assert.strictEqual(relativeSegRes.ok, false);
  }

  //    3c: `controlledEmptyCwd` containing `git.cmd` / `git`
  const pollutedCwd = path.join(tempRoot, "issue10-polluted-cwd");
  fs.mkdirSync(pollutedCwd, { recursive: true });
  writeExecutableDecoyScript(
    path.join(pollutedCwd, IS_WIN32 ? "git.cmd" : "git"),
    path.join(tempRoot, "issue10-cwd-unused.txt"),
    1
  );
  const cwdShadowCheck = verifyBareGitResolutionForStaticEnv({
    canonicalPythonPath: PYTHON_EXE,
    canonicalGitPath: GIT_EXE,
    controlledEmptyCwd: pollutedCwd,
    sanitizedStaticEnv: IS_WIN32
      ? {
          SystemRoot: process.env.SystemRoot || "C:\\Windows",
          PATHEXT: ".COM;.EXE;.BAT;.CMD",
          PATH: `${path.win32.dirname(GIT_EXE)};C:\\Windows\\System32`,
          NoDefaultCurrentDirectoryInExePath: "1",
        }
      : {
          PATH: `${path.posix.dirname(GIT_EXE)}:/usr/bin:/bin`,
        },
  });
  assert.strictEqual(cwdShadowCheck.ok, false);
  assertions += 6;

  // 4. Normal pinned Git configuration -> probe & actual descendant bare `git` execute the EXACT same canonical executable
  const validDesc = makeHostDesc(repoDir);
  const procRunner = new UnifiedProcessRunner();
  const probeRes = await procRunner.probeTrustedRuntimeVersions(validDesc);
  if (!probeRes.ok) assert.fail(probeRes.error);

  const kernelImageQueryPy = IS_WIN32
    ? [
        "import ctypes, ctypes.wintypes, subprocess, hashlib, json, os",
        'p = subprocess.Popen(["git", "-C", ' + JSON.stringify(repoDir) + ', "rev-parse", "HEAD"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)',
        "h = int(p._handle)",
        "buf = ctypes.create_unicode_buffer(32768)",
        "sz = ctypes.wintypes.DWORD(32768)",
        "ok = ctypes.windll.kernel32.QueryFullProcessImageNameW(ctypes.wintypes.HANDLE(h), 0, buf, ctypes.byref(sz))",
        "out, _ = p.communicate()",
        "img = os.path.realpath(buf.value)",
        'sha = hashlib.sha256(open(img, "rb").read()).hexdigest()',
        'print(json.dumps({"ok": bool(ok), "imagePath": img, "sha256": sha, "headOid": out.decode("utf-8").strip()}))',
      ].join("; ")
    : [
        "import subprocess, hashlib, json, os",
        'p = subprocess.Popen(["git", "hash-object", "--stdin"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)',
        'img = os.path.realpath(f"/proc/{p.pid}/exe")',
        'p.communicate(b"probe\\n")',
        'head = subprocess.check_output(["git", "-C", ' + JSON.stringify(repoDir) + ', "rev-parse", "HEAD"]).decode("utf-8").strip()',
        'sha = hashlib.sha256(open(img, "rb").read()).hexdigest()',
        'print(json.dumps({"ok": bool(img), "imagePath": img, "sha256": sha, "headOid": head}))',
      ].join("; ");

  const descExec = await procRunner.executeGatedProcess({
    hostDesc: validDesc,
    executableSelector: (ctx) => ctx.canonicalPythonPath,
    argsBuilder: () => ["-I", "-S", "-B", "-c", kernelImageQueryPy],
    timeoutMs: 15_000,
  });
  if (!descExec.ok) assert.fail(descExec.error);
  const kernelObs = JSON.parse(descExec.value.outcome.stdoutText.trim());
  const expectedGitSha = sha256File(GIT_EXE);

  assert.strictEqual(kernelObs.ok, true);
  assert.strictEqual(
    IS_WIN32 ? kernelObs.imagePath.toLowerCase() : kernelObs.imagePath,
    IS_WIN32 ? GIT_EXE.toLowerCase() : GIT_EXE
  );
  assert.strictEqual(
    IS_WIN32 ? probeRes.value.admission.canonicalGitPath.toLowerCase() : probeRes.value.admission.canonicalGitPath,
    IS_WIN32 ? GIT_EXE.toLowerCase() : GIT_EXE
  );
  assert.strictEqual(kernelObs.sha256, expectedGitSha);
  assert.strictEqual(kernelObs.headOid, headOid);

  const validScan = await engineRunner.executeStaticScan(validDesc, `${baseOid}..${headOid}`);
  assert.strictEqual(validScan.evaluatedState.state, "Pass");
  assert.strictEqual(
    IS_WIN32
      ? validScan.evaluatedState.joinedReport?.scanIdentity.gitExecutable.toLowerCase()
      : validScan.evaluatedState.joinedReport?.scanIdentity.gitExecutable,
    IS_WIN32 ? GIT_EXE.toLowerCase() : GIT_EXE
  );
  assertions += 8;

  // 5. Re-Review Prove Final Environment Bare-`git` Identity Cases:
  //    5a: `proveDir` containing a rogue `git` -> rejected BEFORE spawning!
  const poisonedProveDir = path.join(tempRoot, "issue10-poisoned-prove-dir");
  fs.mkdirSync(poisonedProveDir, { recursive: true });
  const poisonedProveExe = path.join(
    poisonedProveDir,
    IS_WIN32 ? "checkwash-prove.exe" : "checkwash-prove"
  );
  copyExecutablePreservingMode(PROVE_EXE, poisonedProveExe);
  copyExecutablePreservingMode(
    GIT_EXE,
    path.join(poisonedProveDir, IS_WIN32 ? "git.exe" : "git")
  );

  resetTotalBrokerSpawnCountForTests();
  const proveCtrl = new CheckwashLensController();
  const poisonedProvePf = await proveCtrl.prepareProveManualCommandPlan({
    hostDesc: makeHostDesc(repoDir),
    configuredProvePath: poisonedProveExe,
    rawRangeSpec: `${baseOid}..${headOid}`,
    entryKind: "list",
  });
  assert.strictEqual(poisonedProvePf.ok, false, "proveDir with shadowing git must be rejected");
  if (!poisonedProvePf.ok) {
    assert.strictEqual(poisonedProvePf.error.includes("Trusted Git identity mismatch"), true);
  }
  assert.strictEqual(getTotalBrokerSpawnCount(), 0, "Must reject poisoned proveDir with 0 spawns");

  //    5b: `testPyDir` (`configuredTestPythonPath`) containing a rogue `git.cmd` / `git` -> rejected BEFORE spawning!
  const poisonedTestPyDir = path.join(tempRoot, "issue10-poisoned-test-py-dir");
  fs.mkdirSync(poisonedTestPyDir, { recursive: true });
  const poisonedTestPyExe = path.join(
    poisonedTestPyDir,
    IS_WIN32 ? "python.exe" : "python3"
  );
  copyExecutablePreservingMode(PYTHON_EXE, poisonedTestPyExe);
  writeExecutableDecoyScript(
    path.join(poisonedTestPyDir, IS_WIN32 ? "git.cmd" : "git"),
    path.join(tempRoot, "issue10-testpy-unused.txt"),
    1
  );

  resetTotalBrokerSpawnCountForTests();
  const poisonedTestPyPf = await proveCtrl.prepareProveManualCommandPlan({
    hostDesc: makeHostDesc(repoDir),
    configuredProvePath: PROVE_EXE,
    configuredTestPythonPath: poisonedTestPyExe,
    rawRangeSpec: `${baseOid}..${headOid}`,
    entryKind: "list",
  });
  assert.strictEqual(poisonedTestPyPf.ok, false, "testPyDir with shadowing git must be rejected");
  if (!poisonedTestPyPf.ok) {
    assert.strictEqual(poisonedTestPyPf.error.includes("Trusted Git identity"), true);
  }
  assert.strictEqual(getTotalBrokerSpawnCount(), 0, "Must reject poisoned testPyDir with 0 spawns");

  //    5c: Direct `executeGatedProcess` with custom `envSelector` prepending a directory with rogue `git`
  //        ahead of `canonicalGitDir` in `PATH` -> blocked inside `executeGatedProcess` with 0 target spawns!
  resetTotalBrokerSpawnCountForTests();
  const gatedPathShadowRes = await proveCtrl.getProcessRunner().executeGatedProcess({
    hostDesc: makeHostDesc(repoDir),
    executableSelector: () => PROVE_EXE,
    additionalBareGitCallers: (ctx) => [ctx.canonicalPythonPath],
    argsBuilder: () => ["--version"],
    envSelector: (ctx) => ({
      ...ctx.sanitizedStaticEnv,
      PATH: `${poisonedProveDir}${path.delimiter}${ctx.sanitizedStaticEnv.PATH}`,
    }),
    timeoutMs: 10_000,
  });
  assert.strictEqual(gatedPathShadowRes.ok, false, "executeGatedProcess must reject rewritten PATH shadowing canonicalGitPath");
  if (!gatedPathShadowRes.ok) {
    assert.strictEqual(gatedPathShadowRes.error.includes("Trusted Git identity mismatch"), true);
  }
  assert.strictEqual(
    getTotalBrokerSpawnCount() <= 1, // at most 1 broker capability probe (`--probe`), 0 target launches!
    true
  );

  //    5d: Verify `buildSanitizedProveEnv` keeps `canonicalGitDir` at index 0 of `PATH` and passes `verifyBareGitResolutionForProcessLaunch`!
  const admValid = verifyLaunchAdmission(validDesc);
  if (!admValid.ok) assert.fail(admValid.error);
  const builtProveEnv = buildSanitizedProveEnv({
    baseStaticEnv: admValid.value.sanitizedStaticEnv,
    canonicalGitDir: admValid.value.canonicalGitDir,
    proveExecutable: PROVE_EXE,
    hostPythonExecutable: PYTHON_EXE,
    testPythonExecutable: PYTHON_EXE,
  });
  assert.strictEqual(
    IS_WIN32
      ? builtProveEnv.PATH.split(path.delimiter)[0].toLowerCase()
      : builtProveEnv.PATH.split(path.delimiter)[0],
    IS_WIN32 ? admValid.value.canonicalGitDir.toLowerCase() : admValid.value.canonicalGitDir,
    "buildSanitizedProveEnv must keep canonicalGitDir first in PATH"
  );
  const finalProveGitCheck = verifyBareGitResolutionForProcessLaunch({
    callingExecutables: [PROVE_EXE, PYTHON_EXE],
    canonicalGitPath: GIT_EXE,
    cwd: admValid.value.controlledEmptyCwd,
    env: builtProveEnv,
  });
  assert.strictEqual(finalProveGitCheck.ok, true);
  assertions += 11;

  return {
    assertions,
    details: {
      dualGitNewBlocked: true,
      missingBareGitBlocked: true,
      pythonDirAndSystem32ShadowsBlocked: true,
      pollutedCwdBlocked: true,
      proveDirAndTestPyDirAndRewrittenPathShadowsBlocked: true,
      verifiedCanonicalGitPath: GIT_EXE,
      descendantKernelImagePath: kernelObs.imagePath,
      gitSha256: expectedGitSha,
    },
  };
}

// ============================================================================
// Main Runner
// ============================================================================
async function main(): Promise<void> {
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  const tempRoot = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "cw-lens-10-issues-"))
  );

  const suite: Array<{
    issueNumber: number;
    id: string;
    severity: "P1" | "P2";
    title: string;
    fn: () => Promise<{ assertions: number; details: Record<string, unknown> }>;
  }> = [
    {
      issueNumber: 1,
      id: "ISSUE-01",
      severity: "P1",
      title: "Context Diet hunk masking (-- SQL deletion & ++ addition through clipboard)",
      fn: () => testIssue1ContextDietHunkMasking(tempRoot),
    },
    {
      issueNumber: 2,
      id: "ISSUE-02",
      severity: "P1",
      title: "Unconfirmed cleanup prioritized across all cancel/timeout stages",
      fn: () => testIssue2UnconfirmedCleanupAcrossStages(tempRoot),
    },
    {
      issueNumber: 3,
      id: "ISSUE-03",
      severity: "P1",
      title: "Prove authorization bound to immutable execution plan (List, Full, Replay)",
      fn: () => testIssue3ProvePlanBoundAuthorization(tempRoot),
    },
    {
      issueNumber: 4,
      id: "ISSUE-04",
      severity: "P2",
      title: "Prove non-zero exit preserved as Execution error with Replay blocked",
      fn: () => testIssue4ProveNonZeroExitHandling(tempRoot),
    },
    {
      issueNumber: 5,
      id: "ISSUE-05",
      severity: "P2",
      title: "JSON v2 valid empty-string unit accepted without false positioning",
      fn: () => testIssue5EmptyUnitStringAccepted(tempRoot),
    },
    {
      issueNumber: 6,
      id: "ISSUE-06",
      severity: "P2",
      title: "Prove list_only=true early returns classified consistently with full mode",
      fn: () => testIssue6ListOnlyClassificationParity(tempRoot),
    },
    {
      issueNumber: 7,
      id: "ISSUE-07",
      severity: "P2",
      title: "Prove needs_clarification upstream schema (test/reason/also_fails_in_new/detail) & plain-data UI",
      fn: () => testIssue7NeedsClarificationSchemaAndUi(),
    },
    {
      issueNumber: 8,
      id: "ISSUE-08",
      severity: "P2",
      title: "Prove UI scope, cap warnings, rawStatusText, and multiline/special-char notes",
      fn: () => testIssue8ProveUiScopeAndNotes(),
    },
    {
      issueNumber: 9,
      id: "ISSUE-09",
      severity: "P2",
      title: "Windows broker stdin async write/error & close/abort single-settlement races",
      fn: () => testIssue9BrokerStdinAsyncRaces(tempRoot),
    },
    {
      issueNumber: 10,
      id: "ISSUE-10",
      severity: "P2",
      title: "Verified Git vs Checkwash bare git canonical executable identity",
      fn: () => testIssue10BareGitCanonicalIdentity(tempRoot),
    },
  ];

  console.log("=== Checkwash Lens 10 Review Issues Regression Suite ===");
  const results: IssueRegressionResult[] = [];
  const mainKeepAlive = setInterval(() => {}, 1000);

  try {
    for (const item of suite) {
      const start = Date.now();
      try {
        const { assertions, details } = await item.fn();
        const durationMs = Date.now() - start;
        results.push({
          issueNumber: item.issueNumber,
          id: item.id,
          severity: item.severity,
          title: item.title,
          passed: true,
          durationMs,
          assertionsCount: assertions,
          details,
        });
        console.log(`[PASS] ${item.id} [${item.severity}] ${item.title} (${assertions} assertions, ${durationMs}ms)`);
      } catch (err) {
        const durationMs = Date.now() - start;
        const msg = err instanceof Error ? err.stack || err.message : String(err);
        results.push({
          issueNumber: item.issueNumber,
          id: item.id,
          severity: item.severity,
          title: item.title,
          passed: false,
          durationMs,
          assertionsCount: 0,
          details: {},
          error: msg,
        });
        console.error(`[FAIL] ${item.id} [${item.severity}] ${item.title}: ${msg}`);
      }
    }
  } finally {
    clearInterval(mainKeepAlive);
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }

  const probe = (exe: string, args: string[]) => {
    const out = cp.spawnSync(exe, args, { encoding: "utf8", windowsHide: true });
    return out.status === 0 ? (out.stdout || out.stderr || "").trim() : "unknown";
  };
  const sourceSha = probe(GIT_EXE, ["-C", REPO_ROOT, "rev-parse", "HEAD"]);
  const gitDirty = probe(GIT_EXE, ["-C", REPO_ROOT, "status", "--porcelain"]).length > 0;
  const passedCount = results.filter((r) => r.passed).length;
  const exitCode = passedCount === results.length ? 0 : 1;

  const receipt = {
    suite: "Checkwash Lens Review — 10 Issues Regression Suite (ISSUE-01 .. ISSUE-10)",
    testLayer: "unit-integration-and-extension-command-harness",
    ...getPlatformExecutionMetadata(),
    nodeVersion: process.version,
    pythonExecutable: PYTHON_EXE,
    pythonVersion: probe(PYTHON_EXE, ["-I", "-S", "-B", "--version"]),
    gitExecutable: GIT_EXE,
    gitVersion: probe(GIT_EXE, ["--version"]),
    proveExecutable: PROVE_EXE,
    proveVersion: probe(PROVE_EXE, ["--version"]),
    bundledCheckwashPyzSha256: sha256File(path.join(REPO_ROOT, "bundled", "checkwash.pyz")),
    bundledBrokerSha256: sha256File(BROKER_EXE),
    sourceSha,
    workingTreeDirty: gitDirty,
    executedAt: new Date().toISOString(),
    exitCode,
    totalIssues: results.length,
    passedIssues: passedCount,
    failedIssues: results.length - passedCount,
    totalAssertions: results.reduce((acc, r) => acc + r.assertionsCount, 0),
    results,
  };

  fs.writeFileSync(RESULTS_FILE, JSON.stringify(receipt, null, 2), "utf8");
  console.log(`\nWrote 10-issue regression receipt to: ${RESULTS_FILE}`);

  if (exitCode !== 0) {
    process.exitCode = 1;
  }
}

void main();
