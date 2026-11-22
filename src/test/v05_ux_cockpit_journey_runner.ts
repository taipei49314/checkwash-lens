/**
 * src/test/v05_ux_cockpit_journey_runner.ts
 *
 * v0.5.0 Human Developer UX Cockpit & Real VS Code Playthrough Verification Suite
 * (`V05-C1` .. `V05-C6`).
 *
 * Verifies:
 * - V05-C1: Package manifest & VSIX UX hygiene (`viewsContainers.activitybar`, `media/icon.png`,
 *           `media/checkwash-activity.svg`, `scm/title` Pre-Check button, `view/item/context` inline
 *           Diff & Open File buttons, `editor/title` toolbar on `checkwash-rev:`, and strict
 *           lazy `activationEvents` with zero eager startup triggers).
 * - V05-C2: Zero-process Smart Git Range Preset Collector (`collectSmartGitRangePresetsZeroProcess`)
 *           across feature branches (`origin/main...HEAD`, `main...HEAD`), `packed-refs`, `main` branch
 *           deduplication, and adversarial symlink / oversized file rejection (0 child spawns).
 * - V05-C3: Sidebar TreeView Cockpit Ergonomics (`buildCheckwashTreeModel` + `getTreeItem`):
 *           Idle `Not Run` Quick-Start actions + auto-collapsed empty sections (`rootNodes.length === 4`),
 *           auto-expanding `Block` findings & Fast Guard hints with `ThemeIcon`/`ThemeColor`,
 *           plain-string tooltips (never `MarkdownString`), and `checkwashProveReplayable` gating.
 * - V05-C4: Status Bar Quick Actions Hub (`checkwashLens.openQuickActions`) & Interactive Smart Range
 *           Picker (`scanCommittedRange` / `runProveList` without `rangeArg`, including custom range input).
 * - V05-C5: Side-by-Side Diff (`checkwashLens.openFindingDiff` across Modified, Added, and Deleted files +
 *           `editor/title` `checkwash-rev:` invocation) and Jump to Editable File
 *           (`checkwashLens.openWorkspaceFileAtFinding` + symlink escape block + deleted-file diff fallback).
 * - V05-C6: Real Installed-VSIX Human Developer Playthrough inside real VS Code Desktop (`1.146.0`):
 *           Idle Activity Bar -> Working-Tree Pre-Check catches weakened/added/deleted tests ->
 *           Real `vscode.diff` (`TabInputTextDiff`) side-by-side comparison -> Jump from read-only
 *           `checkwash-rev:` to editable `file:` -> Developer fixes tests -> Re-run Pre-Check -> Green `Pass` ->
 *           Environment Doctor report (with optional Win32 `PrintWindow` visual screenshots).
 */

import * as assert from "assert";
import * as cp from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import Module = require("module");
import {
  ACTIVE_PLATFORM,
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
const EVIDENCE_DIR = resolvePlatformEvidenceDir(REPO_ROOT);
const RESULTS_FILE = path.join(EVIDENCE_DIR, "v05-ux-cockpit-journey-results.json");

const PYTHON_EXE = resolveTestPythonExe();
const GIT_EXE = resolveTestGitExe();
const PROVE_EXE = resolveTestProveExe();
const CODE_EXE = resolveTestVscodeExe();

const PKG_JSON = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8")) as {
  name: string;
  version: string;
  icon?: string;
  activationEvents: string[];
  contributes: {
    viewsContainers?: {
      activitybar?: Array<{ id: string; title: string; icon: string }>;
    };
    views?: Record<string, Array<{ id: string; name: string }>>;
    commands: Array<{ command: string; title: string; icon?: string }>;
    menus: Record<string, Array<{ command: string; when?: string; group?: string }>>;
  };
};

interface V05CaseResult {
  id: string;
  name: string;
  passed: boolean;
  durationMs: number;
  details: Record<string, unknown>;
  error?: string;
}

function sha256Buffer(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
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
    throw new Error("Invalid VSIX ZIP: EOCD not found");
  }
  const total = zipBuf.readUInt16LE(eocdOffset + 10);
  let cursor = zipBuf.readUInt32LE(eocdOffset + 16);
  const out: string[] = [];
  for (let i = 0; i < total; i++) {
    if (zipBuf.readUInt32LE(cursor) !== 0x02014b50) {
      throw new Error(`Invalid CD header at ${cursor}`);
    }
    const nameLen = zipBuf.readUInt16LE(cursor + 28);
    const extraLen = zipBuf.readUInt16LE(cursor + 30);
    const commentLen = zipBuf.readUInt16LE(cursor + 32);
    out.push(zipBuf.subarray(cursor + 46, cursor + 46 + nameLen).toString("utf8"));
    cursor += 46 + nameLen + extraLen + commentLen;
  }
  return out;
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

// ============================================================================
// Lightweight Programmable VS Code Mock for V05-C3..V05-C5
// ============================================================================

class MockUri {
  public readonly scheme: string;
  public readonly authority: string;
  public readonly path: string;
  public readonly query: string;
  public readonly fragment: string;
  public readonly fsPath: string;

  constructor(
    scheme: string,
    authority: string,
    uriPath: string,
    query: string = "",
    fragment: string = "",
    explicitFsPath?: string
  ) {
    this.scheme = scheme;
    this.authority = authority;
    this.path = uriPath;
    this.query = query;
    this.fragment = fragment;
    this.fsPath =
      explicitFsPath !== undefined
        ? explicitFsPath
        : scheme === "file"
          ? IS_WIN32 || /^\/[a-zA-Z]:/.test(uriPath)
            ? path.win32.normalize(uriPath.replace(/^\/([a-zA-Z]:)/, "$1"))
            : path.posix.normalize(uriPath)
          : uriPath;
  }

  public static file(filePath: string): MockUri {
    if (IS_WIN32 || /^[a-zA-Z]:[\\/]/.test(filePath)) {
      const resolved = path.win32
        .resolve(filePath)
        .replace(/^([A-Z]):/, (_m, d: string) => `${d.toLowerCase()}:`);
      return new MockUri("file", "", "/" + resolved.replace(/\\/g, "/"), "", "", resolved);
    }
    const resolvedPosix = path.posix.resolve(filePath);
    return new MockUri("file", "", resolvedPosix, "", "", resolvedPosix);
  }

  public static parse(value: string): MockUri {
    const match = /^([a-zA-Z0-9+.-]+):(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/.exec(
      value
    );
    if (!match) {
      return new MockUri("unknown", "", value, "", "", "");
    }
    const [, scheme, authority = "", rawPath = "", rawQuery = "", rawFragment = ""] = match;
    const dec = (s: string) => {
      try {
        return decodeURIComponent(s);
      } catch {
        return s;
      }
    };
    const dp = dec(rawPath);
    const dq = dec(rawQuery);
    const df = dec(rawFragment);
    if (scheme === "file") {
      if (IS_WIN32 || /^\/[a-zA-Z]:/.test(dp)) {
        return new MockUri(
          scheme,
          authority,
          dp,
          dq,
          df,
          path.win32.normalize(dp.replace(/^\/([a-zA-Z]:)/, "$1"))
        );
      }
      return new MockUri(scheme, authority, dp, dq, df, path.posix.normalize(dp));
    }
    return new MockUri(scheme, authority, dp, dq, df, dp);
  }

  public toString(): string {
    const encSegs = this.path
      .split("/")
      .map((s) => encodeURIComponent(s).replace(/%2B/gi, "+"))
      .join("/");
    if (this.scheme === "file") {
      const slash = this.fsPath.replace(/\\/g, "/");
      const lead = slash.startsWith("/") ? slash : `/${slash}`;
      return `file://${lead
        .split("/")
        .map((s) => encodeURIComponent(s).replace(/%3A/gi, ":"))
        .join("/")}`;
    }
    const q = this.query ? `?${encodeURIComponent(this.query).replace(/%2B/gi, "+")}` : "";
    return `${this.scheme}:${this.authority ? `//${this.authority}` : ""}${encSegs}${q}`;
  }
}

class MockPosition {
  constructor(
    public readonly line: number,
    public readonly character: number
  ) {}
}

class MockRange {
  public readonly start: MockPosition;
  public readonly end: MockPosition;
  constructor(
    a: number | MockPosition,
    b: number | MockPosition,
    c?: number,
    d?: number
  ) {
    if (typeof a === "number" && typeof b === "number") {
      this.start = new MockPosition(a, b);
      this.end = new MockPosition(c ?? a, d ?? b);
    } else {
      this.start = a as MockPosition;
      this.end = b as MockPosition;
    }
  }
}

class MockSelection extends MockRange {
  public readonly anchor: MockPosition;
  public readonly active: MockPosition;
  constructor(anchor: MockPosition, active: MockPosition) {
    super(anchor, active);
    this.anchor = anchor;
    this.active = active;
  }
}

class MockThemeColor {
  constructor(public readonly id: string) {}
}

class MockThemeIcon {
  constructor(
    public readonly id: string,
    public readonly color?: MockThemeColor
  ) {}
}

class MockTreeItem {
  public id?: string;
  public description?: string;
  public tooltip?: string;
  public contextValue?: string;
  public iconPath?: MockThemeIcon;
  public command?: { command: string; title: string; arguments?: unknown[] };
  constructor(
    public readonly label: string,
    public readonly collapsibleState: number = 0
  ) {}
}

class MockEventEmitter<T> {
  private listeners: Array<(e: T) => void> = [];
  public readonly event = (l: (e: T) => void) => {
    this.listeners.push(l);
    return {
      dispose: () => {
        this.listeners = this.listeners.filter((x) => x !== l);
      },
    };
  };
  public fire(data: T): void {
    for (const l of [...this.listeners]) l(data);
  }
  public dispose(): void {
    this.listeners = [];
  }
}

const mockHost = {
  isTrusted: true,
  workspaceFolders: [] as Array<{ uri: MockUri; name: string; index: number }>,
  textDocuments: [] as Array<{
    uri: MockUri;
    fsPath: string;
    version: number;
    isDirty: boolean;
    isClosed: boolean;
    lineCount: number;
    getText(): string;
  }>,
  activeTextEditor: undefined as
    | {
        document: { uri: MockUri; fsPath: string; getText(): string };
        selection: MockSelection;
      }
    | undefined,
  configGlobals: new Map<string, string>(),
  registeredCommands: new Map<string, (...args: unknown[]) => unknown>(),
  contentProviders: new Map<string, { provideTextDocumentContent(uri: MockUri): Promise<string> }>(),
  treeDataProviders: new Map<string, any>(),
  statusBarItem: {
    text: "",
    tooltip: undefined as string | undefined,
    command: undefined as string | undefined,
    shown: false,
  },
  diffCalls: [] as Array<{ left: MockUri; right: MockUri; title: string; options?: any }>,
  quickPickQueue: [] as Array<(items: any[], options?: any) => any>,
  inputBoxQueue: [] as Array<(options?: any) => string | undefined>,
  infoActionHandler: null as ((msg: string, items: string[]) => Promise<string | undefined>) | null,
  shownErrors: [] as string[],
  shownWarnings: [] as string[],
  shownInfos: [] as string[],
  lastShownDoc: null as any,
  lastEditorSelection: null as MockSelection | null,
  clipboardText: "",

  reset() {
    this.isTrusted = true;
    this.workspaceFolders = [];
    this.textDocuments = [];
    this.activeTextEditor = undefined;
    this.configGlobals.clear();
    this.registeredCommands.clear();
    this.contentProviders.clear();
    this.treeDataProviders.clear();
    this.statusBarItem = { text: "", tooltip: undefined, command: undefined, shown: false };
    this.diffCalls = [];
    this.quickPickQueue = [];
    this.inputBoxQueue = [];
    this.infoActionHandler = null;
    this.shownErrors = [];
    this.shownWarnings = [];
    this.shownInfos = [];
    this.lastShownDoc = null;
    this.lastEditorSelection = null;
    this.clipboardText = "";
  },
};

const mockVscode = {
  Uri: MockUri,
  Position: MockPosition,
  Range: MockRange,
  Selection: MockSelection,
  ThemeColor: MockThemeColor,
  ThemeIcon: MockThemeIcon,
  Diagnostic: class {
    public source?: string;
    public code?: string | number;
    constructor(
      public range: MockRange,
      public message: string,
      public severity: number
    ) {}
  },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
  MarkdownString: class {
    public isTrusted = false;
    constructor(public value: string = "") {}
  },
  Hover: class {
    constructor(
      public contents: any,
      public range?: MockRange
    ) {}
  },
  TreeItem: MockTreeItem,
  TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
  StatusBarAlignment: { Left: 1, Right: 2 },
  TextEditorRevealType: { Default: 0, InCenter: 1, InCenterIfOutsideViewport: 2, AtTop: 3 },
  ProgressLocation: { SourceControl: 1, Window: 10, Notification: 15 },
  ConfigurationTarget: { Global: 1, Workspace: 2, WorkspaceFolder: 3 },
  EventEmitter: MockEventEmitter,
  workspace: {
    get isTrusted() {
      return mockHost.isTrusted;
    },
    get workspaceFolders() {
      return mockHost.workspaceFolders;
    },
    get textDocuments() {
      return mockHost.textDocuments;
    },
    getConfiguration: () => ({
      inspect: (key: string) => ({
        globalValue: mockHost.configGlobals.get(key),
      }),
      get: (key: string, def?: unknown) => mockHost.configGlobals.get(key) ?? def,
      update: async (key: string, val: unknown) => {
        if (typeof val === "string") mockHost.configGlobals.set(key, val);
      },
    }),
    registerTextDocumentContentProvider: (scheme: string, provider: any) => {
      mockHost.contentProviders.set(scheme, provider);
      return { dispose: () => mockHost.contentProviders.delete(scheme) };
    },
    openTextDocument: async (uri: MockUri) => {
      const prov = mockHost.contentProviders.get(uri.scheme);
      const text = prov
        ? await prov.provideTextDocumentContent(uri)
        : uri.scheme === "file" && fs.existsSync(uri.fsPath)
          ? fs.readFileSync(uri.fsPath, "utf8")
          : "";
      const lines = text.split(/\r?\n/).length;
      return {
        uri,
        fsPath: uri.fsPath,
        version: 1,
        isDirty: false,
        isClosed: false,
        lineCount: lines,
        getText: () => text,
      };
    },
    onDidChangeTextDocument: () => ({ dispose: () => {} }),
    onDidCloseTextDocument: () => ({ dispose: () => {} }),
    onDidSaveTextDocument: () => ({ dispose: () => {} }),
    onDidGrantWorkspaceTrust: () => ({ dispose: () => {} }),
    onDidChangeWorkspaceFolders: () => ({ dispose: () => {} }),
    onDidChangeConfiguration: () => ({ dispose: () => {} }),
  },
  window: {
    get activeTextEditor() {
      return mockHost.activeTextEditor;
    },
    createStatusBarItem: () => ({
      get text() {
        return mockHost.statusBarItem.text;
      },
      set text(v: string) {
        mockHost.statusBarItem.text = v;
      },
      get tooltip() {
        return mockHost.statusBarItem.tooltip;
      },
      set tooltip(v: string | undefined) {
        mockHost.statusBarItem.tooltip = v;
      },
      get command() {
        return mockHost.statusBarItem.command;
      },
      set command(v: string | undefined) {
        mockHost.statusBarItem.command = v;
      },
      backgroundColor: undefined,
      show: () => {
        mockHost.statusBarItem.shown = true;
      },
      dispose: () => {},
    }),
    createTreeView: (id: string, opts: { treeDataProvider: any }) => {
      mockHost.treeDataProviders.set(id, opts.treeDataProvider);
      return { dispose: () => mockHost.treeDataProviders.delete(id) };
    },
    showErrorMessage: async (msg: string) => {
      mockHost.shownErrors.push(msg);
      return undefined;
    },
    showWarningMessage: async (msg: string) => {
      mockHost.shownWarnings.push(msg);
      return undefined;
    },
    showInformationMessage: async (msg: string, ...items: string[]) => {
      mockHost.shownInfos.push(msg);
      if (mockHost.infoActionHandler) {
        return mockHost.infoActionHandler(msg, items);
      }
      return undefined;
    },
    showQuickPick: async (items: any[], options?: any) => {
      const next = mockHost.quickPickQueue.shift();
      return next ? next(items, options) : undefined;
    },
    showInputBox: async (options?: any) => {
      const next = mockHost.inputBoxQueue.shift();
      return next ? next(options) : undefined;
    },
    showOpenDialog: async () => undefined,
    withProgress: async (_opts: any, task: any) =>
      task({ report: () => {} }, { isCancellationRequested: false, onCancellationRequested: () => ({ dispose: () => {} }) }),
    showTextDocument: async (doc: any) => {
      mockHost.lastShownDoc = doc;
      const sel = new MockSelection(new MockPosition(0, 0), new MockPosition(0, 0));
      const editor: any = {
        document: doc,
        selection: sel,
        revealRange: () => {},
      };
      const proxy = new Proxy(editor, {
        set(target, prop, value) {
          if (prop === "selection") {
            mockHost.lastEditorSelection = value as MockSelection;
          }
          target[prop] = value;
          return true;
        },
      });
      mockHost.activeTextEditor = proxy;
      return proxy;
    },
  },
  languages: {
    createDiagnosticCollection: () => ({
      set: () => {},
      clear: () => {},
      dispose: () => {},
    }),
    registerHoverProvider: () => ({ dispose: () => {} }),
  },
  commands: {
    registerCommand: (id: string, handler: (...args: unknown[]) => unknown) => {
      mockHost.registeredCommands.set(id, handler);
      return { dispose: () => mockHost.registeredCommands.delete(id) };
    },
    executeCommand: async <T = unknown>(id: string, ...args: unknown[]): Promise<T> => {
      if (id === "vscode.diff") {
        mockHost.diffCalls.push({
          left: args[0] as MockUri,
          right: args[1] as MockUri,
          title: String(args[2] ?? ""),
          options: args[3],
        });
        return undefined as T;
      }
      const fn = mockHost.registeredCommands.get(id);
      if (!fn) {
        throw new Error(`Command not registered: ${id}`);
      }
      return (await fn(...args)) as T;
    },
  },
  env: {
    remoteName: undefined,
    clipboard: {
      writeText: async (t: string) => {
        mockHost.clipboardText = t;
      },
      readText: async () => mockHost.clipboardText,
    },
  },
};

const origLoad = (Module as any)._load;
(Module as any)._load = function (request: string, parent: unknown, isMain: boolean) {
  if (request === "vscode") {
    return mockVscode;
  }
  return origLoad.call(this, request, parent, isMain);
};

import {
  activate,
  CHECKWASH_EMPTY_URI_SCHEME,
  collectSmartGitRangePresetsZeroProcess,
  deactivate,
  FindingDiffOpenResult,
  resolveSafeEditableWorkspaceFilePath,
} from "../extension";
import { ControllerViewSnapshot } from "../ui/commands";
import { CheckwashTreeNode } from "../ui/treeView";

function findTreeNodeById(
  nodes: readonly CheckwashTreeNode[],
  id: string
): CheckwashTreeNode | null {
  for (const n of nodes) {
    if (n.id === id) return n;
    const sub = findTreeNodeById(n.children, id);
    if (sub) return sub;
  }
  return null;
}

function collectAllNodes(nodes: readonly CheckwashTreeNode[]): CheckwashTreeNode[] {
  const out: CheckwashTreeNode[] = [];
  for (const n of nodes) {
    out.push(n);
    if (n.children.length > 0) out.push(...collectAllNodes(n.children));
  }
  return out;
}

function createPricingTestRepo(parentDir: string, folderName: string): {
  repoDir: string;
  baseOid: string;
} {
  const repoDir = path.join(parentDir, folderName);
  fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
  fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });

  runGit(repoDir, ["init", "-b", "main"]);
  runGit(repoDir, ["config", "user.name", "Checkwash UX Test"]);
  runGit(repoDir, ["config", "user.email", "ux@example.invalid"]);
  runGit(repoDir, ["config", "commit.gpgsign", "false"]);

  fs.writeFileSync(
    path.join(repoDir, "src", "pricing.py"),
    [
      "def calculate_total(subtotal_cents: int, coupon: str | None) -> int:",
      "    if subtotal_cents < 0:",
      "        raise ValueError('subtotal cannot be negative')",
      "    if coupon == 'VIP20':",
      "        return int(subtotal_cents * 0.8)",
      "    if coupon is not None:",
      "        raise ValueError(f'unknown coupon: {coupon}')",
      "    return subtotal_cents",
      "",
    ].join("\n"),
    "utf8"
  );

  fs.writeFileSync(
    path.join(repoDir, "tests", "test_pricing.py"),
    [
      "import pytest",
      "from src.pricing import calculate_total",
      "",
      "def test_vip_discount():",
      "    assert calculate_total(200, 'VIP20') == 160",
      "    assert calculate_total(100, None) == 100",
      "",
      "def test_invalid_coupon_rejected():",
      "    with pytest.raises(ValueError):",
      "        calculate_total(100, 'BAD_CODE')",
      "",
    ].join("\n"),
    "utf8"
  );

  fs.writeFileSync(
    path.join(repoDir, "tests", "test_refund_guard.py"),
    [
      "import pytest",
      "from src.pricing import calculate_total",
      "",
      "def test_negative_subtotal_raises():",
      "    with pytest.raises(ValueError):",
      "        calculate_total(-50, None)",
      "",
    ].join("\n"),
    "utf8"
  );

  runGit(repoDir, ["add", "."]);
  runGit(repoDir, ["commit", "-m", "feat: baseline pricing engine and strict tests"]);
  const baseOid = runGit(repoDir, ["rev-parse", "HEAD"]);
  return { repoDir, baseOid };
}

// ============================================================================
// V05-C1: Package Manifest, Activity Bar, SCM Pre-Check & VSIX Media Hygiene
// ============================================================================

async function testV05C1ManifestAndVsixMediaHygiene(): Promise<Record<string, unknown>> {
  assert.match(PKG_JSON.version, /^\d+\.\d+\.\d+$/, "Expected SemVer package.json version");
  const versionLocalPath = path.join(REPO_ROOT, "VERSION-LOCAL.json");
  if (fs.existsSync(versionLocalPath)) {
    const versionLocal = JSON.parse(fs.readFileSync(versionLocalPath, "utf8")) as {
      publicVersion: string;
      publicSeries: string;
      localVersion: string;
    };
    assert.strictEqual(
      versionLocal.publicVersion,
      PKG_JSON.version,
      "VERSION-LOCAL.json publicVersion must match package.json version"
    );
    assert.strictEqual(
      PKG_JSON.version.startsWith(`${versionLocal.publicSeries}.`),
      true,
      "package.json version must match VERSION-LOCAL.json publicSeries"
    );
  }
  assert.strictEqual(PKG_JSON.icon, "media/icon.png", "Expected package.json icon media/icon.png");

  // 1. Verify Activity Bar container & view registration
  const activityContainers = PKG_JSON.contributes.viewsContainers?.activitybar ?? [];
  assert.strictEqual(activityContainers.length, 1, "Expected 1 Activity Bar container");
  assert.strictEqual(activityContainers[0].id, "checkwash-lens");
  assert.strictEqual(activityContainers[0].icon, "media/checkwash-activity.svg");

  const containerViews = PKG_JSON.contributes.views?.["checkwash-lens"] ?? [];
  assert.strictEqual(containerViews.length, 1);
  assert.strictEqual(containerViews[0].id, "checkwashLens.findingsView");
  assert.strictEqual(
    PKG_JSON.contributes.views?.["explorer"],
    undefined,
    "checkwashLens.findingsView must live in its dedicated Activity Bar container, not buried in explorer"
  );

  // 2. Verify strict lazy activationEvents (no eager triggers that would violate B01)
  for (const ev of PKG_JSON.activationEvents) {
    assert.strictEqual(
      ev.startsWith("onCommand:checkwashLens.") || ev === "onView:checkwashLens.findingsView",
      true,
      `Forbidden eager activationEvent in package.json: ${ev}`
    );
  }
  assert.strictEqual(PKG_JSON.activationEvents.length, 16);
  assert.strictEqual(PKG_JSON.contributes.commands.length, 15);

  // 3. Verify SCM title Pre-Check button, TreeItem inline buttons, and editor/title buttons
  const scmTitle = PKG_JSON.contributes.menus["scm/title"] ?? [];
  assert.strictEqual(
    scmTitle.some((m) => m.command === "checkwashLens.scanUncommittedSnapshot"),
    true,
    "Expected scanUncommittedSnapshot in menus['scm/title']"
  );

  const itemContext = PKG_JSON.contributes.menus["view/item/context"] ?? [];
  assert.strictEqual(
    itemContext.some(
      (m) =>
        m.command === "checkwashLens.openFindingDiff" &&
        (m.group ?? "").startsWith("inline")
    ),
    true
  );
  assert.strictEqual(
    itemContext.some(
      (m) =>
        m.command === "checkwashLens.openWorkspaceFileAtFinding" &&
        (m.group ?? "").startsWith("inline")
    ),
    true
  );

  const editorTitle = PKG_JSON.contributes.menus["editor/title"] ?? [];
  assert.strictEqual(
    editorTitle.some(
      (m) =>
        m.command === "checkwashLens.openFindingDiff" &&
        m.when === "resourceScheme == checkwash-rev"
    ),
    true
  );
  assert.strictEqual(
    editorTitle.some(
      (m) =>
        m.command === "checkwashLens.openWorkspaceFileAtFinding" &&
        m.when === "resourceScheme == checkwash-rev"
    ),
    true
  );

  // 4. Verify PNG signature (128x128 RGBA) and SVG content
  const pngBuf = fs.readFileSync(path.join(REPO_ROOT, "media", "icon.png"));
  assert.strictEqual(pngBuf.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])), true);
  assert.strictEqual(pngBuf.readUInt32BE(16), 128, "icon.png width must be 128");
  assert.strictEqual(pngBuf.readUInt32BE(20), 128, "icon.png height must be 128");

  const svgText = fs.readFileSync(path.join(REPO_ROOT, "media", "checkwash-activity.svg"), "utf8");
  assert.strictEqual(svgText.includes('stroke="currentColor"'), true);

  // 5. Build or inspect platform VSIX & verify media assets and manifest <Icon>
  const vsixFilename = `${PKG_JSON.name}-${PKG_JSON.version}-${ACTIVE_VSIX_TARGET}.vsix`;
  const vsixPath = path.join(REPO_ROOT, vsixFilename);
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
  const vsixBuf = fs.readFileSync(vsixPath);
  const entries = readZipEntryNames(vsixBuf);
  assert.strictEqual(entries.includes("extension/media/icon.png"), true);
  assert.strictEqual(entries.includes("extension/media/checkwash-activity.svg"), true);
  assert.strictEqual(
    entries.includes(`extension/bundled/${resolveBundledBrokerFilename()}`),
    true
  );

  return {
    vsixFilename,
    vsixBytes: vsixBuf.length,
    vsixSha256: sha256Buffer(vsixBuf),
    pngBytes: pngBuf.length,
    svgBytes: Buffer.byteLength(svgText, "utf8"),
    commandCount: PKG_JSON.contributes.commands.length,
  };
}

// ============================================================================
// V05-C2: Zero-Process Smart Git Range Preset Collector
// ============================================================================

async function testV05C2ZeroProcessSmartGitRangePresets(): Promise<Record<string, unknown>> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cw-v05-c2-"));
  try {
    const { repoDir, baseOid } = createPricingTestRepo(tmpDir, "repo-presets");

    // 1. On `main` branch itself: `main...HEAD` must NOT be suggested redundantly
    const onMainPresets = collectSmartGitRangePresetsZeroProcess(repoDir);
    assert.strictEqual(
      onMainPresets.some((p) => p.rangeSpec === "main...HEAD"),
      false,
      "Should not suggest main...HEAD when HEAD is already on main"
    );
    assert.strictEqual(onMainPresets[0].rangeSpec, "HEAD~1..HEAD");
    assert.strictEqual(onMainPresets.some((p) => Boolean(p.isCustomInput)), true);

    // 2. Switch to feature branch `feat/vip-tier` and add `origin/main` + `packed-refs` `develop`
    runGit(repoDir, ["checkout", "-b", "feat/vip-tier"]);
    const originDir = path.join(repoDir, ".git", "refs", "remotes", "origin");
    fs.mkdirSync(originDir, { recursive: true });
    fs.writeFileSync(path.join(originDir, "main"), `${baseOid}\n`, "utf8");
    fs.writeFileSync(
      path.join(repoDir, ".git", "packed-refs"),
      `# pack-refs with: peeled fully-peeled sorted\n${baseOid} refs/heads/develop\n`,
      "utf8"
    );

    const onFeaturePresets = collectSmartGitRangePresetsZeroProcess(repoDir);
    const specs = onFeaturePresets.map((p) => p.rangeSpec || "CUSTOM");
    assert.strictEqual(specs[0], "origin/main...HEAD");
    assert.strictEqual(specs[1], "main...HEAD");
    assert.strictEqual(specs.includes("develop...HEAD"), true);
    assert.strictEqual(specs.includes("HEAD~1..HEAD"), true);
    assert.strictEqual(specs[specs.length - 1], "CUSTOM");

    // 3. Adversarial oversized packed-refs (> 256 KiB) is safely ignored
    fs.writeFileSync(
      path.join(repoDir, ".git", "packed-refs"),
      `${baseOid} refs/heads/trunk\n` + "#".repeat(300_000),
      "utf8"
    );
    const afterOversized = collectSmartGitRangePresetsZeroProcess(repoDir);
    assert.strictEqual(
      afterOversized.some((p) => p.rangeSpec === "trunk...HEAD"),
      false,
      "Oversized packed-refs (>256 KiB) must be bounded and ignored"
    );

    return {
      onMainSpecs: onMainPresets.map((p) => p.rangeSpec || "CUSTOM"),
      onFeatureSpecs: specs,
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ============================================================================
// V05-C3: TreeView Cockpit Ergonomics (Quick-Start, Auto-Collapse, ThemeIcons)
// ============================================================================

async function testV05C3TreeViewCockpitErgonomics(): Promise<Record<string, unknown>> {
  mockHost.reset();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cw-v05-c3-"));
  try {
    const { repoDir } = createPricingTestRepo(tmpDir, "repo-tree");
    mockHost.workspaceFolders = [{ uri: MockUri.file(repoDir), name: "repo-tree", index: 0 }];
    mockHost.configGlobals.set("pythonPath", PYTHON_EXE);
    mockHost.configGlobals.set("gitPath", GIT_EXE);

    const subs: Array<{ dispose(): unknown }> = [];
    const ctx = {
      extensionPath: REPO_ROOT,
      subscriptions: subs,
    } as any;

    const controller = activate(ctx);
    const treeProvider = mockHost.treeDataProviders.get("checkwashLens.findingsView");
    assert.ok(treeProvider, "Expected TreeDataProvider to be registered");

    // 1. Idle `Not Run` state: 4 root nodes, verdict_root Expanded with Quick Start, 0-item siblings Collapsed
    const idleRoots: CheckwashTreeNode[] = treeProvider.getChildren();
    assert.strictEqual(idleRoots.length, 4);
    const idleVerdictItem = treeProvider.getTreeItem(idleRoots[0]);
    const idleFindingsItem = treeProvider.getTreeItem(idleRoots[1]);
    const idleFgItem = treeProvider.getTreeItem(idleRoots[2]);
    const idleProveItem = treeProvider.getTreeItem(idleRoots[3]);

    assert.strictEqual(idleVerdictItem.collapsibleState, 2, "verdict_root must start Expanded");
    assert.strictEqual(idleFindingsItem.collapsibleState, 1, "Empty findings_root must start Collapsed");
    assert.strictEqual(idleFindingsItem.id, "findings_root::1");
    assert.strictEqual(idleFgItem.collapsibleState, 0, "0-child fast_guard_root starts None (compact)");
    assert.strictEqual(idleProveItem.collapsibleState, 0, "0-child prove_root starts None (compact)");
    assert.strictEqual(idleVerdictItem.iconPath?.id, "shield");

    const quickStartGroup = findTreeNodeById(idleRoots, "verdict_quickstart_group");
    assert.ok(quickStartGroup, "Expected Quick Start group under idle verdict_root");
    assert.strictEqual(quickStartGroup.children.length, 5);
    assert.strictEqual(
      quickStartGroup.children[0].command?.commandId,
      "checkwashLens.scanUncommittedSnapshot"
    );

    // 2. Introduce uncommitted weakening + skip decorator and run Pre-Check
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_pricing.py"),
      [
        "import pytest",
        "from src.pricing import calculate_total",
        "",
        "def test_vip_discount():",
        "    assert True",
        "",
        "@pytest.mark.skip(reason='skip check')",
        "def test_invalid_coupon_rejected():",
        "    with pytest.raises(ValueError):",
        "        calculate_total(100, 'BAD_CODE')",
        "",
      ].join("\n"),
      "utf8"
    );

    const blockSnap = await mockVscode.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanUncommittedSnapshot",
      "worktree"
    );
    assert.strictEqual(blockSnap?.evaluatedState.state, "Block");

    const activeRoots: CheckwashTreeNode[] = treeProvider.getChildren();
    assert.strictEqual(
      findTreeNodeById(activeRoots, "verdict_quickstart_group"),
      null,
      "Quick Start group must hide once a scan result is active"
    );
    const activeVerdictItem = treeProvider.getTreeItem(activeRoots[0]);
    const activeFindingsItem = treeProvider.getTreeItem(activeRoots[1]);
    const activeFgItem = treeProvider.getTreeItem(activeRoots[2]);

    assert.strictEqual(activeVerdictItem.iconPath?.id, "error");
    assert.strictEqual(activeFindingsItem.collapsibleState, 2, "Non-empty findings_root must auto-expand");
    assert.strictEqual(
      activeFindingsItem.id,
      "findings_root::2",
      "Dynamic TreeItem.id suffix must bust VS Code cached collapsed state when findings appear"
    );
    assert.strictEqual(activeFgItem.collapsibleState, 2, "Non-empty fast_guard_root must auto-expand");

    // Verify finding TreeItems have scannable `basename(:line) · RULE` labels, contextValue="checkwashFinding", ThemeIcon, and plain-string tooltip
    const firstFindingNode = findTreeNodeById(activeRoots, "cw_finding_0");
    const secondFindingNode = findTreeNodeById(activeRoots, "cw_finding_1");
    assert.ok(firstFindingNode && secondFindingNode);
    assert.strictEqual(
      firstFindingNode.label.includes(".py") && firstFindingNode.label.includes(" · "),
      true,
      `Expected scannable 'basename · RULE' label, got: ${firstFindingNode.label}`
    );
    assert.strictEqual(
      secondFindingNode.label.includes(".py:") && secondFindingNode.label.includes(" · "),
      true,
      `Expected scannable 'basename:line · RULE' label, got: ${secondFindingNode.label}`
    );
    const firstFindingItem = treeProvider.getTreeItem(firstFindingNode);
    assert.strictEqual(firstFindingItem.contextValue, "checkwashFinding");
    assert.strictEqual(typeof firstFindingItem.tooltip, "string");
    assert.strictEqual(
      firstFindingItem.command?.command,
      "checkwashLens.openImmutableRevision"
    );

    // Verify imported external Prove report never sets `checkwashProveReplayable` or `command`
    const proveFixturePath = path.join(
      REPO_ROOT,
      "fixtures",
      "phase0",
      "a11-prove-mixed-coexisting.json"
    );
    const offlineImportRes = controller.viewOfflineReportFileReadOnly(proveFixturePath);
    assert.strictEqual(offlineImportRes.ok, true, "Expected Prove fixture import to succeed");
    const afterImportRoots: CheckwashTreeNode[] = treeProvider.getChildren();
    const proveRootAfterImport = findTreeNodeById(afterImportRoots, "prove_root")!;
    assert.strictEqual(treeProvider.getTreeItem(proveRootAfterImport).collapsibleState, 2);
    for (const n of collectAllNodes(proveRootAfterImport.children)) {
      const ti = treeProvider.getTreeItem(n);
      assert.strictEqual(ti.contextValue, undefined, `Imported Prove node ${n.id} must not be replayable`);
      assert.strictEqual(ti.command, undefined, `Imported Prove node ${n.id} must have no command`);
      if (ti.tooltip !== undefined) {
        assert.strictEqual(typeof ti.tooltip, "string");
      }
    }

    await deactivate();
    for (const s of subs) s.dispose();

    return {
      idleQuickStartItems: quickStartGroup.children.map((c) => c.id),
      activeFindingCount: blockSnap.enrichedFindings.length,
      fastGuardHintCount: blockSnap.fastGuardResult?.hints.length ?? 0,
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ============================================================================
// V05-C4: Status Bar Quick Actions Hub & Smart Range Picker Execution
// ============================================================================

async function testV05C4QuickActionsHubAndRangePicker(): Promise<Record<string, unknown>> {
  mockHost.reset();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cw-v05-c4-"));
  try {
    const { repoDir } = createPricingTestRepo(tmpDir, "repo-hub");
    // Create feature branch `feat/discount` with a weakened commit ahead of `main`
    runGit(repoDir, ["checkout", "-b", "feat/discount"]);
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_pricing.py"),
      [
        "import pytest",
        "from src.pricing import calculate_total",
        "",
        "def test_vip_discount():",
        "    assert True",
        "",
        "def test_invalid_coupon_rejected():",
        "    with pytest.raises(ValueError):",
        "        calculate_total(100, 'BAD_CODE')",
        "",
      ].join("\n"),
      "utf8"
    );
    runGit(repoDir, ["add", "."]);
    runGit(repoDir, ["commit", "-m", "chore: weaken vip discount test"]);

    mockHost.workspaceFolders = [{ uri: MockUri.file(repoDir), name: "repo-hub", index: 0 }];
    mockHost.configGlobals.set("pythonPath", PYTHON_EXE);
    mockHost.configGlobals.set("gitPath", GIT_EXE);

    const subs: Array<{ dispose(): unknown }> = [];
    activate({ extensionPath: REPO_ROOT, subscriptions: subs } as any);

    assert.strictEqual(mockHost.statusBarItem.command, "checkwashLens.openQuickActions");

    // 1. Click Status Bar -> `openQuickActions` -> pick `Scan Branch or Custom Git Range...` -> pick `main...HEAD`!
    let hubActionIdsOnIdle: string[] = [];
    let rangePresetsShown: string[] = [];
    mockHost.quickPickQueue.push(
      (items) => {
        hubActionIdsOnIdle = items.map((i: any) => i.actionId);
        return items.find((i: any) => i.actionId === "scan-range-picker");
      },
      (presets) => {
        rangePresetsShown = presets.map((p: any) => p.rangeSpec || "CUSTOM");
        return presets.find((p: any) => p.rangeSpec === "main...HEAD");
      }
    );

    const scanViaHubSnap = await mockVscode.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.openQuickActions"
    );
    assert.strictEqual(scanViaHubSnap?.evaluatedState.state, "Block");
    assert.strictEqual(
      scanViaHubSnap?.evaluatedState.joinedReport?.scanIdentity.rawRangeSpec,
      "main...HEAD"
    );
    assert.strictEqual(rangePresetsShown.includes("main...HEAD"), true);

    // 2. Now click Status Bar again while in `Block` state: Quick Actions must now expose
    //    `finding-diff`, `finding-edit`, and `copy-diet`!
    let hubActionIdsOnBlock: string[] = [];
    mockHost.quickPickQueue.push((items) => {
      hubActionIdsOnBlock = items.map((i: any) => i.actionId);
      return items.find((i: any) => i.actionId === "copy-diet");
    });
    await mockVscode.commands.executeCommand("checkwashLens.openQuickActions");
    assert.strictEqual(hubActionIdsOnBlock.includes("finding-diff"), true);
    assert.strictEqual(hubActionIdsOnBlock.includes("finding-edit"), true);
    assert.strictEqual(hubActionIdsOnBlock.includes("copy-diet"), true);
    assert.strictEqual(mockHost.clipboardText.includes("test_pricing.py"), true);

    // 3. Test selecting `Custom Git Range...` in `scanCommittedRange()` -> falls through to `showInputBox`
    let inputBoxPrompted = false;
    mockHost.quickPickQueue.push((presets) => presets.find((p: any) => Boolean(p.isCustomInput)));
    mockHost.inputBoxQueue.push(() => {
      inputBoxPrompted = true;
      return "HEAD~1..HEAD";
    });
    const customRangeSnap = await mockVscode.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanCommittedRange"
    );
    assert.strictEqual(inputBoxPrompted, true);
    assert.strictEqual(
      customRangeSnap?.evaluatedState.joinedReport?.scanIdentity.rawRangeSpec,
      "HEAD~1..HEAD"
    );

    await deactivate();
    for (const s of subs) s.dispose();

    return {
      hubActionIdsOnIdle,
      hubActionIdsOnBlock,
      rangePresetsShown,
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ============================================================================
// V05-C5: Side-by-Side Diff (Modified/Added/Deleted) & Safe Editable File Jump
// ============================================================================

async function testV05C5DiffAndEditableFileSecurity(): Promise<Record<string, unknown>> {
  mockHost.reset();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cw-v05-c5-"));
  try {
    const { repoDir } = createPricingTestRepo(tmpDir, "repo-diff");
    const outsideSecretFile = path.join(tmpDir, "outside_secret.py");
    fs.writeFileSync(outsideSecretFile, "SECRET = 1\n", "utf8");

    // Working-tree edits:
    // 1) Modified: `tests/test_pricing.py` weakened to `assert True`
    // 2) Added: `tests/test_added_weak.py` (`def test_new(): assert True`)
    // 3) Deleted: `tests/test_refund_guard.py` removed!
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_pricing.py"),
      [
        "import pytest",
        "from src.pricing import calculate_total",
        "",
        "def test_vip_discount():",
        "    assert True",
        "",
        "def test_invalid_coupon_rejected():",
        "    with pytest.raises(ValueError):",
        "        calculate_total(100, 'BAD_CODE')",
        "",
      ].join("\n"),
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_added_weak.py"),
      [
        "import pytest",
        "",
        "@pytest.mark.skip(reason='new test skipped immediately')",
        "def test_new_smoke():",
        "    assert True",
        "",
      ].join("\n"),
      "utf8"
    );
    fs.unlinkSync(path.join(repoDir, "tests", "test_refund_guard.py"));

    mockHost.workspaceFolders = [{ uri: MockUri.file(repoDir), name: "repo-diff", index: 0 }];
    mockHost.configGlobals.set("pythonPath", PYTHON_EXE);
    mockHost.configGlobals.set("gitPath", GIT_EXE);

    const subs: Array<{ dispose(): unknown }> = [];
    activate({ extensionPath: REPO_ROOT, subscriptions: subs } as any);

    const snap = await mockVscode.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanUncommittedSnapshot",
      "worktree"
    );
    assert.strictEqual(snap?.evaluatedState.state, "Block");

    const allNodes = collectAllNodes(snap.treeNodes);
    const modNode = allNodes.find((n) => n.findingNav?.relativePath === "tests/test_pricing.py");
    const addNode = allNodes.find(
      (n) => n.findingNav?.relativePath === "tests/test_added_weak.py"
    );
    const delNode = allNodes.find(
      (n) => n.findingNav?.relativePath === "tests/test_refund_guard.py"
    );
    assert.ok(modNode && addNode && delNode, "Expected modified, added, and deleted finding nodes");

    // 1. Modified file diff: both sides use `checkwash-rev:`
    const modDiff = await mockVscode.commands.executeCommand<FindingDiffOpenResult>(
      "checkwashLens.openFindingDiff",
      modNode
    );
    assert.ok(modDiff);
    assert.strictEqual(modDiff.leftUri.startsWith("checkwash-rev:/"), true);
    assert.strictEqual(modDiff.rightUri.startsWith("checkwash-rev:/"), true);

    // 2. Added file diff: left side uses `checkwash-empty:`, right side uses `checkwash-rev:`
    const addDiff = await mockVscode.commands.executeCommand<FindingDiffOpenResult>(
      "checkwashLens.openFindingDiff",
      addNode
    );
    assert.ok(addDiff);
    assert.strictEqual(addDiff.leftUri.startsWith(`${CHECKWASH_EMPTY_URI_SCHEME}:/`), true);
    assert.strictEqual(addDiff.rightUri.startsWith("checkwash-rev:/"), true);

    // 3. Deleted file diff: left side uses `checkwash-rev:`, right side uses `checkwash-empty:`
    const delDiff = await mockVscode.commands.executeCommand<FindingDiffOpenResult>(
      "checkwashLens.openFindingDiff",
      delNode
    );
    assert.ok(delDiff);
    assert.strictEqual(delDiff.leftUri.startsWith("checkwash-rev:/"), true);
    assert.strictEqual(delDiff.rightUri.startsWith(`${CHECKWASH_EMPTY_URI_SCHEME}:/`), true);

    // 4. Deleted file `openWorkspaceFileAtFinding`: offers "Compare Base ↔ Head Diff" gracefully!
    const diffCountBeforeDeletedJump = mockHost.diffCalls.length;
    mockHost.infoActionHandler = async (_msg, items) =>
      items.find((i) => i === "Compare Base ↔ Head Diff");
    const delJumpRes = await mockVscode.commands.executeCommand(
      "checkwashLens.openWorkspaceFileAtFinding",
      delNode
    );
    mockHost.infoActionHandler = null;
    assert.strictEqual(delJumpRes, null);
    assert.strictEqual(
      mockHost.diffCalls.length,
      diffCountBeforeDeletedJump + 1,
      "Clicking 'Compare Base ↔ Head Diff' on deleted file prompt must open the Base vs Empty diff"
    );

    // 5. Jump from open `checkwash-rev:` editor (`editor/title` invocation passing `vscode.Uri`) to editable file
    await mockVscode.commands.executeCommand(
      "checkwashLens.openImmutableRevision",
      modNode.findingNav!.preferredRevisionUri,
      modNode.findingNav!.revealLine1Based
    );
    assert.strictEqual(mockHost.activeTextEditor?.document.uri.scheme, "checkwash-rev");

    const openedEditable = await mockVscode.commands.executeCommand<any>(
      "checkwashLens.openWorkspaceFileAtFinding",
      mockHost.activeTextEditor?.document.uri
    );
    assert.ok(openedEditable);
    assert.strictEqual(openedEditable.uri.scheme, "file");
    assert.strictEqual(
      mockHost.lastEditorSelection?.start.line,
      (modNode.findingNav!.revealLine1Based ?? 1) - 1
    );

    // 6. Security boundary: path traversal (`../outside_secret.py`) and symlink escape are strictly blocked
    const traversalCheck = resolveSafeEditableWorkspaceFilePath(
      repoDir,
      "../outside_secret.py",
      mockHost.workspaceFolders as any
    );
    assert.strictEqual(traversalCheck.ok, false);

    let symlinkTested = false;
    const symlinkTargetInRepo = path.join(repoDir, "tests", "symlink_escape.py");
    try {
      fs.symlinkSync(outsideSecretFile, symlinkTargetInRepo, "file");
      symlinkTested = true;
    } catch {
      // On Windows without Developer Mode symlink privilege, skip symlink creation gracefully
    }
    if (symlinkTested) {
      const symCheck = resolveSafeEditableWorkspaceFilePath(
        repoDir,
        "tests/symlink_escape.py",
        mockHost.workspaceFolders as any
      );
      assert.strictEqual(symCheck.ok, false, "Symlink inside workspace must be rejected");
      assert.strictEqual(
        symCheck.ok === false && symCheck.error.includes("symbolic link"),
        true
      );
    }

    await deactivate();
    for (const s of subs) s.dispose();

    return {
      diffCallsCount: mockHost.diffCalls.length,
      modifiedDiffTitle: modDiff.title,
      addedLeftScheme: MockUri.parse(addDiff.leftUri).scheme,
      deletedRightScheme: MockUri.parse(delDiff.rightUri).scheme,
      symlinkTested,
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ============================================================================
// V05-C6: Real VS Code Desktop (1.146.0) 6-Act Human Developer Playthrough
// ============================================================================

function findVsCodeCliJs(codeExePath: string): string {
  const codeDir = path.dirname(codeExePath);
  const direct = path.join(codeDir, "resources", "app", "out", "cli.js");
  if (fs.existsSync(direct)) return direct;
  for (const entry of fs.readdirSync(codeDir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      const sub = path.join(codeDir, entry.name, "resources", "app", "out", "cli.js");
      if (fs.existsSync(sub)) return sub;
    }
  }
  throw new Error(`Cannot locate VS Code cli.js under ${codeDir}`);
}

function createRealVscodePlaythroughDriver(tempRoot: string): {
  driverDir: string;
  runnerJsPath: string;
} {
  const driverDir = path.join(tempRoot, "v05-ux-playthrough-driver");
  fs.mkdirSync(driverDir, { recursive: true });
  fs.writeFileSync(
    path.join(driverDir, "package.json"),
    JSON.stringify(
      {
        name: "v05-ux-playthrough-driver",
        publisher: "local-test",
        version: "0.0.1",
        engines: { vscode: "^1.96.0" },
        main: "./extension.js",
      },
      null,
      2
    ),
    "utf8"
  );
  fs.writeFileSync(
    path.join(driverDir, "extension.js"),
    "exports.activate = function() {}; exports.deactivate = function() {};\n",
    "utf8"
  );

  const runnerJsPath = path.join(driverDir, "playthrough_runner.js");
  const winCapturePsScriptPath = path.join(driverDir, "capture_window.ps1");

  if (IS_WIN32) {
    fs.writeFileSync(
      winCapturePsScriptPath,
      [
        "param([string]$TitleMatch, [string]$OutPng)",
        "$ErrorActionPreference = 'Stop'",
        "Add-Type -AssemblyName System.Drawing",
        "Add-Type @'",
        "using System;",
        "using System.Runtime.InteropServices;",
        "using System.Text;",
        "public class WinCap {",
        "  public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);",
        "  [DllImport(\"user32.dll\")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);",
        "  [DllImport(\"user32.dll\")] public static extern bool IsWindowVisible(IntPtr hWnd);",
        "  [DllImport(\"user32.dll\", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);",
        "  [DllImport(\"user32.dll\")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);",
        "  [DllImport(\"user32.dll\")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);",
        "  [DllImport(\"user32.dll\")] public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);",
        "  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }",
        "}",
        "'@",
        "$script:targetHwnd = [IntPtr]::Zero",
        "[WinCap]::EnumWindows({ param($h, $l)",
        "  if ([WinCap]::IsWindowVisible($h)) {",
        "    $sb = New-Object System.Text.StringBuilder 512",
        "    [void][WinCap]::GetWindowText($h, $sb, $sb.Capacity)",
        "    $t = $sb.ToString()",
        "    if ($t -like \"*$TitleMatch*\") {",
        "      $script:targetHwnd = $h",
        "      return $false",
        "    }",
        "  }",
        "  return $true",
        "}, [IntPtr]::Zero) | Out-Null",
        "if ($script:targetHwnd -eq [IntPtr]::Zero) { throw \"Window matching '$TitleMatch' not found\" }",
        "$rect = New-Object WinCap+RECT",
        "[void][WinCap]::GetWindowRect($script:targetHwnd, [ref]$rect)",
        "$w = $rect.Right - $rect.Left",
        "$h = $rect.Bottom - $rect.Top",
        "if ($w -lt 1280 -or $h -lt 780) {",
        "  [void][WinCap]::MoveWindow($script:targetHwnd, 60, 40, 1440, 900, $true)",
        "  Start-Sleep -Milliseconds 350",
        "  [void][WinCap]::GetWindowRect($script:targetHwnd, [ref]$rect)",
        "  $w = $rect.Right - $rect.Left",
        "  $h = $rect.Bottom - $rect.Top",
        "}",
        "$bmp = New-Object System.Drawing.Bitmap($w, $h)",
        "$g = [System.Drawing.Graphics]::FromImage($bmp)",
        "$hdc = $g.GetHdc()",
        "[void][WinCap]::PrintWindow($script:targetHwnd, $hdc, 2)",
        "$g.ReleaseHdc($hdc)",
        "$g.Dispose()",
        "$bmp.Save($OutPng, [System.Drawing.Imaging.ImageFormat]::Png)",
        "$bmp.Dispose()",
      ].join("\r\n"),
      "utf8"
    );
  }

  const runnerJsSource = `
"use strict";
const assert = require("assert");
const cp = require("child_process");
const fs = require("fs");
const path = require("path");
const vscode = require("vscode");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function findNode(nodes, id) {
  for (const n of nodes || []) {
    if (n.id === id) return n;
    const sub = findNode(n.children, id);
    if (sub) return sub;
  }
  return null;
}

function collectAll(nodes) {
  const out = [];
  for (const n of nodes || []) {
    out.push(n);
    if (n.children && n.children.length > 0) out.push(...collectAll(n.children));
  }
  return out;
}

function captureWinScreenshotIfConfigured(cfg, stepFilename) {
  if (!cfg.screenshotDir || process.platform !== "win32") {
    return null;
  }
  fs.mkdirSync(cfg.screenshotDir, { recursive: true });
  const outPath = path.join(cfg.screenshotDir, stepFilename);
  const res = cp.spawnSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      ${JSON.stringify(winCapturePsScriptPath)},
      "-TitleMatch",
      cfg.windowTitleMatch,
      "-OutPng",
      outPath,
    ],
    { encoding: "utf8", windowsHide: true, timeout: 15000 }
  );
  if (res.status === 0 && fs.existsSync(outPath)) {
    return outPath;
  }
  return null;
}

exports.run = async function run() {
  const cfg = JSON.parse(fs.readFileSync(process.env.CW_V05_PLAYTHROUGH_CONFIG, "utf8"));
  const screenshots = [];

  const ext = vscode.extensions.getExtension("taipei49314.checkwash-lens");
  assert.ok(ext, "Installed extension taipei49314.checkwash-lens not found in real VS Code");

  // Act 1: Lazy startup check -> Open Checkwash Lens Activity Bar Container!
  const wasActiveOnStartup = ext.isActive;
  try {
    await vscode.commands.executeCommand("workbench.action.closeAuxiliaryBar");
  } catch {}
  await vscode.commands.executeCommand("workbench.view.extension.checkwash-lens");
  await sleep(600);

  const controller = await ext.activate();
  assert.ok(controller, "Controller must be returned on activation");

  const pricingPyPath = path.join(cfg.repoDir, "tests", "test_pricing.py");
  const baseDoc = await vscode.workspace.openTextDocument(vscode.Uri.file(pricingPyPath));
  await vscode.window.showTextDocument(baseDoc, { preview: false });
  await sleep(700);

  const idleSnap = controller.getViewSnapshot();
  assert.strictEqual(idleSnap.evaluatedState.state, "Not Run");
  const quickStart = findNode(idleSnap.treeNodes, "verdict_quickstart_group");
  assert.ok(quickStart && quickStart.children.length === 5, "Expected 5 Quick Start actions in idle sidebar");

  const shot1 = captureWinScreenshotIfConfigured(cfg, "01-idle-activitybar-quickstart.png");
  if (shot1) screenshots.push(shot1);

  // Act 2: Human / AI weakens tests in working tree -> Run Pre-Check Working Tree!
  fs.writeFileSync(
    pricingPyPath,
    [
      "import pytest",
      "from src.pricing import calculate_total",
      "",
      "def test_vip_discount():",
      "    assert True",
      "",
      "@pytest.mark.skip(reason='temporarily disabled by AI')",
      "def test_invalid_coupon_rejected():",
      "    with pytest.raises(ValueError):",
      "        calculate_total(100, 'BAD_CODE')",
      "",
    ].join("\\n"),
    "utf8"
  );
  const addedWeakPath = path.join(cfg.repoDir, "tests", "test_new_checkout.py");
  fs.writeFileSync(
    addedWeakPath,
    [
      "import pytest",
      "",
      "@pytest.mark.skip(reason='skipped new checkout test')",
      "def test_checkout_smoke():",
      "    assert True",
      "",
    ].join("\\n"),
    "utf8"
  );
  const deletedGuardPath = path.join(cfg.repoDir, "tests", "test_refund_guard.py");
  fs.unlinkSync(deletedGuardPath);

  // Ensure open editor buffer reloads disk edit cleanly before pre-check
  try {
    await vscode.commands.executeCommand("workbench.action.files.revert");
  } catch {}
  await sleep(500);

  const blockSnap = await vscode.commands.executeCommand(
    "checkwashLens.scanUncommittedSnapshot",
    "worktree"
  );
  assert.strictEqual(blockSnap.evaluatedState.state, "Block");
  assert.strictEqual(blockSnap.enrichedFindings.length >= 2, true);
  assert.strictEqual((blockSnap.fastGuardResult?.hints.length ?? 0) >= 1, true);
  await sleep(700);

  const liveDiagsOnPricing = vscode.languages.getDiagnostics(vscode.Uri.file(pricingPyPath));
  assert.strictEqual(
    liveDiagsOnPricing.length >= 2,
    true,
    "Expected live Checkwash + Fast Guard squiggles on clean open test_pricing.py"
  );
  assert.strictEqual(
    liveDiagsOnPricing.some((d) => d.severity === vscode.DiagnosticSeverity.Error),
    true,
    "Expected Checkwash 'high'/'critical' finding to render as red Error squiggle"
  );

  const shot2 = captureWinScreenshotIfConfigured(cfg, "02-precheck-block-findings-and-squiggles.png");
  if (shot2) screenshots.push(shot2);

  // Act 3: Click Compare Base <-> Head Diff across Modified, Added, and Deleted findings!
  const allBlockNodes = collectAll(blockSnap.treeNodes);
  const pricingFindingNode = allBlockNodes.find(
    (n) => n.findingNav && n.findingNav.relativePath === "tests/test_pricing.py"
  );
  const addedFindingNode = allBlockNodes.find(
    (n) => n.findingNav && n.findingNav.relativePath === "tests/test_new_checkout.py"
  );
  const deletedFindingNode = allBlockNodes.find(
    (n) => n.findingNav && n.findingNav.relativePath === "tests/test_refund_guard.py"
  );
  assert.ok(pricingFindingNode && addedFindingNode && deletedFindingNode);

  // Open side-by-side diff for added & deleted files first to verify real VS Code Diff Editor handles checkwash-empty:
  const addedDiffRes = await vscode.commands.executeCommand(
    "checkwashLens.openFindingDiff",
    addedFindingNode
  );
  assert.ok(addedDiffRes && addedDiffRes.leftUri.startsWith("checkwash-empty:/"));
  await sleep(250);

  const deletedDiffRes = await vscode.commands.executeCommand(
    "checkwashLens.openFindingDiff",
    deletedFindingNode
  );
  assert.ok(deletedDiffRes && deletedDiffRes.rightUri.startsWith("checkwash-empty:/"));
  await sleep(250);

  // Now focus the Modified test_pricing.py side-by-side red/green diff!
  const pricingDiffRes = await vscode.commands.executeCommand(
    "checkwashLens.openFindingDiff",
    pricingFindingNode
  );
  assert.ok(pricingDiffRes);
  await sleep(800);

  const activeTab = vscode.window.tabGroups?.activeTabGroup?.activeTab;
  const isNativeDiffTab = Boolean(
    activeTab &&
      activeTab.input &&
      activeTab.input.original &&
      activeTab.input.modified &&
      activeTab.input.original.scheme === "checkwash-rev" &&
      activeTab.input.modified.scheme === "checkwash-rev"
  );
  assert.strictEqual(isNativeDiffTab, true, "Expected active tab to be native VS Code TabInputTextDiff");

  const shot3 = captureWinScreenshotIfConfigured(cfg, "03-side-by-side-base-vs-worktree-diff.png");
  if (shot3) screenshots.push(shot3);

  // Act 4: Open immutable revision ('checkwash-rev:'), then jump straight to editable workspace file!
  await vscode.commands.executeCommand(
    "checkwashLens.openImmutableRevision",
    pricingFindingNode.findingNav.preferredRevisionUri,
    pricingFindingNode.findingNav.revealLine1Based
  );
  await sleep(300);
  assert.strictEqual(vscode.window.activeTextEditor?.document.uri.scheme, "checkwash-rev");

  const editableDoc = await vscode.commands.executeCommand("checkwashLens.openWorkspaceFileAtFinding");
  await sleep(300);
  assert.ok(editableDoc);
  assert.strictEqual(vscode.window.activeTextEditor?.document.uri.scheme, "file");
  assert.strictEqual(
    vscode.window.activeTextEditor?.selection.active.line,
    (pricingFindingNode.findingNav.revealLine1Based || 1) - 1
  );

  // Act 5: Developer fixes the weakened tests -> Re-runs Pre-Check -> Green Pass!
  await vscode.commands.executeCommand("workbench.action.closeOtherEditors");
  fs.writeFileSync(
    pricingPyPath,
    [
      "import pytest",
      "from src.pricing import calculate_total",
      "",
      "def test_vip_discount():",
      "    assert calculate_total(200, 'VIP20') == 160",
      "    assert calculate_total(100, None) == 100",
      "    assert calculate_total(50, 'VIP20') == 40",
      "",
      "def test_invalid_coupon_rejected():",
      "    with pytest.raises(ValueError):",
      "        calculate_total(100, 'BAD_CODE')",
      "",
    ].join("\\n"),
    "utf8"
  );
  fs.writeFileSync(
    addedWeakPath,
    [
      "from src.pricing import calculate_total",
      "",
      "def test_checkout_smoke():",
      "    assert calculate_total(50, None) == 50",
      "",
    ].join("\\n"),
    "utf8"
  );
  fs.writeFileSync(
    deletedGuardPath,
    [
      "import pytest",
      "from src.pricing import calculate_total",
      "",
      "def test_negative_subtotal_raises():",
      "    with pytest.raises(ValueError):",
      "        calculate_total(-50, None)",
      "",
    ].join("\\n"),
    "utf8"
  );

  // Open Source Control view briefly if capturing screenshots so SCM shield icon is exercised, then Checkwash Lens view
  const passSnap = await vscode.commands.executeCommand(
    "checkwashLens.scanUncommittedSnapshot",
    "worktree"
  );
  assert.strictEqual(passSnap.evaluatedState.state, "Pass");
  assert.strictEqual(passSnap.enrichedFindings.length, 0);
  await vscode.commands.executeCommand("workbench.view.extension.checkwash-lens");
  await sleep(700);

  const diagsAfterFix = vscode.languages.getDiagnostics(vscode.Uri.file(pricingPyPath));
  assert.strictEqual(diagsAfterFix.length, 0, "Squiggles must clear to 0 after fixing tests");

  const shot4 = captureWinScreenshotIfConfigured(cfg, "04-fixed-tests-green-pass-verdict.png");
  if (shot4) screenshots.push(shot4);

  // Act 6: Run Environment Doctor & open rendered Markdown preview
  const docReport = await vscode.commands.executeCommand(
    "checkwashLens.runEnvironmentDoctor",
    { silentUi: false }
  );
  assert.strictEqual(docReport.overallReadyForStaticScan, true);
  try {
    await vscode.commands.executeCommand("markdown.showPreview");
  } catch {}
  await sleep(800);

  const shot5 = captureWinScreenshotIfConfigured(cfg, "05-environment-doctor-report.png");
  if (shot5) screenshots.push(shot5);

  fs.writeFileSync(
    cfg.receiptPath,
    JSON.stringify(
      {
        ok: true,
        vscodeVersion: vscode.version,
        wasActiveOnStartup,
        idleQuickStartCount: quickStart.children.length,
        blockStatusBarText: blockSnap.statusBar.text,
        blockFindingsCount: blockSnap.enrichedFindings.length,
        blockFastGuardCount: blockSnap.fastGuardResult?.hints.length ?? 0,
        isNativeDiffTab,
        pricingDiffTitle: pricingDiffRes.title,
        passStatusBarText: passSnap.statusBar.text,
        doctorReady: docReport.overallReadyForStaticScan,
        screenshotsCapturedCount: screenshots.length,
        screenshots,
      },
      null,
      2
    ),
    "utf8"
  );
};
`;

  fs.writeFileSync(runnerJsPath, runnerJsSource, "utf8");
  return { driverDir, runnerJsPath };
}

async function testV05C6RealVscodeHumanPlaythrough(): Promise<Record<string, unknown>> {
  assert.strictEqual(fs.existsSync(CODE_EXE), true, `VS Code Desktop not found at ${CODE_EXE}`);
  const vsixPath = path.join(
    REPO_ROOT,
    `${PKG_JSON.name}-${PKG_JSON.version}-${ACTIVE_VSIX_TARGET}.vsix`
  );
  assert.strictEqual(fs.existsSync(vsixPath), true, `Built VSIX missing at ${vsixPath}`);

  const cliJs = findVsCodeCliJs(CODE_EXE);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-v05-playthrough-"));
  const screenshotDir = process.env.CHECKWASH_V05_SCREENSHOT_DIR?.trim() || "";
  const captureVisualWindow = Boolean(screenshotDir && IS_WIN32);

  try {
    const repoFolderName = "booking-pricing-ux-demo";
    const { repoDir } = createPricingTestRepo(tempRoot, repoFolderName);
    const { driverDir, runnerJsPath } = createRealVscodePlaythroughDriver(tempRoot);

    const userDataDir = path.join(tempRoot, "user-data");
    const extensionsDir = path.join(tempRoot, "extensions");
    fs.mkdirSync(path.join(userDataDir, "User"), { recursive: true });
    fs.mkdirSync(extensionsDir, { recursive: true });

    // Install built 0.5.0 VSIX into isolated profile
    const installRes = cp.spawnSync(
      CODE_EXE,
      [
        cliJs,
        "--install-extension",
        vsixPath,
        "--extensions-dir",
        extensionsDir,
        "--user-data-dir",
        userDataDir,
        "--force",
      ],
      {
        encoding: "utf8",
        env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" },
        timeout: 60_000,
        windowsHide: true,
      }
    );
    assert.strictEqual(
      installRes.status,
      0,
      `VSIX install failed: ${installRes.stderr || installRes.stdout}`
    );

    fs.writeFileSync(
      path.join(userDataDir, "User", "settings.json"),
      JSON.stringify(
        {
          "security.workspace.trust.enabled": false,
          "security.workspace.trust.startupPrompt": "never",
          "telemetry.telemetryLevel": "off",
          "update.mode": "none",
          "window.restoreWindows": "none",
          "window.newWindowDimensions": "maximized",
          "workbench.startupEditor": "none",
          "workbench.tips.enabled": false,
          "git.openRepositoryInParentFolders": "never",
          "checkwashLens.pythonPath": PYTHON_EXE,
          "checkwashLens.gitPath": GIT_EXE,
          ...(fs.existsSync(PROVE_EXE) ? { "checkwashLens.provePath": PROVE_EXE } : {}),
        },
        null,
        2
      ),
      "utf8"
    );

    const receiptPath = path.join(tempRoot, "v05-playthrough-receipt.json");
    const configPath = path.join(tempRoot, "v05-playthrough-config.json");
    fs.writeFileSync(
      configPath,
      JSON.stringify(
        {
          repoDir,
          windowTitleMatch: repoFolderName,
          screenshotDir: captureVisualWindow ? path.resolve(screenshotDir) : "",
          receiptPath,
        },
        null,
        2
      ),
      "utf8"
    );

    const env: NodeJS.ProcessEnv = {
      ...process.env,
      CW_V05_PLAYTHROUGH_CONFIG: configPath,
    };
    delete env.ELECTRON_RUN_AS_NODE;

    const launchArgs = [
      ...(captureVisualWindow ? [] : ["--headless"]),
      ...getPlatformVscodeLaunchArgs(),
      "--disable-gpu",
      "--disable-updates",
      "--skip-welcome",
      "--skip-release-notes",
      ...(captureVisualWindow ? [] : ["--disable-extension=vscode.git"]),
      "--disable-extension=vscode.github",
      "--disable-extension=vscode.typescript-language-features",
      "--user-data-dir",
      userDataDir,
      "--extensions-dir",
      extensionsDir,
      "--extensionDevelopmentPath",
      driverDir,
      "--extensionTestsPath",
      runnerJsPath,
      repoDir,
    ];

    const child = cp.spawn(CODE_EXE, launchArgs, {
      env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: !captureVisualWindow,
      detached: !IS_WIN32,
    });

    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr?.on("data", (d) => {
      stderr += d.toString();
    });

    const exitCode = await new Promise<number | null>((resolve, reject) => {
      const timer = setTimeout(() => {
        killProcessTreeBestEffort(child.pid);
        reject(new Error(`Timed out waiting for real VS Code v0.5 playthrough (120s)\nstderr=${stderr}`));
      }, 120_000);
      child.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        resolve(code);
      });
    });

    killProcessTreeBestEffort(child.pid);

    assert.strictEqual(
      exitCode === 0 && fs.existsSync(receiptPath),
      true,
      `Real VS Code v0.5 playthrough failed (exit=${exitCode}):\nstdout=${stdout}\nstderr=${stderr}`
    );

    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8")) as {
      ok: boolean;
      vscodeVersion: string;
      wasActiveOnStartup: boolean;
      idleQuickStartCount: number;
      blockStatusBarText: string;
      blockFindingsCount: number;
      blockFastGuardCount: number;
      isNativeDiffTab: boolean;
      pricingDiffTitle: string;
      passStatusBarText: string;
      doctorReady: boolean;
      screenshotsCapturedCount: number;
    };

    assert.strictEqual(receipt.ok, true);
    assert.strictEqual(
      receipt.wasActiveOnStartup,
      false,
      "Checkwash Lens MUST stay inactive on startup before user clicks Activity Bar / SCM button (B01)"
    );
    assert.strictEqual(receipt.isNativeDiffTab, true);
    assert.strictEqual(receipt.passStatusBarText.includes("Pass"), true);

    return {
      vscodeVersion: receipt.vscodeVersion,
      wasActiveOnStartup: receipt.wasActiveOnStartup,
      idleQuickStartCount: receipt.idleQuickStartCount,
      blockStatusBarText: receipt.blockStatusBarText,
      blockFindingsCount: receipt.blockFindingsCount,
      blockFastGuardCount: receipt.blockFastGuardCount,
      isNativeDiffTab: receipt.isNativeDiffTab,
      pricingDiffTitle: receipt.pricingDiffTitle,
      passStatusBarText: receipt.passStatusBarText,
      doctorReady: receipt.doctorReady,
      screenshotsCapturedCount: receipt.screenshotsCapturedCount,
    };
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

// ============================================================================
// Main Runner & Evidence Writer
// ============================================================================

async function runCase(
  id: string,
  name: string,
  fn: () => Promise<Record<string, unknown>>
): Promise<V05CaseResult> {
  const t0 = Date.now();
  try {
    const details = await fn();
    const durationMs = Date.now() - t0;
    console.log(`  [PASS] ${id} — ${name} (${durationMs} ms)`);
    return { id, name, passed: true, durationMs, details };
  } catch (err) {
    const durationMs = Date.now() - t0;
    const message = err instanceof Error ? err.stack || err.message : String(err);
    console.error(`  [FAIL] ${id} — ${name} (${durationMs} ms)\n${message}`);
    return { id, name, passed: false, durationMs, details: {}, error: message };
  }
}

async function main(): Promise<void> {
  console.log(`=== Checkwash Lens v0.5.0 UX Cockpit & Human Playthrough (${ACTIVE_PLATFORM}) ===`);

  const cases: V05CaseResult[] = [];
  cases.push(
    await runCase(
      "V05-C1",
      "Activity Bar, SCM Pre-Check, Inline Diff/Edit Menus & VSIX Media Hygiene",
      testV05C1ManifestAndVsixMediaHygiene
    )
  );
  cases.push(
    await runCase(
      "V05-C2",
      "Zero-Process Smart Git Range Preset Collector (Branches, Packed-Refs & Bounds)",
      testV05C2ZeroProcessSmartGitRangePresets
    )
  );
  cases.push(
    await runCase(
      "V05-C3",
      "Sidebar TreeView Cockpit Ergonomics (Idle Quick-Start, Auto-Collapse & ThemeIcons)",
      testV05C3TreeViewCockpitErgonomics
    )
  );
  cases.push(
    await runCase(
      "V05-C4",
      "Status Bar Quick Actions Hub & Interactive Smart Range Picker",
      testV05C4QuickActionsHubAndRangePicker
    )
  );
  cases.push(
    await runCase(
      "V05-C5",
      "Side-by-Side Diff (Modified/Added/Deleted) & Safe Editable File Jump",
      testV05C5DiffAndEditableFileSecurity
    )
  );
  cases.push(
    await runCase(
      "V05-C6",
      "Real VS Code Desktop (1.146.0) 6-Act Human Developer Playthrough",
      testV05C6RealVscodeHumanPlaythrough
    )
  );

  let sourceHeadSha = "unknown";
  let worktreeClean = false;
  try {
    sourceHeadSha = cp
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

  const passedCount = cases.filter((c) => c.passed).length;
  const execMeta = getPlatformExecutionMetadata();

  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  fs.writeFileSync(
    RESULTS_FILE,
    JSON.stringify(
      {
        suite: "v05-ux-cockpit-journey",
        version: PKG_JSON.version,
        timestampUtc: new Date().toISOString(),
        ...execMeta,
        platform: ACTIVE_PLATFORM,
        arch: process.arch,
        nodeVersion: process.version,
        sourceHeadSha,
        worktreeClean,
        totalCases: cases.length,
        passedCases: passedCount,
        failedCases: cases.length - passedCount,
        allPassed: passedCount === cases.length,
        cases,
      },
      null,
      2
    ) + "\n",
    "utf8"
  );

  console.log(
    `=== Wrote v0.5.0 UX receipt to ${RESULTS_FILE} (${passedCount}/${cases.length} passed) ===`
  );
  if (passedCount !== cases.length) {
    process.exit(1);
  }
}

void main();
