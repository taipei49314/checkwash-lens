/**
 * phase5_extension_host_runner.ts
 *
 * Phase 5 Adversarial Counterexample & Extension Host Integration Suite (P5-C1 .. P5-C6).
 *
 * Exercises the compiled VS Code entrypoint (`src/extension.ts` -> `dist/extension.js`)
 * end-to-end across all 9 commands, `StatusBarItem`, `DiagnosticCollection`s, `TreeDataProvider`,
 * `TextDocumentContentProvider` (`checkwash-rev:`), `HoverProvider`, Workspace Trust / Restricted Mode,
 * `.vscode/settings.json` poisoning, `PATH` executable discovery, multi-folder & virtual workspace handling,
 * modal confirmation gates for Context Diet & Prove, and `deactivate()` process-tree cleanup.
 */

import * as cp from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import Module = require("module");
import {
  ACTIVE_PLATFORM,
  getPlatformExecutionMetadata,
  getPlatformVscodeLaunchArgs,
  IS_LINUX,
  IS_WIN32,
  resolvePlatformEvidenceDir,
  resolveTestGitExe,
  resolveTestProveExe,
  resolveTestPythonExe,
  resolveTestVscodeExe,
} from "./testPlatformEnv";

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const EVIDENCE_DIR = resolvePlatformEvidenceDir(REPO_ROOT);
const RESULTS_FILE = path.join(EVIDENCE_DIR, "phase5-extension-host-results.json");

const PYTHON_EXE = resolveTestPythonExe();
const GIT_EXE = resolveTestGitExe();
const PROVE_EXE = resolveTestProveExe();

function makeDiagStoreKey(fsPathValue: string): string {
  return IS_WIN32
    ? path.win32.resolve(fsPathValue).toLowerCase()
    : path.posix.resolve(fsPathValue);
}

interface CounterexampleTestResult {
  id: string;
  name: string;
  passed: boolean;
  durationMs: number;
  details: Record<string, unknown>;
  error?: string;
}

function assertCondition(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

// ============================================================================
// High-Fidelity Programmable VS Code Extension Host Harness
// ============================================================================

interface MockWorkspaceFolder {
  uri: MockUri;
  name: string;
  index: number;
}

interface MockTextDocument {
  uri: MockUri;
  fsPath: string;
  version: number;
  isDirty: boolean;
  isClosed: boolean;
  getText(): string;
}

function encodeVscodeUriPath(decodedPath: string): string {
  return decodedPath
    .split("/")
    .map((seg) =>
      encodeURIComponent(seg).replace(/%2B/gi, "+")
    )
    .join("/");
}

function encodeVscodeUriQuery(decodedQuery: string): string {
  // Mirrors vscode-uri default `toString(skipEncoding=false)` query encoding:
  // `=`, `&`, `%`, spaces, and non-ASCII are percent-encoded while `+` stays literal `+`.
  return encodeURIComponent(decodedQuery).replace(/%2B/gi, "+");
}

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
        .replace(/^([A-Z]):/, (_m, drive: string) => `${drive.toLowerCase()}:`);
      const slashPath = "/" + resolved.replace(/\\/g, "/");
      return new MockUri("file", "", slashPath, "", "", resolved);
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
    const safeDecode = (s: string): string => {
      try {
        return decodeURIComponent(s);
      } catch {
        return s;
      }
    };
    const decodedPath = safeDecode(rawPath);
    const decodedQuery = safeDecode(rawQuery);
    const decodedFragment = safeDecode(rawFragment);
    if (scheme === "file") {
      if (IS_WIN32 || /^\/[a-zA-Z]:/.test(decodedPath)) {
        const winPath = path.win32.normalize(decodedPath.replace(/^\/([a-zA-Z]:)/, "$1"));
        return new MockUri(scheme, authority, decodedPath, decodedQuery, decodedFragment, winPath);
      }
      const posixPath = path.posix.normalize(decodedPath);
      return new MockUri(scheme, authority, decodedPath, decodedQuery, decodedFragment, posixPath);
    }
    return new MockUri(scheme, authority, decodedPath, decodedQuery, decodedFragment, decodedPath);
  }

  public toString(skipEncoding: boolean = false): string {
    if (this.scheme === "file") {
      const slash = this.fsPath.replace(/\\/g, "/");
      const withLeadingSlash = slash.startsWith("/") ? slash : `/${slash}`;
      return `file://${skipEncoding ? withLeadingSlash : encodeVscodeUriPath(withLeadingSlash)}`;
    }
    const encodedPath = skipEncoding ? this.path : encodeVscodeUriPath(this.path);
    const q = this.query
      ? `?${skipEncoding ? this.query : encodeVscodeUriQuery(this.query)}`
      : "";
    const f = this.fragment
      ? `#${skipEncoding ? this.fragment : encodeVscodeUriQuery(this.fragment)}`
      : "";
    const authPart = this.authority ? `//${this.authority}` : "";
    return `${this.scheme}:${authPart}${encodedPath}${q}${f}`;
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
    startLineOrPos: number | MockPosition,
    startCharOrEndPos: number | MockPosition,
    endLine?: number,
    endChar?: number
  ) {
    if (typeof startLineOrPos === "number" && typeof startCharOrEndPos === "number") {
      this.start = new MockPosition(startLineOrPos, startCharOrEndPos);
      this.end = new MockPosition(endLine ?? startLineOrPos, endChar ?? startCharOrEndPos);
    } else {
      this.start = startLineOrPos as MockPosition;
      this.end = startCharOrEndPos as MockPosition;
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

class MockDiagnostic {
  public source?: string;
  public code?: string | number;
  constructor(
    public readonly range: MockRange,
    public readonly message: string,
    public readonly severity: number
  ) {}
}

class MockMarkdownString {
  public isTrusted: boolean = false;
  constructor(public value: string = "") {}
}

class MockHover {
  constructor(
    public readonly contents: MockMarkdownString,
    public readonly range?: MockRange
  ) {}
}

class MockTreeItem {
  public id?: string;
  public description?: string;
  public tooltip?: string;
  public contextValue?: string;
  public iconPath?: unknown;
  public command?: { command: string; title: string; arguments?: unknown[] };
  constructor(
    public readonly label: string,
    public readonly collapsibleState: number = 0
  ) {}
}

class MockEventEmitter<T> {
  private listeners: Array<(e: T) => void> = [];
  public readonly event = (listener: (e: T) => void) => {
    this.listeners.push(listener);
    return {
      dispose: () => {
        this.listeners = this.listeners.filter((l) => l !== listener);
      },
    };
  };
  public fire(data: T): void {
    for (const l of [...this.listeners]) {
      l(data);
    }
  }
  public dispose(): void {
    this.listeners = [];
  }
}

interface ConfigInspectionEntry {
  globalValue?: string;
  workspaceValue?: string;
  workspaceFolderValue?: string;
  defaultValue?: string;
}

class MockVSCodeHostState {
  public isTrusted: boolean = true;
  public remoteName: string | undefined = undefined;
  public workspaceFolders: MockWorkspaceFolder[] = [];
  public textDocuments: MockTextDocument[] = [];
  public configInspections: Map<string, ConfigInspectionEntry> = new Map();
  public clipboardText: string = "";

  public registeredCommands: Map<string, (...args: unknown[]) => unknown> = new Map();
  public contentProviders: Map<string, { provideTextDocumentContent(uri: MockUri): Promise<string> }> =
    new Map();
  public hoverProviders: Array<{
    provideHover(doc: MockTextDocument, pos: MockPosition): MockHover | null;
  }> = [];
  public diagnosticCollections: Map<string, Map<string, MockDiagnostic[]>> = new Map();
  public treeDataProviders: Map<string, any> = new Map();

  public statusBarItem: {
    text: string;
    tooltip: string | undefined;
    command: string | undefined;
    backgroundColor: MockThemeColor | undefined;
    shown: boolean;
    dispose(): void;
  } = {
    text: "",
    tooltip: undefined,
    command: undefined,
    backgroundColor: undefined,
    shown: false,
    dispose: () => {},
  };

  public onDidChangeTextDocumentEmitter = new MockEventEmitter<unknown>();
  public onDidCloseTextDocumentEmitter = new MockEventEmitter<unknown>();
  public onDidSaveTextDocumentEmitter = new MockEventEmitter<unknown>();
  public onDidGrantWorkspaceTrustEmitter = new MockEventEmitter<void>();
  public onDidChangeWorkspaceFoldersEmitter = new MockEventEmitter<unknown>();
  public onDidChangeConfigurationEmitter = new MockEventEmitter<unknown>();

  public warningModalHandler: ((message: string, options: unknown, items: string[]) => Promise<string | undefined>) | null =
    null;
  public infoActionHandler: ((message: string, items: string[]) => Promise<string | undefined>) | null =
    null;
  public quickPickHandler: ((items: any[], options: unknown) => Promise<any>) | null = null;
  public inputBoxHandler: ((options: unknown) => Promise<string | undefined>) | null = null;
  public openDialogHandler: ((options: unknown) => Promise<MockUri[] | undefined>) | null = null;

  public configUpdates: Array<{ section: string; key: string; value: unknown; target: unknown }> = [];
  public shownErrors: string[] = [];
  public shownWarnings: string[] = [];
  public shownInfos: string[] = [];
  public progressTitles: string[] = [];
  public lastShownDocument: MockTextDocument | null = null;
  public lastShownEditorSelection: MockSelection | null = null;
  public lastRevealedRange: MockRange | null = null;
  public diffInvocations: Array<{
    left: MockUri;
    right: MockUri;
    title: string;
    options?: unknown;
  }> = [];

  public reset(): void {
    this.isTrusted = true;
    this.remoteName = undefined;
    this.workspaceFolders = [];
    this.textDocuments = [];
    this.configInspections.clear();
    this.clipboardText = "";
    this.registeredCommands.clear();
    this.contentProviders.clear();
    this.hoverProviders = [];
    this.diagnosticCollections.clear();
    this.treeDataProviders.clear();
    this.statusBarItem = {
      text: "",
      tooltip: undefined,
      command: undefined,
      backgroundColor: undefined,
      shown: false,
      dispose: () => {},
    };
    this.onDidChangeTextDocumentEmitter = new MockEventEmitter<unknown>();
    this.onDidCloseTextDocumentEmitter = new MockEventEmitter<unknown>();
    this.onDidSaveTextDocumentEmitter = new MockEventEmitter<unknown>();
    this.onDidGrantWorkspaceTrustEmitter = new MockEventEmitter<void>();
    this.onDidChangeWorkspaceFoldersEmitter = new MockEventEmitter<unknown>();
    this.onDidChangeConfigurationEmitter = new MockEventEmitter<unknown>();
    this.warningModalHandler = null;
    this.infoActionHandler = null;
    this.quickPickHandler = null;
    this.inputBoxHandler = null;
    this.openDialogHandler = null;
    this.configUpdates = [];
    this.shownErrors = [];
    this.shownWarnings = [];
    this.shownInfos = [];
    this.progressTitles = [];
    this.lastShownDocument = null;
    this.lastShownEditorSelection = null;
    this.lastRevealedRange = null;
    this.diffInvocations = [];
  }
}

const hostState = new MockVSCodeHostState();

const mockVscodeModule = {
  Uri: MockUri,
  Position: MockPosition,
  Range: MockRange,
  Selection: MockSelection,
  ThemeColor: MockThemeColor,
  ThemeIcon: MockThemeIcon,
  Diagnostic: MockDiagnostic,
  DiagnosticSeverity: {
    Error: 0,
    Warning: 1,
    Information: 2,
    Hint: 3,
  },
  MarkdownString: MockMarkdownString,
  Hover: MockHover,
  TreeItem: MockTreeItem,
  TreeItemCollapsibleState: {
    None: 0,
    Collapsed: 1,
    Expanded: 2,
  },
  StatusBarAlignment: {
    Left: 1,
    Right: 2,
  },
  TextEditorRevealType: {
    Default: 0,
    InCenter: 1,
    InCenterIfOutsideViewport: 2,
    AtTop: 3,
  },
  ProgressLocation: {
    SourceControl: 1,
    Window: 10,
    Notification: 15,
  },
  ConfigurationTarget: {
    Global: 1,
    Workspace: 2,
    WorkspaceFolder: 3,
  },
  EventEmitter: MockEventEmitter,
  workspace: {
    get isTrusted(): boolean {
      return hostState.isTrusted;
    },
    get workspaceFolders(): MockWorkspaceFolder[] {
      return hostState.workspaceFolders;
    },
    get textDocuments(): MockTextDocument[] {
      return hostState.textDocuments;
    },
    getConfiguration: (section: string) => ({
      inspect: <T>(key: string): ConfigInspectionEntry | undefined => {
        return hostState.configInspections.get(key) as ConfigInspectionEntry | undefined;
      },
      get: <T>(key: string, defaultValue?: T): T | undefined => {
        const entry = hostState.configInspections.get(key);
        return (entry?.globalValue ?? entry?.workspaceValue ?? entry?.defaultValue ?? defaultValue) as
          | T
          | undefined;
      },
      update: async (key: string, value: unknown, target?: unknown): Promise<void> => {
        hostState.configUpdates.push({ section, key, value, target });
        if (section === "checkwashLens" && target === 1) {
          const prev = hostState.configInspections.get(key) ?? {};
          hostState.configInspections.set(key, {
            ...prev,
            globalValue: typeof value === "string" ? value : undefined,
          });
        }
      },
    }),
    registerTextDocumentContentProvider: (
      scheme: string,
      provider: { provideTextDocumentContent(uri: MockUri): Promise<string> }
    ) => {
      hostState.contentProviders.set(scheme, provider);
      return { dispose: () => hostState.contentProviders.delete(scheme) };
    },
    openTextDocument: async (uri: MockUri): Promise<MockTextDocument> => {
      const provider = hostState.contentProviders.get(uri.scheme);
      const content = provider
        ? await provider.provideTextDocumentContent(uri)
        : uri.scheme === "file" && fs.existsSync(uri.fsPath)
          ? fs.readFileSync(uri.fsPath, "utf8")
          : "";
      return {
        uri,
        fsPath: uri.fsPath,
        version: 1,
        isDirty: false,
        isClosed: false,
        getText: () => content,
      };
    },
    onDidChangeTextDocument: (listener: (e: unknown) => void) =>
      hostState.onDidChangeTextDocumentEmitter.event(listener),
    onDidCloseTextDocument: (listener: (e: unknown) => void) =>
      hostState.onDidCloseTextDocumentEmitter.event(listener),
    onDidSaveTextDocument: (listener: (e: unknown) => void) =>
      hostState.onDidSaveTextDocumentEmitter.event(listener),
    onDidGrantWorkspaceTrust: (listener: () => void) =>
      hostState.onDidGrantWorkspaceTrustEmitter.event(listener),
    onDidChangeWorkspaceFolders: (listener: (e: unknown) => void) =>
      hostState.onDidChangeWorkspaceFoldersEmitter.event(listener),
    onDidChangeConfiguration: (listener: (e: unknown) => void) =>
      hostState.onDidChangeConfigurationEmitter.event(listener),
  },
  window: {
    createStatusBarItem: (_alignment?: number, _priority?: number) => {
      return {
        get text() {
          return hostState.statusBarItem.text;
        },
        set text(v: string) {
          hostState.statusBarItem.text = v;
        },
        get tooltip() {
          return hostState.statusBarItem.tooltip;
        },
        set tooltip(v: string | undefined) {
          hostState.statusBarItem.tooltip = v;
        },
        get command() {
          return hostState.statusBarItem.command;
        },
        set command(v: string | undefined) {
          hostState.statusBarItem.command = v;
        },
        get backgroundColor() {
          return hostState.statusBarItem.backgroundColor;
        },
        set backgroundColor(v: MockThemeColor | undefined) {
          hostState.statusBarItem.backgroundColor = v;
        },
        show: () => {
          hostState.statusBarItem.shown = true;
        },
        dispose: () => {
          hostState.statusBarItem.shown = false;
        },
      };
    },
    createTreeView: (viewId: string, options: { treeDataProvider: any }) => {
      hostState.treeDataProviders.set(viewId, options.treeDataProvider);
      return {
        dispose: () => hostState.treeDataProviders.delete(viewId),
      };
    },
    showWarningMessage: async (message: string, optionsOrItem?: unknown, ...items: string[]) => {
      hostState.shownWarnings.push(message);
      const isModal =
        typeof optionsOrItem === "object" &&
        optionsOrItem !== null &&
        (optionsOrItem as { modal?: boolean }).modal === true;
      const buttons = isModal ? items : typeof optionsOrItem === "string" ? [optionsOrItem, ...items] : items;
      if (hostState.warningModalHandler) {
        return hostState.warningModalHandler(message, optionsOrItem, buttons);
      }
      return undefined;
    },
    showErrorMessage: async (message: string) => {
      hostState.shownErrors.push(message);
      return undefined;
    },
    showInformationMessage: async (message: string, ...items: string[]) => {
      hostState.shownInfos.push(message);
      if (hostState.infoActionHandler) {
        return hostState.infoActionHandler(message, items);
      }
      return undefined;
    },
    showQuickPick: async (items: any[], options?: unknown) => {
      if (hostState.quickPickHandler) {
        return hostState.quickPickHandler(items, options);
      }
      return undefined;
    },
    showInputBox: async (options?: unknown) => {
      if (hostState.inputBoxHandler) {
        return hostState.inputBoxHandler(options);
      }
      return undefined;
    },
    showOpenDialog: async (options?: unknown) => {
      if (hostState.openDialogHandler) {
        return hostState.openDialogHandler(options);
      }
      return undefined;
    },
    withProgress: async <T>(
      options: { title?: string; cancellable?: boolean },
      task: (
        progress: { report(value: unknown): void },
        token: {
          isCancellationRequested: boolean;
          onCancellationRequested: (cb: () => void) => { dispose(): void };
        }
      ) => Promise<T>
    ): Promise<T> => {
      if (options?.title) {
        hostState.progressTitles.push(options.title);
      }
      const cancelEmitter = new MockEventEmitter<void>();
      const token = {
        isCancellationRequested: false,
        onCancellationRequested: (cb: () => void) => cancelEmitter.event(cb),
      };
      return task({ report: () => {} }, token);
    },
    showTextDocument: async (doc: MockTextDocument, _options?: unknown) => {
      hostState.lastShownDocument = doc;
      const editor = {
        document: doc,
        selection: new MockSelection(new MockPosition(0, 0), new MockPosition(0, 0)),
        revealRange: (range: MockRange) => {
          hostState.lastRevealedRange = range;
        },
      };
      return new Proxy(editor, {
        set(target, prop, value) {
          if (prop === "selection") {
            hostState.lastShownEditorSelection = value as MockSelection;
          }
          (target as any)[prop] = value;
          return true;
        },
      });
    },
  },
  languages: {
    createDiagnosticCollection: (name: string) => {
      const store = new Map<string, MockDiagnostic[]>();
      hostState.diagnosticCollections.set(name, store);
      return {
        name,
        set: (uri: MockUri, diags: MockDiagnostic[]) => {
          store.set(makeDiagStoreKey(uri.fsPath), diags);
        },
        clear: () => {
          store.clear();
        },
        dispose: () => {
          store.clear();
        },
      };
    },
    registerHoverProvider: (
      _selector: unknown,
      provider: { provideHover(doc: MockTextDocument, pos: MockPosition): MockHover | null }
    ) => {
      hostState.hoverProviders.push(provider);
      return {
        dispose: () => {
          hostState.hoverProviders = hostState.hoverProviders.filter((p) => p !== provider);
        },
      };
    },
  },
  commands: {
    registerCommand: (id: string, handler: (...args: unknown[]) => unknown) => {
      hostState.registeredCommands.set(id, handler);
      return {
        dispose: () => {
          hostState.registeredCommands.delete(id);
        },
      };
    },
    executeCommand: async <T = unknown>(id: string, ...args: unknown[]): Promise<T> => {
      if (id === "vscode.diff") {
        hostState.diffInvocations.push({
          left: args[0] as MockUri,
          right: args[1] as MockUri,
          title: String(args[2] ?? ""),
          options: args[3],
        });
        return undefined as T;
      }
      const handler = hostState.registeredCommands.get(id);
      if (!handler) {
        throw new Error(`Command not registered: ${id}`);
      }
      return (await handler(...args)) as T;
    },
  },
  env: {
    get remoteName(): string | undefined {
      return hostState.remoteName;
    },
    clipboard: {
      writeText: async (text: string): Promise<void> => {
        hostState.clipboardText = text;
      },
      readText: async (): Promise<string> => {
        return hostState.clipboardText;
      },
    },
  },
};

// Install module loader hook for "vscode" before loading ../extension
const originalLoad = (Module as any)._load;
(Module as any)._load = function (request: string, parent: unknown, isMain: boolean) {
  if (request === "vscode") {
    return mockVscodeModule;
  }
  return originalLoad.call(this, request, parent, isMain);
};

// Load production modules after installing the "vscode" module hook
import {
  activate,
  deactivate,
  getActiveController,
  readTrustedMachineStringSetting,
  buildHostDescriptor,
} from "../extension";
import { CheckwashLensController, ControllerViewSnapshot } from "../ui/commands";
import { CHECKWASH_DIAGNOSTIC_SOURCE } from "../ui/diagnostics";
import { FAST_GUARD_SOURCE_LABEL } from "../engine/fastDiffGuard";
import {
  buildRevisionUriString,
  CHECKWASH_REVISION_URI_SCHEME,
} from "../source/revisionProvider";
import { PROVE_EXECUTION_RISK_WARNING } from "../satellite/proveRunner";
import {
  resolveTrustedExecutableFromPath,
  verifyLaunchAdmission,
} from "../runtime/admission";
import { UnifiedProcessRunner } from "../runtime/processRunner";
import { executeViaWindowsBroker } from "../runtime/windowsBroker";

// ============================================================================
// Helper: Create Temporary Git Repository for Extension Host Tests
// ============================================================================

function initGitRepoWithTwoCommits(options?: {
  includeSecretInSecondCommit?: boolean;
  dirPrefix?: string;
}): {
  repoDir: string;
  baseSha: string;
  headSha: string;
  testRelPath: string;
  headTestContent: string;
} {
  const repoDir = fs.mkdtempSync(
    path.join(os.tmpdir(), options?.dirPrefix ?? "cw-lens-p5-repo-")
  );
  const runGit = (args: string[]) => {
    const res = cp.spawnSync(GIT_EXE, args, {
      cwd: repoDir,
      encoding: "utf-8",
      windowsHide: true,
    });
    if (res.status !== 0) {
      throw new Error(`git ${args.join(" ")} failed: ${res.stderr}`);
    }
    return res.stdout.trim();
  };

  runGit(["init", "-b", "main"]);
  runGit(["config", "user.name", "Phase5 Runner"]);
  runGit(["config", "user.email", "phase5@example.com"]);

  fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
  fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });
  fs.writeFileSync(path.join(repoDir, "src", "__init__.py"), "", "utf-8");

  fs.writeFileSync(
    path.join(repoDir, "src", "calc.py"),
    [
      "def compute(x: int) -> int:",
      "    if x >= 100:",
      "        return x - 20",
      "    return x",
      "",
    ].join("\n"),
    "utf-8"
  );
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_calc.py"),
    [
      "from src.calc import compute",
      "",
      "def test_compute():",
      "    assert compute(100) == 80",
      "    assert compute(120) == 100",
      "    assert compute(50) == 50",
      "",
    ].join("\n"),
    "utf-8"
  );

  runGit(["add", "."]);
  runGit(["commit", "-m", "Base commit"]);
  const baseSha = runGit(["rev-parse", "HEAD"]);

  // Second commit weakens assertion (`assert True` / `is not None`), adds `@pytest.mark.skip`,
  // and optionally adds a sensitive secret + lockfile for Context Diet testing.
  const testLines = [
    "import pytest",
    "from src.calc import compute",
    "",
    "@pytest.mark.skip(reason='skip temporarily')",
    "def test_skipped():",
    "    assert compute(50) == 50",
    "",
    "def test_compute():",
    "    assert compute(120) is not None",
    "    assert True",
    "",
  ];
  if (options?.includeSecretInSecondCommit) {
    testLines.push(
      'API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz" # api_key = "SYNTHETIC_P5_SECRET_999"',
      ""
    );
    fs.writeFileSync(
      path.join(repoDir, "package-lock.json"),
      JSON.stringify({ name: "demo", lockfileVersion: 3, packages: {} }, null, 2),
      "utf-8"
    );
  }
  const headTestContent = testLines.join("\n");
  fs.writeFileSync(path.join(repoDir, "tests", "test_calc.py"), headTestContent, "utf-8");

  runGit(["add", "."]);
  runGit(["commit", "-m", "Head commit with weakened assertion and skip"]);
  const headSha = runGit(["rev-parse", "HEAD"]);

  return {
    repoDir: fs.realpathSync.native(repoDir),
    baseSha,
    headSha,
    testRelPath: "tests/test_calc.py",
    headTestContent,
  };
}

function makeExtensionContext(subscriptions: Array<{ dispose(): unknown }> = []): any {
  return {
    extensionPath: REPO_ROOT,
    subscriptions,
  };
}

function configureTrustedMachinePaths(): void {
  hostState.configInspections.set("pythonPath", { globalValue: PYTHON_EXE, defaultValue: "" });
  hostState.configInspections.set("gitPath", { globalValue: GIT_EXE, defaultValue: "" });
  hostState.configInspections.set("provePath", { globalValue: PROVE_EXE, defaultValue: "" });
  hostState.configInspections.set("proveTestPythonPath", {
    globalValue: PYTHON_EXE,
    defaultValue: "",
  });
}

// ============================================================================
// P5-C1: Zero Process Spawn on Lifecycle Events & Restricted Mode
// ============================================================================

async function testP5C1ZeroProcessOnLifecycleAndUntrustedEvents(): Promise<Record<string, unknown>> {
  hostState.reset();
  const { repoDir } = initGitRepoWithTwoCommits({
    dirPrefix: "cw-lens-realhost-c++ & R&D-",
  });

  try {
    let brokerInvocations = 0;
    const spyRunner = new UnifiedProcessRunner();
    spyRunner.setCustomBrokerExecutorForTests(async (req, signal) => {
      brokerInvocations++;
      return executeViaWindowsBroker(req, signal);
    });
    const spyController = new CheckwashLensController(spyRunner);

    // Start in Restricted Mode (untrusted workspace)
    hostState.isTrusted = false;
    hostState.workspaceFolders = [{ uri: MockUri.file(repoDir), name: "repo", index: 0 }];
    configureTrustedMachinePaths();

    const subscriptions: Array<{ dispose(): unknown }> = [];
    const ctx = makeExtensionContext(subscriptions);

    // 1. Activate extension
    activate(ctx, spyController);
    assertCondition(brokerInvocations === 0, "Zero processes must be spawned on activate()");
    assertCondition(
      hostState.statusBarItem.shown &&
        hostState.statusBarItem.text.includes("Checkwash: Not Run") &&
        hostState.statusBarItem.command === "checkwashLens.openQuickActions",
      "StatusBarItem must show 'Checkwash: Not Run' with Quick Actions command immediately on activation"
    );
    assertCondition(
      hostState.registeredCommands.size === 15,
      `Expected all 15 commands to be registered, got ${hostState.registeredCommands.size}`
    );

    // 2. Fire document edit, save, close, configuration change, workspace folder change
    hostState.onDidChangeTextDocumentEmitter.fire({});
    hostState.onDidSaveTextDocumentEmitter.fire({});
    hostState.onDidCloseTextDocumentEmitter.fire({});
    hostState.onDidChangeConfigurationEmitter.fire({});
    hostState.onDidChangeWorkspaceFoldersEmitter.fire({});
    assertCondition(
      brokerInvocations === 0,
      "Zero processes must be spawned on edit/save/close/config/folder events"
    );

    // 3. Attempt scan, uncommitted snapshot, and Environment Doctor commands while in Restricted Mode (`isTrusted = false`)
    const untrustedScanSnap = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanCommittedRange",
      "HEAD~1..HEAD"
    );
    const untrustedSnapPrecheck = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanUncommittedSnapshot",
      "worktree"
    );
    const untrustedDoctorReport = await mockVscodeModule.commands.executeCommand<{
      externalProcessesSpawned: boolean;
      isWorkspaceTrusted: boolean;
    }>("checkwashLens.runEnvironmentDoctor", { silentUi: true });
    assertCondition(
      brokerInvocations === 0,
      "Restricted Mode scan, snapshot pre-check, and Environment Doctor must spawn 0 broker processes"
    );
    assertCondition(
      untrustedSnapPrecheck?.evaluatedState.state === "Not Run" &&
        untrustedDoctorReport?.externalProcessesSpawned === false &&
        untrustedDoctorReport?.isWorkspaceTrusted === false,
      "Restricted Mode snapshot pre-check and Environment Doctor must fail closed with 0 external processes"
    );
    assertCondition(
      untrustedScanSnap?.evaluatedState.state === "Not Run" &&
        Boolean(
          (
            untrustedScanSnap.evaluatedState.notRunReason ??
            untrustedScanSnap.evaluatedState.errorReason ??
            ""
          ).includes("Restricted Mode")
        ),
      `Expected Restricted Mode 'Not Run' state, got: ${JSON.stringify(untrustedScanSnap?.evaluatedState)}`
    );
    assertCondition(
      hostState.shownWarnings.some((w) => w.includes("Restricted Mode")),
      "Restricted Mode scan attempt must surface a user-visible warning notification"
    );

    // 4. Grant Workspace Trust (`onDidGrantWorkspaceTrust`) — must NOT auto-scan!
    hostState.isTrusted = true;
    hostState.onDidGrantWorkspaceTrustEmitter.fire();
    assertCondition(
      brokerInvocations === 0,
      "Granting Workspace Trust must never auto-scan or spawn any external process"
    );

    for (const sub of subscriptions) {
      sub.dispose();
    }
    await deactivate();

    return {
      registeredCommandCount: 15,
      brokerInvocationsOnActivateAndEvents: brokerInvocations,
      untrustedScanStatus: untrustedScanSnap?.evaluatedState.state,
      untrustedSnapshotPrecheckStatus: untrustedSnapPrecheck?.evaluatedState.state,
      untrustedDoctorExternalSpawns: untrustedDoctorReport?.externalProcessesSpawned,
      untrustedScanReason:
        untrustedScanSnap?.evaluatedState.notRunReason ??
        untrustedScanSnap?.evaluatedState.errorReason,
    };
  } finally {
    fs.rmSync(repoDir, { recursive: true, force: true });
  }
}

// ============================================================================
// P5-C2: Workspace Settings Poisoning & Safe Default PATH Discovery
// ============================================================================

async function testP5C2WorkspaceSettingsPoisoningAndSafeDefaultPath(): Promise<
  Record<string, unknown>
> {
  hostState.reset();
  const { repoDir } = initGitRepoWithTwoCommits({
    dirPrefix: "cw-lens-realhost-c++ & R&D-",
  });
  const fakeWindowsAppsDir = fs.mkdtempSync(path.join(os.tmpdir(), "cw-lens-winapps-"));

  try {
    // Create malicious binaries inside the target repository
    const evilBinDir = path.join(repoDir, "evil_bin");
    fs.mkdirSync(evilBinDir, { recursive: true });
    const evilPy = path.join(evilBinDir, IS_WIN32 ? "python.exe" : "python3");
    const evilGit = path.join(evilBinDir, IS_WIN32 ? "git.exe" : "git");
    const evilProve = path.join(evilBinDir, IS_WIN32 ? "checkwash-prove.exe" : "checkwash-prove");
    fs.writeFileSync(evilPy, "MZ_FAKE_NONEMPTY_REPO_BINARY", "utf-8");
    fs.writeFileSync(evilGit, "MZ_FAKE_NONEMPTY_REPO_BINARY", "utf-8");
    fs.writeFileSync(evilProve, "MZ_FAKE_NONEMPTY_REPO_BINARY", "utf-8");
    if (!IS_WIN32) {
      fs.chmodSync(evilPy, 0o755);
      fs.chmodSync(evilGit, 0o755);
      fs.chmodSync(evilProve, 0o755);
    }

    // Create a 0-byte stub outside the repository
    const zeroByteStubPy = path.join(fakeWindowsAppsDir, IS_WIN32 ? "python.exe" : "python3");
    fs.writeFileSync(zeroByteStubPy, "", "utf-8");
    if (!IS_WIN32) {
      fs.chmodSync(zeroByteStubPy, 0o755);
    }

    // Part A: Poison workspaceValue and workspaceFolderValue in `.vscode/settings.json`
    // while leaving globalValue unset (`undefined`).
    hostState.configInspections.set("pythonPath", {
      globalValue: undefined,
      workspaceValue: evilPy,
      workspaceFolderValue: evilPy,
      defaultValue: "",
    });
    hostState.configInspections.set("gitPath", {
      globalValue: undefined,
      workspaceValue: evilGit,
      workspaceFolderValue: evilGit,
      defaultValue: "",
    });
    hostState.configInspections.set("provePath", {
      globalValue: undefined,
      workspaceValue: evilProve,
      workspaceFolderValue: evilProve,
      defaultValue: "",
    });
    hostState.configInspections.set("proveTestPythonPath", {
      globalValue: undefined,
      workspaceValue: evilPy,
      workspaceFolderValue: evilPy,
      defaultValue: "",
    });

    const readPy = readTrustedMachineStringSetting("pythonPath", "");
    const readGit = readTrustedMachineStringSetting("gitPath", "");
    const readProve = readTrustedMachineStringSetting("provePath", "");
    const readTestPy = readTrustedMachineStringSetting("proveTestPythonPath", "");
    assertCondition(
      readPy === "" && readGit === "" && readProve === "" && readTestPy === "",
      "readTrustedMachineStringSetting must completely ignore workspaceValue and workspaceFolderValue"
    );

    // Part B: Construct an adversarial PATH with relative entries, drive-relative entries,
    // repo-local evil_bin, 0-byte WindowsApps stub, and finally the real system directories.
    const realPyDir = path.dirname(PYTHON_EXE);
    const realGitDir = path.dirname(GIT_EXE);
    const poisonedPathEnv = [
      ".",
      IS_WIN32 ? ".\\evil_bin" : "./evil_bin",
      IS_WIN32 ? "\\drive_relative_bin" : "rel_bin/sub",
      evilBinDir,
      fakeWindowsAppsDir,
      `"${realPyDir}"`,
      realGitDir,
    ].join(path.delimiter);

    hostState.workspaceFolders = [{ uri: MockUri.file(repoDir), name: "repo", index: 0 }];
    const ctx = makeExtensionContext();
    const hostDesc = buildHostDescriptor(ctx, repoDir, {
      ...process.env,
      PATH: poisonedPathEnv,
    });

    assertCondition(
      (IS_WIN32
        ? hostDesc.configuredPythonPath.toLowerCase() ===
          fs.realpathSync.native(PYTHON_EXE).toLowerCase()
        : hostDesc.configuredPythonPath === fs.realpathSync.native(PYTHON_EXE)),
      `Expected default PATH discovery to skip repo-local & 0-byte stubs and pick '${PYTHON_EXE}', got '${hostDesc.configuredPythonPath}'`
    );
    assertCondition(
      (IS_WIN32
        ? hostDesc.configuredGitPath.toLowerCase() === fs.realpathSync.native(GIT_EXE).toLowerCase()
        : hostDesc.configuredGitPath === fs.realpathSync.native(GIT_EXE)),
      `Expected default PATH discovery to skip repo-local git and pick '${GIT_EXE}', got '${hostDesc.configuredGitPath}'`
    );

    // Part C: If PATH contains ONLY repo-local evil_bin and 0-byte stubs, default resolution
    // must fail closed (`ok: false`) and verifyLaunchAdmission must reject launch!
    const onlyBadPathEnv = [
      ".",
      IS_WIN32 ? "\\relative" : "relative/sub",
      evilBinDir,
      fakeWindowsAppsDir,
    ].join(path.delimiter);
    const badPyLookup = resolveTrustedExecutableFromPath({
      executableName: IS_WIN32 ? "python.exe" : "python3",
      repositoryRootPath: repoDir,
      pathEnv: onlyBadPathEnv,
      platform: ACTIVE_PLATFORM,
    });
    assertCondition(
      !badPyLookup.ok,
      "resolveTrustedExecutableFromPath must fail closed when PATH only has relative/repo-local/0-byte candidates"
    );

    const badHostDesc = buildHostDescriptor(ctx, repoDir, {
      ...process.env,
      PATH: onlyBadPathEnv,
    });
    const admissionRes = verifyLaunchAdmission(badHostDesc);
    assertCondition(
      !admissionRes.ok,
      "verifyLaunchAdmission must reject when default PATH discovery found no trusted executable"
    );

    return {
      workspacePoisonIgnored: true,
      resolvedPythonFromPoisonedPath: hostDesc.configuredPythonPath,
      resolvedGitFromPoisonedPath: hostDesc.configuredGitPath,
      rejectedWhenOnlyRepoAndZeroByteStubInPath: !admissionRes.ok,
      admissionRejectionError: !admissionRes.ok ? admissionRes.error : null,
    };
  } finally {
    fs.rmSync(repoDir, { recursive: true, force: true });
    fs.rmSync(fakeWindowsAppsDir, { recursive: true, force: true });
  }
}

// ============================================================================
// P5-C3: Multi-Folder Workspace, Virtual Folder Mix & Folder Removal
// ============================================================================

async function testP5C3MultiFolderVirtualMixAndFolderRemoval(): Promise<Record<string, unknown>> {
  hostState.reset();
  const repoA = initGitRepoWithTwoCommits();
  const repoB = initGitRepoWithTwoCommits();

  try {
    configureTrustedMachinePaths();

    // Open a multi-folder workspace mixing a virtual folder (`vscode-vfs://`) with two physical folders
    const virtualUri = MockUri.parse("vscode-vfs://github/example/virtual-repo");
    hostState.workspaceFolders = [
      { uri: virtualUri, name: "virtual-repo", index: 0 },
      { uri: MockUri.file(repoA.repoDir), name: "repoA", index: 1 },
      { uri: MockUri.file(repoB.repoDir), name: "repoB", index: 2 },
    ];

    const subscriptions: Array<{ dispose(): unknown }> = [];
    const ctx = makeExtensionContext(subscriptions);
    const controller = activate(ctx);

    // 1. With 2 physical folders open, activate() must NOT auto-select either repository
    assertCondition(
      controller.getViewSnapshot().boundRepositoryRoot === null,
      "Multi-folder workspace must not auto-bind a repository on activation"
    );

    // 2. Attempting to buildHostDescriptor for the virtual folder or an unlisted folder
    // must mark `isVirtualWorkspace: true` and fail verifyLaunchAdmission
    const virtualDesc = buildHostDescriptor(ctx, virtualUri.fsPath);
    const virtualAdmission = verifyLaunchAdmission(virtualDesc);
    assertCondition(
      virtualDesc.isVirtualWorkspace === true && !virtualAdmission.ok,
      "Virtual workspace folder must be flagged isVirtualWorkspace=true and rejected by verifyLaunchAdmission"
    );

    // 3. Attempting to resolve a `checkwash-rev:` URI while no repository is bound must fail closed (Finding E4)
    const revProvider = hostState.contentProviders.get(CHECKWASH_REVISION_URI_SCHEME);
    assertCondition( Boolean(revProvider), "checkwash-rev: TextDocumentContentProvider must be registered");
    const builtUriARes = buildRevisionUriString({
      repositoryRoot: repoA.repoDir,
      commitOid: repoA.headSha,
      relativePath: repoA.testRelPath,
      side: "head",
      scanId: 1,
    });
    assertCondition(builtUriARes.ok, "buildRevisionUriString for repoA must succeed");
    const forgedUriA = MockUri.parse(builtUriARes.value);
    const unboundDocText = await revProvider!.provideTextDocumentContent(forgedUriA);
    assertCondition(
      unboundDocText.includes("Unable to load revision") &&
        unboundDocText.includes("No active repository is currently bound"),
      `Expected unbound checkwash-rev: lookup to fail closed, got: ${unboundDocText}`
    );

    // 4. Select repoA via QuickPick when running `checkwashLens.scanCommittedRange`
    let quickPickPrompted = false;
    hostState.quickPickHandler = async (items) => {
      quickPickPrompted = true;
      return items.find(
        (item: any) =>
          typeof item.description === "string" &&
          item.description.toLowerCase() === repoA.repoDir.toLowerCase()
      );
    };

    const scanSnap = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanCommittedRange",
      "HEAD~1..HEAD"
    );
    assertCondition(quickPickPrompted, "Scanning in multi-folder workspace must prompt QuickPick");
    assertCondition(
      scanSnap?.boundRepositoryRoot?.toLowerCase() === repoA.repoDir.toLowerCase(),
      `Expected boundRepositoryRoot to be repoA ('${repoA.repoDir}'), got '${scanSnap?.boundRepositoryRoot}'`
    );
    assertCondition(
      scanSnap?.evaluatedState.state === "Block",
      `Expected 'Block' on repoA scan, got '${scanSnap?.evaluatedState.state}'`
    );
    assertCondition(
      hostState.progressTitles.some((t) => t.includes("Checkwash Lens: Scanning committed range")),
      "Scanning committed range must run inside a cancellable progress notification"
    );

    // 5. `checkwash-rev:` for bound repoA succeeds; forged `checkwash-rev:` for repoB is rejected
    const boundDocText = await revProvider!.provideTextDocumentContent(forgedUriA);
    assertCondition(
      boundDocText.includes("def test_compute():") && boundDocText.includes("assert True"),
      "checkwash-rev: provider must return exact committed HEAD blob for bound repoA"
    );

    const builtUriBRes = buildRevisionUriString({
      repositoryRoot: repoB.repoDir,
      commitOid: repoB.headSha,
      relativePath: repoB.testRelPath,
      side: "head",
      scanId: 1,
    });
    assertCondition(builtUriBRes.ok, "buildRevisionUriString for repoB must succeed");
    const forgedUriB = MockUri.parse(builtUriBRes.value);
    const crossRepoDocText = await revProvider!.provideTextDocumentContent(forgedUriB);
    assertCondition(
      crossRepoDocText.includes("Unable to load revision") &&
        crossRepoDocText.includes("does not match active repository"),
      `Expected cross-repo checkwash-rev: lookup to be rejected, got: ${crossRepoDocText}`
    );

    // 6. Remove repoA from workspaceFolders and fire `onDidChangeWorkspaceFolders`
    hostState.workspaceFolders = [
      { uri: virtualUri, name: "virtual-repo", index: 0 },
      { uri: MockUri.file(repoB.repoDir), name: "repoB", index: 1 },
    ];
    hostState.onDidChangeWorkspaceFoldersEmitter.fire({});

    const snapAfterRemoval = controller.getViewSnapshot();
    const cwDiagsAfterRemoval =
      hostState.diagnosticCollections.get(CHECKWASH_DIAGNOSTIC_SOURCE)?.size ?? 0;
    const fgDiagsAfterRemoval =
      hostState.diagnosticCollections.get(FAST_GUARD_SOURCE_LABEL)?.size ?? 0;

    assertCondition(
      snapAfterRemoval.boundRepositoryRoot === null,
      "Removing bound folder from workspaceFolders must unbind the repository"
    );
    assertCondition(
      snapAfterRemoval.evaluatedState.state === "Not Run" &&
        hostState.statusBarItem.text.includes("Checkwash: Not Run"),
      "Removing bound folder must reset evaluatedState and StatusBarItem to 'Not Run'"
    );
    assertCondition(
      cwDiagsAfterRemoval === 0 && fgDiagsAfterRemoval === 0,
      "Removing bound folder must clear all live diagnostics"
    );

    for (const sub of subscriptions) {
      sub.dispose();
    }
    await deactivate();

    return {
      quickPickPrompted,
      virtualFolderRejected: !virtualAdmission.ok,
      unboundRevisionRejected: unboundDocText.includes("No active repository is currently bound"),
      crossRepoRevisionRejected: crossRepoDocText.includes("does not match active repository"),
      unboundOnFolderRemoval: snapAfterRemoval.boundRepositoryRoot === null,
      diagnosticsAfterRemoval: cwDiagsAfterRemoval + fgDiagsAfterRemoval,
    };
  } finally {
    fs.rmSync(repoA.repoDir, { recursive: true, force: true });
    fs.rmSync(repoB.repoDir, { recursive: true, force: true });
  }
}

// ============================================================================
// P5-C4: End-to-End Commands, Diagnostics, Hover, TreeView & Dirty Invalidation
// ============================================================================

async function testP5C4EndToEndCommandsDiagnosticsHoverAndDirtyEdit(): Promise<
  Record<string, unknown>
> {
  hostState.reset();
  const { repoDir, headTestContent } = initGitRepoWithTwoCommits();

  try {
    configureTrustedMachinePaths();
    hostState.workspaceFolders = [{ uri: MockUri.file(repoDir), name: "repo", index: 0 }];

    const testFileAbsPath = path.join(repoDir, "tests", "test_calc.py");
    const openDoc: MockTextDocument = {
      uri: MockUri.file(testFileAbsPath),
      fsPath: testFileAbsPath,
      version: 1,
      isDirty: false,
      isClosed: false,
      getText: () => headTestContent,
    };
    hostState.textDocuments = [openDoc];

    let brokerInvocations = 0;
    const spyRunner = new UnifiedProcessRunner();
    spyRunner.setCustomBrokerExecutorForTests(async (req, signal) => {
      brokerInvocations++;
      return executeViaWindowsBroker(req, signal);
    });
    const spyController = new CheckwashLensController(spyRunner);

    const subscriptions: Array<{ dispose(): unknown }> = [];
    const ctx = makeExtensionContext(subscriptions);
    activate(ctx, spyController);

    // 1. Run `checkwashLens.scanCommittedRange` with clean editor buffer matching HEAD
    const snap = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanCommittedRange",
      "HEAD~1..HEAD"
    );
    const invocationsAfterScan = brokerInvocations;
    assertCondition(
      snap?.evaluatedState.state === "Block",
      `Expected 'Block', got '${snap?.evaluatedState.state}'`
    );
    assertCondition(
      hostState.statusBarItem.text.startsWith("$(error) Checkwash: Block") &&
        hostState.statusBarItem.backgroundColor?.id === "statusBarItem.errorBackground",
      `Unexpected StatusBarItem state: text='${hostState.statusBarItem.text}', bg='${hostState.statusBarItem.backgroundColor?.id}'`
    );

    // 2. Verify separate DiagnosticCollections (`Checkwash` vs `Fast Guard (Heuristic)`)
    const cwStore = hostState.diagnosticCollections.get(CHECKWASH_DIAGNOSTIC_SOURCE)!;
    const fgStore = hostState.diagnosticCollections.get(FAST_GUARD_SOURCE_LABEL)!;
    const docKey = makeDiagStoreKey(testFileAbsPath);
    const cwDiags = cwStore.get(docKey) ?? [];
    const fgDiags = fgStore.get(docKey) ?? [];

    assertCondition(cwDiags.length >= 1, "Expected >=1 Checkwash live diagnostic on clean file");
    assertCondition(fgDiags.length >= 1, "Expected >=1 Fast Guard live diagnostic on clean file");
    assertCondition(
      cwDiags.every((d) => d.source === CHECKWASH_DIAGNOSTIC_SOURCE) &&
        fgDiags.every((d) => d.source === FAST_GUARD_SOURCE_LABEL),
      "Checkwash and Fast Guard DiagnosticCollections must keep distinct source labels"
    );

    // 3. Verify HoverProvider on the Checkwash finding line and Fast Guard hint line
    assertCondition(hostState.hoverProviders.length === 1, "HoverProvider must be registered");
    const hoverProvider = hostState.hoverProviders[0];
    const cwLine0 = cwDiags[0].range.start.line;
    const fgLine0 = fgDiags[0].range.start.line;

    const cwHover = hoverProvider.provideHover(openDoc, new MockPosition(cwLine0, 4));
    const fgHover = hoverProvider.provideHover(openDoc, new MockPosition(fgLine0, 4));
    const emptyHover = hoverProvider.provideHover(openDoc, new MockPosition(0, 0));

    assertCondition(
      cwHover !== null &&
        cwHover.contents.isTrusted === false &&
        cwHover.contents.value.includes(`[${CHECKWASH_DIAGNOSTIC_SOURCE}]`),
      "Hover on Checkwash finding line must return untrusted-safe MarkdownString with Checkwash source"
    );
    assertCondition(
      fgHover !== null &&
        fgHover.contents.isTrusted === false &&
        fgHover.contents.value.includes(`[${FAST_GUARD_SOURCE_LABEL}]`),
      "Hover on Fast Guard line must return untrusted-safe MarkdownString with Fast Guard source"
    );
    assertCondition(emptyHover === null, "Hover on line 0 with no finding must return null");

    // 4. Verify TreeDataProvider nodes and `checkwashLens.openImmutableRevision` command
    const treeProvider = hostState.treeDataProviders.get("checkwashLens.findingsView");
    assertCondition(Boolean(treeProvider), "TreeDataProvider must be registered");
    const rootNodes = treeProvider.getChildren();
    assertCondition(rootNodes.length === 4, `Expected 4 root tree sections, got ${rootNodes.length}`);

    const headFinding =
      snap!.enrichedFindings.find((f) => f.item.evidenceSide === "head") ??
      snap!.enrichedFindings[0];
    const headFindingUri = headFinding.preferredRevisionUri;
    const headFindingLine = headFinding.revealLine1Based;
    const openedRevDoc = await mockVscodeModule.commands.executeCommand<MockTextDocument>(
      "checkwashLens.openImmutableRevision",
      headFindingUri,
      headFindingLine
    );
    assertCondition(
      Boolean(openedRevDoc) && openedRevDoc.getText().includes("assert True"),
      "openImmutableRevision on head finding must open the read-only HEAD checkwash-rev: document"
    );
    assertCondition(
      hostState.lastShownEditorSelection?.start.line === (headFindingLine ?? 1) - 1,
      "openImmutableRevision must position editor selection at 0-based target line"
    );

    const baseFinding = snap!.enrichedFindings.find((f) => f.item.evidenceSide === "base");
    if (baseFinding && baseFinding.preferredRevisionUri) {
      const openedBaseDoc = await mockVscodeModule.commands.executeCommand<MockTextDocument>(
        "checkwashLens.openImmutableRevision",
        baseFinding.preferredRevisionUri,
        baseFinding.revealLine1Based
      );
      assertCondition(
        Boolean(openedBaseDoc) && openedBaseDoc.getText().includes("assert compute(100) == 80"),
        "openImmutableRevision on base finding must open the read-only BASE checkwash-rev: document"
      );
    }

    // 5. Simulate user typing in the open editor (`isDirty = true`, `version = 2`)
    openDoc.isDirty = true;
    openDoc.version = 2;
    const invocationsBeforeEdit = brokerInvocations;
    hostState.onDidChangeTextDocumentEmitter.fire({});

    const cwDiagsAfterDirty = cwStore.get(docKey) ?? [];
    const fgDiagsAfterDirty = fgStore.get(docKey) ?? [];
    assertCondition(
      brokerInvocations === invocationsBeforeEdit,
      "Editing document must spawn 0 external processes"
    );
    assertCondition(
      cwDiagsAfterDirty.length === 0 && fgDiagsAfterDirty.length === 0,
      "Dirty buffer edit must immediately clear live inline diagnostics in both collections"
    );
    assertCondition(
      hostState.statusBarItem.text.startsWith("$(error) Checkwash: Block"),
      "Dirty buffer edit must NOT clear committed Checkwash verdict in StatusBarItem"
    );

    for (const sub of subscriptions) {
      sub.dispose();
    }
    await deactivate();

    return {
      invocationsAfterScan,
      cleanCheckwashDiagnosticsCount: cwDiags.length,
      cleanFastGuardDiagnosticsCount: fgDiags.length,
      hoverIsTrustedFlag: cwHover!.contents.isTrusted,
      diagnosticsAfterDirtyEdit: cwDiagsAfterDirty.length + fgDiagsAfterDirty.length,
      statusBarPreservedAfterDirtyEdit: hostState.statusBarItem.text,
    };
  } finally {
    fs.rmSync(repoDir, { recursive: true, force: true });
  }
}

// ============================================================================
// P5-C5: Context Diet Modal Clipboard Gate Through Extension Command
// ============================================================================

async function testP5C5ContextDietModalClipboardGate(): Promise<Record<string, unknown>> {
  hostState.reset();
  const { repoDir } = initGitRepoWithTwoCommits({ includeSecretInSecondCommit: true });

  try {
    configureTrustedMachinePaths();
    hostState.workspaceFolders = [{ uri: MockUri.file(repoDir), name: "repo", index: 0 }];

    const subscriptions: Array<{ dispose(): unknown }> = [];
    const ctx = makeExtensionContext(subscriptions);
    activate(ctx);

    await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanCommittedRange",
      "HEAD~1..HEAD"
    );

    // 1. User dismisses the Sensitive Data Guard modal (`undefined`) -> nothing copied
    hostState.clipboardText = "INITIAL_CLIPBOARD";
    hostState.warningModalHandler = async (_msg, _opts, _buttons) => undefined;
    const cancelRes = await mockVscodeModule.commands.executeCommand(
      "checkwashLens.copyContextDietDiff"
    );
    assertCondition(
      cancelRes === null && hostState.clipboardText === "INITIAL_CLIPBOARD",
      "Dismissing Context Diet modal must not write to clipboard"
    );

    // 2. User selects "Copy Redacted Diff (Recommended)" -> redacted diff copied, zero raw secrets
    hostState.warningModalHandler = async (_msg, _opts, buttons) =>
      buttons.find((b) => b.includes("Copy Redacted Diff"));
    const redactedRes = await mockVscodeModule.commands.executeCommand<{
      payloadToCopy: string;
      modeUsed: string;
    }>("checkwashLens.copyContextDietDiff");
    assertCondition(
      redactedRes?.modeUsed === "redacted" &&
        hostState.clipboardText.includes("[REDACTED:") &&
        hostState.clipboardText.includes("package-lock.json") &&
        !hostState.clipboardText.includes("SYNTHETIC_P5_SECRET_999") &&
        !hostState.clipboardText.includes("ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
      "Redacted copy must mask all secrets in both notice and diff body while preserving omitted-file notice"
    );

    // 3. User selects "Copy Unredacted Diff (Unsafe)" -> unredacted diff copied after explicit modal confirmation
    hostState.warningModalHandler = async (_msg, _opts, buttons) =>
      buttons.find((b) => b.includes("Copy Unredacted Diff (Unsafe)"));
    const unredactedRes = await mockVscodeModule.commands.executeCommand<{
      payloadToCopy: string;
      modeUsed: string;
    }>("checkwashLens.copyContextDietDiff");
    assertCondition(
      unredactedRes?.modeUsed === "unredacted" &&
        hostState.clipboardText.includes("SYNTHETIC_P5_SECRET_999"),
      "Confirmed unredacted copy must copy unredacted payload when explicitly chosen in modal"
    );

    for (const sub of subscriptions) {
      sub.dispose();
    }
    await deactivate();

    return {
      cancelledModalClipboardUnchanged: true,
      redactedModeUsed: redactedRes?.modeUsed,
      redactedLeakedSecret:
        redactedRes!.payloadToCopy.includes("SYNTHETIC_P5_SECRET_999") ||
        redactedRes!.payloadToCopy.includes("ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
      unredactedModeUsed: unredactedRes?.modeUsed,
    };
  } finally {
    fs.rmSync(repoDir, { recursive: true, force: true });
  }
}

// ============================================================================
// P5-C6: Prove Modal Confirmation Gate, Offline Report Read-Only & Deactivate
// ============================================================================

async function testP5C6ProveModalGateOfflineReportAndDeactivate(): Promise<
  Record<string, unknown>
> {
  hostState.reset();
  const { repoDir } = initGitRepoWithTwoCommits({
    dirPrefix: "cw-lens-realhost-c++ & R&D-",
  });

  try {
    configureTrustedMachinePaths();
    hostState.workspaceFolders = [{ uri: MockUri.file(repoDir), name: "repo", index: 0 }];

    let brokerInvocations = 0;
    const spyRunner = new UnifiedProcessRunner();
    spyRunner.setCustomBrokerExecutorForTests(async (req, signal) => {
      brokerInvocations++;
      return executeViaWindowsBroker(req, signal);
    });
    const spyController = new CheckwashLensController(spyRunner);

    const subscriptions: Array<{ dispose(): unknown }> = [];
    const ctx = makeExtensionContext(subscriptions);
    activate(ctx, spyController);

    // Part A0: Missing `provePath` must fail fast with a clear error message BEFORE prompting any modal
    hostState.configInspections.set("provePath", { globalValue: "", defaultValue: "" });
    let modalPromptedWhenUnconfigured = false;
    hostState.warningModalHandler = async () => {
      modalPromptedWhenUnconfigured = true;
      return undefined;
    };
    const unconfiguredProveRes = await mockVscodeModule.commands.executeCommand(
      "checkwashLens.runProveList",
      "HEAD~1..HEAD"
    );
    assertCondition(
      unconfiguredProveRes === null &&
        !modalPromptedWhenUnconfigured &&
        brokerInvocations === 0 &&
        hostState.shownErrors.some((e) => e.includes("checkwashLens.provePath")),
      "Unconfigured provePath must fail fast with showErrorMessage and 0 modal prompts"
    );
    hostState.shownErrors.length = 0;
    configureTrustedMachinePaths();

    // Part A: Dismissing the Prove execution-risk modal for `runProveList`, `runProveFull`,
    // and `replayMutant` must NEVER execute Prove analysis (only read-only preflight `--version`/`rev-parse`
    // runs during plan preparation, and nonexistent replay record fails before spawning anything)!
    const modalMessagesSeen: string[] = [];
    const proveExecInvocationsSeen: string[][] = [];
    spyRunner.setCustomBrokerExecutorForTests(async (req, sig) => {
      brokerInvocations++;
      if (
        path.basename(req.executable).toLowerCase().includes("prove") &&
        !(req.args.length === 1 && req.args[0] === "--version")
      ) {
        proveExecInvocationsSeen.push([...req.args]);
      }
      return executeViaWindowsBroker(req, sig);
    });
    hostState.warningModalHandler = async (msg) => {
      modalMessagesSeen.push(msg);
      return undefined; // User cancels modal
    };

    const listCancelled = await mockVscodeModule.commands.executeCommand(
      "checkwashLens.runProveList",
      "HEAD~1..HEAD"
    );
    const fullCancelled = await mockVscodeModule.commands.executeCommand(
      "checkwashLens.runProveFull",
      "HEAD~1..HEAD"
    );
    const invBeforeInvalidReplay = brokerInvocations;
    const nonexistentReplay = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.replayMutant",
      999,
      "m1"
    );

    assertCondition(
      listCancelled === null && fullCancelled === null,
      "Cancelling Prove List/Full modals must return null"
    );
    assertCondition(
      nonexistentReplay?.proveOutcome.status === "Execution error" &&
        brokerInvocations === invBeforeInvalidReplay,
      "Replay on nonexistent record must fail closed before spawning any process"
    );
    assertCondition(
      proveExecInvocationsSeen.length === 0,
      `Cancelling Prove modals must launch 0 Prove analysis runs, got ${proveExecInvocationsSeen.length}`
    );
    assertCondition(
      modalMessagesSeen.length === 2 &&
        modalMessagesSeen.every(
          (m) => m.includes(PROVE_EXECUTION_RISK_WARNING) && m.includes("Pinned Commits:")
        ),
      "Prove List & Full modals must display PROVE_EXECUTION_RISK_WARNING and pinned commit OIDs"
    );

    // Part B: Confirm modal and execute real `runProveFull`, test cancelling Replay modal on real record, then confirm Replay
    hostState.warningModalHandler = async (_msg, _opts, buttons) => buttons[0];
    const proveFullSnap = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.runProveFull",
      "HEAD~1..HEAD"
    );
    assertCondition(
      proveFullSnap?.proveOutcome.status === "Compared" &&
        proveFullSnap.proveOutcome.record !== null,
      `Expected real Prove full command to complete with status 'Compared', got '${proveFullSnap?.proveOutcome.status}' (${proveFullSnap?.proveOutcome.errorReason})`
    );
    assertCondition(
      hostState.progressTitles.some((t) => t.includes("Checkwash Lens: Running full Prove analysis")),
      "Prove full execution must display a cancellable progress notification"
    );
    assertCondition(
      proveFullSnap.evaluatedState.state === "Not Run",
      "Running Prove without a static scan must keep Checkwash static verdict at 'Not Run' (Prove never alters static verdict)"
    );

    const recordRunId = proveFullSnap.proveOutcome.record!.runId;
    const parsedRep = proveFullSnap.proveOutcome.record!.parsedReport;
    const firstMutantId =
      parsedRep.protectionLosses[0]?.id ??
      parsedRep.unconfirmedLosses[0]?.id ??
      parsedRep.candidates[0]?.id;
    assertCondition(Boolean(firstMutantId), "Expected >=1 mutant from real Prove run");

    // Cancel Replay modal on real record -> 0 new Prove analysis invocations
    const proveRunsBeforeReplayCancel = proveExecInvocationsSeen.length;
    let replayModalSeen = "";
    hostState.warningModalHandler = async (msg) => {
      replayModalSeen = msg;
      return undefined;
    };
    const replayCancelled = await mockVscodeModule.commands.executeCommand(
      "checkwashLens.replayMutant",
      recordRunId,
      firstMutantId
    );
    assertCondition(
      replayCancelled === null &&
        proveExecInvocationsSeen.length === proveRunsBeforeReplayCancel &&
        replayModalSeen.includes(PROVE_EXECUTION_RISK_WARNING) &&
        replayModalSeen.includes(`Pinned Mutant ID: ${firstMutantId}`),
      "Cancelling Replay modal must display pinned mutant details and spawn 0 Prove replay runs"
    );

    // Now confirm Replay modal and execute real single-mutant Replay
    hostState.warningModalHandler = async (_msg, _opts, buttons) => buttons[0];
    const replaySnap = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.replayMutant",
      recordRunId,
      firstMutantId
    );
    assertCondition(
      replaySnap?.proveOutcome.status === "Compared" &&
        replaySnap.proveOutcome.record?.entryKind === "replay",
      `Expected real mutant replay to complete with status 'Compared', got '${replaySnap?.proveOutcome.status}'`
    );

    // Part C: Offline report import (`viewOfflineReport`) rejects non-file URIs, loads local JSON
    // in read-only mode, and blocks `replayMutant` on imported offline records even if modal is confirmed!
    const virtualReportRes = await mockVscodeModule.commands.executeCommand(
      "checkwashLens.viewOfflineReport",
      MockUri.parse("vscode-vfs://github/org/repo/report.json")
    );
    assertCondition(
      virtualReportRes === null &&
        hostState.shownErrors.some((e) => e.includes("Offline report must be a local file")),
      "viewOfflineReport must reject non-file:// URIs"
    );

    const offlineJsonPath = path.join(repoDir, "offline-prove-report.json");
    fs.writeFileSync(
      offlineJsonPath,
      JSON.stringify(parsedRep.raw, null, 2),
      "utf-8"
    );
    const offlineSnap = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.viewOfflineReport",
      MockUri.file(offlineJsonPath)
    );
    const offlineRunId = offlineSnap?.proveOutcome.record?.runId;
    assertCondition(
      offlineSnap?.proveOutcome.record?.isImportedExternalReport === true &&
        typeof offlineRunId === "number",
      "viewOfflineReport must import report with isImportedExternalReport=true"
    );

    const invocationsBeforeOfflineReplay = brokerInvocations;
    const offlineReplaySnap = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.replayMutant",
      offlineRunId,
      firstMutantId
    );
    assertCondition(
      brokerInvocations === invocationsBeforeOfflineReplay &&
        offlineReplaySnap?.proveOutcome.status === "Execution error" &&
        Boolean(offlineReplaySnap.proveOutcome.errorReason?.toLowerCase().includes("external")),
      `Attempting to replay an offline-imported report must fail closed with 0 processes spawned, got: ${JSON.stringify(offlineReplaySnap?.proveOutcome)}`
    );

    // Part D: `deactivate()` cancels active operation and clears activeController
    await deactivate();
    assertCondition(
      getActiveController() === null && !spyController.getProcessRunner().isOperationActive(),
      "deactivate() must stop active operations and clear activeController"
    );

    for (const sub of subscriptions) {
      sub.dispose();
    }

    return {
      invocationsWhenModalsCancelled: 0,
      proveFullStatus: proveFullSnap.proveOutcome.status,
      staticVerdictUnchangedByProve: proveFullSnap.evaluatedState.state,
      replayedMutantId: firstMutantId,
      offlineReportIsImportedExternal: offlineSnap?.proveOutcome.record?.isImportedExternalReport,
      offlineReplayBlockedWithZeroProcesses: brokerInvocations === invocationsBeforeOfflineReplay,
      deactivatedCleanly: getActiveController() === null,
    };
  } finally {
    fs.rmSync(repoDir, { recursive: true, force: true });
  }
}

// ============================================================================
// P5-C7: Real Desktop VS Code 1.136.0 Extension Host Activation & Scan
// ============================================================================

async function testP5C7RealDesktopVSCodeExtensionHost(): Promise<Record<string, unknown>> {
  const codeExePath = process.env.CW_TEST_CODE_EXE || resolveTestVscodeExe();
  assertCondition(
    fs.existsSync(codeExePath),
    `Desktop VS Code executable not found at '${codeExePath}'`
  );

  const { repoDir } = initGitRepoWithTwoCommits({
    dirPrefix: "cw-lens-realhost-c++ & R&D-",
  });
  const tempHostRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-lens-real-vscode-"));
  const userDataDir = path.join(tempHostRoot, "user-data");
  const extensionsDir = path.join(tempHostRoot, "extensions");
  const receiptPath = path.join(tempHostRoot, "real-vscode-receipt.json");

  try {
    fs.mkdirSync(path.join(userDataDir, "User"), { recursive: true });
    fs.mkdirSync(extensionsDir, { recursive: true });

    // Configure User settings in the isolated VS Code user-data-dir
    fs.writeFileSync(
      path.join(userDataDir, "User", "settings.json"),
      JSON.stringify(
        {
          "security.workspace.trust.enabled": false,
          "window.restoreWindows": "none",
          "telemetry.telemetryLevel": "off",
          "update.mode": "none",
          "checkwashLens.pythonPath": PYTHON_EXE,
          "checkwashLens.gitPath": GIT_EXE,
        },
        null,
        2
      ),
      "utf-8"
    );

    const testEntryJs = path.join(REPO_ROOT, "dist", "test", "vscode_real_host_entry.js");
    const envForCode: NodeJS.ProcessEnv = {
      ...process.env,
      CW_LENS_REAL_VSCODE_RECEIPT_PATH: receiptPath,
      CW_LENS_REAL_VSCODE_REPO_DIR: repoDir,
    };
    delete envForCode.ELECTRON_RUN_AS_NODE;

    const args = [
      "--headless",
      ...getPlatformVscodeLaunchArgs(),
      "--disable-gpu",
      "--disable-updates",
      "--skip-welcome",
      "--skip-release-notes",
      "--disable-workspace-trust",
      "--disable-extensions",
      `--user-data-dir=${userDataDir}`,
      `--extensions-dir=${extensionsDir}`,
      `--extensionDevelopmentPath=${REPO_ROOT}`,
      `--extensionTestsPath=${testEntryJs}`,
      repoDir,
    ];

    const spawnRes = cp.spawnSync(codeExePath, args, {
      cwd: REPO_ROOT,
      env: envForCode,
      encoding: "utf-8",
      timeout: 60_000,
      windowsHide: true,
    });

    assertCondition(
      fs.existsSync(receiptPath),
      `Real VS Code Extension Host did not write receipt (exit=${spawnRes.status}, stderr=${spawnRes.stderr})`
    );
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf-8")) as Record<string, unknown>;
    assertCondition(
      receipt.ok === true && spawnRes.status === 0,
      `Real VS Code Extension Host test failed: ${JSON.stringify(receipt)} (exit=${spawnRes.status})`
    );

    return receipt;
  } finally {
    fs.rmSync(repoDir, { recursive: true, force: true });
    try {
      fs.rmSync(tempHostRoot, { recursive: true, force: true });
    } catch {
      // Ignore transient VS Code log file locks during cleanup
    }
  }
}

// ============================================================================
// P5-C8: Windows Directory Junction Workspace + Special-Char URI + Zero-Spawn Cache
// ============================================================================

async function testP5C8JunctionWorkspaceAndSpecialUriRoundTrip(): Promise<
  Record<string, unknown>
> {
  hostState.reset();
  const { repoDir: realRepoDir, headTestContent } = initGitRepoWithTwoCommits({
    dirPrefix: "cw-lens-real-c++ & R&D 100%-",
  });
  const junctionParent = fs.mkdtempSync(path.join(os.tmpdir(), "cw-lens-junc-"));
  const junctionPath = path.join(junctionParent, "ws-junction-link");
  fs.symlinkSync(realRepoDir, junctionPath, IS_WIN32 ? "junction" : "dir");

  try {
    configureTrustedMachinePaths();
    hostState.workspaceFolders = [{ uri: MockUri.file(junctionPath), name: "junc-repo", index: 0 }];

    const juncTestFileAbs = path.join(junctionPath, "tests", "test_calc.py");
    const openDoc: MockTextDocument = {
      uri: MockUri.file(juncTestFileAbs),
      fsPath: juncTestFileAbs,
      version: 1,
      isDirty: false,
      isClosed: false,
      getText: () => headTestContent,
    };
    hostState.textDocuments = [openDoc];

    let brokerInvocations = 0;
    const spyRunner = new UnifiedProcessRunner();
    spyRunner.setCustomBrokerExecutorForTests(async (req, signal) => {
      brokerInvocations++;
      return executeViaWindowsBroker(req, signal);
    });
    const spyController = new CheckwashLensController(spyRunner);

    const subscriptions: Array<{ dispose(): unknown }> = [];
    const ctx = makeExtensionContext(subscriptions);
    activate(ctx, spyController);

    // 1. Scan #1 through junction workspace folder
    const snap1 = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanCommittedRange",
      "HEAD~1..HEAD"
    );
    assertCondition(
      snap1?.evaluatedState.state === "Block",
      `Expected Scan #1 state 'Block' on junction workspace, got '${snap1?.evaluatedState.state}'`
    );

    // 2. Live diagnostics must attach to the junction workspace URI (matching the open editor tab!)
    const cwStore = hostState.diagnosticCollections.get(CHECKWASH_DIAGNOSTIC_SOURCE)!;
    const fgStore = hostState.diagnosticCollections.get(FAST_GUARD_SOURCE_LABEL)!;
    const juncDocKey = makeDiagStoreKey(juncTestFileAbs);
    const cwDiags = cwStore.get(juncDocKey) ?? [];
    const fgDiags = fgStore.get(juncDocKey) ?? [];
    assertCondition(
      cwDiags.length >= 1 && fgDiags.length >= 1,
      `Expected live diagnostics on junction file URI '${juncDocKey}', got cw=${cwDiags.length}, fg=${fgDiags.length}`
    );

    // 3. Hover on junction-opened file must resolve Checkwash diagnostic after boundRepositoryRoot canonicalized
    const hoverProvider = hostState.hoverProviders[0];
    const hoverRes = hoverProvider.provideHover(
      openDoc,
      new MockPosition(cwDiags[0].range.start.line, 4)
    );
    assertCondition(
      hoverRes !== null && hoverRes.contents.value.includes(`[${CHECKWASH_DIAGNOSTIC_SOURCE}]`),
      "Hover on junction-opened document must succeed after canonical repo binding"
    );

    // 4. Opening `checkwash-rev:` URI (with `+`, `&`, `%`, spaces in canonical repo path) must round-trip
    //    through MockUri.parse().toString() AND hit RevisionProvider.blobCache in 0 spawns!
    const headFinding =
      snap1!.enrichedFindings.find((f) => f.item.evidenceSide === "head") ??
      snap1!.enrichedFindings[0];
    const spawnsBeforeRevOpen = brokerInvocations;
    const revDoc = await mockVscodeModule.commands.executeCommand<MockTextDocument>(
      "checkwashLens.openImmutableRevision",
      headFinding.preferredRevisionUri,
      headFinding.revealLine1Based
    );
    const spawnsForCachedRevOpen = brokerInvocations - spawnsBeforeRevOpen;
    assertCondition(
      Boolean(revDoc) && revDoc.getText().includes("assert True"),
      `Failed to open checkwash-rev: URI with special characters: ${revDoc?.getText()}`
    );
    assertCondition(
      spawnsForCachedRevOpen === 0,
      `Expected 0 broker spawns on cached checkwash-rev: blob open, got ${spawnsForCachedRevOpen}`
    );

    // 5. Scan #2 on the same junction workspace must NOT unbind or fail ensureSelectedRepo
    const snap2 = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanCommittedRange",
      "HEAD~1..HEAD"
    );
    assertCondition(
      snap2?.evaluatedState.state === "Block" && (cwStore.get(juncDocKey) ?? []).length >= 1,
      "Scan #2 on junction workspace must preserve canonical binding and live diagnostics"
    );

    // 6. Dirty edit on junction-opened document must clear live diagnostics immediately with 0 spawns
    openDoc.isDirty = true;
    openDoc.version = 2;
    const spawnsBeforeDirty = brokerInvocations;
    hostState.onDidChangeTextDocumentEmitter.fire({});
    assertCondition(
      brokerInvocations === spawnsBeforeDirty &&
        (cwStore.get(juncDocKey) ?? []).length === 0 &&
        (fgStore.get(juncDocKey) ?? []).length === 0,
      "Dirty edit on junction-opened document must clear live diagnostics with 0 spawns"
    );

    for (const sub of subscriptions) {
      sub.dispose();
    }
    await deactivate();

    return {
      junctionPath,
      canonicalRepoDir: fs.realpathSync.native(realRepoDir),
      scan1Verdict: snap1?.evaluatedState.state,
      scan2Verdict: snap2?.evaluatedState.state,
      junctionCheckwashDiagnostics: cwDiags.length,
      junctionFastGuardDiagnostics: fgDiags.length,
      spawnsForCachedRevOpen,
    };
  } finally {
    try {
      fs.rmSync(junctionParent, { recursive: true, force: true });
    } catch {
      // Ignore junction cleanup error
    }
    fs.rmSync(realRepoDir, { recursive: true, force: true });
  }
}

// ============================================================================
// P5-C9: Environment Doctor Guided Global Setup + Uncommitted Snapshot QuickPick
// ============================================================================

async function testP5C9EnvironmentDoctorGuidedSetupAndSnapshotQuickPick(): Promise<
  Record<string, unknown>
> {
  hostState.reset();
  const { repoDir } = initGitRepoWithTwoCommits();

  try {
    // Configure broken global pythonPath + poisoned workspace settings so Doctor diagnoses both
    const staleBrokenPy = IS_WIN32
      ? "C:\\NonExistentCheckwashPython99\\python.exe"
      : "/nonexistent-checkwash-python99/bin/python3";
    hostState.configInspections.set("pythonPath", {
      globalValue: staleBrokenPy,
      workspaceValue: path.join(repoDir, IS_WIN32 ? "evil_workspace_python.exe" : "evil_workspace_python3"),
      defaultValue: "",
    });
    hostState.configInspections.set("gitPath", {
      globalValue: GIT_EXE,
      workspaceFolderValue: path.join(repoDir, IS_WIN32 ? "evil_folder_git.exe" : "evil_folder_git"),
      defaultValue: "",
    });
    hostState.configInspections.set("provePath", {
      globalValue: PROVE_EXE,
      defaultValue: "",
    });
    hostState.workspaceFolders = [{ uri: MockUri.file(repoDir), name: "repo", index: 0 }];

    const subscriptions: Array<{ dispose(): unknown }> = [];
    const ctx = makeExtensionContext(subscriptions);
    activate(ctx);

    // 1. User clicks "Save Verified Paths to User Settings" when prompted by Environment Doctor
    hostState.infoActionHandler = async (_msg, items) =>
      items.find((i) => i === "Save Verified Paths to User Settings");

    const doctorReport = await mockVscodeModule.commands.executeCommand<{
      overallReadyForStaticScan: boolean;
      workspaceSettingsWarnings: Array<{ key: string }>;
      recommendedUserSettingsPatch: Record<string, string>;
    }>("checkwashLens.runEnvironmentDoctor");

    assertCondition(
      doctorReport?.overallReadyForStaticScan === false &&
        doctorReport.workspaceSettingsWarnings.length === 2,
      "Expected Environment Doctor to detect broken pythonPath and 2 poisoned workspace overrides"
    );
    assertCondition(
      hostState.lastShownDocument?.uri.scheme === "checkwash-doctor" &&
        hostState.lastShownDocument.getText().includes("Ignored Workspace Settings"),
      "Expected Environment Doctor to open read-only checkwash-doctor: virtual Markdown report"
    );
    assertCondition(
      hostState.configUpdates.length >= 1 &&
        hostState.configUpdates.every(
          (u) => u.section === "checkwashLens" && u.target === 1
        ) &&
        hostState.configUpdates.some(
          (u) =>
            u.key === "pythonPath" &&
            typeof u.value === "string" &&
            u.value === doctorReport.recommendedUserSettingsPatch.pythonPath &&
            fs.existsSync(u.value)
        ),
      `Expected Environment Doctor to write repaired settings strictly to ConfigurationTarget.Global (1), got: ${JSON.stringify(hostState.configUpdates)}`
    );

    // 2. Re-run Doctor silently after Global setting repair -> now static & Prove are both READY!
    const repairedReport = await mockVscodeModule.commands.executeCommand<{
      overallReadyForStaticScan: boolean;
      overallReadyForProve: boolean;
    }>("checkwashLens.runEnvironmentDoctor", { silentUi: true });
    assertCondition(
      repairedReport?.overallReadyForStaticScan === true &&
        repairedReport.overallReadyForProve === true,
      "Expected Environment Doctor to report overallReadyForStaticScan=true and overallReadyForProve=true after Global repair"
    );

    // 3. Create an untracked `tests/conftest.py` autouse skip and run `scanUncommittedSnapshot` via QuickPick
    const untrackedConftest = path.join(repoDir, "tests", "conftest.py");
    fs.writeFileSync(
      untrackedConftest,
      'import pytest\n\n@pytest.fixture(autouse=True)\ndef _skip_all():\n    pytest.skip("wip")\n',
      "utf-8"
    );
    const gitCountBefore = cp
      .spawnSync(GIT_EXE, ["-C", repoDir, "count-objects", "-v"], {
        encoding: "utf-8",
        windowsHide: true,
      })
      .stdout.trim();

    let snapshotQuickPickShown = false;
    hostState.quickPickHandler = async (items) => {
      snapshotQuickPickShown = true;
      return items.find((i: any) => i.mode === "worktree");
    };

    const precheckSnap = await mockVscodeModule.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanUncommittedSnapshot"
    );
    const gitCountAfter = cp
      .spawnSync(GIT_EXE, ["-C", repoDir, "count-objects", "-v"], {
        encoding: "utf-8",
        windowsHide: true,
      })
      .stdout.trim();

    assertCondition(snapshotQuickPickShown, "Expected QuickPick when modeArg is omitted");
    assertCondition(
      precheckSnap?.evaluatedState.state === "Block" &&
        precheckSnap.evaluatedState.scanScope === "worktree-precheck" &&
        hostState.statusBarItem.text.startsWith("$(error) Checkwash [Worktree Pre-Check]: Block"),
      `Expected Worktree Pre-Check Block verdict & badge, got: ${hostState.statusBarItem.text}`
    );
    assertCondition(
      gitCountAfter === gitCountBefore,
      "Uncommitted snapshot pre-check must not write any objects into .git/objects"
    );

    for (const sub of subscriptions) {
      sub.dispose();
    }
    await deactivate();

    return {
      doctorDetectedPoisonedSettings: doctorReport?.workspaceSettingsWarnings.length,
      doctorOpenedScheme: hostState.lastShownDocument?.uri.scheme,
      globalConfigTargetUsed: hostState.configUpdates[0]?.target,
      repairedReadyStatic: repairedReport?.overallReadyForStaticScan,
      repairedReadyProve: repairedReport?.overallReadyForProve,
      snapshotQuickPickShown,
      precheckVerdict: precheckSnap?.evaluatedState.state,
      precheckScope: precheckSnap?.evaluatedState.scanScope,
      statusBarText: hostState.statusBarItem.text,
      gitObjectsUnchanged: gitCountAfter === gitCountBefore,
    };
  } finally {
    fs.rmSync(repoDir, { recursive: true, force: true });
  }
}

// ============================================================================
// Main Runner
// ============================================================================

async function main(): Promise<void> {
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

  const results: CounterexampleTestResult[] = [];
  const suite: Array<{
    id: string;
    name: string;
    fn: () => Promise<Record<string, unknown>>;
  }> = [
    {
      id: "P5-C1",
      name: "zero_process_on_lifecycle_and_untrusted_events",
      fn: testP5C1ZeroProcessOnLifecycleAndUntrustedEvents,
    },
    {
      id: "P5-C2",
      name: "workspace_settings_poisoning_and_safe_default_path_discovery",
      fn: testP5C2WorkspaceSettingsPoisoningAndSafeDefaultPath,
    },
    {
      id: "P5-C3",
      name: "multi_folder_virtual_mix_and_workspace_folder_removal",
      fn: testP5C3MultiFolderVirtualMixAndFolderRemoval,
    },
    {
      id: "P5-C4",
      name: "end_to_end_extension_commands_diagnostics_hover_and_dirty_invalidation",
      fn: testP5C4EndToEndCommandsDiagnosticsHoverAndDirtyEdit,
    },
    {
      id: "P5-C5",
      name: "context_diet_modal_clipboard_gate_through_extension_command",
      fn: testP5C5ContextDietModalClipboardGate,
    },
    {
      id: "P5-C6",
      name: "prove_modal_gate_and_offline_report_read_only_through_extension_commands",
      fn: testP5C6ProveModalGateOfflineReportAndDeactivate,
    },
    {
      id: "P5-C7",
      name: "real_desktop_vscode_extension_host_activation_and_scan",
      fn: testP5C7RealDesktopVSCodeExtensionHost,
    },
    {
      id: "P5-C8",
      name: "junction_workspace_special_uri_roundtrip_and_zero_spawn_cache",
      fn: testP5C8JunctionWorkspaceAndSpecialUriRoundTrip,
    },
    {
      id: "P5-C9",
      name: "environment_doctor_guided_global_setup_and_uncommitted_snapshot_quickpick",
      fn: testP5C9EnvironmentDoctorGuidedSetupAndSnapshotQuickPick,
    },
  ];

  console.log("=== Checkwash Lens Phase 5 Extension Host & Counterexample Suite ===");

  for (const item of suite) {
    const start = Date.now();
    try {
      const details = await item.fn();
      const durationMs = Date.now() - start;
      results.push({
        id: item.id,
        name: item.name,
        passed: true,
        durationMs,
        details,
      });
      console.log(`[PASS] ${item.id} (${item.name}) - ${durationMs}ms`);
    } catch (err) {
      const durationMs = Date.now() - start;
      const errorMsg = err instanceof Error ? err.stack || err.message : String(err);
      results.push({
        id: item.id,
        name: item.name,
        passed: false,
        durationMs,
        details: {},
        error: errorMsg,
      });
      console.error(`[FAIL] ${item.id} (${item.name}) - ${errorMsg}`);
    }
  }

  const probeCmd = (exe: string, args: string[]): string => {
    const out = cp.spawnSync(exe, args, { encoding: "utf-8", windowsHide: true });
    return out.status === 0 ? (out.stdout || out.stderr || "").trim() : "unknown";
  };
  const sourceSha = probeCmd(GIT_EXE, ["-C", REPO_ROOT, "rev-parse", "HEAD"]);
  const pythonVersion = probeCmd(PYTHON_EXE, ["--version"]);
  const gitVersion = probeCmd(GIT_EXE, ["--version"]);

  const passedCount = results.filter((r) => r.passed).length;
  const exitCode = passedCount === results.length ? 0 : 1;
  const execMeta = getPlatformExecutionMetadata();
  const summary = {
    phase: "Phase 5 — VS Code Extension Host & End-to-End Counterexamples",
    executionTag: execMeta.evidenceTag,
    executionEnvironment: execMeta.executionEnvironment,
    hostname: execMeta.hostname,
    hostMachineHostname: execMeta.hostMachineHostname,
    containerHostname: execMeta.containerHostname,
    sourceSha,
    timestamp: new Date().toISOString(),
    platform: `${process.platform}-${process.arch}`,
    osRelease: os.release(),
    nodeVersion: process.version,
    pythonVersion,
    gitVersion,
    vscodeDesktopVersionVerified:
      (results.find((r) => r.id === "P5-C7")?.details?.vscodeVersion as string | undefined) ??
      "unknown",
    windows10Status: IS_LINUX
      ? "NOT_APPLICABLE_IN_LINUX_RECEIPT (Windows 10 x64 remains NOT_RUN overall; see Windows receipt)"
      : "NOT_RUN: Windows 10 x64 standalone verification not executed (verified on Windows 11 Pro 10.0.26200 x64)",
    exitCode,
    totalTests: results.length,
    passedTests: passedCount,
    failedTests: results.length - passedCount,
    results,
  };

  fs.writeFileSync(RESULTS_FILE, JSON.stringify(summary, null, 2), "utf-8");
  console.log(`\nWrote Phase 5 evidence to: ${RESULTS_FILE}`);

  if (passedCount !== results.length) {
    process.exit(1);
  }
}

void main();
