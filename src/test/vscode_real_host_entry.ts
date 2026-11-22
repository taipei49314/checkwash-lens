/**
 * vscode_real_host_entry.ts
 *
 * Executed inside the real Desktop VS Code (`Code.exe`) Extension Host via
 * `--extensionDevelopmentPath` and `--extensionTestsPath`.
 *
 * Verifies real VS Code Extension Host activation, command registration in
 * `vscode.commands.getCommands(true)`, real committed-range scan execution,
 * real `vscode.languages.getDiagnostics()`, real `checkwash-rev:` document opening
 * via `vscode.workspace.openTextDocument()`, and real hover resolution via
 * `vscode.commands.executeCommand("vscode.executeHoverProvider", ...)`.
 */

import * as cp from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import { getActiveController, readTrustedMachineStringSetting } from "../extension";
import {
  areSameWinRepositoryPath,
  resolveTrustedExecutableFromPath,
} from "../runtime/admission";
import { ControllerViewSnapshot } from "../ui/commands";
import { CHECKWASH_DIAGNOSTIC_SOURCE } from "../ui/diagnostics";
import { FAST_GUARD_SOURCE_LABEL } from "../engine/fastDiffGuard";

function createStandaloneTwoCommitRepo(parentDir: string): string {
  const configuredGit =
    process.env.CW_TEST_GIT_EXE?.trim() || readTrustedMachineStringSetting("gitPath", "");
  const resolvedGitRes = configuredGit
    ? { ok: true as const, value: configuredGit }
    : resolveTrustedExecutableFromPath({
        executableName: process.platform === "win32" ? "git.exe" : "git",
        repositoryRootPath: "",
        pathEnv: process.env.PATH ?? process.env.Path ?? "",
        platform: process.platform,
      });
  if (!resolvedGitRes.ok) {
    throw new Error(`Cannot locate git.exe for standalone F5 test repo: ${resolvedGitRes.error}`);
  }
  const gitExe = resolvedGitRes.value;
  const repoDir = path.join(parentDir, "repo-c++ & R&D");
  fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
  fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });

  const runGit = (args: string[]) => {
    const out = cp.spawnSync(gitExe, ["-C", repoDir, ...args], {
      encoding: "utf-8",
      windowsHide: true,
    });
    if (out.status !== 0) {
      throw new Error(`git ${args.join(" ")} failed: ${out.stderr}`);
    }
  };

  runGit(["init"]);
  runGit(["config", "user.email", "f5-test@example.local"]);
  runGit(["config", "user.name", "F5 Host Test"]);

  fs.writeFileSync(
    path.join(repoDir, "src", "calc.py"),
    "def compute(x: int) -> int:\n    return x - 20\n",
    "utf-8"
  );
  fs.writeFileSync(
    path.join(repoDir, "tests", "test_calc.py"),
    "from src.calc import compute\n\ndef test_compute():\n    assert compute(100) == 80\n",
    "utf-8"
  );
  runGit(["add", "."]);
  runGit(["commit", "-m", "base commit"]);

  fs.writeFileSync(
    path.join(repoDir, "tests", "test_calc.py"),
    "import time\nfrom src.calc import compute\n\ndef test_compute():\n    time.sleep(1)\n    _ = compute(100)\n    assert True\n",
    "utf-8"
  );
  runGit(["add", "."]);
  runGit(["commit", "-m", "head commit"]);

  return repoDir;
}

export async function run(): Promise<void> {
  let selfBootstrapRoot: string | null = null;
  let addedWorkspaceFolderIndex: number | null = null;

  let targetRepoDir = process.env.CW_LENS_REAL_VSCODE_REPO_DIR;
  let receiptPath = process.env.CW_LENS_REAL_VSCODE_RECEIPT_PATH;

  if (!targetRepoDir || !receiptPath) {
    selfBootstrapRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-lens-f5-self-"));
    if (!targetRepoDir) {
      targetRepoDir = createStandaloneTwoCommitRepo(selfBootstrapRoot);
    }
    if (!receiptPath) {
      receiptPath = path.join(selfBootstrapRoot, "f5-real-host-receipt.json");
    }
  }

  try {
    const ext = vscode.extensions.getExtension("taipei49314.checkwash-lens");
    if (!ext) {
      throw new Error("Extension 'taipei49314.checkwash-lens' not found in real VS Code host");
    }

    await ext.activate();
    const controller = getActiveController();
    if (!controller) {
      throw new Error("getActiveController() returned null after real VS Code activation");
    }

    const initialSnap = controller.getViewSnapshot();
    if (initialSnap.evaluatedState.state !== "Not Run") {
      throw new Error(
        `Expected initial state 'Not Run' after activation, got '${initialSnap.evaluatedState.state}'`
      );
    }

    const allCommands = await vscode.commands.getCommands(true);
    const expectedCommands = [
      "checkwashLens.openQuickActions",
      "checkwashLens.selectRepository",
      "checkwashLens.scanCommittedRange",
      "checkwashLens.scanUncommittedSnapshot",
      "checkwashLens.runEnvironmentDoctor",
      "checkwashLens.cancelActiveScan",
      "checkwashLens.copyContextDietDiff",
      "checkwashLens.openImmutableRevision",
      "checkwashLens.openFindingDiff",
      "checkwashLens.openWorkspaceFileAtFinding",
      "checkwashLens.runProveList",
      "checkwashLens.runProveFull",
      "checkwashLens.replayMutant",
      "checkwashLens.viewOfflineReport",
    ];
    for (const cmd of expectedCommands) {
      if (!allCommands.includes(cmd)) {
        throw new Error(`Command '${cmd}' missing from vscode.commands.getCommands(true)`);
      }
    }

    const currentFolders = vscode.workspace.workspaceFolders ?? [];
    const alreadyInWorkspace = currentFolders.some(
      (f) => f.uri.scheme === "file" && areSameWinRepositoryPath(f.uri.fsPath, targetRepoDir)
    );
    if (!alreadyInWorkspace) {
      const insertAt = currentFolders.length;
      const added = vscode.workspace.updateWorkspaceFolders(insertAt, 0, {
        uri: vscode.Uri.file(targetRepoDir),
        name: "cw-f5-self-test",
      });
      if (!added) {
        throw new Error(
          `Failed to add temporary test repository '${targetRepoDir}' to workspaceFolders`
        );
      }
      addedWorkspaceFolderIndex = insertAt;
    }

    // Bind the target repository explicitly and open tests/test_calc.py in the real VS Code host
    controller.selectRepository(targetRepoDir);
    const testFilePath = path.join(targetRepoDir, "tests", "test_calc.py");
    const testFileUri = vscode.Uri.file(testFilePath);
    const openTestDoc = await vscode.workspace.openTextDocument(testFileUri);
    await vscode.window.showTextDocument(openTestDoc, { preview: false });

    // Execute real scan command inside the VS Code Extension Host
    const scanSnap = await vscode.commands.executeCommand<ControllerViewSnapshot>(
      "checkwashLens.scanCommittedRange",
      "HEAD~1..HEAD"
    );
    if (!scanSnap || scanSnap.evaluatedState.state !== "Block") {
      throw new Error(
        `Expected real VS Code scan state 'Block', got '${scanSnap?.evaluatedState.state}' (${scanSnap?.evaluatedState.errorReason ?? scanSnap?.evaluatedState.notRunReason})`
      );
    }

    // Query real VS Code Diagnostics on test_calc.py
    const realDiagnostics = vscode.languages.getDiagnostics(testFileUri);
    const cwDiags = realDiagnostics.filter((d) => d.source === CHECKWASH_DIAGNOSTIC_SOURCE);
    const fgDiags = realDiagnostics.filter((d) => d.source === FAST_GUARD_SOURCE_LABEL);
    if (cwDiags.length < 1 || fgDiags.length < 1) {
      throw new Error(
        `Expected both Checkwash and Fast Guard diagnostics in real VS Code host, got cw=${cwDiags.length}, fg=${fgDiags.length}`
      );
    }

    // Open immutable `checkwash-rev:` document through real `vscode.workspace.openTextDocument`
    const headFinding =
      scanSnap.enrichedFindings.find((f) => f.item.evidenceSide === "head") ??
      scanSnap.enrichedFindings[0];
    if (!headFinding?.preferredRevisionUri) {
      throw new Error("Missing preferredRevisionUri on head finding");
    }
    const revDoc = await vscode.workspace.openTextDocument(
      vscode.Uri.parse(headFinding.preferredRevisionUri)
    );
    const revText = revDoc.getText();
    if (!revText.includes("assert True")) {
      throw new Error(`Unexpected checkwash-rev: document content in real VS Code host: ${revText}`);
    }

    // Execute real VS Code Hover provider on the Checkwash diagnostic line
    const targetLine0 = cwDiags[0].range.start.line;
    const hovers = await vscode.commands.executeCommand<vscode.Hover[]>(
      "vscode.executeHoverProvider",
      testFileUri,
      new vscode.Position(targetLine0, 4)
    );
    const hasCheckwashHover = (hovers ?? []).some((h) =>
      h.contents.some((c) => {
        const val = typeof c === "string" ? c : "value" in c ? c.value : "";
        return val.includes(CHECKWASH_DIAGNOSTIC_SOURCE);
      })
    );
    if (!hasCheckwashHover) {
      throw new Error("vscode.executeHoverProvider did not return Checkwash hover in real VS Code host");
    }

    const receipt = {
      ok: true,
      vscodeVersion: vscode.version,
      extensionId: ext.id,
      isWorkspaceTrusted: vscode.workspace.isTrusted,
      registeredCheckwashCommands: expectedCommands.length,
      scanVerdictState: scanSnap.evaluatedState.state,
      realCheckwashDiagnosticCount: cwDiags.length,
      realFastGuardDiagnosticCount: fgDiags.length,
      revisionUriOpenedScheme: revDoc.uri.scheme,
      hoverVerified: hasCheckwashHover,
      selfBootstrapped: selfBootstrapRoot !== null,
    };
    fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2), "utf-8");
  } catch (err) {
    const errorReceipt = {
      ok: false,
      vscodeVersion: vscode.version,
      error: err instanceof Error ? err.stack || err.message : String(err),
    };
    fs.writeFileSync(receiptPath, JSON.stringify(errorReceipt, null, 2), "utf-8");
    throw err;
  } finally {
    if (addedWorkspaceFolderIndex !== null) {
      try {
        vscode.workspace.updateWorkspaceFolders(addedWorkspaceFolderIndex, 1);
      } catch {
        // Best-effort folder cleanup
      }
    }
    if (selfBootstrapRoot) {
      try {
        fs.rmSync(selfBootstrapRoot, { recursive: true, force: true });
      } catch {
        // Ignore transient Windows file lock during host exit
      }
    }
  }
}
