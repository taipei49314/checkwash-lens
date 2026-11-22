/**
 * test/v02_doctor_staged_b08_runner.ts
 *
 * Regression & Counterexample Verification Suite for Checkwash Lens v0.2.0:
 * - Environment Doctor (`runtime/environmentDoctor.ts` & `controller.runEnvironmentDoctor`):
 *   - DOCTOR-01: Restricted Mode zero-process guarantee + `.vscode/settings.json` poisoning detection
 *   - DOCTOR-02: Inside-repo / invalid runtime rejection + safe outside-repo candidate discovery & patch
 *   - DOCTOR-03: Bare-`git` CreateProcessW loading-directory shadowing detection
 * - Uncommitted Snapshot Pre-Check (`engine/snapshotBuilder.ts` & `controller.scanUncommittedSnapshot`):
 *   - SNAP-01: Staged Pre-Check (`HEAD -> Index`) isolation from unstaged edits & untracked files,
 *              live projection withholding on diverged worktree, `checkwash-rev:` staged blob accuracy,
 *              explicit Pre-Check UI badging, and zero `.git/index` / `.git/objects` mutation
 *   - SNAP-02: Working-Tree Pre-Check (`HEAD -> Worktree`) catching untracked weakened test files,
 *              SQL `-- ` comment secret redaction in Context Diet, live projection + dirty buffer clear,
 *              and zero `.git/index` / `.git/objects` mutation
 *   - SNAP-03: Malicious `.gitattributes` `filter.*.clean` immunity (`--no-filters` & plumbing-only proof)
 *   - SNAP-04: Clean staged/worktree (`Not Run`), unborn `HEAD` rejection, NTFS directory junction
 *              escape rejection, Windows NTFS case-only rename detection, and `dispose()` temp cleanup
 */

import * as assert from "assert";
import * as cp from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { HostEnvironmentDescriptor, normalizePlatformLookupKey } from "../runtime/admission";
import { CheckwashLensController } from "../ui/commands";
import { CheckwashTreeNode } from "../ui/treeView";
import {
  ACTIVE_ARCH,
  ACTIVE_PLATFORM,
  copyExecutablePreservingMode,
  getPlatformExecutionMetadata,
  IS_WIN32,
  resolvePlatformEvidenceDir,
  resolveTestGitExe,
  resolveTestProveExe,
  resolveTestPythonExe,
} from "./testPlatformEnv";

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const EVIDENCE_DIR = resolvePlatformEvidenceDir(REPO_ROOT);
const RESULTS_FILE = path.join(EVIDENCE_DIR, "v02-doctor-staged-b08-results.json");

const PYTHON_EXE = fs.realpathSync.native(resolveTestPythonExe());
const GIT_EXE = fs.realpathSync.native(resolveTestGitExe());
const PROVE_EXE = fs.realpathSync.native(resolveTestProveExe());

function gitExec(repoDir: string, args: string[]): string {
  const res = cp.spawnSync(GIT_EXE, ["-C", repoDir, ...args], {
    encoding: "utf8",
    windowsHide: true,
  });
  if (res.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed in ${repoDir}: ${res.stderr}`);
  }
  return (res.stdout || "").trim();
}

function sha256FileIfExists(filePath: string): string | null {
  if (!fs.existsSync(filePath)) {
    return null;
  }
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function countGitObjects(repoDir: string): Record<string, string> {
  const raw = gitExec(repoDir, ["count-objects", "-v"]);
  const out: Record<string, string> = {};
  for (const line of raw.split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    }
  }
  return out;
}

function findTreeNode(nodes: readonly CheckwashTreeNode[], id: string): CheckwashTreeNode | null {
  for (const n of nodes) {
    if (n.id === id) {
      return n;
    }
    const child = findTreeNode(n.children, id);
    if (child) {
      return child;
    }
  }
  return null;
}

function makeHostDesc(
  repoDir: string,
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
    repositoryRootPath: repoDir,
    configuredPythonPath: PYTHON_EXE,
    configuredGitPath: GIT_EXE,
    inheritedEnv: process.env,
    ...overrides,
  };
}

interface SubTestReceipt {
  id: string;
  name: string;
  passed: boolean;
  durationMs: number;
  details: Record<string, unknown>;
}

async function main(): Promise<void> {
  console.log("=== Checkwash Lens v0.2.0 Regression Suite (Environment Doctor + Snapshot Pre-Check) ===");
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-v02-suite-"));
  const subTests: SubTestReceipt[] = [];

  const runCase = async (
    id: string,
    name: string,
    fn: () => Promise<Record<string, unknown>>
  ): Promise<void> => {
    const start = Date.now();
    const details = await fn();
    const durationMs = Date.now() - start;
    subTests.push({ id, name, passed: true, durationMs, details });
    console.log(`  [PASS] ${id}: ${name} (${durationMs}ms)`);
  };

  try {
    // Prepare baseline test repository
    const repoDir = path.join(tempRoot, "repo");
    fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
    fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });
    gitExec(repoDir, ["init", "-b", "main"]);
    gitExec(repoDir, ["config", "user.name", "V02 Tester"]);
    gitExec(repoDir, ["config", "user.email", "v02@example.com"]);

    fs.writeFileSync(
      path.join(repoDir, "src", "calc.py"),
      "def add(a: int, b: int) -> int:\n    return a + b\n",
      "utf8"
    );
    const sqlSecret = "sk-live-V02Secret998877665544332211";
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_calc.py"),
      [
        "from src.calc import add",
        "",
        "def test_add():",
        `    sql_note = \"-- api_key = '${sqlSecret}'\"`,
        "    assert add(2, 3) == 5",
        "",
      ].join("\n"),
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Initial baseline commit"]);
    const baseHeadOid = gitExec(repoDir, ["rev-parse", "HEAD"]);

    // =========================================================================
    // DOCTOR-01: Restricted Mode Zero-Process + Workspace Settings Poisoning Audit
    // =========================================================================
    await runCase(
      "DOCTOR-01",
      "Environment Doctor spawns 0 external processes in Restricted Mode while flagging ignored .vscode/settings.json overrides",
      async () => {
        const controller = new CheckwashLensController();
        let brokerInvocations = 0;
        controller.getProcessRunner().setCustomBrokerExecutorForTests(async () => {
          brokerInvocations++;
          throw new Error("Broker must NEVER be invoked in Restricted Mode");
        });

        const untrustedDesc = makeHostDesc(repoDir, { isWorkspaceTrusted: false });
        const report = await controller.runEnvironmentDoctor({
          hostDesc: untrustedDesc,
          configuredProvePath: PROVE_EXE,
          settingInspections: [
            {
              key: "pythonPath",
              globalValue: PYTHON_EXE,
              workspaceValue: path.join(repoDir, ".venv", "Scripts", "python.exe"),
              workspaceFolderValue: "",
            },
            {
              key: "gitPath",
              globalValue: "",
              workspaceValue: "",
              workspaceFolderValue: path.join(repoDir, "tools", "git.exe"),
            },
            {
              key: "provePath",
              globalValue: "",
              workspaceValue: path.join(repoDir, "evil_prove.exe"),
              workspaceFolderValue: "",
            },
            {
              key: "proveTestPythonPath",
              globalValue: "",
              workspaceValue: "",
              workspaceFolderValue: "",
            },
          ],
        });

        assert.strictEqual(brokerInvocations, 0);
        assert.strictEqual(report.isWorkspaceTrusted, false);
        assert.strictEqual(report.externalProcessesSpawned, false);
        assert.strictEqual(report.overallReadyForStaticScan, false);
        assert.strictEqual(report.overallReadyForProve, false);
        assert.strictEqual(report.checks.bundledArtifacts.status, "ready");
        assert.strictEqual(report.checks.pythonRuntime.status, "skipped");
        assert.strictEqual(report.checks.gitRuntimeAndBareGit.status, "skipped");
        assert.strictEqual(report.checks.proveSatellite.status, "skipped");
        assert.strictEqual(report.workspaceSettingsWarnings.length, 3);
        assert.strictEqual(
          report.markdownSummary.includes("Ignored Workspace Settings"),
          true
        );

        controller.dispose();
        return {
          brokerInvocations,
          externalProcessesSpawned: report.externalProcessesSpawned,
          warningsCount: report.workspaceSettingsWarnings.length,
          bundledStatus: report.checks.bundledArtifacts.status,
        };
      }
    );

    // =========================================================================
    // DOCTOR-02: Inside-Repo Runtime Rejection + Safe Outside-Repo Discovery
    // =========================================================================
    await runCase(
      "DOCTOR-02",
      "Environment Doctor rejects inside-repository Python path, discovers outside-repository CPython 3.11+ & Git, and verifies Prove v0.1.0",
      async () => {
        const insideRepoFakePy = path.join(
          repoDir,
          "tools",
          IS_WIN32 ? "python.exe" : "python3"
        );
        fs.mkdirSync(path.dirname(insideRepoFakePy), { recursive: true });
        copyExecutablePreservingMode(PYTHON_EXE, insideRepoFakePy);

        try {
          const controller = new CheckwashLensController();
          const badPyDesc = makeHostDesc(repoDir, {
            configuredPythonPath: insideRepoFakePy,
            configuredGitPath: GIT_EXE,
            inheritedEnv: {
              ...process.env,
              PATH: [
                path.dirname(insideRepoFakePy),
                path.dirname(PYTHON_EXE),
                path.dirname(GIT_EXE),
              ].join(path.delimiter),
            },
          });

          const report = await controller.runEnvironmentDoctor({
            hostDesc: badPyDesc,
            configuredProvePath: PROVE_EXE,
            settingInspections: [
              { key: "pythonPath", globalValue: insideRepoFakePy, workspaceValue: "", workspaceFolderValue: "" },
              { key: "gitPath", globalValue: GIT_EXE, workspaceValue: "", workspaceFolderValue: "" },
              { key: "provePath", globalValue: PROVE_EXE, workspaceValue: "", workspaceFolderValue: "" },
              { key: "proveTestPythonPath", globalValue: "", workspaceValue: "", workspaceFolderValue: "" },
            ],
          });

          assert.strictEqual(report.overallReadyForStaticScan, false);
          assert.strictEqual(report.checks.pythonRuntime.status, "error");
          assert.strictEqual(
            report.checks.pythonRuntime.summary.includes("inside target repository"),
            true,
            `Expected inside-repo error summary, got: ${report.checks.pythonRuntime.summary}`
          );
          assert.strictEqual(
            normalizePlatformLookupKey(report.checks.pythonRuntime.discoveredCandidatePath ?? ""),
            normalizePlatformLookupKey(PYTHON_EXE)
          );
          assert.strictEqual(
            normalizePlatformLookupKey(report.recommendedUserSettingsPatch.pythonPath ?? ""),
            normalizePlatformLookupKey(PYTHON_EXE)
          );
          assert.strictEqual(report.checks.proveSatellite.status, "ready");

          // Also verify healthy report when valid outside-repo paths are configured
          const healthyReport = await controller.runEnvironmentDoctor({
            hostDesc: makeHostDesc(repoDir),
            configuredProvePath: PROVE_EXE,
            settingInspections: [
              { key: "pythonPath", globalValue: PYTHON_EXE, workspaceValue: "", workspaceFolderValue: "" },
              { key: "gitPath", globalValue: GIT_EXE, workspaceValue: "", workspaceFolderValue: "" },
              { key: "provePath", globalValue: PROVE_EXE, workspaceValue: "", workspaceFolderValue: "" },
              { key: "proveTestPythonPath", globalValue: "", workspaceValue: "", workspaceFolderValue: "" },
            ],
          });
          assert.strictEqual(healthyReport.overallReadyForStaticScan, true);
          assert.strictEqual(healthyReport.overallReadyForProve, true);
          assert.strictEqual(Object.keys(healthyReport.recommendedUserSettingsPatch).length, 0);

          controller.dispose();
          return {
            rejectedInsideRepoPython: true,
            discoveredPythonPath: report.checks.pythonRuntime.discoveredCandidatePath,
            proveStatus: report.checks.proveSatellite.status,
            healthyStaticReady: healthyReport.overallReadyForStaticScan,
            healthyProveReady: healthyReport.overallReadyForProve,
          };
        } finally {
          fs.rmSync(path.join(repoDir, "tools"), { recursive: true, force: true });
        }
      }
    );

    // =========================================================================
    // DOCTOR-03: Bare-'git' Shadowing Detection in Environment Doctor
    // =========================================================================
    await runCase(
      "DOCTOR-03",
      "Environment Doctor detects bare-'git' search-order shadowing in Prove executable directory",
      async () => {
        const shadowProveDir = path.join(tempRoot, "shadow-prove-dir");
        fs.mkdirSync(shadowProveDir, { recursive: true });
        const copiedProveExe = path.join(
          shadowProveDir,
          IS_WIN32 ? "checkwash-prove.exe" : "checkwash-prove"
        );
        const shadowingGitExe = path.join(shadowProveDir, IS_WIN32 ? "git.exe" : "git");
        copyExecutablePreservingMode(PROVE_EXE, copiedProveExe);
        copyExecutablePreservingMode(GIT_EXE, shadowingGitExe);

        const controller = new CheckwashLensController();
        const report = await controller.runEnvironmentDoctor({
          hostDesc: makeHostDesc(repoDir),
          configuredProvePath: copiedProveExe,
        });

        assert.strictEqual(report.overallReadyForStaticScan, true);
        assert.strictEqual(report.overallReadyForProve, false);
        assert.strictEqual(report.checks.proveSatellite.status, "error");
        assert.strictEqual(
          report.checks.proveSatellite.summary.includes("Trusted Git identity mismatch"),
          true,
          `Expected bare-git mismatch in Prove check, got: ${report.checks.proveSatellite.summary}`
        );

        controller.dispose();
        return {
          staticReady: report.overallReadyForStaticScan,
          proveReady: report.overallReadyForProve,
          proveSummary: report.checks.proveSatellite.summary,
        };
      }
    );

    // =========================================================================
    // SNAP-01: Staged Pre-Check Isolation, Diverged Live Buffer, & Zero .git Mutation
    // =========================================================================
    await runCase(
      "SNAP-01",
      "Staged Pre-Check (HEAD -> Index) isolates staged changes from unstaged worktree & untracked files, badges UI distinctly, and leaves .git/objects & .git/index untouched",
      async () => {
        const testCalcPath = path.join(repoDir, "tests", "test_calc.py");
        const untrackedTestPath = path.join(repoDir, "tests", "test_untracked_wip.py");

        // 1. Stage a weakened test in `.git/index`
        const stagedContent = [
          "from src.calc import add",
          "",
          "def test_add():",
          "    assert True",
          "",
        ].join("\n");
        fs.writeFileSync(testCalcPath, stagedContent, "utf8");
        gitExec(repoDir, ["add", "tests/test_calc.py"]);

        // 2. Now modify working tree further (unstaged) AND add an untracked file
        const divergedWorktreeContent = [
          "# Unstaged header line 1",
          "# Unstaged header line 2",
          "from src.calc import add",
          "",
          "def test_add():",
          "    assert add(2, 3) == 5",
          "",
        ].join("\n");
        fs.writeFileSync(testCalcPath, divergedWorktreeContent, "utf8");
        fs.writeFileSync(
          untrackedTestPath,
          "def test_untracked_weak():\n    assert True\n",
          "utf8"
        );

        const indexPath = path.join(repoDir, ".git", "index");
        const indexShaBefore = sha256FileIfExists(indexPath);
        const objectsBefore = countGitObjects(repoDir);
        const headBefore = gitExec(repoDir, ["rev-parse", "HEAD"]);

        const controller = new CheckwashLensController();
        const hostDesc = makeHostDesc(repoDir);
        const snap = await controller.scanUncommittedSnapshot(hostDesc, "staged", [
          {
            repositoryRoot: fs.realpathSync.native(repoDir),
            relativePath: "tests/test_calc.py",
            isDirty: false,
            verifiedVersion: 1,
            currentVersionAtPublish: 1,
            text: divergedWorktreeContent,
          },
        ]);

        const indexShaAfter = sha256FileIfExists(indexPath);
        const objectsAfter = countGitObjects(repoDir);
        const headAfter = gitExec(repoDir, ["rev-parse", "HEAD"]);

        assert.strictEqual(snap.evaluatedState.state, "Block");
        assert.strictEqual(snap.evaluatedState.scanScope, "staged-precheck");
        assert.strictEqual(
          snap.statusBar.text.startsWith("$(error) Checkwash [Staged Pre-Check]: Block"),
          true,
          `Unexpected statusBar text: ${snap.statusBar.text}`
        );

        const verdictRoot = findTreeNode(snap.treeNodes, "verdict_root");
        const scopeNotice = findTreeNode(snap.treeNodes, "verdict_precheck_scope_notice");
        assert.ok(verdictRoot);
        assert.strictEqual(verdictRoot.label, "Checkwash Pre-Check (Staged Index): Block");
        assert.ok(scopeNotice, "Expected verdict_precheck_scope_notice node in TreeView");

        // Verify untracked file was NOT included in Staged Pre-Check
        const changedPaths = (snap.contextDietResult?.keptFilePaths ?? []).concat(
          snap.contextDietResult?.omittedFiles.map((o) => o.path) ?? []
        );
        assert.strictEqual(
          changedPaths.some((p: string) => p.includes("test_untracked_wip.py")),
          false,
          `Untracked file leaked into staged pre-check: ${JSON.stringify(changedPaths)}`
        );

        // Verify live squiggle was withheld because worktree diverged from staged blob,
        // while `checkwash-rev:` opens the EXACT staged blob (`assert True`)!
        assert.strictEqual(snap.enrichedFindings.length >= 1, true);
        const ef = snap.enrichedFindings[0];
        assert.strictEqual(ef.liveProjectionAllowed, false);
        assert.ok(ef.preferredRevisionUri);
        const revBlob = await controller.resolveImmutableRevisionUri(
          hostDesc,
          ef.preferredRevisionUri
        );
        assert.strictEqual(revBlob.ok, true);
        if (revBlob.ok) {
          assert.strictEqual(revBlob.value.utf8Text, stagedContent);
        }

        // Verify zero mutation to .git/index, .git/objects, and HEAD
        assert.strictEqual(indexShaAfter, indexShaBefore, ".git/index was modified!");
        assert.deepStrictEqual(objectsAfter, objectsBefore, ".git/objects count changed!");
        assert.strictEqual(headAfter, headBefore, "HEAD moved!");

        controller.dispose();
        gitExec(repoDir, ["reset", "--hard", baseHeadOid]);
        fs.rmSync(untrackedTestPath, { force: true });

        return {
          verdict: snap.evaluatedState.state,
          scanScope: snap.evaluatedState.scanScope,
          statusBarText: snap.statusBar.text,
          liveProjectionWithheldOnDivergedWorktree: !ef.liveProjectionAllowed,
          stagedBlobVerifiedViaRevUri: true,
          gitIndexUnchanged: indexShaAfter === indexShaBefore,
          gitObjectsCountBefore: objectsBefore.count,
          gitObjectsCountAfter: objectsAfter.count,
        };
      }
    );

    // =========================================================================
    // SNAP-02: Worktree Pre-Check (Untracked conftest.py Disable + SQL Secret Diet + Live Projection)
    // =========================================================================
    await runCase(
      "SNAP-02",
      "Working-Tree Pre-Check (HEAD -> Worktree) catches untracked conftest.py suite-disable washing, masks deleted SQL '-- ' secret in Context Diet, projects live diagnostics cleanly, and writes 0 objects to .git/objects",
      async () => {
        const testCalcPath = path.join(repoDir, "tests", "test_calc.py");
        const untrackedPath = path.join(repoDir, "tests", "conftest.py");

        // Modify tracked file (removing SQL `-- api_key = ...` line so diff has `--- api_key`)
        const modifiedCalcText = [
          "from src.calc import add",
          "",
          "def test_add():",
          "    assert add(2, 3) == 5",
          "",
        ].join("\n");
        fs.writeFileSync(testCalcPath, modifiedCalcText, "utf8");

        // Create untracked `tests/conftest.py` with autouse skip (never `git add`ed!)
        const untrackedConftestText = [
          "import pytest",
          "",
          "@pytest.fixture(autouse=True)",
          "def _skip_all():",
          '    pytest.skip("wip")',
          "",
        ].join("\n");
        fs.writeFileSync(untrackedPath, untrackedConftestText, "utf8");

        const indexPath = path.join(repoDir, ".git", "index");
        const indexShaBefore = sha256FileIfExists(indexPath);
        const objectsBefore = countGitObjects(repoDir);

        const controller = new CheckwashLensController();
        const hostDesc = makeHostDesc(repoDir);
        const canonRepo = fs.realpathSync.native(repoDir);

        const snap = await controller.scanUncommittedSnapshot(hostDesc, "worktree", [
          {
            repositoryRoot: canonRepo,
            relativePath: "tests/conftest.py",
            isDirty: false,
            verifiedVersion: 1,
            currentVersionAtPublish: 1,
            text: untrackedConftestText,
          },
        ]);

        const indexShaAfter = sha256FileIfExists(indexPath);
        const objectsAfter = countGitObjects(repoDir);

        assert.strictEqual(snap.evaluatedState.state, "Block");
        assert.strictEqual(snap.evaluatedState.scanScope, "worktree-precheck");
        assert.strictEqual(
          snap.statusBar.text.startsWith("$(error) Checkwash [Worktree Pre-Check]: Block"),
          true
        );

        const untrackedFinding = snap.enrichedFindings.find(
          (f) => f.item.resolvedSourcePath === "tests/conftest.py"
        );
        assert.ok(untrackedFinding, "Expected Checkwash finding on untracked tests/conftest.py");
        assert.strictEqual(untrackedFinding.liveProjectionAllowed, true);
        assert.strictEqual(
          (snap.diagnosticsPlan.checkwashByFile.get("tests/conftest.py") ?? []).length >= 1,
          true
        );

        // Verify dirtying buffer clears live diagnostic immediately with 0 processes
        const afterDirtySnap = controller.onOpenDocumentsChanged([
          {
            repositoryRoot: canonRepo,
            relativePath: "tests/conftest.py",
            isDirty: true,
            verifiedVersion: 1,
            currentVersionAtPublish: 2,
            text: untrackedConftestText + "# unsaved typing\n",
          },
        ]);
        assert.strictEqual(
          (afterDirtySnap.diagnosticsPlan.checkwashByFile.get("tests/conftest.py") ?? [])
            .length,
          0
        );

        // Verify Context Diet masks the deleted SQL `-- api_key` secret
        const dietCopy = controller.prepareContextDietCopy({ mode: "redacted" });
        assert.strictEqual(dietCopy.ok, true);
        if (dietCopy.ok) {
          assert.strictEqual(
            dietCopy.value.payloadToCopy.includes(sqlSecret),
            false,
            "SQL secret leaked into redacted Context Diet payload!"
          );
        }

        // Verify zero mutation to .git/index and .git/objects
        assert.strictEqual(indexShaAfter, indexShaBefore);
        assert.deepStrictEqual(objectsAfter, objectsBefore);

        controller.dispose();
        gitExec(repoDir, ["reset", "--hard", baseHeadOid]);
        fs.rmSync(untrackedPath, { force: true });

        return {
          verdict: snap.evaluatedState.state,
          scanScope: snap.evaluatedState.scanScope,
          caughtUntrackedTestWeakening: true,
          sqlSecretMaskedInContextDiet: true,
          gitObjectsCountBefore: objectsBefore.count,
          gitObjectsCountAfter: objectsAfter.count,
        };
      }
    );

    // =========================================================================
    // SNAP-03: Malicious .gitattributes Filter Immunity (--no-filters Proof)
    // =========================================================================
    await runCase(
      "SNAP-03",
      "Working-Tree Pre-Check never executes .gitattributes filter.*.clean commands (--no-filters & plumbing-only proof)",
      async () => {
        const sentinelFile = path.join(tempRoot, "evil-filter-sentinel.txt");
        fs.rmSync(sentinelFile, { force: true });

        fs.writeFileSync(path.join(repoDir, ".gitattributes"), "*.py filter=evil\n", "utf8");
        const filterCmd = IS_WIN32
          ? `cmd.exe /d /c echo PWNED > "${sentinelFile}" && type`
          : `/bin/sh -c 'echo PWNED > "${sentinelFile}" && cat'`;
        gitExec(repoDir, [
          "config",
          "filter.evil.clean",
          filterCmd,
        ]);
        fs.writeFileSync(
          path.join(repoDir, "tests", "test_calc.py"),
          "from src.calc import add\n\ndef test_add():\n    assert True\n",
          "utf8"
        );

        try {
          const controller = new CheckwashLensController();
          const snap = await controller.scanUncommittedSnapshot(
            makeHostDesc(repoDir),
            "worktree",
            []
          );
          assert.strictEqual(snap.evaluatedState.state, "Block");
          assert.strictEqual(
            fs.existsSync(sentinelFile),
            false,
            "SECURITY FAILURE: .gitattributes filter.evil.clean was executed during snapshot pre-check!"
          );
          controller.dispose();
          return {
            verdict: snap.evaluatedState.state,
            evilFilterSentinelExists: fs.existsSync(sentinelFile),
          };
        } finally {
          gitExec(repoDir, ["config", "--unset", "filter.evil.clean"]);
          fs.rmSync(path.join(repoDir, ".gitattributes"), { force: true });
          gitExec(repoDir, ["reset", "--hard", baseHeadOid]);
        }
      }
    );

    // =========================================================================
    // SNAP-04: Clean Not Run, Unborn HEAD, NTFS Junction Rejection, Case-Only Rename, & Cleanup
    // =========================================================================
    await runCase(
      "SNAP-04",
      "Clean staged/worktree return Not Run, unborn HEAD & NTFS directory junctions fail closed, Windows case-only renames are caught, and dispose() removes ephemeral snapshot dirs",
      async () => {
        const controller = new CheckwashLensController();
        const hostDesc = makeHostDesc(repoDir);

        // 1. Clean staged & clean worktree -> Not Run
        const cleanStaged = await controller.scanUncommittedSnapshot(hostDesc, "staged", []);
        assert.strictEqual(cleanStaged.evaluatedState.state, "Not Run");
        assert.strictEqual(cleanStaged.evaluatedState.scanScope, "staged-precheck");

        const cleanWorktree = await controller.scanUncommittedSnapshot(hostDesc, "worktree", []);
        assert.strictEqual(cleanWorktree.evaluatedState.state, "Not Run");
        assert.strictEqual(cleanWorktree.evaluatedState.scanScope, "worktree-precheck");

        // 2. Unborn HEAD repository -> Error
        const unbornRepo = path.join(tempRoot, "unborn-repo");
        fs.mkdirSync(unbornRepo, { recursive: true });
        gitExec(unbornRepo, ["init", "-b", "main"]);
        fs.writeFileSync(path.join(unbornRepo, "test_a.py"), "def test_a(): assert True\n", "utf8");
        const unbornSnap = await controller.scanUncommittedSnapshot(
          makeHostDesc(unbornRepo),
          "worktree",
          []
        );
        assert.strictEqual(unbornSnap.evaluatedState.state, "Error");
        assert.strictEqual(
          (unbornSnap.evaluatedState.errorReason ?? "").includes("unborn"),
          true,
          `Expected unborn branch error, got: ${unbornSnap.evaluatedState.errorReason}`
        );

        // 3. Directory junction / symlink inside working tree -> Fail closed Error
        const outsideTargetDir = path.join(tempRoot, "outside-secret-dir");
        fs.mkdirSync(outsideTargetDir, { recursive: true });
        fs.writeFileSync(
          path.join(outsideTargetDir, "test_outside.py"),
          "def test_outside(): assert True\n",
          "utf8"
        );
        const junctionPath = path.join(repoDir, "tests", "escaped_junction");
        if (IS_WIN32) {
          const mklinkRes = cp.spawnSync(
            "cmd.exe",
            ["/d", "/c", "mklink", "/J", junctionPath, outsideTargetDir],
            { encoding: "utf8", windowsHide: true }
          );
          assert.strictEqual(mklinkRes.status, 0, `mklink /J failed: ${mklinkRes.stderr}`);
        } else {
          fs.symlinkSync(outsideTargetDir, junctionPath, "dir");
        }

        try {
          const junctionSnap = await controller.scanUncommittedSnapshot(
            hostDesc,
            "worktree",
            []
          );
          assert.strictEqual(junctionSnap.evaluatedState.state, "Error");
          assert.strictEqual(
            /symbolic link|junction|escapes repository/i.test(
              junctionSnap.evaluatedState.errorReason ?? ""
            ),
            true,
            `Expected symlink/junction error, got: ${junctionSnap.evaluatedState.errorReason}`
          );
        } finally {
          if (IS_WIN32) {
            cp.spawnSync("cmd.exe", ["/d", "/c", "rmdir", junctionPath], { windowsHide: true });
          } else {
            fs.rmSync(junctionPath, { force: true });
          }
        }

        // 4. Case-only test rename on Windows NTFS (`test_calc.py` -> `Test_Calc.py` + weakened assertion)
        const origPath = path.join(repoDir, "tests", "test_calc.py");
        const tmpRenamePath = path.join(repoDir, "tests", "test_calc_tmp_rename.py");
        const caseRenamedPath = path.join(repoDir, "tests", "Test_Calc.py");
        fs.renameSync(origPath, tmpRenamePath);
        fs.renameSync(tmpRenamePath, caseRenamedPath);
        fs.writeFileSync(
          caseRenamedPath,
          "from src.calc import add\n\ndef test_add():\n    assert True\n",
          "utf8"
        );

        let capturedSnapDir: string | undefined;
        try {
          const caseSnap = await controller.scanUncommittedSnapshot(hostDesc, "worktree", []);
          assert.strictEqual(
            caseSnap.evaluatedState.state,
            "Block",
            `Expected Block on case-renamed weakened test, got: ${caseSnap.evaluatedState.state} (${caseSnap.evaluatedState.errorReason ?? caseSnap.evaluatedState.notRunReason ?? ""})`
          );
          // Inspect active snapshot dir via controller's internal revisionProvider before dispose()
          const revProv = (controller as unknown as {
            revisionProvider: { getActiveSnapshotOverlay(): { snapshotDir: string } | null };
          }).revisionProvider;
          capturedSnapDir = revProv.getActiveSnapshotOverlay()?.snapshotDir;
          assert.ok(capturedSnapDir && fs.existsSync(capturedSnapDir));

          controller.dispose();
          assert.strictEqual(
            fs.existsSync(capturedSnapDir),
            false,
            "dispose() must delete the ephemeral snapshot directory"
          );
        } finally {
          fs.rmSync(caseRenamedPath, { force: true });
          gitExec(repoDir, ["reset", "--hard", baseHeadOid]);
        }

        return {
          cleanStagedState: cleanStaged.evaluatedState.state,
          cleanWorktreeState: cleanWorktree.evaluatedState.state,
          unbornRejected: true,
          ntfsJunctionRejected: true,
          caseOnlyRenameWeakeningCaught: true,
          ephemeralDirCleanedOnDispose: true,
        };
      }
    );

    // Write structured receipt
    const sourceSha = gitExec(REPO_ROOT, ["rev-parse", "HEAD"]);
    const statusPorcelain = gitExec(REPO_ROOT, ["status", "--porcelain"]);
    const execMeta = getPlatformExecutionMetadata();
    const summary = {
      suite: "Checkwash Lens v0.2.0 Regressions (Environment Doctor & Uncommitted Snapshot Pre-Check)",
      executionTag: execMeta.evidenceTag,
      executionEnvironment: execMeta.executionEnvironment,
      hostname: execMeta.hostname,
      hostMachineHostname: execMeta.hostMachineHostname,
      containerHostname: execMeta.containerHostname,
      platform: `${process.platform}-${process.arch}`,
      osRelease: os.release(),
      nodeVersion: process.version,
      sourceSha,
      worktreeClean: statusPorcelain.length === 0,
      timestamp: new Date().toISOString(),
      exitCode: 0,
      totalTests: subTests.length,
      passedTests: subTests.filter((t) => t.passed).length,
      failedTests: subTests.filter((t) => !t.passed).length,
      tests: subTests,
    };

    fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
    fs.writeFileSync(RESULTS_FILE, JSON.stringify(summary, null, 2), "utf8");
    console.log(`\nWrote v0.2.0 regression receipt to: ${RESULTS_FILE}`);
  } finally {
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch {
      // Ignore cleanup lock
    }
  }
}

void main().catch((err) => {
  console.error("FATAL error in v02_doctor_staged_b08_runner:", err);
  process.exit(1);
});
