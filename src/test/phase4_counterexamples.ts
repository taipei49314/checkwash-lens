/**
 * test/phase4_counterexamples.ts
 *
 * Counterexample & Negative Verification Suite for Phase 4 UI & Controller:
 * - ui/statusBar.ts
 * - ui/diagnostics.ts
 * - ui/treeView.ts
 * - ui/commands.ts (CheckwashLensController)
 */

import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";
import { FIXED_PASS_DISCLAIMER } from "../core/verdictModel";
import { HostEnvironmentDescriptor } from "../runtime/admission";
import {
  getTotalBrokerSpawnCount,
  resetTotalBrokerSpawnCountForTests,
} from "../runtime/windowsBroker";
import { buildStatusBarViewModel } from "../ui/statusBar";
import { CheckwashLensController } from "../ui/commands";
import { CheckwashTreeNode } from "../ui/treeView";
import {
  ACTIVE_ARCH,
  ACTIVE_PLATFORM,
  resolveTestGitExe,
  resolveTestProveExe,
  resolveTestPythonExe,
} from "./testPlatformEnv";

const EXTENSION_ROOT = path.resolve(__dirname, "..", "..");
const PYTHON_EXE = resolveTestPythonExe();
const GIT_EXE = resolveTestGitExe();
const PROVE_EXE = resolveTestProveExe();

function gitExec(repoDir: string, args: string[]): string {
  return execFileSync(GIT_EXE, ["-C", repoDir, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function makeHostDesc(repoDir: string, trusted: boolean = true): HostEnvironmentDescriptor {
  return {
    isWorkspaceTrusted: trusted,
    platform: ACTIVE_PLATFORM,
    arch: ACTIVE_ARCH,
    workspaceScheme: "file",
    isRemote: false,
    isVirtualWorkspace: false,
    extensionRootPath: EXTENSION_ROOT,
    repositoryRootPath: repoDir,
    configuredPythonPath: PYTHON_EXE,
    configuredGitPath: GIT_EXE,
    inheritedEnv: process.env,
  };
}

function findTreeNodeById(nodes: CheckwashTreeNode[], id: string): CheckwashTreeNode | null {
  for (const n of nodes) {
    if (n.id === id) return n;
    const found = findTreeNodeById(n.children, id);
    if (found) return found;
  }
  return null;
}

async function main(): Promise<void> {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-phase4-ce-"));
  console.log(`[Phase 4 Counterexamples] Using temp dir: ${tempRoot}`);

  try {
    const repoA = path.join(tempRoot, "repoA");
    const repoB = path.join(tempRoot, "repoB");
    fs.mkdirSync(repoA, { recursive: true });
    fs.mkdirSync(repoB, { recursive: true });

    for (const r of [repoA, repoB]) {
      gitExec(r, ["init", "-b", "main"]);
      gitExec(r, ["config", "user.name", "Phase4 Tester"]);
      gitExec(r, ["config", "user.email", "phase4@example.com"]);
    }

    fs.mkdirSync(path.join(repoA, "src"), { recursive: true });
    fs.mkdirSync(path.join(repoA, "tests"), { recursive: true });
    fs.writeFileSync(
      path.join(repoA, "src", "math_util.py"),
      "def double(n: int) -> int:\n    return n * 2\n",
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoA, "tests", "test_math_util.py"),
      "from src.math_util import double\n\ndef test_double():\n    assert double(3) == 6\n    assert double(5) == 10\n",
      "utf8"
    );
    gitExec(repoA, ["add", "."]);
    gitExec(repoA, ["commit", "-m", "RepoA base"]);
    const repoABase = gitExec(repoA, ["rev-parse", "HEAD"]);

    // Commit 2 on repoA: weaken test + add Fast Guard skip
    fs.writeFileSync(
      path.join(repoA, "tests", "test_math_util.py"),
      "import pytest\nfrom src.math_util import double\n\n@pytest.mark.skip(reason='skip')\ndef test_double():\n    assert double(3) is not None\n",
      "utf8"
    );
    gitExec(repoA, ["add", "."]);
    gitExec(repoA, ["commit", "-m", "RepoA head block"]);
    const repoAHead = gitExec(repoA, ["rev-parse", "HEAD"]);
    const repoATestText = fs.readFileSync(path.join(repoA, "tests", "test_math_util.py"), "utf8");

    const controller = new CheckwashLensController();

    // =========================================================================
    // C1: Status Bar 5-State & Analyzing Lifecycle Overlay Counterexamples
    // =========================================================================
    console.log("Running C1: Status Bar 5-State & Analyzing Overlay Counterexamples...");
    // 1a: Stale Pass while analyzing MUST NOT show "Checkwash: Pass"
    const analyzingOverPass = buildStatusBarViewModel({
      state: "Pass",
      verdictFromEngine: "pass",
      disclaimer: FIXED_PASS_DISCLAIMER,
      errorReason: null,
      notRunReason: null,
      gaps: {
        hasAnyGap: false,
        unread: [],
        skippedFiles: [],
        configErrors: [],
        sarifNotifications: [],
        jsonStderrNotes: [],
        sarifStderrNotes: [],
      },
      joinedReport: null,
      lifecycle: { analyzing: true, stale: true, cancelRequested: false },
    });
    assert.strictEqual(analyzingOverPass.isAnalyzing, true);
    assert.strictEqual(analyzingOverPass.isStale, true);
    assert.strictEqual(
      analyzingOverPass.text.includes("Pass"),
      false,
      "Status bar text must NEVER display 'Pass' while a scan is analyzing"
    );
    assert.ok(analyzingOverPass.text.includes("Analyzing..."));

    // 1b: Block + Gaps shows (+Gaps)
    const blockWithGaps = buildStatusBarViewModel({
      state: "Block",
      verdictFromEngine: "block",
      disclaimer: null,
      errorReason: null,
      notRunReason: null,
      gaps: {
        hasAnyGap: true,
        unread: [{ path: "huge.py", side: "head", size: 2000000, limit: 1000000 }],
        skippedFiles: [],
        configErrors: [],
        sarifNotifications: [],
        jsonStderrNotes: [],
        sarifStderrNotes: [],
      },
      joinedReport: null,
      lifecycle: { analyzing: false, stale: false, cancelRequested: false },
    });
    assert.strictEqual(blockWithGaps.colorTheme, "error");
    assert.ok(blockWithGaps.text.includes("Block (+Gaps)"));

    // 1c: Pass tooltip always includes FIXED_PASS_DISCLAIMER
    const cleanPassVm = buildStatusBarViewModel({
      state: "Pass",
      verdictFromEngine: "pass",
      disclaimer: FIXED_PASS_DISCLAIMER,
      errorReason: null,
      notRunReason: null,
      gaps: {
        hasAnyGap: false,
        unread: [],
        skippedFiles: [],
        configErrors: [],
        sarifNotifications: [],
        jsonStderrNotes: [],
        sarifStderrNotes: [],
      },
      joinedReport: null,
      lifecycle: { analyzing: false, stale: false, cancelRequested: false },
    });
    assert.ok(cleanPassVm.tooltip.includes(FIXED_PASS_DISCLAIMER));
    console.log("  [PASS] C1: Status bar 5-state and analyzing overlay invariants verified.");

    // =========================================================================
    // C2: Multi-Folder Repository Switch Bleed & Live Diagnostic Invalidation
    // =========================================================================
    console.log("Running C2: Multi-Folder Repository Switch & Live Diagnostic Invalidation Counterexamples...");
    const hostA = makeHostDesc(repoA, true);
    const snapA = await controller.scanCommittedRange(
      hostA,
      `${repoABase}..${repoAHead}`,
      [
        {
          repositoryRoot: fs.realpathSync.native(repoA),
          relativePath: "tests/test_math_util.py",
          isDirty: false,
          verifiedVersion: 1,
          currentVersionAtPublish: 1,
          text: repoATestText,
        },
      ]
    );

    assert.strictEqual(snapA.evaluatedState.state, "Block");
    assert.ok(snapA.diagnosticsPlan.checkwashByFile.has("tests/test_math_util.py"));
    assert.ok(snapA.diagnosticsPlan.fastGuardByFile.has("tests/test_math_util.py"));
    const revUriA = snapA.enrichedFindings[0]?.preferredRevisionUri ?? null;
    const findingNodeA = findTreeNodeById(snapA.treeNodes, "cw_finding_0");
    assert.ok(findingNodeA !== null && findingNodeA.command !== undefined);
    const uriArgFromTree = findingNodeA!.command!.arguments[0] as string;
    assert.ok(uriArgFromTree.startsWith("checkwash-rev:/"));

    // Verify resolving immutable revision URI while bound to repoA works
    const revReadOk = await controller.resolveImmutableRevisionUri(hostA, uriArgFromTree);
    assert.strictEqual(revReadOk.ok, true);

    // Counterexample 2a: User edits buffer in memory (isDirty=true) -> zero processes spawned, live diagnostics cleared immediately
    resetTotalBrokerSpawnCountForTests();
    const snapDirty = controller.onOpenDocumentsChanged([
      {
        repositoryRoot: fs.realpathSync.native(repoA),
        relativePath: "tests/test_math_util.py",
        isDirty: true,
        verifiedVersion: 2,
        currentVersionAtPublish: 2,
        text: "# dirty edit\n" + repoATestText,
      },
    ]);
    assert.strictEqual(
      getTotalBrokerSpawnCount(),
      0,
      "Editing open document must spawn ZERO external processes"
    );
    assert.strictEqual(
      snapDirty.diagnosticsPlan.checkwashByFile.size,
      0,
      "Dirty buffer must immediately clear Checkwash live inline diagnostics"
    );
    assert.strictEqual(
      snapDirty.diagnosticsPlan.fastGuardByFile.size,
      0,
      "Dirty buffer must immediately clear Fast Guard live inline diagnostics"
    );
    // Verdict and TreeView findings remain intact
    assert.strictEqual(snapDirty.evaluatedState.state, "Block");

    // Counterexample 2b: Switch active repository to repoB -> repoA state must NOT bleed into repoB
    controller.selectRepository(repoB);
    const snapB = controller.getViewSnapshot();
    assert.strictEqual(snapB.evaluatedState.state, "Not Run");
    assert.strictEqual(snapB.diagnosticsPlan.checkwashByFile.size, 0);
    assert.strictEqual(snapB.diagnosticsPlan.fastGuardByFile.size, 0);
    assert.strictEqual(snapB.fastGuardResult, null);
    assert.strictEqual(snapB.contextDietResult, null);

    // Attempting to resolve repoA's checkwash-rev: URI while bound to repoB must be rejected
    const hostB = makeHostDesc(repoB, true);
    const crossRepoUriAttempt = await controller.resolveImmutableRevisionUri(hostB, uriArgFromTree);
    assert.strictEqual(
      crossRepoUriAttempt.ok,
      false,
      "Cross-repository checkwash-rev: URI must be rejected when bound to another repo"
    );
    void revUriA;
    console.log("  [PASS] C2: Dirty edit zero-spawn invalidation and multi-folder repository isolation verified.");

    // =========================================================================
    // C3: Offline Report Import Never Pollutes Live Verdict or Grants Replay
    // =========================================================================
    console.log("Running C3: Offline Report Import Isolation Counterexamples...");
    resetTotalBrokerSpawnCountForTests();

    // 3a: Import offline Checkwash JSON v2 Block report while workspace state is Not Run
    const offlineCwRes = controller.viewOfflineReportFileReadOnly(
      path.join(EXTENSION_ROOT, "fixtures", "phase0", "a01-block.findings.json")
    );
    assert.strictEqual(offlineCwRes.ok, true);
    assert.strictEqual(
      controller.getViewSnapshot().evaluatedState.state,
      "Not Run",
      "Importing an offline Checkwash report must NEVER overwrite the live workspace verdict"
    );
    assert.ok(controller.getOfflineReadOnlyFindingsPreview() !== null);

    // 3b: Import offline Prove mixed coexisting report -> all 4 groups shown in TreeView, zero Replay commands attached
    const offlineProveRes = controller.viewOfflineReportFileReadOnly(
      path.join(EXTENSION_ROOT, "fixtures", "phase0", "a11-prove-mixed-coexisting.json")
    );
    assert.strictEqual(offlineProveRes.ok, true);
    const snapAfterProveImport = controller.getViewSnapshot();
    const proveRoot = findTreeNodeById(snapAfterProveImport.treeNodes, "prove_root");
    assert.ok(proveRoot !== null);
    assert.ok(findTreeNodeById(proveRoot!.children, "prove_group_protection_losses") !== null);
    assert.ok(findTreeNodeById(proveRoot!.children, "prove_group_unconfirmed_losses") !== null);
    assert.ok(findTreeNodeById(proveRoot!.children, "prove_group_needs_clarification") !== null);
    assert.ok(findTreeNodeById(proveRoot!.children, "prove_group_undecided") !== null);

    // Verify NO node under proveRoot has a replayMutant command because it's an imported external report
    const checkNoReplayCmd = (nodes: CheckwashTreeNode[]) => {
      for (const n of nodes) {
        assert.notStrictEqual(
          n.command?.commandId,
          "checkwashLens.replayMutant",
          `Imported report node '${n.id}' must NOT expose replayMutant command`
        );
        checkNoReplayCmd(n.children);
      }
    };
    checkNoReplayCmd(proveRoot!.children);

    // Attempt to call runProveReplayCommand on the imported record's runId
    const importedRunId = snapAfterProveImport.proveOutcome.record!.runId;
    const replayAttemptSnap = await controller.runProveReplayCommand({
      hostDesc: hostB,
      configuredProvePath: PROVE_EXE,
      recordRunId: importedRunId,
      selectedMutantId: "m0001",
      authorization: null,
    });
    assert.strictEqual(replayAttemptSnap.proveOutcome.status, "Execution error");
    assert.ok(
      replayAttemptSnap.proveOutcome.errorReason?.includes("No trusted session Prove execution record found")
    );

    // 3c: Attempt to import a directory or invalid file as offline report
    const dirImportRes = controller.viewOfflineReportFileReadOnly(tempRoot);
    assert.strictEqual(dirImportRes.ok, false);
    assert.strictEqual(
      getTotalBrokerSpawnCount(),
      0,
      "All offline report imports and failed replay checks must spawn ZERO external processes"
    );
    console.log("  [PASS] C3: Offline report imports are read-only, preserve all coexisting groups, and spawn 0 processes.");

    // =========================================================================
    // C4: Restricted Mode (Untrusted Workspace) Controller Counterexample
    // =========================================================================
    console.log("Running C4: Restricted Mode Controller Counterexample...");
    resetTotalBrokerSpawnCountForTests();
    const untrustedHost = makeHostDesc(repoA, false);
    const untrustedSnap = await controller.scanCommittedRange(
      untrustedHost,
      `${repoABase}..${repoAHead}`
    );
    assert.strictEqual(untrustedSnap.evaluatedState.state, "Not Run");
    assert.ok(untrustedSnap.evaluatedState.notRunReason?.includes("Restricted Mode"));
    assert.strictEqual(getTotalBrokerSpawnCount(), 0);
    console.log("  [PASS] C4: Controller rejected Restricted Mode scan with 0 process spawns.");

    console.log("\n=== ALL PHASE 4 COUNTEREXAMPLES PASSED (4 / 4 groups) ===");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("[Phase 4 Counterexamples FAILED]", err);
  process.exit(1);
});
