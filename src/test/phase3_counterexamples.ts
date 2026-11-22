/**
 * test/phase3_counterexamples.ts
 *
 * Counterexample & Negative Verification Suite for Phase 3:
 * - satellite/proveRunner.ts
 */

import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";
import { HostEnvironmentDescriptor } from "../runtime/admission";
import { UnifiedProcessRunner } from "../runtime/processRunner";
import { ProveSatelliteRunner } from "../satellite/proveRunner";
import {
  ACTIVE_ARCH,
  ACTIVE_PLATFORM,
  copyExecutablePreservingMode,
  IS_WIN32,
  resolveTestGitExe,
  resolveTestProveExe,
  resolveTestPythonExe,
} from "./testPlatformEnv";

const EXTENSION_ROOT = path.resolve(__dirname, "..", "..");
const PYTHON_EXE = resolveTestPythonExe();
const PROVE_EXE = resolveTestProveExe();
const GIT_EXE = resolveTestGitExe();

function gitExec(repoDir: string, args: string[]): string {
  return execFileSync(GIT_EXE, ["-C", repoDir, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function makeHostDesc(repoDir: string): HostEnvironmentDescriptor {
  return {
    isWorkspaceTrusted: true,
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

async function main(): Promise<void> {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-phase3-ce-"));
  console.log(`[Phase 3 Counterexamples] Using temp dir: ${tempRoot}`);

  try {
    const repoDir = path.join(tempRoot, "repo");
    fs.mkdirSync(repoDir, { recursive: true });
    gitExec(repoDir, ["init", "-b", "main"]);
    gitExec(repoDir, ["config", "user.name", "Phase3 Tester"]);
    gitExec(repoDir, ["config", "user.email", "phase3@example.com"]);

    fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
    fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(repoDir, "src", "__init__.py"), "", "utf8");
    fs.writeFileSync(
      path.join(repoDir, "src", "pricing.py"),
      "def discount(price: int) -> int:\n    if price >= 100:\n        return price - 20\n    return price\n",
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_pricing.py"),
      "from src.pricing import discount\n\ndef test_discount():\n    assert discount(100) == 80\n    assert discount(120) == 100\n    assert discount(50) == 50\n",
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Base commit with boundary tests"]);
    const baseOid = gitExec(repoDir, ["rev-parse", "HEAD"]);

    // Commit B: weaken test_pricing so boundary/value mutants survive (causing protection_loss)
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_pricing.py"),
      "from src.pricing import discount\n\ndef test_discount():\n    assert discount(120) is not None\n",
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Head commit weakening tests"]);
    const headOid = gitExec(repoDir, ["rev-parse", "HEAD"]);
    const rangeSpec = `${baseOid}..${headOid}`;

    const processRunner = new UnifiedProcessRunner();
    const proveRunner = new ProveSatelliteRunner(processRunner);
    const hostDesc = makeHostDesc(repoDir);

    // =========================================================================
    // C1: Manual Authorization Gate Counterexamples (List, Full, Token Reuse, Kind Mismatch)
    // =========================================================================
    console.log("Running C1: Manual Authorization Gate Counterexamples...");
    // 1a: Missing authorization on --list (Issue #2: --list executes target code and MUST require manual auth)
    const noAuthList = await proveRunner.runManualProve({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: rangeSpec,
      entryKind: "list",
      authorization: null,
    });
    assert.strictEqual(noAuthList.status, "Execution error");
    assert.ok(noAuthList.errorReason?.includes("missing explicit manual user authorization"));

    // 1b: userConfirmedExecutionRisk = false
    const plan1b = await proveRunner.prepareManualProvePlan({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: rangeSpec,
      entryKind: "list",
    });
    assert.strictEqual(plan1b.ok, true);
    const unconfirmedToken = proveRunner.issueManualAuthorizationToken({
      plan: plan1b.value,
      userConfirmedExecutionRisk: false,
    });
    const unconfirmedRes = await proveRunner.runManualProve({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: rangeSpec,
      entryKind: "list",
      authorization: unconfirmedToken,
    });
    assert.strictEqual(unconfirmedRes.status, "Execution error");
    assert.ok(unconfirmedRes.errorReason?.includes("did not confirm execution risk"));

    // 1c: Token kind mismatch (plan/token prepared for 'list', used for 'full')
    const plan1c = await proveRunner.prepareManualProvePlan({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: rangeSpec,
      entryKind: "list",
    });
    assert.strictEqual(plan1c.ok, true);
    const listTokenForFull = proveRunner.issueManualAuthorizationToken({
      plan: plan1c.value,
      userConfirmedExecutionRisk: true,
    });
    const mismatchKindRes = await proveRunner.runManualProve({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: rangeSpec,
      entryKind: "full",
      authorization: listTokenForFull,
    });
    assert.strictEqual(mismatchKindRes.status, "Execution error");
    assert.ok(mismatchKindRes.errorReason?.includes("authorization kind mismatch"));

    // 1d: Valid single-use plan-bound token works ONCE for --list, then fails if re-used!
    const plan1d = await proveRunner.prepareManualProvePlan({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: rangeSpec,
      entryKind: "list",
    });
    assert.strictEqual(plan1d.ok, true);
    const validListToken = proveRunner.issueManualAuthorizationToken({
      plan: plan1d.value,
      userConfirmedExecutionRisk: true,
    });
    const firstListRes = await proveRunner.runManualProve({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: rangeSpec,
      entryKind: "list",
      authorization: validListToken,
    });
    assert.strictEqual(firstListRes.status, "Listed");
    assert.ok(firstListRes.record !== null);
    assert.ok(firstListRes.record!.parsedReport.candidates.length >= 1);

    const reusedListRes = await proveRunner.runManualProve({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: rangeSpec,
      entryKind: "list",
      authorization: validListToken,
    });
    assert.strictEqual(reusedListRes.status, "Execution error");
    assert.ok(reusedListRes.errorReason?.includes("already consumed"));
    console.log("  [PASS] C1: Missing auth, unconfirmed risk, kind mismatch, and token reuse all blocked.");

    // =========================================================================
    // C2: Repo-Local Prove & Test Python Binary Poisoning Counterexamples
    // =========================================================================
    console.log("Running C2: Repo-Local Prove & Test Python Binary Poisoning Counterexamples...");
    const fakeVenvDir = path.join(repoDir, ".venv", IS_WIN32 ? "Scripts" : "bin");
    fs.mkdirSync(fakeVenvDir, { recursive: true });
    const repoProveCopy = path.join(fakeVenvDir, IS_WIN32 ? "checkwash-prove.exe" : "checkwash-prove");
    const repoPythonCopy = path.join(fakeVenvDir, IS_WIN32 ? "python.exe" : "python3");
    copyExecutablePreservingMode(PROVE_EXE, repoProveCopy);
    copyExecutablePreservingMode(PYTHON_EXE, repoPythonCopy);

    const repoProveRes = await proveRunner.verifyProveRuntimeIdentity(
      hostDesc,
      repoProveCopy,
      PYTHON_EXE
    );
    assert.strictEqual(repoProveRes.ok, false, "Prove binary inside target repository must be rejected");
    if (!repoProveRes.ok) {
      assert.ok(repoProveRes.error.includes("inside target repository"));
    }

    const repoPyRes = await proveRunner.verifyProveRuntimeIdentity(
      hostDesc,
      PROVE_EXE,
      repoPythonCopy
    );
    assert.strictEqual(repoPyRes.ok, false, "Test Python binary inside target repository must be rejected");
    if (!repoPyRes.ok) {
      assert.ok(repoPyRes.error.includes("inside target repository"));
    }
    fs.rmSync(path.join(repoDir, ".venv"), { recursive: true, force: true });
    console.log("  [PASS] C2: Repo-local checkwash-prove.exe and python.exe rejected before spawn.");

    // =========================================================================
    // C3: Imported External Report Read-Only Isolation Counterexample
    // =========================================================================
    console.log("Running C3: Imported External Report Read-Only Replay Block Counterexample...");
    const fixtureRaw = fs.readFileSync(
      path.join(EXTENSION_ROOT, "fixtures", "phase0", "a11-prove-protection-loss.json"),
      "utf8"
    );
    const fixtureObj = JSON.parse(fixtureRaw);
    fixtureObj.protection_losses[0].replay = "calc.exe && del /f /q *";
    fixtureObj.python = "C:\\evil\\python.exe";

    const importRes = proveRunner.importExternalProveReportReadOnly(
      JSON.stringify(fixtureObj),
      fs.realpathSync.native(repoDir)
    );
    assert.strictEqual(importRes.ok, true);
    if (importRes.ok) {
      const importedRecord = importRes.value.record!;
      assert.strictEqual(importedRecord.isImportedExternalReport, true);
      const targetMutant = importedRecord.parsedReport.protectionLosses[0].id;

      const replayImportPlan = await proveRunner.prepareReplayProvePlan({
        hostDesc,
        configuredProvePath: PROVE_EXE,
        recordOrRunId: importedRecord,
        selectedMutantId: targetMutant,
      });
      assert.strictEqual(replayImportPlan.ok, false);
      if (!replayImportPlan.ok) {
        assert.ok(
          replayImportPlan.error.includes("strictly read-only and cannot trigger Replay"),
          `Unexpected preflight error: ${replayImportPlan.error}`
        );
      }

      const replayImportAttempt = await proveRunner.runSingleMutantReplay({
        hostDesc,
        configuredProvePath: PROVE_EXE,
        record: importedRecord,
        selectedMutantId: targetMutant,
        authorization: null,
      });
      assert.strictEqual(replayImportAttempt.status, "Execution error");
      assert.ok(
        replayImportAttempt.errorReason?.includes("strictly read-only and cannot trigger Replay"),
        `Unexpected error: ${replayImportAttempt.errorReason}`
      );
    }
    console.log("  [PASS] C3: Imported external report is strictly read-only and blocked from Replay.");

    // =========================================================================
    // C4: Real Full Prove + Replay After Branch Moves, Malicious loss.replay, & Binary Change
    // =========================================================================
    console.log("Running C4: Real Full Prove + Replay Counterexamples...");
    const fullPlanRes = await proveRunner.prepareManualProvePlan({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: rangeSpec,
      entryKind: "full",
    });
    assert.strictEqual(fullPlanRes.ok, true);
    const fullAuth = proveRunner.issueManualAuthorizationToken({
      plan: fullPlanRes.value,
      userConfirmedExecutionRisk: true,
    });
    const fullOutcome = await proveRunner.runManualProve({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      rawRangeSpec: rangeSpec,
      entryKind: "full",
      authorization: fullAuth,
    });
    assert.strictEqual(fullOutcome.status, "Compared");
    assert.ok(fullOutcome.record !== null);
    const sessionRecord = fullOutcome.record!;
    assert.ok(
      sessionRecord.parsedReport.protectionLosses.length >= 1,
      "Expected at least 1 real protection_loss in sessionRecord"
    );

    const targetMutantId = sessionRecord.parsedReport.protectionLosses[0].id;
    // Poison loss.replay in memory to prove Replay ignores it
    sessionRecord.parsedReport.protectionLosses[0].replay = "cmd.exe /c echo PWNED_BY_REPORT";

    // Move HEAD forward with a new commit restoring tests
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_pricing.py"),
      "from src.pricing import discount\n\ndef test_discount():\n    assert discount(100) == 80\n    assert discount(120) == 100\n    assert discount(50) == 50\n",
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Commit C: restore tests on HEAD"]);

    // 4a: Valid Replay uses pinned OIDs from sessionRecord (ignoring new HEAD and ignoring loss.replay)
    const replayPlanRes = await proveRunner.prepareReplayProvePlan({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      recordOrRunId: sessionRecord,
      selectedMutantId: targetMutantId,
    });
    assert.strictEqual(replayPlanRes.ok, true);
    const replayAuth = proveRunner.issueManualAuthorizationToken({
      plan: replayPlanRes.value,
      userConfirmedExecutionRisk: true,
    });
    const replayOutcome = await proveRunner.runSingleMutantReplay({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      record: sessionRecord,
      selectedMutantId: targetMutantId,
      authorization: replayAuth,
    });
    assert.strictEqual(replayOutcome.status, "Compared");
    assert.ok(replayOutcome.record !== null);
    assert.strictEqual(replayOutcome.record!.parsedReport.runCount, 1);
    assert.strictEqual(
      replayOutcome.replayPlanUsed?.effectiveRangeArg,
      `${baseOid}..${headOid}`,
      "Replay must use pinned effectiveBaseOid..effectiveHeadOid even after HEAD moved"
    );

    // 4b: Replay a non-existent mutant ID ("m9999") -> rejected at plan preparation
    const badMutantPlan = await proveRunner.prepareReplayProvePlan({
      hostDesc,
      configuredProvePath: PROVE_EXE,
      recordOrRunId: sessionRecord,
      selectedMutantId: "m9999",
    });
    assert.strictEqual(badMutantPlan.ok, false);
    if (!badMutantPlan.ok) {
      assert.ok(badMutantPlan.error.includes("does not belong to execution record"));
    }

    // 4c: If the Prove binary path/SHA changes after record creation (or after plan confirmation) -> Replay rejected
    const externalProveCopy = path.join(
      tempRoot,
      IS_WIN32 ? "checkwash-prove-copy.exe" : "checkwash-prove-copy"
    );
    copyExecutablePreservingMode(PROVE_EXE, externalProveCopy);
    const changedBinPlan = await proveRunner.prepareReplayProvePlan({
      hostDesc,
      configuredProvePath: externalProveCopy,
      recordOrRunId: sessionRecord,
      selectedMutantId: targetMutantId,
    });
    assert.strictEqual(changedBinPlan.ok, false);
    if (!changedBinPlan.ok) {
      assert.ok(
        changedBinPlan.error.includes("Runtime or Prove executable identity has changed"),
        `Unexpected error: ${changedBinPlan.error}`
      );
    }
    console.log("  [PASS] C4: Real Prove + Replay verified against HEAD move, poisoned loss.replay, unknown mutant ID, and binary swap.");

    console.log("\n=== ALL PHASE 3 COUNTEREXAMPLES PASSED (4 / 4 groups) ===");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("[Phase 3 Counterexamples FAILED]", err);
  process.exit(1);
});
