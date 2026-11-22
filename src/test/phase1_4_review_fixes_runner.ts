/**
 * test/phase1_4_review_fixes_runner.ts
 *
 * Executable Reproduction & Verification Suite for the 10 Phase 1–4 Engineering Review Findings:
 *   - R01 [P1]: Redacted copy leaks second secret on same line in Sensitive Data Guard Notice preview
 *   - R02 [P1]: Static diff reading executes repository's diff.<driver>.textconv command
 *   - R03 [P1]: Prove / Replay missing cancellation & exclusive execution management
 *   - R04 [P1]: Prove TEMP directory wiped by subsequent verifyLaunchAdmission() re-admission
 *   - R05 [P1]: Editor buffer becoming dirty during in-flight scan still publishes stale inline diagnostics
 *   - R06 [P1]: Multi-repo switching leaks previous repo findings on editor event or in-flight scan completion
 *   - R07 [P2]: StatusBar & evaluatedState do not show Analyzing/Stale while a scan is in flight
 *   - R08 [P2]: Standalone Fast Guard hints (with 0 Checkwash findings) fail live inline projection due to missing head blob
 *   - R09 [P2]: Offline Checkwash JSON v2 report preview is stored but not rendered in TreeView
 *   - R10 [P2]: Malformed Prove report array elements (e.g. protection_losses: [null]) poison view snapshot
 */

import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { validateProveReportJson } from "../core/proveModel";
import {
  authorizeClipboardCopy,
  buildContextDietDiff,
} from "../engine/contextDiet";
import { OpenEditorDocumentSnapshot } from "../engine/checkwashRunner";
import {
  HostEnvironmentDescriptor,
  verifyLaunchAdmission,
} from "../runtime/admission";
import { UnifiedProcessRunner } from "../runtime/processRunner";
import { executeViaWindowsBroker } from "../runtime/windowsBroker";
import {
  buildRevisionUriString,
  CommittedDiffSnapshot,
  parseRevisionUriString,
  RevisionProvider,
} from "../source/revisionProvider";
import { CheckwashLensController, ControllerViewSnapshot } from "../ui/commands";

import {
  ACTIVE_ARCH,
  ACTIVE_PLATFORM,
  getPlatformExecutionMetadata,
  isGitExecutableName,
  isProveExecutableName,
  resolvePlatformEvidenceDir,
  resolveTestGitExe,
  resolveTestProveExe,
  resolveTestPythonExe,
} from "./testPlatformEnv";

interface ReviewFixTestResult {
  id: string;
  severity: "P1" | "P2";
  reviewName: string;
  description: string;
  passed: boolean;
  details: string;
}

const EXTENSION_ROOT = path.resolve(__dirname, "..", "..");
const PYTHON_EXE = resolveTestPythonExe();
const GIT_EXE = resolveTestGitExe();
const PROVE_EXE_PATH = resolveTestProveExe();

function runGitInitCmd(cwd: string, args: string[]): string {
  return execFileSync(GIT_EXE, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function makeTrustedHostDesc(repoRoot: string): HostEnvironmentDescriptor {
  return {
    isWorkspaceTrusted: true,
    platform: ACTIVE_PLATFORM,
    arch: ACTIVE_ARCH,
    workspaceScheme: "file",
    isRemote: false,
    isVirtualWorkspace: false,
    extensionRootPath: EXTENSION_ROOT,
    repositoryRootPath: repoRoot,
    configuredPythonPath: PYTHON_EXE,
    configuredGitPath: GIT_EXE,
    inheritedEnv: process.env,
  };
}

function createCustomRepo(
  parentDir: string,
  name: string,
  baseFiles: Record<string, string>,
  headFiles: Record<string, string>
): { repoDir: string; baseOid: string; headOid: string } {
  const repoDir = path.join(parentDir, name);
  fs.mkdirSync(repoDir, { recursive: true });
  runGitInitCmd(repoDir, ["init"]);
  runGitInitCmd(repoDir, ["config", "user.email", "test@example.com"]);
  runGitInitCmd(repoDir, ["config", "user.name", "Checkwash Test"]);
  runGitInitCmd(repoDir, ["config", "core.autocrlf", "false"]);

  for (const [rel, content] of Object.entries(baseFiles)) {
    const abs = path.join(repoDir, ...rel.split("/"));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  }
  runGitInitCmd(repoDir, ["add", "."]);
  runGitInitCmd(repoDir, ["commit", "-m", "Base commit"]);
  const baseOid = runGitInitCmd(repoDir, ["rev-parse", "HEAD"]);

  for (const [rel, content] of Object.entries(headFiles)) {
    const abs = path.join(repoDir, ...rel.split("/"));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  }
  runGitInitCmd(repoDir, ["add", "-A"]);
  runGitInitCmd(repoDir, ["commit", "-m", "Head commit"]);
  const headOid = runGitInitCmd(repoDir, ["rev-parse", "HEAD"]);

  return { repoDir, baseOid, headOid };
}

async function runReviewFixSuite(): Promise<void> {
  const results: ReviewFixTestResult[] = [];
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-lens-rev14-fixes-"));

  try {
    // =========================================================================
    // R01 [P1]: redacted_notice_leaks_other_secret
    // =========================================================================
    {
      const syntheticApiKey = "SYNTHETIC_SECRET_123";
      const syntheticGhToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
      const patchLine = `+api_key = "${syntheticApiKey}" # token=${syntheticGhToken}`;

      const diffSnap: CommittedDiffSnapshot = {
        repositoryRoot: tempRoot,
        effectiveBaseOid: "a".repeat(40),
        effectiveHeadOid: "b".repeat(40),
        rawUnifiedDiff: [
          "diff --git a/src/config.py b/src/config.py",
          "--- a/src/config.py",
          "+++ b/src/config.py",
          "@@ -1,1 +1,2 @@",
          " x = 1",
          patchLine,
        ].join("\n"),
        changedFiles: [
          {
            status: "M",
            oldPath: "src/config.py",
            newPath: "src/config.py",
          },
        ],
      };

      const diet = buildContextDietDiff(diffSnap);
      const copyRes = authorizeClipboardCopy({
        dietResult: diet,
        mode: "redacted",
      });

      const previewContainsApiKey = diet.sensitiveFindings.some((f) =>
        f.previewRedacted.includes(syntheticApiKey)
      );
      const previewContainsGhToken = diet.sensitiveFindings.some((f) =>
        f.previewRedacted.includes(syntheticGhToken)
      );
      const payloadContainsApiKey =
        copyRes.ok && copyRes.value.payloadToCopy.includes(syntheticApiKey);
      const payloadContainsGhToken =
        copyRes.ok && copyRes.value.payloadToCopy.includes(syntheticGhToken);

      const passed =
        diet.hasSensitiveData &&
        diet.sensitiveFindings.length >= 2 &&
        copyRes.ok &&
        !previewContainsApiKey &&
        !previewContainsGhToken &&
        !payloadContainsApiKey &&
        !payloadContainsGhToken;

      results.push({
        id: "R01",
        severity: "P1",
        reviewName: "redacted_notice_leaks_other_secret",
        description:
          "Same-line multi-secret (api_key + GitHub token) is fully redacted across all rules before building previewRedacted and Sensitive Data Guard Notice.",
        passed,
        details: `findings=${diet.sensitiveFindings.length}, previewLeakedApiKey=${previewContainsApiKey}, payloadLeakedApiKey=${payloadContainsApiKey}, payloadLeakedGhToken=${payloadContainsGhToken}`,
      });
    }

    // =========================================================================
    // R02 [P1]: static_diff_runs_textconv
    // =========================================================================
    {
      const { repoDir, baseOid, headOid } = createCustomRepo(
        tempRoot,
        "repo-r02-textconv",
        {
          ".gitattributes": "*.py diff=custom\n",
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_sample.py":
            "from src.calc import add\n\ndef test_a():\n    assert add(1, 2) == 3\n    assert add(2, 3) == 5\n",
        },
        {
          ".gitattributes": "*.py diff=custom\n",
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_sample.py":
            "from src.calc import add\n\ndef test_a():\n    assert add(1, 2) is not None\n",
        }
      );

      const markerPath = path.join(repoDir, "textconv-executed.marker");
      const helperScript = path.join(repoDir, "textconv_helper.py");
      fs.writeFileSync(
        helperScript,
        [
          "import pathlib, sys",
          `pathlib.Path(${JSON.stringify(markerPath)}).write_text("ran", encoding="utf-8")`,
          "print(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'), end='')",
        ].join("\n"),
        "utf8"
      );

      // Configure diff.custom.textconv in .git/config
      const textconvCmd = `python "${helperScript.replace(/\\/g, "/")}"`;
      runGitInitCmd(repoDir, ["config", "diff.custom.textconv", textconvCmd]);

      const hostDesc = makeTrustedHostDesc(repoDir);
      const controller = new CheckwashLensController();
      const revProvider = new RevisionProvider(controller.getProcessRunner());

      const diffRes = await revProvider.readCommittedDiff(
        hostDesc,
        baseOid,
        headOid
      );
      const markerAfterDiff = fs.existsSync(markerPath);

      const scanSnap = await controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", []);
      const markerAfterScan = fs.existsSync(markerPath);

      const passed =
        diffRes.ok &&
        !markerAfterDiff &&
        !markerAfterScan &&
        scanSnap.evaluatedState.state === "Block";

      results.push({
        id: "R02",
        severity: "P1",
        reviewName: "static_diff_runs_textconv",
        description:
          "RevisionProvider.readCommittedDiff and scanCommittedRange pass --no-textconv so repo diff.<driver>.textconv is never executed.",
        passed,
        details: `diffOk=${diffRes.ok}, markerAfterDiff=${markerAfterDiff}, markerAfterScan=${markerAfterScan}, scanState=${scanSnap.evaluatedState.state}`,
      });
    }

    // =========================================================================
    // R03 [P1]: prove_cancel_controlled_interleaving
    // =========================================================================
    {
      const { repoDir } = createCustomRepo(
        tempRoot,
        "repo-r03-prove-cancel",
        {
          "pyproject.toml": '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_calc.py": "from src.calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n",
        },
        {
          "pyproject.toml": '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_calc.py": "from src.calc import add\n\ndef test_add():\n    assert add(2, 3) is not None\n",
        }
      );

      const runner = new UnifiedProcessRunner();
      const controller = new CheckwashLensController(runner);
      const hostDesc = makeTrustedHostDesc(repoDir);

      let capturedProveAbortSignal: AbortSignal | undefined;
      let proveBrokerStartedResolve!: () => void;
      const proveBrokerStarted = new Promise<void>((r) => {
        proveBrokerStartedResolve = r;
      });

      runner.setCustomBrokerExecutorForTests(async (req, abortSignal) => {
        const isMainProveRun =
          isProveExecutableName(req.executable) && !req.args.includes("--version");
        if (!isMainProveRun) {
          return executeViaWindowsBroker(req, abortSignal);
        }

        // Main checkwash-prove invocation: capture abortSignal and wait for cancel!
        capturedProveAbortSignal = abortSignal;
        proveBrokerStartedResolve();

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
          childPid: 1003,
          stdoutRaw: Buffer.alloc(0),
          stderrRaw: Buffer.from("Cancelled via Job Object", "utf8"),
          stdoutUtf8Valid: true,
          stderrUtf8Valid: true,
          stdoutText: "",
          stderrText: "Cancelled via Job Object",
          cleanupConfirmed: true,
          activeProcessesRemaining: 0,
        };
      });

      const planListRes = await controller.prepareProveManualCommandPlan({
        hostDesc,
        configuredProvePath: PROVE_EXE_PATH,
        rawRangeSpec: "HEAD~1..HEAD",
        entryKind: "list",
      });
      if (!planListRes.ok) {
        throw new Error(`R03 prepareProveManualCommandPlan failed: ${planListRes.error}`);
      }
      const authList = controller.getProveRunner().issueManualAuthorizationToken({
        plan: planListRes.value,
        userConfirmedExecutionRisk: true,
      });

      const provePromise = controller.runProveManualCommand({
        hostDesc,
        configuredProvePath: PROVE_EXE_PATH,
        rawRangeSpec: "HEAD~1..HEAD",
        entryKind: "list",
        authorization: authList,
      });

      const raceRes = await Promise.race([
        proveBrokerStarted.then(() => ({ kind: "started" as const })),
        provePromise.then((snap) => ({ kind: "early" as const, snap })),
      ]);
      if (raceRes.kind === "early") {
        throw new Error(
          `R03 provePromise resolved early before main broker launch: status=${raceRes.snap.proveOutcome.status}, error=${raceRes.snap.proveOutcome.errorReason}`
        );
      }
      const activeDuringProve = runner.isOperationActive();

      const cancelOutcome = await runner.cancelActiveRunAndConfirmStop();
      const finalSnap = await provePromise;

      const passed =
        Boolean(capturedProveAbortSignal) &&
        capturedProveAbortSignal?.aborted === true &&
        activeDuringProve === true &&
        cancelOutcome.stopped === true &&
        cancelOutcome.cleanupConfirmed === true &&
        finalSnap.proveOutcome.status === "Not Run / Cancelled" &&
        finalSnap.proveOutcome.errorReason === null;

      runner.setCustomBrokerExecutorForTests(null);

      results.push({
        id: "R03",
        severity: "P1",
        reviewName: "prove_cancel_controlled_interleaving",
        description:
          "Prove & Replay register with UnifiedProcessRunner exclusive cancelable execution and pass abortSignal to executeGatedProcess.",
        passed,
        details: `hasAbortSignal=${Boolean(capturedProveAbortSignal)}, aborted=${capturedProveAbortSignal?.aborted}, activeDuring=${activeDuringProve}, finalStatus=${finalSnap.proveOutcome.status}`,
      });
    }

    // =========================================================================
    // R04 [P1]: prove_temp_removed_on_readmission
    // =========================================================================
    {
      const customTmpRoot = path.join(tempRoot, "r04-os-tmpdir");
      fs.mkdirSync(customTmpRoot, { recursive: true });
      const origTemp = process.env.TEMP;
      const origTmp = process.env.TMP;
      const origTmpDir = process.env.TMPDIR;
      process.env.TEMP = customTmpRoot;
      process.env.TMP = customTmpRoot;
      process.env.TMPDIR = customTmpRoot;

      try {
        const { repoDir } = createCustomRepo(
          tempRoot,
          "repo-r04-temp",
          { "a.py": "x = 1\n" },
          { "a.py": "x = 2\n" }
        );
        const hostDesc = makeTrustedHostDesc(repoDir);

        // Admission 1: e.g. Prove starts and creates a mkdtemp snapshot inside its isolatedTempDir
        const adm1 = verifyLaunchAdmission(hostDesc);
        if (!adm1.ok) {
          throw new Error(`adm1 failed: ${adm1.error}`);
        }
        const proveTempDir = adm1.value.isolatedTempDir;
        const simulatedProveSnapshotDir = fs.mkdtempSync(
          path.join(proveTempDir, "checkwash-prove-")
        );
        const simulatedSnapshotFile = path.join(simulatedProveSnapshotDir, "snapshot.py");
        fs.writeFileSync(simulatedSnapshotFile, "x = 2\n", "utf8");

        // Admission 2: e.g. RevisionProvider or another gated check runs while Prove is still alive
        const adm2 = verifyLaunchAdmission(hostDesc);
        if (!adm2.ok) {
          throw new Error(`adm2 failed: ${adm2.error}`);
        }

        // Also run a full gated git process under Admission 2 so its finally block cleans up adm2's temp dir
        const runner = new UnifiedProcessRunner();
        const gitRes = await runner.runTrustedGitRead(hostDesc, ["rev-parse", "HEAD"]);

        const snapshotStillExists = fs.existsSync(simulatedSnapshotFile);
        const distinctTempDirs = adm1.value.isolatedTempDir !== adm2.value.isolatedTempDir;

        const passed = gitRes.ok && distinctTempDirs && snapshotStillExists;

        results.push({
          id: "R04",
          severity: "P1",
          reviewName: "prove_temp_removed_on_readmission",
          description:
            "Each admission allocates an isolated per-invocation temp directory; subsequent admissions and process completions never wipe an active Prove run's TEMP directory.",
          passed,
          details: `distinctTempDirs=${distinctTempDirs}, gitResOk=${gitRes.ok}, snapshotStillExists=${snapshotStillExists}`,
        });
      } finally {
        if (origTemp === undefined) {
          delete process.env.TEMP;
        } else {
          process.env.TEMP = origTemp;
        }
        if (origTmp === undefined) {
          delete process.env.TMP;
        } else {
          process.env.TMP = origTmp;
        }
        if (origTmpDir === undefined) {
          delete process.env.TMPDIR;
        } else {
          process.env.TMPDIR = origTmpDir;
        }
      }
    }

    // =========================================================================
    // R05 [P1]: dirty_during_scan
    // =========================================================================
    {
      const headTestText = [
        "import time",
        "from src.calc import add",
        "",
        "def test_dirty_race():",
        "    time.sleep(1)",
        "    assert add(1, 2) is not None",
        "",
      ].join("\n");

      const { repoDir } = createCustomRepo(
        tempRoot,
        "repo-r05-dirty-midscan",
        {
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_dirty_race.py":
            "from src.calc import add\n\ndef test_dirty_race():\n    assert add(1, 2) == 3\n    assert add(2, 3) == 5\n",
        },
        {
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_dirty_race.py": headTestText,
        }
      );

      const hostDesc = makeTrustedHostDesc(repoDir);
      const controller = new CheckwashLensController();

      const initialCleanDoc: OpenEditorDocumentSnapshot = {
        repositoryRoot: repoDir,
        relativePath: "tests/test_dirty_race.py",
        isDirty: false,
        verifiedVersion: 1,
        currentVersionAtPublish: 1,
        text: headTestText,
        isClosedOrDeleted: false,
      };

      const scanPromise = controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", [
        initialCleanDoc,
      ]);

      // Immediately simulate user editing the buffer in VS Code while the scan is in flight
      const editedDirtyDoc: OpenEditorDocumentSnapshot = {
        repositoryRoot: repoDir,
        relativePath: "tests/test_dirty_race.py",
        isDirty: true,
        verifiedVersion: 1,
        currentVersionAtPublish: 2,
        text: "# user typed a line during scan\n" + headTestText,
        isClosedOrDeleted: false,
      };
      controller.onOpenDocumentsChanged([editedDirtyDoc]);

      const completedSnap = await scanPromise;

      const cwDiagCount = completedSnap.diagnosticsPlan.checkwashByFile.size;
      const fgDiagCount = completedSnap.diagnosticsPlan.fastGuardByFile.size;
      const allCwWithheld = completedSnap.enrichedFindings.every(
        (ef) => !ef.liveProjectionAllowed
      );
      const allFgWithheld = (completedSnap.fastGuardResult?.hints ?? []).every(
        (h) => !h.liveProjectionAllowed
      );

      const passed =
        completedSnap.evaluatedState.state === "Block" &&
        completedSnap.enrichedFindings.length > 0 &&
        (completedSnap.fastGuardResult?.hints.length ?? 0) > 0 &&
        allCwWithheld &&
        allFgWithheld &&
        cwDiagCount === 0 &&
        fgDiagCount === 0;

      results.push({
        id: "R05",
        severity: "P1",
        reviewName: "dirty_during_scan",
        description:
          "When an open document becomes dirty or changes version while a scan is in flight, scan completion reconciles with the latest document state and publishes 0 stale inline diagnostics.",
        passed,
        details: `state=${completedSnap.evaluatedState.state}, cwFindings=${completedSnap.enrichedFindings.length}, fgHints=${completedSnap.fastGuardResult?.hints.length ?? 0}, cwDiagFiles=${cwDiagCount}, fgDiagFiles=${fgDiagCount}`,
      });
    }

    // =========================================================================
    // R06 [P1]: repository_switch_then_editor_event & repository_switch_during_scan
    // =========================================================================
    {
      const { repoDir: repoA } = createCustomRepo(
        tempRoot,
        "repo-r06-A",
        {
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_a.py":
            "from src.calc import add\n\ndef test_a():\n    assert add(1, 2) == 3\n    assert add(2, 3) == 5\n",
        },
        {
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_a.py":
            "import time\nfrom src.calc import add\n\ndef test_a():\n    time.sleep(1)\n    assert add(1, 2) is not None\n",
        }
      );
      const { repoDir: repoB } = createCustomRepo(
        tempRoot,
        "repo-r06-B",
        { "tests/test_b.py": "def test_b():\n    assert 2 == 2\n" },
        { "tests/test_b.py": "def test_b():\n    assert 2 + 2 == 4\n" }
      );

      const controller = new CheckwashLensController();
      const hostA = makeTrustedHostDesc(repoA);

      // Part A: Scan repoA -> switch to repoB -> fire onOpenDocumentsChanged([])
      const snapA = await controller.scanCommittedRange(hostA, "HEAD~1..HEAD", []);
      controller.selectRepository(repoB);
      const snapAfterEditorEvent = controller.onOpenDocumentsChanged([]);

      const partAPassed =
        snapA.evaluatedState.state === "Block" &&
        snapAfterEditorEvent.boundRepositoryRoot?.toLowerCase() ===
          path.resolve(repoB).toLowerCase() &&
        snapAfterEditorEvent.evaluatedState.state === "Not Run" &&
        snapAfterEditorEvent.enrichedFindings.length === 0 &&
        snapAfterEditorEvent.fastGuardResult === null;

      // Part B: Start scan on repoA -> switch to repoB while scan is in flight -> await scanA
      const inFlightScanA = controller.scanCommittedRange(hostA, "HEAD~1..HEAD", []);
      controller.selectRepository(repoB);
      const snapAfterInFlightDone = await inFlightScanA;

      const partBPassed =
        snapAfterInFlightDone.boundRepositoryRoot?.toLowerCase() ===
          path.resolve(repoB).toLowerCase() &&
        snapAfterInFlightDone.evaluatedState.state === "Not Run" &&
        snapAfterInFlightDone.enrichedFindings.length === 0 &&
        snapAfterInFlightDone.fastGuardResult === null;

      const passed = partAPassed && partBPassed;

      results.push({
        id: "R06",
        severity: "P1",
        reviewName: "repository_switch_then_editor_event / repository_switch_during_scan",
        description:
          "Switching repositories clears engine/prove sessions and increments repositoryGeneration so neither editor events nor in-flight scans from repoA bleed into repoB.",
        passed,
        details: `partAPassed=${partAPassed}, partBPassed=${partBPassed}, finalBoundRepo=${snapAfterInFlightDone.boundRepositoryRoot}, finalState=${snapAfterInFlightDone.evaluatedState.state}`,
      });
    }

    // =========================================================================
    // R07 [P2]: status_during_scan
    // =========================================================================
    {
      const { repoDir } = createCustomRepo(
        tempRoot,
        "repo-r07-status",
        { "tests/test_pass.py": "def test_ok():\n    assert 1 == 1\n" },
        { "tests/test_pass.py": "def test_ok():\n    assert 1 == 1\n    assert 2 == 2\n" }
      );
      const hostDesc = makeTrustedHostDesc(repoDir);
      const controller = new CheckwashLensController();

      // First scan -> Pass
      const firstSnap = await controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", []);

      const observedDuringSecondScan: ControllerViewSnapshot[] = [];
      const unsubscribe = controller.onDidChangeViewSnapshot((snap) => {
        observedDuringSecondScan.push(snap);
      });

      const secondScanPromise = controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", []);
      // Also poll getViewSnapshot() immediately while secondScanPromise is in flight
      const polledSnapWhileRunning = controller.getViewSnapshot();
      const secondSnap = await secondScanPromise;
      unsubscribe();

      const sawAnalyzingSnapshot =
        polledSnapWhileRunning.statusBar.isAnalyzing ||
        observedDuringSecondScan.some(
          (s) =>
            s.statusBar.isAnalyzing &&
            s.statusBar.isStale &&
            s.statusBar.text === "$(sync~spin) Checkwash: Analyzing..."
        );

      const passed =
        firstSnap.evaluatedState.state === "Pass" &&
        sawAnalyzingSnapshot &&
        secondSnap.evaluatedState.state === "Pass" &&
        !secondSnap.statusBar.isAnalyzing;

      results.push({
        id: "R07",
        severity: "P2",
        reviewName: "status_during_scan",
        description:
          "While a subsequent scan is in flight, controller.getViewSnapshot().statusBar and onDidChangeViewSnapshot immediately report Analyzing... and Stale instead of the old Pass state.",
        passed,
        details: `firstState=${firstSnap.evaluatedState.state}, polledWhileRunningText='${polledSnapWhileRunning.statusBar.text}', sawAnalyzingSnapshot=${sawAnalyzingSnapshot}, finalState=${secondSnap.evaluatedState.state}`,
      });
    }

    // =========================================================================
    // R08 [P2]: standalone_fast_guard
    // =========================================================================
    {
      const headSleepOnlyText = [
        "import time",
        "",
        "def test_standalone_sleep():",
        "    time.sleep(1)",
        "    assert 1 + 1 == 2",
        "",
      ].join("\n");

      const { repoDir } = createCustomRepo(
        tempRoot,
        "repo-r08-standalone-fg",
        {
          "tests/test_standalone_sleep.py": "def test_standalone_sleep():\n    assert 1 + 1 == 2\n",
        },
        {
          "tests/test_standalone_sleep.py": headSleepOnlyText,
        }
      );

      const hostDesc = makeTrustedHostDesc(repoDir);
      const controller = new CheckwashLensController();
      const openDoc: OpenEditorDocumentSnapshot = {
        repositoryRoot: repoDir,
        relativePath: "tests/test_standalone_sleep.py",
        isDirty: false,
        verifiedVersion: 1,
        currentVersionAtPublish: 1,
        text: headSleepOnlyText,
        isClosedOrDeleted: false,
      };

      const snap = await controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", [openDoc]);
      const sleepHint = (snap.fastGuardResult?.hints ?? []).find(
        (h) => h.ruleId === "FG-TIMEOUT-SLEEP-ADDED"
      );
      const fgDiagsForFile =
        snap.diagnosticsPlan.fastGuardByFile.get("tests/test_standalone_sleep.py") ?? [];

      const passed =
        snap.evaluatedState.state === "Pass" &&
        snap.enrichedFindings.length === 0 &&
        Boolean(sleepHint) &&
        sleepHint?.liveProjectionAllowed === true &&
        sleepHint?.liveVscodeLine0Based === 3 &&
        fgDiagsForFile.length === 1 &&
        fgDiagsForFile[0].vscodeLine0Based === 3;

      results.push({
        id: "R08",
        severity: "P2",
        reviewName: "standalone_fast_guard",
        description:
          "Changed files with standalone Fast Guard hints and 0 Checkwash findings still have their head revision blobs prefetched so live inline diagnostics project accurately.",
        passed,
        details: `cwState=${snap.evaluatedState.state}, cwFindings=${snap.enrichedFindings.length}, sleepHintProjected=${sleepHint?.liveProjectionAllowed}, fgDiagCount=${fgDiagsForFile.length}`,
      });
    }

    // =========================================================================
    // R09 [P2]: offline_checkwash_visibility
    // =========================================================================
    {
      const controller = new CheckwashLensController();
      const fixtureReportPath = path.join(
        EXTENSION_ROOT,
        "fixtures",
        "phase0",
        "a01-block.findings.json"
      );

      const importRes = controller.viewOfflineReportFileReadOnly(fixtureReportPath);
      const snap = controller.getViewSnapshot();
      const offlineRoot = snap.treeNodes.find((n) => n.id === "offline_checkwash_root");
      const findingsGroup = offlineRoot?.children.find(
        (c) => c.id === "offline_cw_findings_group"
      );
      const findingNodes = findingsGroup?.children ?? [];
      const hasAnyExecutableCommand = findingNodes.some((n) => Boolean(n.command));

      const passed =
        importRes.ok &&
        importRes.value.kind === "checkwash-findings-v2" &&
        snap.evaluatedState.state === "Not Run" &&
        Boolean(offlineRoot) &&
        findingNodes.length === 4 &&
        !hasAnyExecutableCommand;

      results.push({
        id: "R09",
        severity: "P2",
        reviewName: "offline_checkwash_visibility",
        description:
          "Importing an offline Checkwash JSON v2 report renders a dedicated read-only 'offline_checkwash_root' tree node with all findings while keeping active session verdict 'Not Run'.",
        passed,
        details: `importOk=${importRes.ok}, sessionState=${snap.evaluatedState.state}, hasOfflineRoot=${Boolean(offlineRoot)}, offlineFindingNodes=${findingNodes.length}`,
      });
    }

    // =========================================================================
    // R10 [P2]: malformed_prove_poisoned_view (single-field mutations from valid baseline)
    // =========================================================================
    {
      const validProveFixturePath = path.join(
        EXTENSION_ROOT,
        "fixtures",
        "phase0",
        "a11-prove-mixed-coexisting.json"
      );
      const validBaselineRaw = fs.readFileSync(validProveFixturePath, "utf8");
      const baselineVal = validateProveReportJson(validBaselineRaw);
      const cloneBaseline = (): Record<string, unknown> =>
        JSON.parse(validBaselineRaw) as Record<string, unknown>;

      const malformedPayloads: Array<{
        name: string;
        expectedErrorSubstring: string;
        mutate: (doc: Record<string, unknown>) => void;
      }> = [
        {
          name: "protection_losses_null_element",
          expectedErrorSubstring: "protection_losses[0]",
          mutate: (doc) => {
            doc.protection_losses = [null];
          },
        },
        {
          name: "unconfirmed_losses_missing_fields",
          expectedErrorSubstring: "unconfirmed_losses[0]",
          mutate: (doc) => {
            doc.unconfirmed_losses = [{ id: "m1" }];
          },
        },
        {
          name: "mutation_candidates_null_element",
          expectedErrorSubstring: "mutation.candidates[0]",
          mutate: (doc) => {
            (doc.mutation as Record<string, unknown>).candidates = [null];
          },
        },
        {
          name: "mutation_undecided_non_string_id",
          expectedErrorSubstring: "mutation.undecided[0]",
          mutate: (doc) => {
            (doc.mutation as Record<string, unknown>).undecided = [{ id: 999 }];
          },
        },
        {
          name: "notes_non_string_element",
          expectedErrorSubstring: "notes[0]",
          mutate: (doc) => {
            doc.notes = [12345];
          },
        },
      ];

      let allRejectedWithSpecificFieldError = baselineVal.ok === true;
      let viewNeverThrew = true;

      for (const item of malformedPayloads) {
        const controller = new CheckwashLensController();
        const doc = cloneBaseline();
        item.mutate(doc);
        const file = path.join(tempRoot, `${item.name}.json`);
        const raw = JSON.stringify(doc);
        fs.writeFileSync(file, raw, "utf8");

        const directVal = validateProveReportJson(raw);
        const controllerVal = controller.viewOfflineReportFileReadOnly(file);
        if (
          directVal.ok ||
          controllerVal.ok ||
          !directVal.error.includes(item.expectedErrorSubstring)
        ) {
          allRejectedWithSpecificFieldError = false;
        }

        try {
          const snap = controller.getViewSnapshot();
          if (snap.proveOutcome.record !== null) {
            allRejectedWithSpecificFieldError = false;
          }
        } catch {
          viewNeverThrew = false;
        }
      }

      const passed =
        baselineVal.ok && allRejectedWithSpecificFieldError && viewNeverThrew;

      results.push({
        id: "R10",
        severity: "P2",
        reviewName: "malformed_prove_poisoned_view",
        description:
          "Starting from a valid Prove v0.1.0 fixture baseline, single-field nested array mutations in protection_losses, unconfirmed_losses, mutation.candidates, mutation.undecided, and notes are rejected with field-specific errors and never poison getViewSnapshot().",
        passed,
        details: `baselineOk=${baselineVal.ok}, casesTested=${malformedPayloads.length}, allRejectedWithSpecificFieldError=${allRejectedWithSpecificFieldError}, viewNeverThrew=${viewNeverThrew}`,
      });
    }

    // =========================================================================
    // R11 [P1] (Round 2 #1): hunk_header_secret
    // =========================================================================
    {
      const hunkSecret = "SYNTHETIC_REAL_HUNK_SECRET_123";
      const basePyLines = [
        `def fetch(api_key="${hunkSecret}"):`,
        "    step_1 = 1",
        "    step_2 = 2",
        "    step_3 = 3",
        "    step_4 = 4",
        "    step_5 = 5",
        "    step_6 = 6",
        "    step_7 = 7",
        "    step_8 = 8",
        "    step_9 = 9",
        "    step_10 = 10",
        "    step_11 = 11",
        "    return step_11",
        "",
      ];
      const headPyLines = [...basePyLines];
      headPyLines[12] = "    return step_11 + 1";

      const { repoDir, baseOid, headOid } = createCustomRepo(
        tempRoot,
        "repo-r11-hunk-secret",
        { "src/client.py": basePyLines.join("\n") },
        { "src/client.py": headPyLines.join("\n") }
      );

      const hostDesc = makeTrustedHostDesc(repoDir);
      const runner = new UnifiedProcessRunner();
      const revProvider = new RevisionProvider(runner);
      const diffRes = await revProvider.readCommittedDiff(hostDesc, baseOid, headOid);
      if (!diffRes.ok) {
        throw new Error(`R11 readCommittedDiff failed: ${diffRes.error}`);
      }

      const rawDiffHasHunkSecret = diffRes.value.rawUnifiedDiff.includes(
        `@@ -10,5 +10,5 @@ def fetch(api_key="${hunkSecret}"):`
      ) || diffRes.value.rawUnifiedDiff.includes(hunkSecret);

      const diet = buildContextDietDiff(diffRes.value);
      const copyRes = authorizeClipboardCopy({
        dietResult: diet,
        mode: "redacted",
      });

      const redactedDiffLeaked = diet.redactedFormattedPayload.includes(hunkSecret);
      const previewLeaked = diet.sensitiveFindings.some((f) =>
        f.previewRedacted.includes(hunkSecret)
      );
      const payloadLeaked =
        copyRes.ok && copyRes.value.payloadToCopy.includes(hunkSecret);
      const preservedHunkCoordPrefix = /@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@ def fetch\(/.test(
        diet.redactedFormattedPayload
      );

      const passed =
        rawDiffHasHunkSecret &&
        diet.hasSensitiveData === true &&
        diet.sensitiveFindings.length >= 1 &&
        copyRes.ok &&
        !redactedDiffLeaked &&
        !previewLeaked &&
        !payloadLeaked &&
        preservedHunkCoordPrefix;

      results.push({
        id: "R11",
        severity: "P1",
        reviewName: "hunk_header_secret",
        description:
          "Secrets inside a real Git hunk header's trailing function signature context (@@ ... @@ def fetch(api_key=...)) are detected and redacted while preserving hunk coordinates.",
        passed,
        details: `rawDiffHasHunkSecret=${rawDiffHasHunkSecret}, hasSensitiveData=${diet.hasSensitiveData}, findings=${diet.sensitiveFindings.length}, payloadLeaked=${payloadLeaked}, preservedHunkCoordPrefix=${preservedHunkCoordPrefix}`,
      });
    }

    // =========================================================================
    // R12 [P1] (Round 2 #2): exclusive_multiple_waiters
    // =========================================================================
    {
      const runner = new UnifiedProcessRunner();
      let activeCount = 0;
      let maxConcurrentActiveRuns = 0;
      const runLog: string[] = [];

      let releaseA!: () => void;
      const aStoppingGate = new Promise<void>((r) => {
        releaseA = r;
      });
      let aStartedResolve!: () => void;
      const aStarted = new Promise<void>((r) => {
        aStartedResolve = r;
      });

      let bStartedResolve!: () => void;
      const bStarted = new Promise<void>((r) => {
        bStartedResolve = r;
      });
      let bSawAbort: boolean = false;

      let cStartedResolve!: () => void;
      const cStarted = new Promise<void>((r) => {
        cStartedResolve = r;
      });
      let cSawAbort: boolean = false;

      // Start operation A
      const promiseA = runner.runExclusiveCancelableOperation(async (sigA) => {
        activeCount++;
        maxConcurrentActiveRuns = Math.max(maxConcurrentActiveRuns, activeCount);
        runLog.push("A:start");
        aStartedResolve();
        await new Promise<void>((r) => {
          if (sigA.aborted) r();
          else sigA.addEventListener("abort", () => r(), { once: true });
        });
        await aStoppingGate;
        runLog.push("A:done");
        activeCount--;
        return "A";
      });

      await aStarted;

      // Enqueue B and C while A is still stopping
      const promiseB = runner.runExclusiveCancelableOperation(async (sigB) => {
        activeCount++;
        maxConcurrentActiveRuns = Math.max(maxConcurrentActiveRuns, activeCount);
        runLog.push("B:start");
        bStartedResolve();
        await new Promise<void>((r) => {
          if (sigB.aborted) {
            bSawAbort = true;
            r();
          } else {
            sigB.addEventListener(
              "abort",
              () => {
                bSawAbort = true;
                r();
              },
              { once: true }
            );
          }
        });
        runLog.push("B:done");
        activeCount--;
        return "B";
      });

      const promiseC = runner.runExclusiveCancelableOperation(async (sigC) => {
        activeCount++;
        maxConcurrentActiveRuns = Math.max(maxConcurrentActiveRuns, activeCount);
        runLog.push("C:start");
        cStartedResolve();
        await new Promise<void>((r) => {
          if (sigC.aborted) {
            cSawAbort = true;
            r();
          } else {
            sigC.addEventListener(
              "abort",
              () => {
                cSawAbort = true;
                r();
              },
              { once: true }
            );
          }
        });
        runLog.push("C:done");
        activeCount--;
        return "C";
      });

      // Release A so the queue advances to B (which is immediately aborted because C is waiting) and then C
      releaseA();
      await bStarted;
      await cStarted;

      // Now cancel C via cancelActiveRunAndConfirmStop()
      const cancelRes = await runner.cancelActiveRunAndConfirmStop();
      await Promise.all([promiseA, promiseB, promiseC]);

      const passed =
        maxConcurrentActiveRuns === 1 &&
        Boolean(bSawAbort) &&
        Boolean(cSawAbort) &&
        cancelRes.stopped === true &&
        runner.isOperationActive() === false &&
        runLog.join(",") === "A:start,A:done,B:start,B:done,C:start,C:done";

      results.push({
        id: "R12",
        severity: "P1",
        reviewName: "exclusive_multiple_waiters",
        description:
          "Multiple concurrent waiters on runExclusiveCancelableOperation serialize strictly via a FIFO queue (maxConcurrent=1), superseded waiters are aborted, and cancelActiveRunAndConfirmStop drains all active and queued runs.",
        passed,
        details: `maxConcurrent=${maxConcurrentActiveRuns}, bSawAbort=${bSawAbort}, cSawAbort=${cSawAbort}, isActiveAfter=${runner.isOperationActive()}, order=${runLog.join("->")}`,
      });
    }

    // =========================================================================
    // R13 [P1] (Round 2 #3): already_aborted_real_broker
    // =========================================================================
    {
      const { repoDir } = createCustomRepo(
        tempRoot,
        "repo-r13-aborted-broker",
        { "a.py": "x = 1\n" },
        { "a.py": "x = 2\n" }
      );
      const hostDesc = makeTrustedHostDesc(repoDir);
      const runner = new UnifiedProcessRunner();

      const preAbortedController = new AbortController();
      preAbortedController.abort();

      // 1. Test executeGatedProcess with real broker (customBrokerExecutor === null) and pre-aborted signal
      const gatedRes = await runner.executeGatedProcess({
        hostDesc,
        executableSelector: (ctx) => ctx.canonicalGitPath,
        argsBuilder: (ctx) => ["-C", ctx.canonicalRepositoryRoot, "rev-parse", "HEAD"],
        timeoutMs: 10_000,
        abortSignal: preAbortedController.signal,
      });

      // 2. Also test executeViaWindowsBroker directly when abort fires immediately after spawn
      const admRes = verifyLaunchAdmission(hostDesc);
      if (!admRes.ok) {
        throw new Error(`R13 admRes failed: ${admRes.error}`);
      }
      const postSpawnAbort = new AbortController();
      const brokerPromise = executeViaWindowsBroker(
        {
          brokerExecutablePath: admRes.value.bundledBrokerPath,
          executable: admRes.value.canonicalPythonPath,
          args: ["-I", "-S", "-B", "-c", "import time; time.sleep(5)"],
          cwd: admRes.value.canonicalRepositoryRoot,
          env: admRes.value.sanitizedStaticEnv,
          timeoutMs: 10_000,
          maxStdoutBytes: 16 * 1024 * 1024,
          maxStderrBytes: 16 * 1024 * 1024,
        },
        postSpawnAbort.signal
      );
      postSpawnAbort.abort();
      const directBrokerOut = await brokerPromise;

      // 3. Verify runner is NOT poisoned by unconfirmedCleanupError and subsequent Git read succeeds
      const followUpGit = await runner.runTrustedGitRead(hostDesc, ["rev-parse", "HEAD"]);

      const passed =
        gatedRes.ok === true &&
        gatedRes.value.outcome.status === "cancelled" &&
        gatedRes.value.outcome.cleanupConfirmed === true &&
        directBrokerOut.status === "cancelled" &&
        directBrokerOut.cleanupConfirmed === true &&
        followUpGit.ok === true;

      results.push({
        id: "R13",
        severity: "P1",
        reviewName: "already_aborted_real_broker",
        description:
          "Real Windows broker handles pre-aborted and immediately-aborted signals cleanly (sending CWBROKER1 request before CANCEL and returning cleanupConfirmed=true) without poisoning subsequent runs.",
        passed,
        details: `gatedStatus=${gatedRes.ok ? gatedRes.value.outcome.status : "err"}, gatedCleanup=${gatedRes.ok ? gatedRes.value.outcome.cleanupConfirmed : false}, directStatus=${directBrokerOut.status}, directCleanup=${directBrokerOut.cleanupConfirmed}, followUpGitOk=${followUpGit.ok}`,
      });
    }

    // =========================================================================
    // R14 [P1] (Round 2 #4): late_prove_after_repository_switch
    // =========================================================================
    {
      const { repoDir: repoA } = createCustomRepo(
        tempRoot,
        "repo-r14-prove-A",
        {
          "pyproject.toml": '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_calc.py": "from src.calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n",
        },
        {
          "pyproject.toml": '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_calc.py": "from src.calc import add\n\ndef test_add():\n    assert add(2, 3) is not None\n",
        }
      );
      const { repoDir: repoB } = createCustomRepo(
        tempRoot,
        "repo-r14-prove-B",
        { "tests/test_b.py": "def test_b():\n    assert 1 == 1\n" },
        { "tests/test_b.py": "def test_b():\n    assert 2 == 2\n" }
      );

      const runner = new UnifiedProcessRunner();
      const controller = new CheckwashLensController(runner);
      const hostA = makeTrustedHostDesc(repoA);

      let mainProveStartedResolve!: () => void;
      const mainProveStarted = new Promise<void>((r) => {
        mainProveStartedResolve = r;
      });
      let finishLateProveResolve!: () => void;
      const finishLateProve = new Promise<void>((r) => {
        finishLateProveResolve = r;
      });

      const validCompletedProveReport = fs.readFileSync(
        path.join(EXTENSION_ROOT, "fixtures", "phase0", "a11-prove-protection-loss.json"),
        "utf8"
      );

      runner.setCustomBrokerExecutorForTests(async (req, abortSignal) => {
        const isMainProveRun =
          isProveExecutableName(req.executable) && !req.args.includes("--version");
        if (!isMainProveRun) {
          return executeViaWindowsBroker(req, abortSignal);
        }

        mainProveStartedResolve();
        await finishLateProve;

        // Simulate a late completion packet arriving right as/after repo switch happens
        return {
          status: "completed",
          exitCode: 0,
          childPid: 2004,
          stdoutRaw: Buffer.from(validCompletedProveReport, "utf8"),
          stderrRaw: Buffer.alloc(0),
          stdoutUtf8Valid: true,
          stderrUtf8Valid: true,
          stdoutText: validCompletedProveReport,
          stderrText: "",
          cleanupConfirmed: true,
          activeProcessesRemaining: 0,
        };
      });

      const planFullRes = await controller.prepareProveManualCommandPlan({
        hostDesc: hostA,
        configuredProvePath: PROVE_EXE_PATH,
        rawRangeSpec: "HEAD~1..HEAD",
        entryKind: "full",
      });
      if (!planFullRes.ok) {
        throw new Error(`R14 prepareProveManualCommandPlan failed: ${planFullRes.error}`);
      }
      const authFull = controller.getProveRunner().issueManualAuthorizationToken({
        plan: planFullRes.value,
        userConfirmedExecutionRisk: true,
      });

      const proveAPromise = controller.runProveManualCommand({
        hostDesc: hostA,
        configuredProvePath: PROVE_EXE_PATH,
        rawRangeSpec: "HEAD~1..HEAD",
        entryKind: "full",
        authorization: authFull,
      });

      await mainProveStarted;

      // Switch active repository to repoB while repoA Prove is still running
      controller.selectRepository(repoB);

      // Now let the late repoA Prove process finish with a "Compared" report
      finishLateProveResolve();
      const snapAfterLateProve = await proveAPromise;
      runner.setCustomBrokerExecutorForTests(null);

      const leakedRecordInProveRunner = controller.getProveRunner().getTrustedRecord(1);

      const passed =
        snapAfterLateProve.boundRepositoryRoot?.toLowerCase() ===
          path.resolve(repoB).toLowerCase() &&
        snapAfterLateProve.proveOutcome.status === "Not Run / Cancelled" &&
        snapAfterLateProve.proveOutcome.record === null &&
        leakedRecordInProveRunner === undefined;

      results.push({
        id: "R14",
        severity: "P1",
        reviewName: "late_prove_after_repository_switch",
        description:
          "Switching repositories increments Prove sessionGeneration and guards onDidChangeOutcome so a late-finishing Prove run from repoA never overwrites repoB proveOutcome or stores a trusted record.",
        passed,
        details: `boundRepo=${snapAfterLateProve.boundRepositoryRoot}, proveStatus=${snapAfterLateProve.proveOutcome.status}, proveRecord=${snapAfterLateProve.proveOutcome.record}, leakedTrustedRecord=${Boolean(leakedRecordInProveRunner)}`,
      });
    }

    // =========================================================================
    // R15 [P2] (Round 2 #5): nested_undecided_poison
    // =========================================================================
    {
      const validProveFixturePath = path.join(
        EXTENSION_ROOT,
        "fixtures",
        "phase0",
        "a11-prove-mixed-coexisting.json"
      );
      const validBaselineRaw = fs.readFileSync(validProveFixturePath, "utf8");
      const cloneBaseline = (): Record<string, unknown> =>
        JSON.parse(validBaselineRaw) as Record<string, unknown>;

      const nestedPoisonPayloads: Array<{
        name: string;
        expectedErrorSubstring: string;
        mutate: (doc: Record<string, unknown>) => void;
      }> = [
        {
          name: "undecided_non_primitive_path",
          expectedErrorSubstring: "mutation.undecided[0]",
          mutate: (doc) => {
            (doc.mutation as Record<string, unknown>).undecided = [
              { id: "m1", path: { toString: null } },
            ];
          },
        },
        {
          name: "undecided_non_primitive_reason",
          expectedErrorSubstring: "mutation.undecided[0]",
          mutate: (doc) => {
            (doc.mutation as Record<string, unknown>).undecided = [
              { id: "m1", path: "src/a.py", line: 10, reason: { toString: null } },
            ];
          },
        },
        {
          name: "rows_undecided_non_primitive_path",
          expectedErrorSubstring: "mutation.rows[0]",
          mutate: (doc) => {
            (doc.mutation as Record<string, unknown>).rows = [
              { category: "undecided", id: "m1", path: { toString: null } },
            ];
          },
        },
        {
          name: "unconfirmed_loss_non_primitive_why",
          expectedErrorSubstring: "unconfirmed_losses[0]",
          mutate: (doc) => {
            doc.unconfirmed_losses = [
              {
                id: "m1",
                op: "negate_condition",
                path: "src/a.py",
                line: 4,
                before: "a == b",
                after: "a != b",
                old_caught_by: ["tests/test_a.py::test_1"],
                replay: "checkwash-prove --only m1",
                why: { toString: null },
              },
            ];
          },
        },
        {
          name: "needs_clarification_non_primitive_detail",
          expectedErrorSubstring: "needs_clarification[0]",
          mutate: (doc) => {
            doc.needs_clarification = [
              {
                test: "tests/test_a.py::test_old",
                reason: "this old test fails on the new code: the behaviour changed",
                also_fails_in_new: false,
                detail: { toString: null },
              },
            ];
          },
        },
        {
          name: "needs_clarification_legacy_synthetic_shape",
          expectedErrorSubstring: "needs_clarification[0]",
          mutate: (doc) => {
            doc.needs_clarification = [
              { path: "src/a.py", status: "syntax_error", why: "legacy synthetic" },
            ];
          },
        },
      ];

      let allRejected = true;
      let viewNeverThrew = true;

      for (const item of nestedPoisonPayloads) {
        const controller = new CheckwashLensController();
        const doc = cloneBaseline();
        item.mutate(doc);
        const file = path.join(tempRoot, `${item.name}.json`);
        const raw = JSON.stringify(doc);
        fs.writeFileSync(file, raw, "utf8");

        const directVal = validateProveReportJson(raw);
        const controllerVal = controller.viewOfflineReportFileReadOnly(file);
        if (
          directVal.ok ||
          controllerVal.ok ||
          !directVal.error.includes(item.expectedErrorSubstring)
        ) {
          allRejected = false;
        }

        try {
          const snap = controller.getViewSnapshot();
          if (snap.proveOutcome.record !== null) {
            allRejected = false;
          }
        } catch {
          viewNeverThrew = false;
        }
      }

      const passed = allRejected && viewNeverThrew;

      results.push({
        id: "R15",
        severity: "P2",
        reviewName: "nested_undecided_poison",
        description:
          "Non-primitive nested fields in mutation.undecided, mutation.rows, unconfirmed_losses.why, and needs_clarification are rejected at validation time and never throw in getViewSnapshot().",
        passed,
        details: `casesTested=${nestedPoisonPayloads.length}, allRejected=${allRejected}, viewNeverThrew=${viewNeverThrew}`,
      });
    }

    // =========================================================================
    // R16 [P2] (Round 2 #6): static_enrichment_outside_active_lifecycle
    // =========================================================================
    {
      const headSleepText = [
        "import time",
        "",
        "def test_with_sleep():",
        "    time.sleep(1)",
        "    assert 1 == 1",
        "",
      ].join("\n");

      const { repoDir } = createCustomRepo(
        tempRoot,
        "repo-r16-enrichment-lifecycle",
        {
          "src/clean_mod.py": "def helper():\n    return 42\n",
          "tests/test_with_sleep.py": "def test_with_sleep():\n    assert 1 == 1\n",
        },
        {
          "src/clean_mod.py": "def helper():\n    return 43\n",
          "tests/test_with_sleep.py": headSleepText,
        }
      );

      const hostDesc = makeTrustedHostDesc(repoDir);
      const runner = new UnifiedProcessRunner();
      const controller = new CheckwashLensController(runner);

      // Part A: Verify selective Fast Guard blob prefetch (only tests/test_with_sleep.py head blob, NOT src/clean_mod.py or base blobs)
      // and verify that during readCommittedDiff, runner.isOperationActive() is true and statusBar is Analyzing...
      let activeDuringDiffRead: boolean = false;
      let statusBarAnalyzingDuringDiffRead: boolean = false;
      let sawPrematureFinalPassBeforeDiffDone: boolean = false;

      const revProvider = (controller as unknown as { revisionProvider: RevisionProvider })
        .revisionProvider;
      const origReadDiff = revProvider.readCommittedDiff.bind(revProvider);
      const blobReadCalls: Array<{ commitOid: string; relativePath: string }> = [];
      const origReadBlob = revProvider.readCommitBlob.bind(revProvider);

      revProvider.readCommitBlob = async (
        hd,
        commitOid,
        relativePath,
        abortSignal,
        timeoutBudgetMs
      ) => {
        blobReadCalls.push({ commitOid, relativePath });
        return origReadBlob(hd, commitOid, relativePath, abortSignal, timeoutBudgetMs);
      };

      let diffReceivedBoundedBudget: boolean = false;
      revProvider.readCommittedDiff = async (
        hd,
        baseOid,
        headOid,
        abortSignal,
        timeoutBudgetMs
      ) => {
        activeDuringDiffRead = runner.isOperationActive();
        diffReceivedBoundedBudget =
          typeof timeoutBudgetMs === "number" &&
          timeoutBudgetMs > 0 &&
          timeoutBudgetMs <= 90_000;
        const midSnap = controller.getViewSnapshot();
        statusBarAnalyzingDuringDiffRead = midSnap.statusBar.isAnalyzing;
        sawPrematureFinalPassBeforeDiffDone =
          !midSnap.statusBar.isAnalyzing && midSnap.evaluatedState.state === "Pass";
        return origReadDiff(hd, baseOid, headOid, abortSignal, timeoutBudgetMs);
      };

      const snapA = await controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", []);

      // Only tests/test_with_sleep.py has a Fast Guard candidate hit; src/clean_mod.py has none, and Checkwash has 0 findings
      const onlyPrefetchedFastGuardCandidate =
        blobReadCalls.length === 1 &&
        blobReadCalls[0].relativePath === "tests/test_with_sleep.py";

      // Part B: Controlled wiring check from RevisionProvider.readCommittedDiff to broker boundary
      revProvider.readCommittedDiff = origReadDiff;
      revProvider.readCommitBlob = origReadBlob;
      revProvider.clearCache();

      let gitDiffProcessStartedResolve!: () => void;
      const gitDiffProcessStarted = new Promise<void>((r) => {
        gitDiffProcessStartedResolve = r;
      });
      runner.setCustomBrokerExecutorForTests(async (req, abortSignal) => {
        const isPostEngineGitDiff =
          isGitExecutableName(req.executable) &&
          req.args.includes("diff") &&
          req.args.includes("--unified=3");
        if (!isPostEngineGitDiff) {
          return executeViaWindowsBroker(req, abortSignal);
        }
        gitDiffProcessStartedResolve();
        await new Promise<void>((r) => {
          if (abortSignal?.aborted) r();
          else abortSignal?.addEventListener("abort", () => r(), { once: true });
        });
        return {
          status: "cancelled",
          exitCode: null,
          childPid: 3016,
          stdoutRaw: Buffer.alloc(0),
          stderrRaw: Buffer.from("Controlled wiring cancel", "utf8"),
          stdoutUtf8Valid: true,
          stderrUtf8Valid: true,
          stdoutText: "",
          stderrText: "Controlled wiring cancel",
          cleanupConfirmed: true,
          activeProcessesRemaining: 0,
        };
      });

      const scanToCancelWiring = controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", []);
      await gitDiffProcessStarted;
      const cancelWiringRes = await runner.cancelActiveRunAndConfirmStop();
      const snapAfterWiringCancel = await scanToCancelWiring;
      runner.setCustomBrokerExecutorForTests(null);

      const controlledWiringCancelOk =
        cancelWiringRes.stopped === true &&
        snapAfterWiringCancel.evaluatedState.state === "Not Run";

      // Part C: Real Windows Job Object broker (executeViaWindowsBroker) process-tree launch,
      // real OS PID observation, and real Job Object teardown on post-engine cancellation
      const isPidAlive = (pid: number): boolean => {
        if (!Number.isInteger(pid) || pid <= 0) return false;
        try {
          process.kill(pid, 0);
          return true;
        } catch (err: unknown) {
          return (err as NodeJS.ErrnoException)?.code === "EPERM";
        }
      };

      const postEngineTreeScript = path.join(tempRoot, "r16_post_engine_tree.py");
      fs.writeFileSync(
        postEngineTreeScript,
        [
          "import os, pathlib, subprocess, sys, time",
          "pids_file = sys.argv[1]",
          "git_exe = sys.argv[2]",
          "repo_dir = sys.argv[3]",
          'git_child = subprocess.Popen([git_exe, "-C", repo_dir, "hash-object", "--stdin"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)',
          'pathlib.Path(pids_file).write_text(f"{os.getpid()},{git_child.pid}", encoding="utf-8")',
          "time.sleep(60)",
        ].join("\n"),
        "utf8"
      );

      const waitForTwoPids = async (
        pidFile: string
      ): Promise<{ parentPid: number; gitChildPid: number }> => {
        const deadline = Date.now() + 16_000;
        while (Date.now() < deadline) {
          if (fs.existsSync(pidFile)) {
            const raw = fs.readFileSync(pidFile, "utf8").trim();
            const parts = raw.split(",");
            if (parts.length === 2) {
              const parentPid = Number(parts[0]);
              const gitChildPid = Number(parts[1]);
              if (parentPid > 0 && gitChildPid > 0) {
                return { parentPid, gitChildPid };
              }
            }
          }
          await new Promise((r) => setTimeout(r, 30));
        }
        throw new Error(`Timed out waiting for real PIDs in ${pidFile}`);
      };

      revProvider.clearCache();
      const cancelPidFile = path.join(tempRoot, "r16-real-cancel.pids");
      let realCancelBrokerOutcome: Awaited<ReturnType<typeof executeViaWindowsBroker>> | null = null;

      runner.setCustomBrokerExecutorForTests(async (req, abortSignal) => {
        const isPostEngineGitDiff =
          isGitExecutableName(req.executable) &&
          req.args.includes("diff") &&
          req.args.includes("--unified=3");
        if (!isPostEngineGitDiff) {
          return executeViaWindowsBroker(req, abortSignal);
        }
        // Launch a real parent + git.exe child process tree through the real native Windows Job Object broker
        const out = await executeViaWindowsBroker(
          {
            ...req,
            executable: PYTHON_EXE,
            args: ["-I", "-S", "-B", postEngineTreeScript, cancelPidFile, req.executable, repoDir],
          },
          abortSignal
        );
        realCancelBrokerOutcome = out;
        return out;
      });

      const realCancelScanPromise = controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", []);
      const { parentPid: cancelParentPid, gitChildPid: cancelGitPid } =
        await waitForTwoPids(cancelPidFile);
      const aliveBeforeCancel =
        isPidAlive(cancelParentPid) && isPidAlive(cancelGitPid);

      const realCancelStopRes = await runner.cancelActiveRunAndConfirmStop();
      const snapAfterRealCancel = await realCancelScanPromise;
      runner.setCustomBrokerExecutorForTests(null);

      const deadAfterCancel =
        !isPidAlive(cancelParentPid) && !isPidAlive(cancelGitPid);
      const realBrokerCancelOut = realCancelBrokerOutcome as Awaited<
        ReturnType<typeof executeViaWindowsBroker>
      > | null;
      const realBrokerCancelVerified =
        aliveBeforeCancel === true &&
        deadAfterCancel === true &&
        realCancelStopRes.stopped === true &&
        realCancelStopRes.cleanupConfirmed === true &&
        realBrokerCancelOut !== null &&
        realBrokerCancelOut.status === "cancelled" &&
        realBrokerCancelOut.cleanupConfirmed === true &&
        realBrokerCancelOut.activeProcessesRemaining === 0 &&
        realBrokerCancelOut.childPid === cancelParentPid &&
        snapAfterRealCancel.evaluatedState.state === "Not Run";

      // Part D: Post-engine totalScanBudgetMs exhaustion kills real process tree (including git.exe child)
      // via Job Object broker and fails closed into Error ("Static scan exceeded total 90-second budget")
      revProvider.clearCache();
      const budgetPidFile = path.join(tempRoot, "r16-real-budget.pids");
      let realBudgetBrokerOutcome: Awaited<ReturnType<typeof executeViaWindowsBroker>> | null = null;

      runner.setCustomBrokerExecutorForTests(async (req, abortSignal) => {
        const isPostEngineGitDiff =
          isGitExecutableName(req.executable) &&
          req.args.includes("diff") &&
          req.args.includes("--unified=3");
        if (!isPostEngineGitDiff) {
          return executeViaWindowsBroker(req, abortSignal);
        }
        const out = await executeViaWindowsBroker(
          {
            ...req,
            executable: PYTHON_EXE,
            args: ["-I", "-S", "-B", postEngineTreeScript, budgetPidFile, req.executable, repoDir],
          },
          abortSignal
        );
        realBudgetBrokerOutcome = out;
        return out;
      });

      const budgetScanPromise = controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", [], {
        formatTimeoutMs: 30_000,
        totalScanBudgetMs: 12_000,
        maxStdoutBytes: 16 * 1024 * 1024,
        maxStderrBytes: 16 * 1024 * 1024,
      });
      const { parentPid: budgetParentPid, gitChildPid: budgetGitPid } =
        await waitForTwoPids(budgetPidFile);
      const aliveBeforeBudgetExpiry =
        isPidAlive(budgetParentPid) && isPidAlive(budgetGitPid);
      const snapAfterBudgetExhausted = await budgetScanPromise;
      runner.setCustomBrokerExecutorForTests(null);

      const deadAfterBudget =
        !isPidAlive(budgetParentPid) && !isPidAlive(budgetGitPid);
      const realBrokerBudgetOut = realBudgetBrokerOutcome as Awaited<
        ReturnType<typeof executeViaWindowsBroker>
      > | null;
      const realBudgetExhaustionVerified =
        aliveBeforeBudgetExpiry === true &&
        deadAfterBudget === true &&
        realBrokerBudgetOut !== null &&
        realBrokerBudgetOut.cleanupConfirmed === true &&
        realBrokerBudgetOut.activeProcessesRemaining === 0 &&
        realBrokerBudgetOut.childPid === budgetParentPid &&
        snapAfterBudgetExhausted.evaluatedState.state === "Error" &&
        (snapAfterBudgetExhausted.evaluatedState.errorReason ?? "").includes(
          "exceeded total 90-second budget"
        );

      const passed =
        Boolean(activeDuringDiffRead) &&
        Boolean(diffReceivedBoundedBudget) &&
        Boolean(statusBarAnalyzingDuringDiffRead) &&
        !Boolean(sawPrematureFinalPassBeforeDiffDone) &&
        onlyPrefetchedFastGuardCandidate === true &&
        snapA.evaluatedState.state === "Pass" &&
        controlledWiringCancelOk === true &&
        realBrokerCancelVerified === true &&
        realBudgetExhaustionVerified === true;

      results.push({
        id: "R16",
        severity: "P2",
        reviewName: "static_enrichment_outside_active_lifecycle",
        description:
          "Post-engine diff reading and blob verification run inside the active cancelable scan lifecycle (selective Fast Guard head blob prefetch, controlled wiring cancel, real Job Object process-tree + git.exe cancellation with verified dead PIDs, and totalScanBudgetMs exhaustion into Error).",
        passed,
        details: `activeDuringDiff=${activeDuringDiffRead}, boundedBudget=${diffReceivedBoundedBudget}, blobReads=${blobReadCalls.length}, wiringCancelOk=${controlledWiringCancelOk}, realCancelOk=${realBrokerCancelVerified} (pids=${cancelParentPid}/${cancelGitPid}), realBudgetExhaustedOk=${realBudgetExhaustionVerified} (pids=${budgetParentPid}/${budgetGitPid})`,
      });
    }

    // =========================================================================
    // R17 [P1] (Round 3 #1): fifo_handoff_microtask_race
    // =========================================================================
    {
      const runner = new UnifiedProcessRunner();
      let activeCount = 0;
      let maxConcurrent = 0;
      const runLog: string[] = [];

      let releaseA!: () => void;
      const aManualGate = new Promise<string>((r) => {
        releaseA = () => r("A");
      });

      let bAborted: boolean = false;
      let cAborted: boolean = false;
      let cStartedResolve!: () => void;
      const cStarted = new Promise<void>((r) => {
        cStartedResolve = r;
      });

      // 1. Start A, returning the raw manual Promise directly (1 await hop inside runner)
      //    so that releaseA() triggers A's finally block on the first microtask tick,
      //    BEFORE the queueMicrotask(() => startC()) callback runs!
      const promiseA = runner.runExclusiveCancelableOperation(() => {
        activeCount++;
        maxConcurrent = Math.max(maxConcurrent, activeCount);
        runLog.push("A:start");
        return aManualGate.then((val) => {
          runLog.push("A:done");
          activeCount--;
          return val;
        });
      });

      // 2. While A is running, enqueue B
      const promiseB = runner.runExclusiveCancelableOperation(async (sigB) => {
        activeCount++;
        maxConcurrent = Math.max(maxConcurrent, activeCount);
        runLog.push("B:start");
        await new Promise<void>((r) => {
          if (sigB.aborted) {
            bAborted = true;
            r();
          } else {
            sigB.addEventListener(
              "abort",
              () => {
                bAborted = true;
                r();
              },
              { once: true }
            );
          }
        });
        runLog.push("B:done");
        activeCount--;
        return "B";
      });

      // 3. Release A (via a resolved promise chain or direct call) and schedule C via queueMicrotask
      //    right after A's finally block runs, before B's turnGrantedPromise continuation executes
      let promiseC!: Promise<string>;
      let runnerActiveWhenCArrived: boolean = false;
      runLog.push("A:release");
      releaseA();
      // Wait 1 microtask so A's .then() resolves and A's finally block executes next
      queueMicrotask(() => {
        queueMicrotask(() => {
          runnerActiveWhenCArrived = runner.isOperationActive();
          runLog.push("C:invoke");
          promiseC = runner.runExclusiveCancelableOperation(async (sigC) => {
            activeCount++;
            maxConcurrent = Math.max(maxConcurrent, activeCount);
            runLog.push("C:start");
            cStartedResolve();
            await new Promise<void>((r) => {
              if (sigC.aborted) {
                cAborted = true;
                r();
              } else {
                sigC.addEventListener(
                  "abort",
                  () => {
                    cAborted = true;
                    r();
                  },
                  { once: true }
                );
              }
            });
            runLog.push("C:done");
            activeCount--;
            return "C";
          });
        });
      });

      await cStarted;
      const activeWhileCPending = runner.isOperationActive();
      const cancelReturn = await runner.cancelActiveRunAndConfirmStop();
      await Promise.all([promiseA, promiseB, promiseC]);
      const activeAfterCancel = runner.isOperationActive();

      // Verify C:invoke occurred during the handoff window (after A:done, before B:start),
      // yet B still started and finished before C:start!
      const expectedOrder =
        "A:start->A:release->A:done->C:invoke->B:start->B:done->C:start->C:done";
      const actualOrder = runLog.join("->");

      const passed =
        maxConcurrent === 1 &&
        Boolean(runnerActiveWhenCArrived) &&
        Boolean(bAborted) &&
        Boolean(cAborted) &&
        activeWhileCPending === true &&
        activeAfterCancel === false &&
        cancelReturn.stopped === true &&
        cancelReturn.cleanupConfirmed === true &&
        actualOrder === expectedOrder;

      results.push({
        id: "R17",
        severity: "P1",
        reviewName: "fifo_handoff_microtask_race",
        description:
          "Atomic slot handoff in runExclusiveCancelableOperation prevents a microtask-scheduled third operation C (arriving after A's finally and before B's continuation) from cutting in front of B or leaving an uncancelable pending task.",
        passed,
        details: `maxConcurrent=${maxConcurrent}, activeWhenCArrived=${runnerActiveWhenCArrived}, bAborted=${bAborted}, cAborted=${cAborted}, activeAfterCancel=${activeAfterCancel}, order=${actualOrder}`,
      });
    }

    // =========================================================================
    // R18 [P1] (Round 3 #2): superseded_scan_clears_new_scan_tracking
    // =========================================================================
    {
      const headTestText = [
        "import time",
        "from src.calc import add",
        "",
        "def test_handoff_dirty():",
        "    time.sleep(1)",
        "    assert add(1, 2) is not None",
        "",
      ].join("\n");

      const { repoDir } = createCustomRepo(
        tempRoot,
        "repo-r18-superseded-scan-dirty",
        {
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_handoff_dirty.py":
            "from src.calc import add\n\ndef test_handoff_dirty():\n    assert add(1, 2) == 3\n    assert add(2, 3) == 5\n",
        },
        {
          "src/calc.py": "def add(a, b):\n    return a + b\n",
          "tests/test_handoff_dirty.py": headTestText,
        }
      );

      const hostDesc = makeTrustedHostDesc(repoDir);

      const runHandoffSubcase = async (
        midScanEventDocs: readonly OpenEditorDocumentSnapshot[]
      ): Promise<{
        midBStillAnalyzing: boolean;
        finalState: string;
        cwFindings: number;
        fgHints: number;
        cwDiagFiles: number;
        fgDiagFiles: number;
        allCwWithheld: boolean;
        allFgWithheld: boolean;
      }> => {
        const runner = new UnifiedProcessRunner();
        const controller = new CheckwashLensController(runner);

        const origProbe = runner.probeTrustedRuntimeVersions.bind(runner);
        let probeCallCount = 0;
        let probe1StartedResolve!: () => void;
        const probe1Started = new Promise<void>((r) => {
          probe1StartedResolve = r;
        });
        let probe2StartedResolve!: () => void;
        const probe2Started = new Promise<void>((r) => {
          probe2StartedResolve = r;
        });
        let releaseProbe2!: () => void;
        const probe2Gate = new Promise<void>((r) => {
          releaseProbe2 = r;
        });

        runner.probeTrustedRuntimeVersions = async (hd, abortSignal) => {
          probeCallCount++;
          if (probeCallCount === 1) {
            probe1StartedResolve();
            await new Promise<void>((r) => {
              if (abortSignal?.aborted) r();
              else abortSignal?.addEventListener("abort", () => r(), { once: true });
            });
            return { ok: false, error: "Probe 1 aborted by superseded scan" };
          }
          if (probeCallCount === 2) {
            probe2StartedResolve();
            await probe2Gate;
          }
          return origProbe(hd, abortSignal);
        };

        const initialCleanDoc: OpenEditorDocumentSnapshot = {
          repositoryRoot: repoDir,
          relativePath: "tests/test_handoff_dirty.py",
          isDirty: false,
          verifiedVersion: 1,
          currentVersionAtPublish: 1,
          text: headTestText,
          isClosedOrDeleted: false,
        };

        const scanAPromise = controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", [
          initialCleanDoc,
        ]);
        await probe1Started;

        const scanBPromise = controller.scanCommittedRange(hostDesc, "HEAD~1..HEAD", [
          initialCleanDoc,
        ]);
        await Promise.all([scanAPromise, probe2Started]);

        const midBSnap = controller.getViewSnapshot();
        const midBStillAnalyzing =
          midBSnap.evaluatedState.lifecycle.analyzing === true &&
          midBSnap.statusBar.isAnalyzing === true;

        controller.onOpenDocumentsChanged(midScanEventDocs);

        releaseProbe2();
        const finalBSnap = await scanBPromise;

        return {
          midBStillAnalyzing,
          finalState: finalBSnap.evaluatedState.state,
          cwFindings: finalBSnap.enrichedFindings.length,
          fgHints: finalBSnap.fastGuardResult?.hints.length ?? 0,
          cwDiagFiles: finalBSnap.diagnosticsPlan.checkwashByFile.size,
          fgDiagFiles: finalBSnap.diagnosticsPlan.fastGuardByFile.size,
          allCwWithheld: finalBSnap.enrichedFindings.every((ef) => !ef.liveProjectionAllowed),
          allFgWithheld: (finalBSnap.fastGuardResult?.hints ?? []).every(
            (h) => !h.liveProjectionAllowed
          ),
        };
      };

      // Subcase 18a: Document becomes dirty (isDirty=true, version=2) after A->B handoff
      const resDirty = await runHandoffSubcase([
        {
          repositoryRoot: repoDir,
          relativePath: "tests/test_handoff_dirty.py",
          isDirty: true,
          verifiedVersion: 1,
          currentVersionAtPublish: 2,
          text: "# dirtied after Scan A returned\n" + headTestText,
          isClosedOrDeleted: false,
        },
      ]);

      // Subcase 18b: Document changes version cleanly (isDirty=false, version=2) after A->B handoff
      const resVersionChange = await runHandoffSubcase([
        {
          repositoryRoot: repoDir,
          relativePath: "tests/test_handoff_dirty.py",
          isDirty: false,
          verifiedVersion: 1,
          currentVersionAtPublish: 2,
          text: headTestText,
          isClosedOrDeleted: false,
        },
      ]);

      // Subcase 18c: Document is closed (empty openDocuments array) after A->B handoff
      const resClosed = await runHandoffSubcase([]);

      const checkSub = (s: Awaited<ReturnType<typeof runHandoffSubcase>>): boolean =>
        s.midBStillAnalyzing === true &&
        s.finalState === "Block" &&
        s.cwFindings > 0 &&
        s.fgHints > 0 &&
        s.allCwWithheld === true &&
        s.allFgWithheld === true &&
        s.cwDiagFiles === 0 &&
        s.fgDiagFiles === 0;

      const passed =
        checkSub(resDirty) && checkSub(resVersionChange) && checkSub(resClosed);

      results.push({
        id: "R18",
        severity: "P1",
        reviewName: "superseded_scan_clears_new_scan_tracking",
        description:
          "When Scan A is superseded by Scan B on the same repository, Scan A's completion never clears Scan B's active tracking or Analyzing state, and dirty/version/close events during Scan B withhold all inline diagnostics.",
        passed,
        details: `dirtyOk=${checkSub(resDirty)}, versionChangeOk=${checkSub(resVersionChange)}, closedOk=${checkSub(resClosed)} (cwFindings=${resDirty.cwFindings}, fgHints=${resDirty.fgHints}, diagFiles=${resDirty.cwDiagFiles}/${resDirty.fgDiagFiles})`,
      });
    }

    // =========================================================================
    // R19 [P1] (Stage 1): revision_uri_special_chars_and_blob_cache_dedup
    // =========================================================================
    {
      const trickyRepoRoot = "C:\\Users\\dev\\c++ & R&D 100% %25 測試";
      const sampleOid = "0123456789abcdef0123456789abcdef01234567";
      const builtUri = buildRevisionUriString({
        repositoryRoot: trickyRepoRoot,
        commitOid: sampleOid,
        relativePath: "tests/test_c++_100%.py",
        side: "head",
        scanId: 7,
      });

      let roundTripOk = false;
      if (builtUri.ok) {
        const qIdx = builtUri.value.indexOf("?");
        const rawPathPart = builtUri.value.slice(0, qIdx);
        const decodedQuery = decodeURIComponent(builtUri.value.slice(qIdx + 1));
        // Simulate real vscode-uri `Uri.parse(...).toString()` query re-encoding
        const vscodeReEncoded = `${rawPathPart}?${encodeURIComponent(decodedQuery).replace(/%2B/gi, "+")}`;
        const parsedBack = parseRevisionUriString(vscodeReEncoded);
        roundTripOk =
          parsedBack.ok &&
          parsedBack.value.repositoryRoot === trickyRepoRoot &&
          parsedBack.value.commitOid === sampleOid &&
          parsedBack.value.relativePath === "tests/test_c++_100%.py" &&
          parsedBack.value.side === "head" &&
          parsedBack.value.scanId === 7;
      }

      const tamperedCharsRejected = !parseRevisionUriString(
        `checkwash-rev:/src/a.py?repoB64=bad$chars!&oid=${sampleOid}&side=head&scanId=1`
      ).ok;
      const tamperedUtf8B64 = Buffer.from([0xff, 0xfe, 0xfd]).toString("base64url");
      const tamperedUtf8Rejected = !parseRevisionUriString(
        `checkwash-rev:/src/a.py?repoB64=${tamperedUtf8B64}&oid=${sampleOid}&side=head&scanId=1`
      ).ok;

      const { repoDir, headOid } = createCustomRepo(
        tempRoot,
        "repo-r19-cache-dedup",
        {
          "src/a.py": "a = 1\n",
          "src/b.py": "b = 2\n",
        },
        {
          "src/a.py": "a = 10\n",
          "src/b.py": "b = 20\n",
        }
      );
      const hostDesc = makeTrustedHostDesc(repoDir);
      let gitSpawns = 0;
      let commitTypeChecks = 0;
      const runner = new UnifiedProcessRunner();
      runner.setCustomBrokerExecutorForTests(async (req, sig) => {
        gitSpawns++;
        if (req.args.includes("-t") && req.args.includes(headOid)) {
          commitTypeChecks++;
        }
        return executeViaWindowsBroker(req, sig);
      });
      const rev = new RevisionProvider(runner);

      const readA1 = await rev.readCommitBlob(hostDesc, headOid, "src/a.py");
      const spawnsAfterA1 = gitSpawns;
      const readA2 = await rev.readCommitBlob(hostDesc, headOid, "src/a.py");
      const spawnsForCachedA2 = gitSpawns - spawnsAfterA1;
      const readB1 = await rev.readCommitBlob(hostDesc, headOid, "src/b.py");

      const untrustedBlocked = !(
        await rev.readCommitBlob(
          { ...hostDesc, isWorkspaceTrusted: false },
          headOid,
          "src/a.py"
        )
      ).ok;

      const passed =
        roundTripOk &&
        tamperedCharsRejected &&
        tamperedUtf8Rejected &&
        readA1.ok &&
        readA2.ok &&
        readB1.ok &&
        spawnsForCachedA2 === 0 &&
        commitTypeChecks === 1 &&
        untrustedBlocked;

      results.push({
        id: "R19",
        severity: "P1",
        reviewName: "revision_uri_special_chars_and_blob_cache_dedup",
        description:
          "checkwash-rev: URIs round-trip paths with '+', '&', '%', spaces, and Unicode through vscode.Uri query encoding without corruption, reject tampered repoB64, cache blobs in 0 spawns, and verify commit OID type once per commit.",
        passed,
        details: `roundTripOk=${roundTripOk}, tamperedRejected=${tamperedCharsRejected && tamperedUtf8Rejected}, spawnsForCachedHit=${spawnsForCachedA2}, commitTypeChecks=${commitTypeChecks}, untrustedBlocked=${untrustedBlocked}`,
      });
    }
  } finally {
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  }

  console.log("=== Phase 1–4 Engineering Review Fixes Verification (R01–R19) ===");
  for (const r of results) {
    console.log(
      `[${r.passed ? "PASS" : "FAIL"}] ${r.id} [${r.severity}] (${r.reviewName}): ${r.description}\n       -> ${r.details}`
    );
  }

  let sourceSha = "unknown";
  try {
    sourceSha = execFileSync(GIT_EXE, ["-C", EXTENSION_ROOT, "rev-parse", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    // Fallback if outside git checkout
  }
  const failed = results.filter((r) => !r.passed);

  const evidenceDir = resolvePlatformEvidenceDir(EXTENSION_ROOT);
  const evidencePath = path.join(
    evidenceDir,
    "phase1-4-review-fixes-results.json"
  );
  const execMeta = getPlatformExecutionMetadata();
  fs.mkdirSync(path.dirname(evidencePath), { recursive: true });
  fs.writeFileSync(
    evidencePath,
    JSON.stringify(
      {
        suite: "phase1_4_review_fixes_runner",
        executionTag: execMeta.evidenceTag,
        executionEnvironment: execMeta.executionEnvironment,
        hostname: execMeta.hostname,
        hostMachineHostname: execMeta.hostMachineHostname,
        containerHostname: execMeta.containerHostname,
        sourceSha,
        platform: `${process.platform}-${process.arch}`,
        nodeVersion: process.version,
        timestampUtc: new Date().toISOString(),
        exitCode: failed.length === 0 ? 0 : 1,
        total: results.length,
        passed: results.filter((r) => r.passed).length,
        failed: failed.length,
        results,
      },
      null,
      2
    ) + "\n",
    "utf8"
  );

  if (failed.length > 0) {
    console.error(`\nFAILED: ${failed.length} of ${results.length} review fix checks failed.`);
    process.exit(1);
  } else {
    console.log(`\nALL ${results.length} REVIEW FIX CHECKS PASSED (${results.length}/${results.length}).`);
  }
}

runReviewFixSuite().catch((err) => {
  console.error("Unhandled error in runReviewFixSuite:", err);
  process.exit(1);
});
