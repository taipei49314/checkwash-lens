/**
 * test/phase1_counterexamples.ts
 *
 * Counterexample & Negative Verification Suite for Phase 1:
 * - source/revisionProvider.ts
 * - engine/checkwashRunner.ts
 */

import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";
import { HostEnvironmentDescriptor } from "../runtime/admission";
import { UnifiedProcessRunner } from "../runtime/processRunner";
import {
  buildRevisionUriString,
  parseRevisionUriString,
  RevisionProvider,
} from "../source/revisionProvider";
import { CheckwashEngineRunner } from "../engine/checkwashRunner";
import {
  ACTIVE_ARCH,
  ACTIVE_PLATFORM,
  resolveTestGitExe,
  resolveTestPythonExe,
} from "./testPlatformEnv";

const EXTENSION_ROOT = path.resolve(__dirname, "..", "..");
const PYTHON_EXE = resolveTestPythonExe();
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
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-phase1-ce-"));
  console.log(`[Phase 1 Counterexamples] Using temp dir: ${tempRoot}`);

  try {
    const repoDir = path.join(tempRoot, "repo");
    fs.mkdirSync(repoDir, { recursive: true });
    gitExec(repoDir, ["init", "-b", "main"]);
    gitExec(repoDir, ["config", "user.name", "Phase1 Tester"]);
    gitExec(repoDir, ["config", "user.email", "phase1@example.com"]);

    const runner = new UnifiedProcessRunner();
    const revProvider = new RevisionProvider(runner);
    const engineRunner = new CheckwashEngineRunner(runner, revProvider);
    const hostDesc = makeHostDesc(repoDir);

    // =========================================================================
    // C1: Range & Git Option Injection Counterexamples
    // =========================================================================
    console.log("Running C1: Range & Git Option Injection Counterexamples...");
    const injectionSpecs = [
      "--upload-pack=calc.exe..HEAD",
      "HEAD..--output=pwned",
      "-n..HEAD",
      "HEAD..-q",
      "HEAD",
      "HEAD~1..",
      "..HEAD",
      "HEAD~2....HEAD",
      "HEAD~1..HEAD\0evil",
    ];
    for (const badSpec of injectionSpecs) {
      const res = await runner.resolveAndPinCommittedRange(hostDesc, badSpec);
      assert.strictEqual(res.ok, false, `Expected '${badSpec}' to be rejected`);
    }
    console.log("  [PASS] C1: All 9 malformed/option-injection range specs rejected.");

    // =========================================================================
    // C2: Unrelated Histories in Three-Dot Range (A...B merge-base failure)
    // =========================================================================
    console.log("Running C2: Unrelated Histories Three-Dot Range Counterexample...");
    fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
    fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });
    fs.writeFileSync(
      path.join(repoDir, "src", "calc.py"),
      "def add(a, b):\n    return a + b\n",
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoDir, "tests", "conftest.py"),
      "import pytest\n\n@pytest.fixture\ndef checker():\n    def _check(actual, expected):\n        assert actual == expected\n    return _check\n",
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_calc.py"),
      "from src.calc import add\n\ndef test_add(checker):\n    checker(add(1, 2), 3)\n    assert add(2, 3) == 5\n    assert add(4, 5) == 9\n",
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Base commit on main"]);
    const baseCommitOid = gitExec(repoDir, ["rev-parse", "HEAD"]);

    // Create orphan branch with unrelated history
    gitExec(repoDir, ["checkout", "--orphan", "unrelated_branch"]);
    gitExec(repoDir, ["rm", "-rf", "."]);
    fs.writeFileSync(path.join(repoDir, "orphan.txt"), "unrelated root\n", "utf8");
    gitExec(repoDir, ["add", "orphan.txt"]);
    gitExec(repoDir, ["commit", "-m", "Orphan root commit"]);
    const orphanOid = gitExec(repoDir, ["rev-parse", "HEAD"]);

    // Switch back to main
    gitExec(repoDir, ["checkout", "main"]);

    const unrelatedSession = await engineRunner.executeStaticScan(
      hostDesc,
      `${baseCommitOid}...${orphanOid}`
    );
    assert.strictEqual(
      unrelatedSession.evaluatedState.state,
      "Error",
      "Three-dot range on unrelated histories must fail closed to Error, never fallback to two-dot"
    );
    assert.ok(
      unrelatedSession.evaluatedState.errorReason?.includes("Cannot compute merge-base"),
      `Unexpected errorReason: ${unrelatedSession.evaluatedState.errorReason}`
    );
    console.log("  [PASS] C2: Unrelated three-dot merge-base failed closed to Error.");

    // =========================================================================
    // C3: Non-Blob (Tree/Directory), Blob-as-Commit, Path Traversal & Invalid UTF-8 Blob Counterexamples
    // =========================================================================
    console.log("Running C3: Non-Blob, Blob-as-Commit, Traversal & Invalid UTF-8 Counterexamples...");
    // 3a: Requesting a directory ("tests") as a file blob
    const dirBlobRes = await revProvider.readCommitBlob(hostDesc, baseCommitOid, "tests");
    assert.strictEqual(dirBlobRes.ok, false, "Directory 'tests' must not be accepted as a file blob");
    if (!dirBlobRes.ok) {
      assert.ok(
        dirBlobRes.error.includes("not a regular file blob (type='tree')"),
        `Unexpected error for tree object: ${dirBlobRes.error}`
      );
    }

    // 3b: Passing a blob OID instead of a commit OID
    const fileBlobOid = gitExec(repoDir, ["rev-parse", `${baseCommitOid}:src/calc.py`]);
    const blobAsCommitRes = await revProvider.readCommitBlob(hostDesc, fileBlobOid, "src/calc.py");
    assert.strictEqual(blobAsCommitRes.ok, false, "Blob OID must be rejected when a commit OID is required");
    if (!blobAsCommitRes.ok) {
      assert.ok(
        blobAsCommitRes.error.includes("is not a commit (got 'blob')"),
        `Unexpected error for blob-as-commit: ${blobAsCommitRes.error}`
      );
    }

    // 3c: Path traversal, backslash, ADS, reserved names
    for (const badPath of [
      "../secret.py",
      "tests/../src/calc.py",
      "src\\calc.py",
      "src/calc.py:ads",
      "src/CON.py",
      "/src/calc.py",
    ]) {
      const badRes = await revProvider.readCommitBlob(hostDesc, baseCommitOid, badPath);
      assert.strictEqual(badRes.ok, false, `Expected unsafe path '${badPath}' to be rejected`);
    }

    // 3d: Committed file with invalid UTF-8 bytes
    fs.writeFileSync(
      path.join(repoDir, "src", "bad_utf8.py"),
      Buffer.from([0x23, 0x20, 0xff, 0xfe, 0x80, 0x0a])
    );
    gitExec(repoDir, ["add", "src/bad_utf8.py"]);
    gitExec(repoDir, ["commit", "-m", "Add invalid UTF-8 file"]);
    const badUtf8Commit = gitExec(repoDir, ["rev-parse", "HEAD"]);
    const badUtf8BlobRes = await revProvider.readCommitBlob(
      hostDesc,
      badUtf8Commit,
      "src/bad_utf8.py"
    );
    assert.strictEqual(badUtf8BlobRes.ok, false, "Invalid UTF-8 blob must be rejected");
    if (!badUtf8BlobRes.ok) {
      assert.ok(
        badUtf8BlobRes.error.includes("invalid UTF-8"),
        `Unexpected error for invalid UTF-8 blob: ${badUtf8BlobRes.error}`
      );
    }
    // Remove bad_utf8.py so main stays clean for next commit
    gitExec(repoDir, [" reset", "--hard", baseCommitOid].map((s) => s.trim()));
    console.log("  [PASS] C3: Tree object, blob-as-commit, unsafe paths, and invalid UTF-8 blob all rejected.");

    // =========================================================================
    // C4 & C5: Cross-File conftest.py, Base-Only Findings, Dirty Buffers, and Branch Moves
    // =========================================================================
    console.log("Running C4 & C5: Cross-File conftest, Base-Only Findings, Dirty Buffer & Historical Scan Counterexamples...");
    // Commit B: weaken conftest.py fixture (`assert actual == expected` -> `assert actual is not None`)
    // AND delete assertions in tests/test_calc.py
    fs.writeFileSync(
      path.join(repoDir, "tests", "conftest.py"),
      "import pytest\n\n@pytest.fixture\ndef checker():\n    def _check(actual, expected):\n        assert actual is not None\n    return _check\n",
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_calc.py"),
      "from src.calc import add\n\ndef test_add(checker):\n    checker(add(1, 2), 3)\n",
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Commit B: weaken conftest and drop assertions"]);
    const commitBOid = gitExec(repoDir, ["rev-parse", "HEAD"]);

    const commitBConftestText = fs.readFileSync(path.join(repoDir, "tests", "conftest.py"), "utf8");
    const commitBTestCalcText = fs.readFileSync(path.join(repoDir, "tests", "test_calc.py"), "utf8");

    // Case 4a: Both files are open and clean at Commit B
    const sessionB = await engineRunner.executeStaticScan(
      hostDesc,
      `${baseCommitOid}..${commitBOid}`,
      [
        {
          repositoryRoot: fs.realpathSync.native(repoDir),
          relativePath: "tests/conftest.py",
          isDirty: false,
          verifiedVersion: 1,
          currentVersionAtPublish: 1,
          text: commitBConftestText,
        },
        {
          repositoryRoot: fs.realpathSync.native(repoDir),
          relativePath: "tests/test_calc.py",
          isDirty: false,
          verifiedVersion: 1,
          currentVersionAtPublish: 1,
          text: commitBTestCalcText,
        },
      ]
    );

    assert.strictEqual(sessionB.evaluatedState.state, "Block");
    assert.ok(sessionB.enrichedFindings.length > 0, "Expected blocking findings in Commit B");

    // Verify any base-side / file-level finding (startLine1Based === null) NEVER gets liveProjectionAllowed
    for (const ef of sessionB.enrichedFindings) {
      if (ef.item.startLine1Based === null || ef.item.evidenceSide !== "head") {
        assert.strictEqual(
          ef.liveProjectionAllowed,
          false,
          `Non-head or line:null finding (${ef.item.finding.rule}) must never attach live diagnostic`
        );
        assert.strictEqual(ef.liveVscodeLine0Based, null);
      } else {
        // Head-side line-level finding (e.g. W004 on tests/test_calc.py or tests/conftest.py)
        assert.strictEqual(
          ef.liveProjectionAllowed,
          true,
          `Clean matching head buffer should allow live projection for ${ef.item.resolvedSourcePath}:${ef.item.startLine1Based}`
        );
        assert.strictEqual(ef.liveVscodeLine0Based, ef.item.startLine1Based - 1);
      }
      assert.ok(ef.preferredRevisionUri?.startsWith("checkwash-rev:/"));
    }

    // Case 4b: User edits buffer in memory (isDirty = true) -> refreshLiveEditorBindings must immediately revoke liveProjectionAllowed
    const dirtyRefreshed = engineRunner.refreshLiveEditorBindings([
      {
        repositoryRoot: fs.realpathSync.native(repoDir),
        relativePath: "tests/conftest.py",
        isDirty: true,
        verifiedVersion: 2,
        currentVersionAtPublish: 2,
        text: "# unsaved edit\n" + commitBConftestText,
      },
      {
        repositoryRoot: fs.realpathSync.native(repoDir),
        relativePath: "tests/test_calc.py",
        isDirty: true,
        verifiedVersion: 2,
        currentVersionAtPublish: 2,
        text: "# unsaved edit\n" + commitBTestCalcText,
      },
    ]);
    for (const ef of dirtyRefreshed) {
      assert.strictEqual(
        ef.liveProjectionAllowed,
        false,
        "Dirty buffer must immediately revoke live inline diagnostic projection"
      );
      assert.strictEqual(ef.liveVscodeLine0Based, null);
      // Immutable revision URI must remain valid so TreeView click still opens Commit B!
      assert.ok(ef.preferredRevisionUri?.startsWith("checkwash-rev:/"));
    }

    // Case 5: Create Commit C that shifts lines by +10 at top of files, then scan historical range Base..CommitB
    const tenHeaderLines = Array.from({ length: 10 }, (_, i) => `# Header line ${i + 1}`).join("\n") + "\n";
    fs.writeFileSync(
      path.join(repoDir, "tests", "conftest.py"),
      tenHeaderLines + commitBConftestText,
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_calc.py"),
      tenHeaderLines + commitBTestCalcText,
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Commit C: shift lines by +10"]);

    const commitCConftestText = fs.readFileSync(path.join(repoDir, "tests", "conftest.py"), "utf8");
    const commitCTestCalcText = fs.readFileSync(path.join(repoDir, "tests", "test_calc.py"), "utf8");

    // User has Commit C open and clean (isDirty: false), but scans historical range baseCommitOid..commitBOid
    const historicalSession = await engineRunner.executeStaticScan(
      hostDesc,
      `${baseCommitOid}..${commitBOid}`,
      [
        {
          repositoryRoot: fs.realpathSync.native(repoDir),
          relativePath: "tests/conftest.py",
          isDirty: false,
          verifiedVersion: 1,
          currentVersionAtPublish: 1,
          text: commitCConftestText,
        },
        {
          repositoryRoot: fs.realpathSync.native(repoDir),
          relativePath: "tests/test_calc.py",
          isDirty: false,
          verifiedVersion: 1,
          currentVersionAtPublish: 1,
          text: commitCTestCalcText,
        },
      ]
    );

    assert.strictEqual(historicalSession.evaluatedState.state, "Block");
    for (const ef of historicalSession.enrichedFindings) {
      assert.strictEqual(
        ef.liveProjectionAllowed,
        false,
        "Historical scan must NOT project line diagnostics onto Commit C's shifted buffer"
      );
      assert.strictEqual(ef.liveVscodeLine0Based, null);
    }
    console.log("  [PASS] C4 & C5: Base-only, dirty buffer, and historical +10 line shift all prevented false live diagnostics.");

    // =========================================================================
    // C6: Revision URI Tampering Counterexamples
    // =========================================================================
    console.log("Running C6: Revision URI Tampering Counterexamples...");
    const validUriRes = buildRevisionUriString({
      repositoryRoot: "C:\\repo",
      commitOid: commitBOid,
      relativePath: "tests/中文 空白/test_calc.py",
      side: "head",
      scanId: 3,
    });
    assert.strictEqual(validUriRes.ok, true);
    if (validUriRes.ok) {
      const parsed = parseRevisionUriString(validUriRes.value);
      assert.strictEqual(parsed.ok, true);
      if (parsed.ok) {
        assert.strictEqual(parsed.value.relativePath, "tests/中文 空白/test_calc.py");
        assert.strictEqual(parsed.value.commitOid, commitBOid);
        assert.strictEqual(parsed.value.side, "head");
        assert.strictEqual(parsed.value.scanId, 3);
      }
    }

    const tamperedUris = [
      `checkwash-rev:/../secret.py?repo=C%3A%5Crepo&oid=${commitBOid}&side=head&scanId=1`,
      `checkwash-rev:/%2e%2e/secret.py?repo=C%3A%5Crepo&oid=${commitBOid}&side=head&scanId=1`,
      `checkwash-rev:/tests/test.py?repo=C%3A%5Crepo&oid=not_a_commit_oid&side=head&scanId=1`,
      `checkwash-rev:/tests/test.py?repo=C%3A%5Crepo&oid=${commitBOid}&side=worktree&scanId=1`,
      `checkwash-rev:/tests/test.py?repo=C%3A%5Crepo&oid=${commitBOid}&side=head&scanId=0`,
      `checkwash-rev:/tests/test.py?repo=C%3A%5Crepo&oid=${commitBOid}&side=head&scanId=-5`,
      `checkwash-rev:/tests/CON.py?repo=C%3A%5Crepo&oid=${commitBOid}&side=head&scanId=1`,
      `file:///C:/repo/tests/test.py`,
    ];
    for (const tampered of tamperedUris) {
      const pRes = parseRevisionUriString(tampered);
      assert.strictEqual(pRes.ok, false, `Expected tampered URI '${tampered}' to be rejected`);
    }
    console.log("  [PASS] C6: All 8 tampered checkwash-rev: URIs rejected.");

    console.log("\n=== ALL PHASE 1 COUNTEREXAMPLES PASSED (6 / 6 groups) ===");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("[Phase 1 Counterexamples FAILED]", err);
  process.exit(1);
});
