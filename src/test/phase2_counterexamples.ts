/**
 * test/phase2_counterexamples.ts
 *
 * Counterexample & Negative Verification Suite for Phase 2 Core Engines:
 * - engine/fastDiffGuard.ts
 * - engine/contextDiet.ts
 */

import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";
import { decodeStrictUtf8 } from "../core/sourceIdentity";
import { HostEnvironmentDescriptor } from "../runtime/admission";
import { UnifiedProcessRunner } from "../runtime/processRunner";
import { RevisionProvider } from "../source/revisionProvider";
import { CheckwashEngineRunner } from "../engine/checkwashRunner";
import {
  analyzeCommittedDiffWithFastGuard,
  FAST_GUARD_SOURCE_LABEL,
} from "../engine/fastDiffGuard";
import {
  authorizeClipboardCopy,
  buildContextDietDiff,
} from "../engine/contextDiet";
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
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cw-phase2-ce-"));
  console.log(`[Phase 2 Counterexamples] Using temp dir: ${tempRoot}`);

  try {
    const repoDir = path.join(tempRoot, "repo");
    fs.mkdirSync(repoDir, { recursive: true });
    gitExec(repoDir, ["init", "-b", "main"]);
    gitExec(repoDir, ["config", "user.name", "Phase2 Tester"]);
    gitExec(repoDir, ["config", "user.email", "phase2@example.com"]);

    const runner = new UnifiedProcessRunner();
    const revProvider = new RevisionProvider(runner);
    const engineRunner = new CheckwashEngineRunner(runner, revProvider);
    const hostDesc = makeHostDesc(repoDir);

    // Base commit
    fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
    fs.mkdirSync(path.join(repoDir, "tests"), { recursive: true });
    fs.writeFileSync(
      path.join(repoDir, "src", "service.py"),
      "def compute(x: int) -> int:\n    return x * 2\n",
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_service.py"),
      "from src.service import compute\n\ndef test_compute():\n    assert compute(2) == 4\n    assert compute(3) == 6\n",
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Base commit"]);
    const baseOid = gitExec(repoDir, ["rev-parse", "HEAD"]);

    // =========================================================================
    // C1: Fast Guard Never Alters Checkwash Verdict & Never Deduplicates
    // =========================================================================
    console.log("Running C1: Fast Guard vs Checkwash Verdict Independence & Non-Deduplication...");
    // Subcase 1A: Add heuristic triggers in src/service.py while tests remain strong (Checkwash = Pass)
    fs.writeFileSync(
      path.join(repoDir, "src", "service.py"),
      "import time\n\ndef compute(x: int) -> int:\n    time.sleep(5)  # type: ignore\n    return x * 2  # pragma: no cover\n",
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_service.py"),
      "from src.service import compute\n\ndef test_compute():\n    assert compute(2) == 4\n    assert compute(3) == 6\n    assert compute(4) == 8\n",
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Commit 1A: heuristic triggers in src but strong tests"]);
    const commit1AOid = gitExec(repoDir, ["rev-parse", "HEAD"]);

    const session1A = await engineRunner.executeStaticScan(hostDesc, `${baseOid}..${commit1AOid}`);
    assert.strictEqual(
      session1A.evaluatedState.state,
      "Pass",
      "Checkwash state must remain Pass even when Fast Guard heuristics trigger"
    );
    assert.ok(session1A.diffSnapshot !== null);

    const fg1A = analyzeCommittedDiffWithFastGuard({
      scanId: session1A.scanIdentity!.scanId,
      diffSnapshot: session1A.diffSnapshot!,
      headBlobsByPath: session1A.headBlobsByPath,
    });
    assert.strictEqual(
      fg1A.hints.length >= 2,
      true,
      `Expected Fast Guard hints to be preserved when Checkwash is Pass, got ${fg1A.hints.length}`
    );
    // Re-verify Checkwash state was not mutated by Fast Guard
    assert.strictEqual(session1A.evaluatedState.state, "Pass");

    // Subcase 1B & C2: Commit that triggers BOTH Checkwash (W001/W002/W006) AND Fast Guard (skip + removed assert)
    fs.writeFileSync(
      path.join(repoDir, "tests", "test_service.py"),
      "import pytest\nfrom src.service import compute\n\n@pytest.mark.skip(reason='skip for now')\ndef test_compute():\n    assert compute(2) is not None\n",
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Commit 1B: both Checkwash and Fast Guard trigger"]);
    const commit1BOid = gitExec(repoDir, ["rev-parse", "HEAD"]);
    const commit1BTestText = fs.readFileSync(path.join(repoDir, "tests", "test_service.py"), "utf8");

    const session1B = await engineRunner.executeStaticScan(
      hostDesc,
      `${baseOid}..${commit1BOid}`,
      [
        {
          repositoryRoot: fs.realpathSync.native(repoDir),
          relativePath: "tests/test_service.py",
          isDirty: false,
          verifiedVersion: 1,
          currentVersionAtPublish: 1,
          text: commit1BTestText,
        },
      ]
    );
    assert.strictEqual(session1B.evaluatedState.state, "Block");
    assert.ok(session1B.enrichedFindings.length >= 2, "Expected Checkwash blocking findings");

    const fg1B = analyzeCommittedDiffWithFastGuard({
      scanId: session1B.scanIdentity!.scanId,
      diffSnapshot: session1B.diffSnapshot!,
      headBlobsByPath: session1B.headBlobsByPath,
      openDocuments: [
        {
          repositoryRoot: fs.realpathSync.native(repoDir),
          relativePath: "tests/test_service.py",
          isDirty: false,
          verifiedVersion: 1,
          currentVersionAtPublish: 1,
          text: commit1BTestText,
        },
      ],
    });

    const skipHints = fg1B.hints.filter((h) => h.ruleId === "FG-SKIP-XFAIL-ADDED");
    const removedAssertHints = fg1B.hints.filter((h) => h.ruleId === "FG-ASSERT-REMOVED-IN-TEST");
    assert.ok(skipHints.length >= 1, "Expected FG-SKIP-XFAIL-ADDED hint (no deduplication against Checkwash)");
    assert.ok(removedAssertHints.length >= 2, "Expected FG-ASSERT-REMOVED-IN-TEST hints for removed assertions");

    for (const h of fg1B.hints) {
      assert.strictEqual(h.sourceLabel, FAST_GUARD_SOURCE_LABEL);
    }

    // =========================================================================
    // C2: Removed Assertion Hints (side=base) Never Attach to Live Editor
    // =========================================================================
    console.log("Running C2: Removed Assertion Hints (side=base) Live Editor Isolation...");
    for (const rmHint of removedAssertHints) {
      assert.strictEqual(rmHint.side, "base");
      assert.strictEqual(rmHint.headLine1Based, null);
      assert.ok(rmHint.baseLine1Based !== null && rmHint.baseLine1Based >= 1);
      assert.strictEqual(
        rmHint.liveProjectionAllowed,
        false,
        "Removed assertion hint on base revision must NEVER attach to live editor"
      );
      assert.strictEqual(rmHint.liveVscodeLine0Based, null);
      assert.ok(
        rmHint.revisionUri?.includes(`oid=${baseOid}`) && rmHint.revisionUri?.includes("side=base"),
        `Expected base revision URI, got ${rmHint.revisionUri}`
      );
    }
    // Meanwhile, added skip hint on head DOES attach to clean live editor at exact 0-based line
    for (const sh of skipHints) {
      assert.strictEqual(sh.side, "head");
      assert.strictEqual(sh.liveProjectionAllowed, true);
      assert.strictEqual(sh.liveVscodeLine0Based, sh.headLine1Based! - 1);
    }
    console.log("  [PASS] C1 & C2: Fast Guard verdict independence, zero deduplication, and base-side isolation verified.");

    // =========================================================================
    // C3: Context Diet All-Lockfiles / Generated Files Never Silently Empty
    // =========================================================================
    console.log("Running C3: Context Diet All-Lockfiles Omission Disclosure Counterexample...");
    const preLockOid = gitExec(repoDir, ["rev-parse", "HEAD"]);
    fs.mkdirSync(path.join(repoDir, "dist"), { recursive: true });
    fs.writeFileSync(
      path.join(repoDir, "package-lock.json"),
      JSON.stringify({ name: "demo", lockfileVersion: 3, packages: { a: { version: "1.0.0" } } }, null, 2) + "\n",
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoDir, "pnpm-lock.yaml"),
      "lockfileVersion: '9.0'\npackages:\n  /foo@1.0.0:\n    resolution: {integrity: sha512-xyz}\n",
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoDir, "dist", "bundle.min.js"),
      "function a(){return 1;}a();\n",
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Commit C3: only lockfiles and minified dist"]);
    const postLockOid = gitExec(repoDir, ["rev-parse", "HEAD"]);

    const lockDiffRes = await revProvider.readCommittedDiff(hostDesc, preLockOid, postLockOid);
    assert.strictEqual(lockDiffRes.ok, true);
    if (lockDiffRes.ok) {
      const dietLock = buildContextDietDiff(lockDiffRes.value);
      assert.strictEqual(dietLock.keptFilePaths.length, 0);
      assert.strictEqual(dietLock.omittedFiles.length, 3);
      assert.ok(dietLock.redactedFormattedPayload.includes("[Context Diet Omission Disclosure]"));
      assert.ok(dietLock.redactedFormattedPayload.includes("package-lock.json"));
      assert.ok(dietLock.redactedFormattedPayload.includes("pnpm-lock.yaml"));
      assert.ok(dietLock.redactedFormattedPayload.includes("dist/bundle.min.js"));
      assert.ok(
        dietLock.redactedFormattedPayload.includes("No non-omitted diff hunks remain in this range"),
        "All-omitted diff must explicitly state why no hunks remain"
      );
    }
    console.log("  [PASS] C3: All-lockfile/minified diff explicitly discloses every omitted file.");

    // =========================================================================
    // C4: Sensitive Data Copy Gate & Redaction Counterexamples
    // =========================================================================
    console.log("Running C4: Sensitive Data Copy Gate & Redaction Counterexamples...");
    const preSecretOid = gitExec(repoDir, ["rev-parse", "HEAD"]);
    const rawGithubToken = "ghp_1234567890abcdefghijklmnopqrstuvwx";
    const rawAwsKey = "AKIAIOSFODNN7EXAMPLE";
    const rawDbPass = "SuperSecretDbPass99!";
    const rawAssignedSecret = "my_secret_token_987654";

    fs.writeFileSync(
      path.join(repoDir, ".env.production"),
      `GITHUB_TOKEN=${rawGithubToken}\nAWS_ACCESS_KEY_ID=${rawAwsKey}\n`,
      "utf8"
    );
    fs.writeFileSync(
      path.join(repoDir, "src", "config.py"),
      [
        `DB_URI = "postgresql://admin:${rawDbPass}@db.internal:5432/prod"`,
        `api_key = "${rawAssignedSecret}"`,
        `HEADERS = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload"}`,
        `KEY = """-----BEGIN RSA PRIVATE KEY-----`,
        `MIIEpAIBAAKCAQEA0123456789abcdef`,
        `-----END RSA PRIVATE KEY-----"""`,
        "",
      ].join("\n"),
      "utf8"
    );
    gitExec(repoDir, ["add", "."]);
    gitExec(repoDir, ["commit", "-m", "Commit C4: accidental secrets in diff"]);
    const postSecretOid = gitExec(repoDir, ["rev-parse", "HEAD"]);

    const secretDiffRes = await revProvider.readCommittedDiff(hostDesc, preSecretOid, postSecretOid);
    assert.strictEqual(secretDiffRes.ok, true);
    if (secretDiffRes.ok) {
      const dietSecret = buildContextDietDiff(secretDiffRes.value);
      assert.strictEqual(dietSecret.hasSensitiveData, true);
      assert.strictEqual(dietSecret.requiresUserConfirmationBeforeCopy, true);
      assert.ok(dietSecret.sensitiveFindings.length >= 5, `Expected >=5 sensitive findings, got ${dietSecret.sensitiveFindings.length}`);

      // Counterexample 4a: Unconfirmed unredacted copy MUST be blocked
      const blockedCopy = authorizeClipboardCopy({
        dietResult: dietSecret,
        mode: "unredacted",
      });
      assert.strictEqual(blockedCopy.ok, false, "Unconfirmed unredacted copy must be blocked");

      const blockedExplicitFalse = authorizeClipboardCopy({
        dietResult: dietSecret,
        mode: "unredacted",
        userConfirmedUnredactedCopy: false,
      });
      assert.strictEqual(blockedExplicitFalse.ok, false);

      // Counterexample 4b: Redacted copy succeeds and strips ALL raw secret strings
      const redactedCopy = authorizeClipboardCopy({
        dietResult: dietSecret,
        mode: "redacted",
      });
      assert.strictEqual(redactedCopy.ok, true);
      if (redactedCopy.ok) {
        const text = redactedCopy.value.payloadToCopy;
        assert.strictEqual(text.includes(rawGithubToken), false, "GitHub token leaked in redacted payload!");
        assert.strictEqual(text.includes(rawAwsKey), false, "AWS key leaked in redacted payload!");
        assert.strictEqual(text.includes(rawDbPass), false, "DB password leaked in redacted payload!");
        assert.strictEqual(text.includes(rawAssignedSecret), false, "Assigned api_key leaked in redacted payload!");
        assert.strictEqual(text.includes("MIIEpAIBAAKCAQEA0123456789abcdef"), false, "Private key body leaked in redacted payload!");
        assert.ok(text.includes("[REDACTED:github_token]"));
        assert.ok(text.includes("[REDACTED:aws_access_key]"));
        assert.ok(text.includes("[REDACTED:connection_uri_credentials]"));
        assert.ok(text.includes("[REDACTED:credential_assignment]"));
        assert.ok(text.includes("[REDACTED:private_key_block]"));
      }
    }
    console.log("  [PASS] C4: Unconfirmed unredacted copy blocked; redacted copy stripped all 5 secret classes.");

    // =========================================================================
    // C5: Multi-Byte UTF-8 Budget Truncation Boundary Counterexample
    // =========================================================================
    console.log("Running C5: Multi-Byte UTF-8 Budget Truncation Boundary Counterexample...");
    const preUtf8Oid = gitExec(repoDir, ["rev-parse", "HEAD"]);
    const cjkLines = Array.from(
      { length: 40 },
      (_, idx) => `# 第 ${idx + 1} 行：測試中文多重視窗截斷不會切壞任何 UTF-8 多位元組字元序列 🚀`
    ).join("\n") + "\n";
    fs.writeFileSync(path.join(repoDir, "src", "cjk_heavy.py"), cjkLines, "utf8");
    gitExec(repoDir, ["add", "src/cjk_heavy.py"]);
    gitExec(repoDir, ["commit", "-m", "Commit C5: CJK multibyte lines"]);
    const postUtf8Oid = gitExec(repoDir, ["rev-parse", "HEAD"]);

    const utf8DiffRes = await revProvider.readCommittedDiff(hostDesc, preUtf8Oid, postUtf8Oid);
    assert.strictEqual(utf8DiffRes.ok, true);
    if (utf8DiffRes.ok) {
      // Test tight budgets (512 bytes, 777 bytes, 1025 bytes) that would slice mid-character if byte-sliced naively
      for (const tightBudget of [512, 777, 1025]) {
        const dietTrunc = buildContextDietDiff(utf8DiffRes.value, tightBudget);
        assert.strictEqual(dietTrunc.omittedFiles.length, 1);
        assert.strictEqual(dietTrunc.omittedFiles[0].reason, "budget_truncated");
        assert.ok(dietTrunc.omittedFiles[0].omittedLineCount > 0);
        assert.ok(dietTrunc.omittedFiles[0].omittedByteCount > 0);

        const rawBuf = Buffer.from(dietTrunc.unredactedFormattedPayload, "utf8");
        const strictCheck = decodeStrictUtf8(new Uint8Array(rawBuf));
        assert.strictEqual(strictCheck.ok, true, `Budget ${tightBudget} produced invalid UTF-8`);
        assert.strictEqual(
          dietTrunc.unredactedFormattedPayload.includes("\uFFFD"),
          false,
          `Budget ${tightBudget} produced U+FFFD replacement char`
        );
      }
    }
    console.log("  [PASS] C5: Multi-byte UTF-8 CJK/Emoji diff truncated cleanly on line boundaries with zero corruption.");

    console.log("\n=== ALL PHASE 2 COUNTEREXAMPLES PASSED (5 / 5 groups) ===");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("[Phase 2 Counterexamples FAILED]", err);
  process.exit(1);
});
