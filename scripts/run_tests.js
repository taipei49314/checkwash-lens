#!/usr/bin/env node
/**
 * scripts/run_tests.js
 *
 * Unified, zero-dependency, cross-platform test runner for Checkwash Lens.
 *
 * Suites:
 *   --suite core   Headless cross-platform unit, contract, counterexample, and red-team tests
 *                  (requires only Node.js, Python 3.11+, Git, and `npm run build:bundled`).
 *   --suite prove  Opt-in checkwash-prove v0.1.0 integration & regression suites
 *                  (requires checkwash-prove v0.1.0 via CW_TEST_PROVE_EXE or default path).
 *   --suite e2e    Real VS Code Desktop / Extension Host integration suites
 *                  (requires VS Code Desktop via CW_TEST_VSCODE_EXE / CW_TEST_CODE_EXE).
 *
 * Usage:
 *   node scripts/run_tests.js --suite core
 *   node scripts/run_tests.js --suite prove
 *   node scripts/run_tests.js --suite e2e
 */

"use strict";

const cp = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");

const SUITES = {
  core: [
    { name: "phase0a", script: "dist/test/phase0a_runner.js" },
    { name: "phase0b", script: "dist/test/phase0b_runner.js" },
    { name: "phase1", script: "dist/test/phase1_counterexamples.js" },
    { name: "phase2", script: "dist/test/phase2_counterexamples.js" },
    { name: "phase4", script: "dist/test/phase4_counterexamples.js" },
    { name: "redteam", script: "dist/test/v06_redteam_hardening_runner.js" },
  ],
  prove: [
    { name: "phase3", script: "dist/test/phase3_counterexamples.js" },
    { name: "review-fixes", script: "dist/test/phase1_4_review_fixes_runner.js" },
    { name: "review-10", script: "dist/test/lens_review_10_issues_runner.js" },
    { name: "v02", script: "dist/test/v02_doctor_staged_b08_runner.js" },
  ],
  e2e: [
    { name: "phase5", script: "dist/test/phase5_extension_host_runner.js" },
    { name: "v05", script: "dist/test/v05_ux_cockpit_journey_runner.js" },
    { name: "installed-vsix", script: "dist/test/installed_vsix_real_vscode_runner.js" },
  ],
};

function parseSuiteArg(argv) {
  let suite = "core";
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--suite" && i + 1 < argv.length) {
      suite = argv[++i].trim();
    } else if (a.startsWith("--suite=")) {
      suite = a.slice("--suite=".length).trim();
    } else if (a === "--help" || a === "-h") {
      console.log("Usage: node scripts/run_tests.js --suite <core|prove|e2e>");
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${a}`);
    }
  }
  if (!Object.prototype.hasOwnProperty.call(SUITES, suite)) {
    throw new Error(
      `Unsupported --suite '${suite}' (expected one of: ${Object.keys(SUITES).join(", ")})`
    );
  }
  return suite;
}

function main() {
  const suiteName = parseSuiteArg(process.argv);
  const manifestPath = path.join(ROOT, "bundled", "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    console.error(
      "ERROR: bundled/manifest.json is missing. Run `npm run build:bundled` before running tests."
    );
    process.exit(1);
  }

  const entries = SUITES[suiteName];
  const results = [];
  const suiteStart = Date.now();

  console.log(
    `=== Checkwash Lens Test Runner (suite=${suiteName}, platform=${process.platform}-${process.arch}, count=${entries.length}) ===`
  );

  for (const item of entries) {
    const fullScript = path.join(ROOT, item.script);
    if (!fs.existsSync(fullScript)) {
      console.error(
        `ERROR: Compiled test runner missing: ${item.script}. Run \`npm run compile\` first.`
      );
      process.exit(1);
    }

    console.log(`\n>>> [${item.name}] node ${item.script}`);
    const t0 = Date.now();
    const res = cp.spawnSync(process.execPath, [fullScript], {
      cwd: ROOT,
      stdio: "inherit",
      windowsHide: true,
    });
    const elapsedMs = Date.now() - t0;
    const passed = !res.error && res.status === 0;
    results.push({
      name: item.name,
      passed,
      exitCode: res.status,
      signal: res.signal || null,
      elapsedMs,
    });

    if (!passed) {
      console.error(
        `<<< [FAIL] ${item.name} (exit=${String(res.status)}, signal=${String(res.signal)}, ${elapsedMs}ms)`
      );
      break;
    }
    console.log(`<<< [PASS] ${item.name} (${elapsedMs}ms)`);
  }

  const totalMs = Date.now() - suiteStart;
  const passedCount = results.filter((r) => r.passed).length;
  console.log(
    `\n=== Test Runner Summary (suite=${suiteName}): ${passedCount}/${entries.length} PASS (${totalMs}ms) ===`
  );
  for (const r of results) {
    console.log(`  [${r.passed ? "PASS" : "FAIL"}] ${r.name} (${r.elapsedMs}ms)`);
  }

  if (passedCount !== entries.length) {
    process.exit(1);
  }
}

main();
