/**
 * Generates and records real pinned Phase 0 & review-regression fixtures in `fixtures/phase0/`
 * using the pinned `bundled/checkwash.pyz` (from `bundled/upstream.json`), `bundled/checkwash-broker.exe`
 * (CWBROKER1), and `checkwash-prove.exe` (v0.1.0) against controlled, harmless synthetic Git repositories
 * in os.tmpdir().
 *
 * Strictly adheres to Rev 3 §10.1 & §10.2:
 * - Normal fixtures come from real pinned outputs.
 * - A01 records independent observed invocation receipts (argv, exit, signal, stdout, stderr,
 *   runtime/engine identity & SHA-256s, and full 40-char commit OIDs) for all 4 calls.
 * - Negative/edge cases are explicitly labeled variants derived from real pinned outputs.
 * - Never executes tests of any real user repository.
 * - Automatically sanitizes local machine hostnames and developer user paths in saved receipts.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const FIXTURES_DIR = path.join(ROOT, 'fixtures', 'phase0');
const UPSTREAM = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'bundled', 'upstream.json'), 'utf8')
);
const BUNDLED_PYZ = path.join(ROOT, UPSTREAM.checkwash.relativePath);
const BUNDLED_BROKER = path.join(ROOT, UPSTREAM.windowsBroker.relativePath);
const LOCAL_APP_DATA = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
const PYTHON_EXE = fs.realpathSync.native(
  process.env.CW_TEST_PYTHON_EXE ||
    path.join(LOCAL_APP_DATA, 'Programs', 'Python', 'Python311', 'python.exe')
);
const GIT_EXE = fs.realpathSync.native(
  process.env.CW_TEST_GIT_EXE || 'C:\\Program Files\\Git\\cmd\\git.exe'
);
const PROVE_EXE = fs.realpathSync.native(
  process.env.CW_TEST_PROVE_EXE ||
    path.join(os.homedir(), 'dev', 'checkwash-prove-venv', 'Scripts', 'checkwash-prove.exe')
);

const REAL_TMP_DIR = fs.realpathSync.native(os.tmpdir());
const SANITIZED_HOSTNAME = process.platform === 'win32' ? 'WIN11-VERIFY-HOST' : 'LINUX-VERIFY-HOST';
const SANITIZED_PYTHON_EXE = 'C:\\Python311\\python.exe';
const SANITIZED_PROVE_EXE = 'C:\\tools\\checkwash-prove-venv\\Scripts\\checkwash-prove.exe';
const SANITIZED_ROOT = 'C:\\workspace\\checkwash-lens';
const SANITIZED_TMP_DIR = 'C:\\Temp';

function sanitizeRecordedPath(val) {
  if (typeof val !== 'string') return val;
  let out = val;
  const replacements = [
    [PYTHON_EXE, SANITIZED_PYTHON_EXE],
    [PROVE_EXE, SANITIZED_PROVE_EXE],
    [ROOT, SANITIZED_ROOT],
    [REAL_TMP_DIR, SANITIZED_TMP_DIR],
    [os.tmpdir(), SANITIZED_TMP_DIR]
  ];
  for (const [src, dst] of replacements) {
    if (src && out.toLowerCase().includes(src.toLowerCase())) {
      const escaped = src.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      out = out.replace(new RegExp(escaped, 'gi'), dst);
    }
  }
  return out;
}

function sanitizeArgv(argv) {
  return Array.isArray(argv) ? argv.map(sanitizeRecordedPath) : argv;
}

function sanitizeJsonDeep(val) {
  if (typeof val === 'string') return sanitizeRecordedPath(val);
  if (Array.isArray(val)) return val.map(sanitizeJsonDeep);
  if (val && typeof val === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      out[k] = sanitizeJsonDeep(v);
    }
    return out;
  }
  return val;
}

function sanitizeJsonText(raw) {
  if (!raw || !raw.trim()) return raw;
  try {
    return JSON.stringify(sanitizeJsonDeep(JSON.parse(raw)), null, 2) + '\n';
  } catch {
    return sanitizeRecordedPath(raw);
  }
}

function sha256Buffer(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function sha256String(str) {
  return sha256Buffer(Buffer.from(str, 'utf8'));
}

function sha256File(filePath) {
  return sha256Buffer(fs.readFileSync(filePath));
}

function runGit(repo, args) {
  return execFileSync(GIT_EXE, ['-C', repo, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  }).trim();
}

function initSynthRepo(repoPath) {
  fs.mkdirSync(repoPath, { recursive: true });
  runGit(repoPath, ['init']);
  runGit(repoPath, ['config', 'user.name', 'Phase0 Fixture Generator']);
  runGit(repoPath, ['config', 'user.email', 'phase0@example.local']);
}

function runCheckwashObserved(emptyCwd, repo, baseOid, headOid, format) {
  const rangeSpec = `${baseOid}..${headOid}`;
  const args = ['-I', '-S', '-B', BUNDLED_PYZ, '--repo', repo, '--format', format, rangeSpec];
  const sysRoot = process.env.SystemRoot || 'C:\\Windows';
  const env = {
    SystemRoot: sysRoot,
    WINDIR: sysRoot,
    COMSPEC: path.win32.join(sysRoot, 'System32', 'cmd.exe'),
    PATHEXT: '.COM;.EXE;.BAT;.CMD',
    TEMP: os.tmpdir(),
    TMP: os.tmpdir(),
    HOME: emptyCwd,
    USERPROFILE: emptyCwd,
    PATH: `${path.dirname(GIT_EXE)};${path.win32.join(sysRoot, 'System32')}`,
    PYTHONUTF8: '1',
    PYTHONIOENCODING: 'utf-8',
    PYTHONDONTWRITEBYTECODE: '1',
    PYTHONNOUSERSITE: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: 'NUL',
    NoDefaultCurrentDirectoryInExePath: '1'
  };
  const startedAt = new Date().toISOString();
  const res = spawnSync(PYTHON_EXE, args, {
    cwd: emptyCwd,
    env,
    encoding: 'utf8'
  });
  const finishedAt = new Date().toISOString();
  const stdout = typeof res.stdout === 'string' ? res.stdout : '';
  const stderr = typeof res.stderr === 'string' ? res.stderr : '';
  return {
    startedAt,
    finishedAt,
    argv: [PYTHON_EXE, ...args],
    cwd: emptyCwd,
    repositoryRoot: repo,
    rawRangeSpec: rangeSpec,
    effectiveBaseOid: baseOid,
    effectiveHeadOid: headOid,
    format,
    exitCode: res.status,
    signal: res.signal || null,
    stdout,
    stderr,
    stdoutBytes: Buffer.byteLength(stdout, 'utf8'),
    stderrBytes: Buffer.byteLength(stderr, 'utf8'),
    stdoutSha256: sha256String(stdout),
    stderrSha256: sha256String(stderr)
  };
}

function runProveObserved(emptyCwd, repo, extraArgs) {
  const args = ['--repo', repo, '--python', PYTHON_EXE, '--format', 'json', ...extraArgs];
  const sysRoot = process.env.SystemRoot || 'C:\\Windows';
  const env = {
    SystemRoot: sysRoot,
    WINDIR: sysRoot,
    TEMP: os.tmpdir(),
    TMP: os.tmpdir(),
    PATH: `${path.dirname(GIT_EXE)};${path.dirname(PYTHON_EXE)};${path.win32.join(sysRoot, 'System32')}`,
    PYTHONUTF8: '1',
    PYTHONIOENCODING: 'utf-8',
    GIT_TERMINAL_PROMPT: '0'
  };
  const res = spawnSync(PROVE_EXE, args, {
    cwd: emptyCwd,
    env,
    encoding: 'utf8'
  });
  return {
    command: sanitizeArgv([PROVE_EXE, ...args]),
    exitCode: res.status,
    signal: res.signal || null,
    stdout: sanitizeJsonText(res.stdout || ''),
    stderr: sanitizeRecordedPath(res.stderr || '')
  };
}

function main() {
  fs.mkdirSync(FIXTURES_DIR, { recursive: true });
  const tmpBase = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), 'cw-phase0-synth-'))
  );
  const emptyCwd = path.join(tmpBase, 'empty-cwd');
  fs.mkdirSync(emptyCwd, { recursive: true });

  const pyzHash = sha256File(BUNDLED_PYZ);
  const brokerHash = sha256File(BUNDLED_BROKER);
  const pythonHash = sha256File(PYTHON_EXE);
  const gitHash = sha256File(GIT_EXE);
  const proveHash = sha256File(PROVE_EXE);

  const pyVersion = execFileSync(PYTHON_EXE, ['-I', '-S', '-B', '--version'], { encoding: 'utf8' }).trim();
  const gitVersion = execFileSync(GIT_EXE, ['--version'], { encoding: 'utf8' }).trim();
  const proveVersion = execFileSync(PROVE_EXE, ['--version'], { encoding: 'utf8' }).trim();

  // =========================================================================
  // 1. Synthetic Repo 1: Pass + Block + Docs-only + No-Mutants + Syntax-Error
  // =========================================================================
  const repo1 = path.join(tmpBase, 'synth-repo-1');
  fs.mkdirSync(path.join(repo1, 'src'), { recursive: true });
  fs.mkdirSync(path.join(repo1, 'tests'), { recursive: true });
  initSynthRepo(repo1);

  fs.writeFileSync(
    path.join(repo1, 'src', 'calc.py'),
    [
      'def compute_discount(price: int, rate: int) -> int:',
      '    if price < 0:',
      '        raise ValueError("negative price")',
      '    if rate <= 0:',
      '        return price',
      '    return price - (price * rate) // 100',
      ''
    ].join('\n'),
    'utf8'
  );
  fs.writeFileSync(
    path.join(repo1, 'tests', 'test_calc.py'),
    [
      'import pytest',
      'from src.calc import compute_discount',
      '',
      'def test_discount_normal():',
      '    assert compute_discount(100, 20) == 80',
      '    assert compute_discount(200, 0) == 200',
      '',
      'def test_discount_negative_raises():',
      '    with pytest.raises(ValueError):',
      '        compute_discount(-10, 10)',
      ''
    ].join('\n'),
    'utf8'
  );
  runGit(repo1, ['add', '.']);
  runGit(repo1, ['commit', '-m', 'base: initial calc and tests']);
  const c1Base = runGit(repo1, ['rev-parse', 'HEAD']);

  // Commit 2 (Pass): adds stronger test assertion
  fs.writeFileSync(
    path.join(repo1, 'tests', 'test_calc.py'),
    [
      'import pytest',
      'from src.calc import compute_discount',
      '',
      'def test_discount_normal():',
      '    assert compute_discount(100, 20) == 80',
      '    assert compute_discount(200, 0) == 200',
      '    assert compute_discount(50, 10) == 45',
      '',
      'def test_discount_negative_raises():',
      '    with pytest.raises(ValueError):',
      '        compute_discount(-10, 10)',
      ''
    ].join('\n'),
    'utf8'
  );
  runGit(repo1, ['add', '.']);
  runGit(repo1, ['commit', '-m', 'pass: add extra assertion']);
  const c2Pass = runGit(repo1, ['rev-parse', 'HEAD']);

  // Commit 3 (Block + Protection Loss): weakens test by skipping / tautology
  fs.writeFileSync(
    path.join(repo1, 'tests', 'test_calc.py'),
    [
      'import pytest',
      'from src.calc import compute_discount',
      '',
      'def test_discount_normal():',
      '    compute_discount(100, 20)',
      '    assert True',
      '',
      '@pytest.mark.skip(reason="temporarily disabled")',
      'def test_discount_negative_raises():',
      '    with pytest.raises(ValueError):',
      '        compute_discount(-10, 10)',
      ''
    ].join('\n'),
    'utf8'
  );
  runGit(repo1, ['add', '.']);
  runGit(repo1, ['commit', '-m', 'block: weaken assertions and skip negative test']);
  const c3Block = runGit(repo1, ['rev-parse', 'HEAD']);

  // Commit 4 (Docs only - Nothing to compare for Prove)
  fs.writeFileSync(path.join(repo1, 'README.md'), '# Synthetic Repo\n', 'utf8');
  runGit(repo1, ['add', 'README.md']);
  runGit(repo1, ['commit', '-m', 'docs: add readme only']);
  const c4Docs = runGit(repo1, ['rev-parse', 'HEAD']);

  // Capture real Checkwash PASS (c1Base..c2Pass) & BLOCK (c2Pass..c3Block)
  const cwPassJson = runCheckwashObserved(emptyCwd, repo1, c1Base, c2Pass, 'json');
  const cwPassSarif = runCheckwashObserved(emptyCwd, repo1, c1Base, c2Pass, 'sarif');
  const cwBlockJson = runCheckwashObserved(emptyCwd, repo1, c2Pass, c3Block, 'json');
  const cwBlockSarif = runCheckwashObserved(emptyCwd, repo1, c2Pass, c3Block, 'sarif');

  fs.writeFileSync(path.join(FIXTURES_DIR, 'a01-pass.findings.json'), cwPassJson.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a01-pass.sarif.json'), cwPassSarif.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a01-block.findings.json'), cwBlockJson.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a01-block.sarif.json'), cwBlockSarif.stdout, 'utf8');

  const runtimeEngineIdentity = {
    hostname: SANITIZED_HOSTNAME,
    evidenceTag: process.env.CW_EVIDENCE_TAG || 'PINNED_PRODUCER_FIXTURE',
    os: `${os.type()} ${os.release()} (${os.arch()})`,
    checkwashVersion: UPSTREAM.checkwash.version,
    checkwashPyzPath: UPSTREAM.checkwash.relativePath,
    checkwashPyzBytes: fs.statSync(BUNDLED_PYZ).size,
    checkwashPyzSha256: pyzHash,
    checkwashBuildCommit: UPSTREAM.checkwash.artifactBuildSourceCommit,
    brokerPath: UPSTREAM.windowsBroker.relativePath,
    brokerBytes: fs.statSync(BUNDLED_BROKER).size,
    brokerSha256: brokerHash,
    pythonExecutable: sanitizeRecordedPath(PYTHON_EXE),
    pythonVersion: pyVersion,
    pythonSha256: pythonHash,
    gitExecutable: sanitizeRecordedPath(GIT_EXE),
    gitVersion: gitVersion,
    gitSha256: gitHash
  };

  function stripStdoutForReceipt(obs, stdoutFile) {
    return {
      startedAt: obs.startedAt,
      finishedAt: obs.finishedAt,
      argv: sanitizeArgv(obs.argv),
      cwd: sanitizeRecordedPath(obs.cwd),
      repositoryRoot: sanitizeRecordedPath(obs.repositoryRoot),
      rawRangeSpec: obs.rawRangeSpec,
      effectiveBaseOid: obs.effectiveBaseOid,
      effectiveHeadOid: obs.effectiveHeadOid,
      format: obs.format,
      exitCode: obs.exitCode,
      signal: obs.signal,
      stdoutFile,
      stdoutBytes: obs.stdoutBytes,
      stdoutSha256: obs.stdoutSha256,
      stderrText: obs.stderr,
      stderrBytes: obs.stderrBytes,
      stderrSha256: obs.stderrSha256
    };
  }

  const a01Receipts = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    runtimeEngineIdentity,
    fixtureCommits: {
      c1Base,
      c2Pass,
      c3Block,
      c4Docs
    },
    invocations: {
      passJson: stripStdoutForReceipt(cwPassJson, 'a01-pass.findings.json'),
      passSarif: stripStdoutForReceipt(cwPassSarif, 'a01-pass.sarif.json'),
      blockJson: stripStdoutForReceipt(cwBlockJson, 'a01-block.findings.json'),
      blockSarif: stripStdoutForReceipt(cwBlockSarif, 'a01-block.sarif.json')
    }
  };
  fs.writeFileSync(
    path.join(FIXTURES_DIR, 'a01-invocation-receipts.json'),
    JSON.stringify(a01Receipts, null, 2),
    'utf8'
  );

  // =========================================================================
  // 2. Synthetic Repo 2: Empty-title JavaScript test (`unit: ""`) for Issue #5
  // =========================================================================
  const repoJs = path.join(tmpBase, 'synth-repo-js-empty-unit');
  fs.mkdirSync(path.join(repoJs, 'src'), { recursive: true });
  fs.mkdirSync(path.join(repoJs, 'tests'), { recursive: true });
  initSynthRepo(repoJs);

  fs.writeFileSync(
    path.join(repoJs, 'src', 'math.js'),
    'export function doubleVal(x) { return x * 2; }\n',
    'utf8'
  );
  fs.writeFileSync(
    path.join(repoJs, 'tests', 'math.test.js'),
    [
      'import { doubleVal } from "../src/math.js";',
      '',
      'describe("math suite", () => {',
      '  it("", () => {',
      '    expect(doubleVal(21)).toBe(42);',
      '    expect(doubleVal(0)).toBe(0);',
      '  });',
      '});',
      ''
    ].join('\n'),
    'utf8'
  );
  runGit(repoJs, ['add', '.']);
  runGit(repoJs, ['commit', '-m', 'base: js empty-title test']);
  const jsBase = runGit(repoJs, ['rev-parse', 'HEAD']);

  fs.writeFileSync(
    path.join(repoJs, 'tests', 'math.test.js'),
    [
      'import { doubleVal } from "../src/math.js";',
      '',
      'describe("math suite", () => {',
      '  it("", () => {',
      '    doubleVal(21);',
      '    expect(true).toBe(true);',
      '  });',
      '});',
      ''
    ].join('\n'),
    'utf8'
  );
  runGit(repoJs, ['add', '.']);
  runGit(repoJs, ['commit', '-m', 'head: weaken empty-title js test']);
  const jsHead = runGit(repoJs, ['rev-parse', 'HEAD']);

  const cwJsJson = runCheckwashObserved(emptyCwd, repoJs, jsBase, jsHead, 'json');
  const cwJsSarif = runCheckwashObserved(emptyCwd, repoJs, jsBase, jsHead, 'sarif');
  const parsedJsJson = JSON.parse(cwJsJson.stdout);
  if (
    parsedJsJson.verdict !== 'block' ||
    !Array.isArray(parsedJsJson.findings) ||
    !parsedJsJson.findings.some((f) => f.unit === '')
  ) {
    throw new Error(
      `Expected empty-title JS fixture to produce verdict=block with unit="", got: ${cwJsJson.stdout}`
    );
  }
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a02-empty-unit-js.findings.json'), cwJsJson.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a02-empty-unit-js.sarif.json'), cwJsSarif.stdout, 'utf8');
  fs.writeFileSync(
    path.join(FIXTURES_DIR, 'a02-empty-unit-js-receipt.json'),
    JSON.stringify(
      {
        runtimeEngineIdentity,
        jsBase,
        jsHead,
        jsonInvocation: stripStdoutForReceipt(cwJsJson, 'a02-empty-unit-js.findings.json'),
        sarifInvocation: stripStdoutForReceipt(cwJsSarif, 'a02-empty-unit-js.sarif.json')
      },
      null,
      2
    ),
    'utf8'
  );

  // =========================================================================
  // 3. Real Prove v0.1.0 Producer Outputs (Issues #6, #7, #8 & A11, A12)
  // =========================================================================
  const proveZeroLoss = runProveObserved(emptyCwd, repo1, [
    '--workers', '1',
    '--max-mutants', '10',
    '--timeout', '30',
    '--suite-timeout', '120',
    `${c1Base}..${c2Pass}`
  ]);
  const proveWithLoss = runProveObserved(emptyCwd, repo1, [
    '--workers', '1',
    '--max-mutants', '10',
    '--timeout', '30',
    '--suite-timeout', '120',
    `${c2Pass}..${c3Block}`
  ]);
  const proveList = runProveObserved(emptyCwd, repo1, [
    '--list',
    '--workers', '1',
    '--max-mutants', '5',
    '--timeout', '30',
    '--suite-timeout', '120',
    `${c2Pass}..${c3Block}`
  ]);
  const proveNothing = runProveObserved(emptyCwd, repo1, [
    '--workers', '1',
    '--max-mutants', '10',
    '--timeout', '30',
    '--suite-timeout', '120',
    `${c3Block}..${c4Docs}`
  ]);
  const proveListNothing = runProveObserved(emptyCwd, repo1, [
    '--list',
    '--workers', '1',
    '--max-mutants', '10',
    '--timeout', '30',
    '--suite-timeout', '120',
    `${c3Block}..${c4Docs}`
  ]);
  const proveCapZero = runProveObserved(emptyCwd, repo1, [
    '--workers', '1',
    '--max-mutants', '0',
    '--timeout', '30',
    '--suite-timeout', '120',
    `${c2Pass}..${c3Block}`
  ]);

  fs.writeFileSync(path.join(FIXTURES_DIR, 'a11-prove-zero-loss.json'), proveZeroLoss.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a11-prove-protection-loss.json'), proveWithLoss.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a12-prove-list.json'), proveList.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a12-prove-nothing.json'), proveNothing.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'prove-real-list-nothing.json'), proveListNothing.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a12-prove-cap-zero.json'), proveCapZero.stdout, 'utf8');

  // 3b. Synthetic Repo 3: Real `needs_clarification` + `protection_losses` + `unconfirmed_losses`
  const repoClarify = path.join(tmpBase, 'synth-repo-prove-clarify');
  fs.mkdirSync(path.join(repoClarify, 'src'), { recursive: true });
  fs.mkdirSync(path.join(repoClarify, 'tests'), { recursive: true });
  initSynthRepo(repoClarify);

  fs.writeFileSync(
    path.join(repoClarify, 'src', 'billing.py'),
    [
      'def calc_total(subtotal: int, tax: int) -> int:',
      '    if subtotal == 10 and tax == 5:',
      '        return 999',
      '    if subtotal < 0:',
      '        raise ValueError("negative subtotal")',
      '    if tax < -100:',
      '        raise ValueError("negative tax")',
      '    return subtotal + tax',
      ''
    ].join('\n'),
    'utf8'
  );
  fs.writeFileSync(
    path.join(repoClarify, 'tests', 'test_billing.py'),
    [
      'import pytest',
      'from src.billing import calc_total',
      '',
      'def test_legacy_promo_behavior():',
      '    assert calc_total(10, 5) == 999',
      '',
      'def test_negative_subtotal_raises():',
      '    with pytest.raises(ValueError):',
      '        calc_total(-1, 5)',
      '',
      'def test_flaky_negative_tax():',
      '    try:',
      '        calc_total(10, -200)',
      '    except ValueError:',
      '        pass',
      '    parts = __file__.replace("\\\\", "/").split("/")',
      '    if "w0" in parts:',
      '        with pytest.raises(ValueError):',
      '            calc_total(10, -200)',
      ''
    ].join('\n'),
    'utf8'
  );
  runGit(repoClarify, ['add', '.']);
  runGit(repoClarify, ['commit', '-m', 'base: billing with promo, subtotal check, and flaky tax check']);
  const clBase = runGit(repoClarify, ['rev-parse', 'HEAD']);

  fs.writeFileSync(
    path.join(repoClarify, 'src', 'billing.py'),
    [
      'def calc_total(subtotal: int, tax: int) -> int:',
      '    if subtotal < 0:',
      '        raise ValueError("negative subtotal")',
      '    if tax < -100:',
      '        raise ValueError("negative tax")',
      '    return subtotal + tax',
      ''
    ].join('\n'),
    'utf8'
  );
  fs.writeFileSync(
    path.join(repoClarify, 'tests', 'test_billing.py'),
    [
      'import pytest',
      'from src.billing import calc_total',
      '',
      'def test_legacy_promo_behavior():',
      '    assert calc_total(10, 5) == 15',
      '',
      '@pytest.mark.skip(reason="dropped subtotal check")',
      'def test_negative_subtotal_raises():',
      '    with pytest.raises(ValueError):',
      '        calc_total(-1, 5)',
      '',
      '@pytest.mark.skip(reason="dropped tax check")',
      'def test_flaky_negative_tax():',
      '    pass',
      ''
    ].join('\n'),
    'utf8'
  );
  runGit(repoClarify, ['add', '.']);
  runGit(repoClarify, ['commit', '-m', 'head: remove promo and skip negative tests']);
  const clHead = runGit(repoClarify, ['rev-parse', 'HEAD']);

  const proveRealClarifyCoexisting = runProveObserved(emptyCwd, repoClarify, [
    '--workers', '1',
    '--max-mutants', '25',
    '--timeout', '30',
    '--suite-timeout', '120',
    `${clBase}..${clHead}`
  ]);
  const parsedClarifyCoexisting = JSON.parse(proveRealClarifyCoexisting.stdout);
  if (
    parsedClarifyCoexisting.needs_clarification.length === 0 ||
    parsedClarifyCoexisting.protection_losses.length === 0 ||
    parsedClarifyCoexisting.unconfirmed_losses.length === 0
  ) {
    throw new Error(
      `Expected real Prove clarification+losses+unconfirmed coexistence, got: ${proveRealClarifyCoexisting.stdout}`
    );
  }
  fs.writeFileSync(
    path.join(FIXTURES_DIR, 'prove-real-clarification-coexisting.json'),
    proveRealClarifyCoexisting.stdout,
    'utf8'
  );

  // 3c. Synthetic Repo 4: Real early-return pairs (`--list` vs full) for Issue #6
  //     - no_mutants (test touches no product line)
  //     - clean_run_failed (all old tests fail on new code)
  //     - collection_failed (syntax error in changed test file)
  const repoEarly = path.join(tmpBase, 'synth-repo-prove-early');
  fs.mkdirSync(path.join(repoEarly, 'src'), { recursive: true });
  fs.mkdirSync(path.join(repoEarly, 'tests'), { recursive: true });
  initSynthRepo(repoEarly);

  fs.writeFileSync(
    path.join(repoEarly, 'src', 'mod.py'),
    'def greet(name: str) -> str:\n    return "hi " + name\n',
    'utf8'
  );
  fs.writeFileSync(
    path.join(repoEarly, 'tests', 'test_mod.py'),
    'def test_pure_arithmetic():\n    assert 2 + 2 == 4\n',
    'utf8'
  );
  runGit(repoEarly, ['add', '.']);
  runGit(repoEarly, ['commit', '-m', 'base: test does not execute src/mod.py']);
  const e1Base = runGit(repoEarly, ['rev-parse', 'HEAD']);

  // Commit e2NoMutants: test still executes 0 lines of src/mod.py
  fs.writeFileSync(
    path.join(repoEarly, 'tests', 'test_mod.py'),
    'def test_pure_arithmetic():\n    assert 3 + 3 == 6\n',
    'utf8'
  );
  runGit(repoEarly, ['add', '.']);
  runGit(repoEarly, ['commit', '-m', 'no_mutants: changed test executes no product code']);
  const e2NoMutants = runGit(repoEarly, ['rev-parse', 'HEAD']);

  // Commit e3CleanFailBase & e4CleanFailHead: old test imports removed symbol / fails clean run
  fs.writeFileSync(
    path.join(repoEarly, 'src', 'mod.py'),
    'def greet(name: str) -> str:\n    return "hello " + name\n',
    'utf8'
  );
  fs.writeFileSync(
    path.join(repoEarly, 'tests', 'test_mod.py'),
    'from src.mod import greet\n\ndef test_greet():\n    assert greet("a") == "hello a"\n',
    'utf8'
  );
  runGit(repoEarly, ['add', '.']);
  runGit(repoEarly, ['commit', '-m', 'clean_fail_base: working greet']);
  const e3CleanFailBase = runGit(repoEarly, ['rev-parse', 'HEAD']);

  fs.writeFileSync(
    path.join(repoEarly, 'src', 'mod.py'),
    'def greet(name: str) -> str:\n    return "changed " + name\n',
    'utf8'
  );
  fs.writeFileSync(
    path.join(repoEarly, 'tests', 'test_mod.py'),
    'from src.mod import greet\n\ndef test_greet():\n    assert greet("a") == "changed a"\n',
    'utf8'
  );
  runGit(repoEarly, ['add', '.']);
  runGit(repoEarly, ['commit', '-m', 'clean_fail_head: only old test fails on new code']);
  const e4CleanFailHead = runGit(repoEarly, ['rev-parse', 'HEAD']);

  // Commit e5CollectionFailBase & e6CollectionFailHead: old test module-level import fails pytest --collect-only on head
  fs.writeFileSync(
    path.join(repoEarly, 'src', 'mod.py'),
    'def removed_at_head() -> int:\n    return 1\n\ndef greet(name: str) -> str:\n    return "changed " + name\n',
    'utf8'
  );
  fs.writeFileSync(
    path.join(repoEarly, 'tests', 'test_mod.py'),
    'from src.mod import removed_at_head, greet\n\ndef test_greet():\n    assert removed_at_head() == 1\n    assert greet("a") == "changed a"\n',
    'utf8'
  );
  runGit(repoEarly, ['add', '.']);
  runGit(repoEarly, ['commit', '-m', 'collection_fail_base: imports removed_at_head at module level']);
  const e5CollectionFailBase = runGit(repoEarly, ['rev-parse', 'HEAD']);

  fs.writeFileSync(
    path.join(repoEarly, 'src', 'mod.py'),
    'def greet(name: str) -> str:\n    return "changed " + name\n',
    'utf8'
  );
  fs.writeFileSync(
    path.join(repoEarly, 'tests', 'test_mod.py'),
    'from src.mod import greet\n\ndef test_greet():\n    assert greet("a") == "changed a"\n',
    'utf8'
  );
  runGit(repoEarly, ['add', '.']);
  runGit(repoEarly, ['commit', '-m', 'collection_fail_head: remove symbol imported by old test module']);
  const e6CollectionFailHead = runGit(repoEarly, ['rev-parse', 'HEAD']);

  const proveListNoMutants = runProveObserved(emptyCwd, repoEarly, [
    '--list', '--workers', '1', '--max-mutants', '10', `${e1Base}..${e2NoMutants}`
  ]);
  const proveFullNoMutants = runProveObserved(emptyCwd, repoEarly, [
    '--workers', '1', '--max-mutants', '10', `${e1Base}..${e2NoMutants}`
  ]);
  const proveListCleanFail = runProveObserved(emptyCwd, repoEarly, [
    '--list', '--workers', '1', '--max-mutants', '10', `${e3CleanFailBase}..${e4CleanFailHead}`
  ]);
  const proveFullCleanFail = runProveObserved(emptyCwd, repoEarly, [
    '--workers', '1', '--max-mutants', '10', `${e3CleanFailBase}..${e4CleanFailHead}`
  ]);
  const proveListCollectionFail = runProveObserved(emptyCwd, repoEarly, [
    '--list', '--workers', '1', '--max-mutants', '10', `${e5CollectionFailBase}..${e6CollectionFailHead}`
  ]);
  const proveFullCollectionFail = runProveObserved(emptyCwd, repoEarly, [
    '--workers', '1', '--max-mutants', '10', `${e5CollectionFailBase}..${e6CollectionFailHead}`
  ]);

  fs.writeFileSync(path.join(FIXTURES_DIR, 'prove-real-list-no-mutants.json'), proveListNoMutants.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'prove-real-full-no-mutants.json'), proveFullNoMutants.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'prove-real-list-clean-fail.json'), proveListCleanFail.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'prove-real-full-clean-fail.json'), proveFullCleanFail.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'prove-real-list-collection-fail.json'), proveListCollectionFail.stdout, 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'prove-real-full-collection-fail.json'), proveFullCollectionFail.stdout, 'utf8');

  // 3d. Real undecided rows producer output: unchanged sibling test breaks whole-suite baseline()
  const repoUndecided = path.join(tmpBase, 'synth-repo-prove-undecided');
  fs.mkdirSync(path.join(repoUndecided, 'src'), { recursive: true });
  fs.mkdirSync(path.join(repoUndecided, 'tests'), { recursive: true });
  initSynthRepo(repoUndecided);

  fs.writeFileSync(
    path.join(repoUndecided, 'src', 'guard.py'),
    'def check_positive(v: int) -> bool:\n    if v <= 0:\n        raise ValueError("non-positive")\n    return True\n',
    'utf8'
  );
  fs.writeFileSync(
    path.join(repoUndecided, 'tests', 'test_guard.py'),
    'import pytest\nfrom src.guard import check_positive\n\ndef test_guard():\n    assert check_positive(5) is True\n    with pytest.raises(ValueError):\n        check_positive(0)\n',
    'utf8'
  );
  // Unchanged broken sibling test file so whole-suite `pytest` (baseline) exits 3 (internal error -> not usable)
  // while `pytest tests/test_guard.py` never imports `test_unrelated_broken.py`!
  fs.writeFileSync(
    path.join(repoUndecided, 'tests', 'test_unrelated_broken.py'),
    'import os\nos._exit(3)\n',
    'utf8'
  );
  runGit(repoUndecided, ['add', '.']);
  runGit(repoUndecided, ['commit', '-m', 'base: guard test plus broken unrelated module']);
  const uBase = runGit(repoUndecided, ['rev-parse', 'HEAD']);

  fs.writeFileSync(
    path.join(repoUndecided, 'tests', 'test_guard.py'),
    'from src.guard import check_positive\n\ndef test_guard():\n    assert check_positive(5) is True\n',
    'utf8'
  );
  runGit(repoUndecided, ['add', 'tests/test_guard.py']);
  runGit(repoUndecided, ['commit', '-m', 'head: drop non-positive assertion']);
  const uHead = runGit(repoUndecided, ['rev-parse', 'HEAD']);

  const proveRealUndecided = runProveObserved(emptyCwd, repoUndecided, [
    '--workers', '1', '--max-mutants', '10', `${uBase}..${uHead}`
  ]);
  const parsedRealUndecided = JSON.parse(proveRealUndecided.stdout);
  const realUndecidedRows = (parsedRealUndecided.mutation.rows || []).filter(
    (r) => r.category === 'undecided'
  );
  if (realUndecidedRows.length === 0) {
    throw new Error(`Expected real undecided rows in proveRealUndecided, got: ${proveRealUndecided.stdout}`);
  }
  fs.writeFileSync(path.join(FIXTURES_DIR, 'prove-real-undecided.json'), proveRealUndecided.stdout, 'utf8');

  // =========================================================================
  // 4. Labeled Deterministic Variants for A02-A14
  // =========================================================================
  const baseBlockFindingsObj = JSON.parse(cwBlockJson.stdout);
  const baseBlockSarifObj = JSON.parse(cwBlockSarif.stdout);

  // A02 variants:
  const a02Optional = JSON.parse(cwBlockJson.stdout);
  a02Optional.future_top_level_field = { experimental: true };
  if (a02Optional.findings.length > 0) {
    a02Optional.findings[0].rule = 'CW999_FUTURE_RULE';
    a02Optional.findings[0].escalators = ['FUTURE_ESCALATOR_V3'];
    a02Optional.findings[0].deescalators = ['FUTURE_DEESCALATOR_V3'];
    a02Optional.findings[0].extra_finding_meta = 'tolerated';
  }
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a02-unknown-optional.findings.json'), JSON.stringify(a02Optional, null, 2), 'utf8');

  const a02MissingKey = JSON.parse(cwPassJson.stdout);
  delete a02MissingKey.verdict;
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a02-missing-verdict.findings.json'), JSON.stringify(a02MissingKey, null, 2), 'utf8');

  const a02BadVersion = JSON.parse(cwPassJson.stdout);
  a02BadVersion.checkwash_findings_version = 3;
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a02-unsupported-version.findings.json'), JSON.stringify(a02BadVersion, null, 2), 'utf8');

  // A03 variants:
  const a03ExtraSarif = JSON.parse(cwBlockSarif.stdout);
  a03ExtraSarif.runs[0].results.push(JSON.parse(JSON.stringify(a03ExtraSarif.runs[0].results[0])));
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a03-extra-sarif-result.sarif.json'), JSON.stringify(a03ExtraSarif, null, 2), 'utf8');

  const a03WrongFp = JSON.parse(cwBlockSarif.stdout);
  const fpKey = Object.keys(a03WrongFp.runs[0].results[0].partialFingerprints)[0];
  a03WrongFp.runs[0].results[0].partialFingerprints[fpKey] = 'deadbeef00000000';
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a03-wrong-fingerprint.sarif.json'), JSON.stringify(a03WrongFp, null, 2), 'utf8');

  const a03DupJson = JSON.parse(cwBlockJson.stdout);
  const a03DupSarif = JSON.parse(cwBlockSarif.stdout);
  a03DupJson.findings = [a03DupJson.findings[0], JSON.parse(JSON.stringify(a03DupJson.findings[0]))];
  a03DupSarif.runs[0].results = [a03DupSarif.runs[0].results[0], JSON.parse(JSON.stringify(a03DupSarif.runs[0].results[0]))];
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a03-dup.findings.json'), JSON.stringify(a03DupJson, null, 2), 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a03-dup.sarif.json'), JSON.stringify(a03DupSarif, null, 2), 'utf8');

  // A04 variant:
  const a04Json = JSON.parse(cwBlockJson.stdout);
  const a04Sarif = JSON.parse(cwBlockSarif.stdout);
  const allowlistedCopy = JSON.parse(JSON.stringify(a04Json.findings[0]));
  allowlistedCopy.allowlisted = true;
  allowlistedCopy.exemption_reason = 'Ticket-123 approved temporary exemption';
  a04Json.findings.unshift(allowlistedCopy);
  a04Sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = 'tests/conftest.py';
  a04Sarif.runs[0].results[0].locations[0].physicalLocation.region = { startLine: 14 };
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a04-allowlisted-conftest.findings.json'), JSON.stringify(a04Json, null, 2), 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a04-allowlisted-conftest.sarif.json'), JSON.stringify(a04Sarif, null, 2), 'utf8');

  // A05 variant:
  const a05Json = JSON.parse(cwBlockJson.stdout);
  const a05Sarif = JSON.parse(cwBlockSarif.stdout);
  a05Json.findings = a05Json.findings.slice(0, 2);
  a05Sarif.runs[0].results = a05Sarif.runs[0].results.slice(0, 2);
  delete a05Sarif.runs[0].results[0].locations[0].physicalLocation.region;
  a05Sarif.runs[0].results[0].properties = {
    'checkwash.evidenceSide': 'base',
    'checkwash.evidenceText': 'deleted test block'
  };
  delete a05Sarif.runs[0].results[1].locations[0].physicalLocation.region;
  delete a05Sarif.runs[0].results[1].properties;
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a05-noregion.findings.json'), JSON.stringify(a05Json, null, 2), 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a05-noregion.sarif.json'), JSON.stringify(a05Sarif, null, 2), 'utf8');

  // A07 variant:
  const a07PassWithGapsJson = JSON.parse(cwPassJson.stdout);
  a07PassWithGapsJson.unread = [{ path: 'docs/huge.bin', side: 'head', size: 1500000, limit: 1000000 }];
  a07PassWithGapsJson.skipped_files = ['tests/bad_syntax.py'];
  a07PassWithGapsJson.config_errors = ['pyproject.toml: invalid fail_on value'];
  const a07PassWithGapsSarif = JSON.parse(cwPassSarif.stdout);
  a07PassWithGapsSarif.runs[0].invocations = [
    {
      executionSuccessful: true,
      toolExecutionNotifications: [
        {
          descriptor: { id: 'checkwash/unread-side' },
          level: 'warning',
          message: { text: 'docs/huge.bin (head) exceeds limit' }
        }
      ]
    }
  ];
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a07-pass-gaps.findings.json'), JSON.stringify(a07PassWithGapsJson, null, 2), 'utf8');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a07-pass-gaps.sarif.json'), JSON.stringify(a07PassWithGapsSarif, null, 2), 'utf8');

  // A11 composite Prove report: starts from real `prove-real-clarification-coexisting.json`
  // (which already has real producer `needs_clarification`, `protection_losses`, and `unconfirmed_losses`)
  // and appends one real producer `undecided` row from `prove-real-undecided.json` so all 4 groups coexist
  // using 100% genuine upstream v0.1.0 item schemas.
  const a11MixedProve = JSON.parse(proveRealClarifyCoexisting.stdout);
  a11MixedProve.mutation.rows = [
    ...(a11MixedProve.mutation.rows || []),
    realUndecidedRows[0]
  ];
  a11MixedProve.mutation.categories = {
    ...(a11MixedProve.mutation.categories || {}),
    undecided: 1
  };
  fs.writeFileSync(path.join(FIXTURES_DIR, 'a11-prove-mixed-coexisting.json'), JSON.stringify(a11MixedProve, null, 2), 'utf8');

  const runtimeRecord = {
    hostname: SANITIZED_HOSTNAME,
    evidenceTag: process.env.CW_EVIDENCE_TAG || 'PINNED_PRODUCER_FIXTURE',
    os: `${os.type()} ${os.release()} (${os.arch()})`,
    python: { path: sanitizeRecordedPath(PYTHON_EXE), version: pyVersion, sha256: pythonHash },
    git: { path: sanitizeRecordedPath(GIT_EXE), version: gitVersion, sha256: gitHash },
    checkwashPyz: {
      path: UPSTREAM.checkwash.relativePath,
      version: UPSTREAM.checkwash.version,
      bytes: fs.statSync(BUNDLED_PYZ).size,
      sha256: pyzHash,
      artifactBuildSourceCommit: UPSTREAM.checkwash.artifactBuildSourceCommit,
      actionTagCommit: UPSTREAM.checkwash.releaseTagCommit
    },
    checkwashBroker: {
      path: UPSTREAM.windowsBroker.relativePath,
      bytes: fs.statSync(BUNDLED_BROKER).size,
      sha256: brokerHash
    },
    checkwashProve: {
      path: sanitizeRecordedPath(PROVE_EXE),
      version: proveVersion,
      sha256: proveHash,
      sourceCommit: UPSTREAM.proveAdapter.sourceCommit,
      catalogueVersion: UPSTREAM.proveAdapter.catalogueVersion,
      generatorSha256: UPSTREAM.proveAdapter.generatorSha256
    }
  };

  const manifest = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    runtime: runtimeRecord,
    syntheticRepositories: {
      synthRepo1: {
        description: 'Controlled harmless synthetic repository with calc.py and test_calc.py',
        commits: { c1Base, c2Pass, c3Block, c4Docs }
      },
      synthRepoJsEmptyUnit: {
        description: 'Controlled synthetic JS repository with empty-title it("", ...) test',
        commits: { jsBase, jsHead }
      },
      synthRepoProveClarify: {
        description: 'Controlled synthetic Python repository producing real needs_clarification + protection_losses + unconfirmed_losses',
        commits: { clBase, clHead }
      },
      synthRepoProveEarly: {
        description: 'Controlled synthetic Python repository producing real --list and full early-return pairs',
        commits: { e1Base, e2NoMutants, e3CleanFailBase, e4CleanFailHead, e5CollectionFailBase, e6CollectionFailHead }
      },
      synthRepoProveUndecided: {
        description: 'Controlled synthetic Python repository producing real undecided rows',
        commits: { uBase, uHead }
      }
    },
    cases: {
      A01: {
        description: '固定版本 pass／block 原始輸出：JSON、SARIF、四次真實呼叫 argv／exits／stdout／stderr／runtime 與引擎身分／fixture OID 獨立保存',
        origin: 'pinned_real_output',
        commands: {
          passJson: sanitizeArgv(cwPassJson.argv),
          passSarif: sanitizeArgv(cwPassSarif.argv),
          blockJson: sanitizeArgv(cwBlockJson.argv),
          blockSarif: sanitizeArgv(cwBlockSarif.argv)
        },
        files: {
          invocationReceipts: 'a01-invocation-receipts.json',
          passFindings: 'a01-pass.findings.json',
          passSarif: 'a01-pass.sarif.json',
          blockFindings: 'a01-block.findings.json',
          blockSarif: 'a01-block.sarif.json'
        },
        expectedOutcome: {
          passVerdict: 'pass',
          passState: 'Pass',
          passFindingsCount: 0,
          blockVerdict: 'block',
          blockState: 'Block',
          blockFindingsCount: baseBlockFindingsObj.findings.length,
          blockSarifResultsCount: baseBlockSarifObj.runs[0].results.length
        },
        rationale: `Rev 3 §4.3, §5.1, §6: Real v${UPSTREAM.checkwash.version} pass and block outputs read observed exits, stdout, stderr, runtime/engine identity, and full commit OIDs directly from a01-invocation-receipts.json.`
      },
      A02: {
        description: '缺鍵、錯型別、不支援版本拒絕；合法空字串 unit 與未知 optional key／rule／label 可保留',
        origin: 'labeled_variant_from_pinned',
        files: {
          emptyUnitJsFindings: 'a02-empty-unit-js.findings.json',
          emptyUnitJsSarif: 'a02-empty-unit-js.sarif.json',
          emptyUnitJsReceipt: 'a02-empty-unit-js-receipt.json',
          unknownOptional: 'a02-unknown-optional.findings.json',
          missingVerdict: 'a02-missing-verdict.findings.json',
          unsupportedVersion: 'a02-unsupported-version.findings.json'
        },
        expectedOutcome: {
          emptyUnitValid: true,
          unknownOptionalValid: true,
          unknownRuleIdPreserved: 'CW999_FUTURE_RULE',
          missingVerdictValid: false,
          unsupportedVersionValid: false
        },
        rationale: `Rev 3 §5.1: Must accept empty string unit ("") as emitted by Checkwash v${UPSTREAM.checkwash.version} on empty-title JS tests, validate required findings v2 keys/types and version=2, and tolerate unknown optional keys/rules/labels.`
      },
      A03: {
        description: '多項、缺項、錯序、錯 fingerprint 拒絕整組關聯；保留重複 identity 的每一次出現，不截短、不靜默去重',
        origin: 'labeled_variant_from_pinned',
        files: {
          extraSarifResult: 'a03-extra-sarif-result.sarif.json',
          wrongFingerprint: 'a03-wrong-fingerprint.sarif.json',
          dupFindings: 'a03-dup.findings.json',
          dupSarif: 'a03-dup.sarif.json'
        },
        expectedOutcome: {
          extraSarifRejected: true,
          wrongFingerprintRejected: true,
          duplicateCountPreserved: 2
        },
        rationale: 'Rev 3 §5.2: Non-allowlisted JSON findings and SARIF results must match 1-to-1 in order and preserve duplicate identities without truncation or single-key map deduplication.'
      },
      A04: {
        description: 'Allowlisted、helper、conftest：保留 allowlisted；跨檔來源正確，不要求兩種 path 相同',
        origin: 'labeled_variant_from_pinned',
        files: {
          findings: 'a04-allowlisted-conftest.findings.json',
          sarif: 'a04-allowlisted-conftest.sarif.json'
        },
        expectedOutcome: {
          allowlistedPreservedCount: 1,
          allowlistedLine: null,
          crossFileJsonPath: 'tests/test_calc.py',
          crossFileSarifPath: 'tests/conftest.py',
          crossFileLine1Based: 14,
          crossFileLine0Based: 13
        },
        rationale: 'Rev 3 §5.2 & §5.3: Allowlisted findings remain in the joined report with line:null; non-allowlisted findings use SARIF artifactLocation.uri even when it points to an imported helper/conftest file.'
      },
      A05: {
        description: 'Base-only、無 region、歧義來源：line:null；不猜位置、不製造第 1 行診斷',
        origin: 'labeled_variant_from_pinned',
        files: {
          findings: 'a05-noregion.findings.json',
          sarif: 'a05-noregion.sarif.json'
        },
        expectedOutcome: {
          firstFindingLine: null,
          firstFindingEvidenceSide: 'base',
          secondFindingLine: null,
          secondFindingEvidenceSide: 'unknown'
        },
        rationale: 'Rev 3 §5.3: Missing SARIF region must stay line:null (never fake line 1) and record actual checkwash.evidenceSide or unknown.'
      },
      A06: {
        description: '中文、空白、百分號、URI 與換行：解碼一次、路徑有效、行號轉換正確；惡意／不支援路徑拒絕',
        origin: 'labeled_variant_from_pinned',
        expectedOutcome: {
          encodedChineseAndPercentDecodedOnce: 'tests/中文 測試/test_%25_literal.py',
          line1BasedTo0Based: 0,
          schemesRejected: true,
          traversalRejected: true,
          adsRejected: true,
          nulRejected: true
        },
        rationale: 'Rev 3 §5.3 & §5.5: Single percent-decoding preserves literal %25 as %, supports Chinese and spaces, converts 1-based line to 0-based, and rejects schemes, .., NUL, and Windows ADS.'
      },
      A07: {
        description: 'Pass／Block 各與所有缺口組合：Partial 或 Block＋缺口；缺口不隱藏',
        origin: 'labeled_variant_from_pinned',
        files: {
          passWithGapsFindings: 'a07-pass-gaps.findings.json',
          passWithGapsSarif: 'a07-pass-gaps.sarif.json'
        },
        expectedOutcome: {
          passWithGapsState: 'Partial / Review',
          blockWithGapsState: 'Block',
          minGapCount: 4
        },
        rationale: 'Rev 3 §6: Pass with any gap (unread, skipped_files, config_errors, SARIF notification, non-empty stderr) becomes Partial / Review; Block with gaps remains Block and preserves all gaps.'
      },
      A08: {
        description: 'Unread-only exit 2、signal、null、矛盾 exits：一律不是 Pass',
        origin: 'labeled_variant_from_pinned',
        expectedOutcome: {
          exit2State: 'Error',
          signalState: 'Error',
          nullExitState: 'Error',
          contradictoryExit0BlockState: 'Error',
          contradictoryExit1PassState: 'Error'
        },
        rationale: 'Rev 3 §6: Only 0+pass and 1+block are valid completion combinations; exit 2, signals, null exits, or contradictory exits must yield Error and never Pass.'
      },
      A09: {
        description: '歷史來源、dirty buffer、文件 version 改變：不錯掛 live 診斷；修改後立即失效',
        origin: 'labeled_variant_from_pinned',
        expectedOutcome: {
          bomAndCrlfNormalizedMatch: true,
          dirtyBufferAllowed: false,
          versionChangedAllowed: false,
          invalidUtf8Allowed: false
        },
        rationale: 'Rev 3 §5.4: Live diagnostics require valid UTF-8, full-file match after UTF-8 BOM removal and CRLF/CR->LF normalization, and unchanged document.version.'
      },
      A10: {
        description: '分支移動、引擎改變、舊 run 晚到：不改本次來源、不覆蓋新狀態',
        origin: 'labeled_variant_from_pinned',
        expectedOutcome: {
          pinnedOidImmutableOnBranchMove: true,
          engineHashMismatchRejected: true,
          staleScanIdDropped: true
        },
        rationale: 'Rev 3 §4.2, §4.3, §7.4: Scan binds immutable full commit OIDs, verifies identical execution identity across JSON and SARIF, and drops late arrivals from older scanIds.'
      },
      A11: {
        description: 'Prove 零損失、真實 clarification 並存群組與混合報告：分類完整、不遺漏群組、不顯示安全',
        origin: 'pinned_real_output',
        commands: {
          zeroLoss: sanitizeArgv(proveZeroLoss.command),
          withLoss: sanitizeArgv(proveWithLoss.command),
          realClarificationCoexisting: sanitizeArgv(proveRealClarifyCoexisting.command),
          realUndecided: sanitizeArgv(proveRealUndecided.command)
        },
        files: {
          zeroLoss: 'a11-prove-zero-loss.json',
          protectionLoss: 'a11-prove-protection-loss.json',
          realClarificationCoexisting: 'prove-real-clarification-coexisting.json',
          realUndecided: 'prove-real-undecided.json',
          mixedCoexisting: 'a11-prove-mixed-coexisting.json'
        },
        expectedOutcome: {
          zeroLossStatus: 'Compared',
          zeroLossConfirmedCount: 0,
          zeroLossNoConfirmedMessage: '本次有限範圍內未觀察到已確認的保護損失；不代表變更安全或沒有損失。',
          protectionLossStatus: 'Compared',
          protectionLossMinCount: 1,
          mixedHasAllFourGroups: true
        },
        rationale: 'Rev 3 §9.4: Prove preserves protection_losses, unconfirmed_losses, needs_clarification (test/reason/also_fails_in_new/detail), and mutation.undecided simultaneously and never displays a green Pass or safety claim.'
      },
      A12: {
        description: 'Prove list／nothing／no mutants／cap=0／clean-fail／collection-fail：list 提前返回不誤判為 Listed，與 full 模式狀態一致',
        origin: 'pinned_real_output',
        commands: {
          list: sanitizeArgv(proveList.command),
          nothing: sanitizeArgv(proveNothing.command),
          listNothing: sanitizeArgv(proveListNothing.command),
          capZero: sanitizeArgv(proveCapZero.command),
          listNoMutants: sanitizeArgv(proveListNoMutants.command),
          fullNoMutants: sanitizeArgv(proveFullNoMutants.command),
          listCleanFail: sanitizeArgv(proveListCleanFail.command),
          fullCleanFail: sanitizeArgv(proveFullCleanFail.command),
          listCollectionFail: sanitizeArgv(proveListCollectionFail.command),
          fullCollectionFail: sanitizeArgv(proveFullCollectionFail.command)
        },
        files: {
          list: 'a12-prove-list.json',
          nothing: 'a12-prove-nothing.json',
          listNothing: 'prove-real-list-nothing.json',
          capZero: 'a12-prove-cap-zero.json',
          listNoMutants: 'prove-real-list-no-mutants.json',
          fullNoMutants: 'prove-real-full-no-mutants.json',
          listCleanFail: 'prove-real-list-clean-fail.json',
          fullCleanFail: 'prove-real-full-clean-fail.json',
          listCollectionFail: 'prove-real-list-collection-fail.json',
          fullCollectionFail: 'prove-real-full-collection-fail.json'
        },
        expectedOutcome: {
          listStatus: 'Listed',
          listExecutesMutants: false,
          nothingStatus: 'Nothing to compare',
          capZeroStatus: 'Not compared',
          capZeroReason: 'cap_zero',
          noMutantsStatus: 'Not compared',
          noMutantsReason: 'no_mutants',
          collectionFailStatus: 'Not compared',
          collectionFailReason: 'collection_clean_or_trace'
        },
        rationale: 'Rev 3 §9.4: Classifies actual completion outcome so --list early returns show Nothing to compare or Not compared (matching full mode), never Listed.'
      },
      A13: {
        description: 'Replay 特殊字元、HEAD 移動、選項替換：argv 邊界正確；固定來源；報告不能指定可執行程式',
        origin: 'labeled_variant_from_pinned',
        expectedOutcome: {
          workersForcedTo1: true,
          maxMutantsForcedTo1: true,
          listOnlyForcedFalse: true,
          keepForcedFalse: true,
          usesTrustedExecutableNotReport: true,
          usesPinnedOidsNotMovingHead: true
        },
        rationale: 'Rev 3 §9.5: Replay rebuilds argv from extension-owned TrustedProveExecutionRecord with pinned OIDs and single-mutant overrides, never executing loss.replay.'
      },
      A14: {
        description: '匯入報告及不相容 Prove：唯讀；不取得執行能力、不污染目前 verdict',
        origin: 'labeled_variant_from_pinned',
        expectedOutcome: {
          importedReportReplayBlocked: true,
          unsupportedProveVersionRejected: true,
          unsupportedCatalogueHashRejected: true
        },
        rationale: 'Rev 3 §7.1, §9.1, §9.5: Imported reports are strictly read-only without Replay capability and never alter live workspace verdict; unpinned Prove versions/hashes are rejected.'
      }
    }
  };

  fs.writeFileSync(path.join(FIXTURES_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');
  fs.rmSync(tmpBase, { recursive: true, force: true });
  console.log('Generated Phase 0 fixtures, invocation receipts, and manifest.json successfully.');
}

main();
