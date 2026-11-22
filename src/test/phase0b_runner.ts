import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync, spawn } from 'child_process';
import {
  cleanupIsolatedRunDirectory,
  HostEnvironmentDescriptor,
  normalizePlatformLookupKey,
  verifyBareGitResolutionForProcessLaunch,
  verifyLaunchAdmission
} from '../runtime/admission';
import {
  buildBrokerRequestLine,
  executeViaWindowsBroker,
  getTotalBrokerSpawnCount,
  probeWindowsBroker,
  resetTotalBrokerSpawnCountForTests
} from '../runtime/windowsBroker';
import { UnifiedProcessRunner } from '../runtime/processRunner';
import { validateFindingsJsonV2 } from '../core/checkwashSchema';
import { validateProveReportJson } from '../core/proveModel';
import {
  ACTIVE_ARCH,
  ACTIVE_PLATFORM,
  buildDescendantGitIdentityProbeScript,
  copyExecutablePreservingMode,
  getMinimalBrokerEnv,
  getPlatformExecutionMetadata,
  IS_WIN32,
  resolveBundledBrokerExe,
  resolveBundledBrokerFilename,
  resolvePlatformEvidenceDir,
  resolveTestGitExe,
  resolveTestProveExe,
  resolveTestPythonExe,
  writeExecutableDecoyScript,
} from './testPlatformEnv';

const ROOT = path.resolve(__dirname, '..', '..');
const EVIDENCE_DIR = resolvePlatformEvidenceDir(ROOT);
const FIXTURES_DIR = path.join(ROOT, 'fixtures', 'phase0');
const BROKER_EXE = resolveBundledBrokerExe(ROOT);
const BROKER_FILENAME = resolveBundledBrokerFilename();
const PYTHON_EXE = resolveTestPythonExe();
const GIT_EXE = resolveTestGitExe();
const PROVE_EXE = resolveTestProveExe();

interface CaseResultB {
  id: string;
  description: string;
  status: 'PASS' | 'FAIL';
  assertionsCount: number;
  details: string[];
  error?: string;
}

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err: any) {
    return Boolean(err && err.code === 'EPERM');
  }
}

function createSyntheticGitRepo(baseDir: string): {
  repoRoot: string;
  baseOid: string;
  headOid: string;
} {
  const repoRoot = path.join(baseDir, 'synth-b-repo');
  fs.mkdirSync(path.join(repoRoot, 'src'), { recursive: true });
  fs.mkdirSync(path.join(repoRoot, 'tests'), { recursive: true });

  const git = (args: string[]) =>
    execFileSync(GIT_EXE, ['-C', repoRoot, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    }).trim();

  git(['init']);
  git(['config', 'user.name', 'Phase0B Runner']);
  git(['config', 'user.email', 'phase0b@example.local']);

  fs.writeFileSync(
    path.join(repoRoot, 'src', 'app.py'),
    'def greet(name: str) -> str:\n    return f"Hello, {name}"\n',
    'utf8'
  );
  fs.writeFileSync(
    path.join(repoRoot, 'tests', 'test_app.py'),
    'from src.app import greet\ndef test_greet():\n    assert greet("World") == "Hello, World"\n',
    'utf8'
  );
  git(['add', '.']);
  git(['commit', '-m', 'base commit']);
  const baseOid = git(['rev-parse', 'HEAD']);

  fs.writeFileSync(
    path.join(repoRoot, 'tests', 'test_app.py'),
    'from src.app import greet\ndef test_greet():\n    assert greet("World") == "Hello, World"\n    assert greet("Lens") == "Hello, Lens"\n',
    'utf8'
  );
  git(['add', '.']);
  git(['commit', '-m', 'head commit']);
  const headOid = git(['rev-parse', 'HEAD']);

  return { repoRoot, baseOid, headOid };
}

function makeHostDesc(
  repoRoot: string,
  overrides: Partial<HostEnvironmentDescriptor> = {}
): HostEnvironmentDescriptor {
  return {
    isWorkspaceTrusted: true,
    platform: ACTIVE_PLATFORM,
    arch: ACTIVE_ARCH,
    workspaceScheme: 'file',
    isRemote: false,
    isVirtualWorkspace: false,
    extensionRootPath: ROOT,
    repositoryRootPath: repoRoot,
    configuredPythonPath: PYTHON_EXE,
    configuredGitPath: GIT_EXE,
    ...overrides
  };
}

async function runPhase0B(): Promise<void> {
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-phase0b-'));
  const emptyCwd = path.join(tmpBase, 'controlled-empty-cwd');
  fs.mkdirSync(emptyCwd, { recursive: true });

  const { repoRoot, baseOid, headOid } = createSyntheticGitRepo(tmpBase);
  const results: CaseResultB[] = [];

  async function runCase(
    id: string,
    description: string,
    fn: (details: string[]) => Promise<number>
  ): Promise<void> {
    const details: string[] = [];
    try {
      const count = await fn(details);
      results.push({
        id,
        description,
        status: 'PASS',
        assertionsCount: count,
        details
      });
    } catch (err) {
      results.push({
        id,
        description,
        status: 'FAIL',
        assertionsCount: 0,
        details,
        error: err instanceof Error ? `${err.message}\n${err.stack}` : String(err)
      });
    }
  }

  // -------------------------------------------------------------------------
  // B01: 真正 Restricted Mode — activation、命令、事件、設定變更、probe、Git、Replay 全部零外部程序
  // -------------------------------------------------------------------------
  await runCase(
    'B01',
    '真正 Restricted Mode：activation、命令、事件、設定變更、probe、Git、Replay 全部零外部程序',
    async (details) => {
      resetTotalBrokerSpawnCountForTests();
      const runner = new UnifiedProcessRunner();
      const untrustedDesc = makeHostDesc(repoRoot, {
        isWorkspaceTrusted: false
      });

      // 1. Direct admission check (activation / command / event / config change)
      const adm = verifyLaunchAdmission(untrustedDesc);
      assert.strictEqual(adm.ok, false);

      // 2. Python version probe attempt in Restricted Mode
      const probeRes = await runner.probeTrustedRuntimeVersions(untrustedDesc);
      assert.strictEqual(probeRes.ok, false);

      // 3. Git commit resolution attempt in Restricted Mode
      const gitRes = await runner.resolveAndPinCommittedRange(untrustedDesc, `${baseOid}..${headOid}`);
      assert.strictEqual(gitRes.ok, false);

      // 4. Committed Checkwash scan attempt in Restricted Mode
      const scanRes = await runner.runCommittedCheckwashScan(untrustedDesc, `${baseOid}..${headOid}`);
      assert.strictEqual(scanRes.state, 'Not Run');

      // 5. Prove / Replay gated process attempt in Restricted Mode
      const proveRes = await runner.executeGatedProcess({
        hostDesc: untrustedDesc,
        executableSelector: () => PROVE_EXE,
        argsBuilder: () => ['--version'],
        timeoutMs: 10_000
      });
      assert.strictEqual(proveRes.ok, false);

      // Confirm ZERO external processes were spawned
      assert.strictEqual(getTotalBrokerSpawnCount(), 0, 'Broker spawn count must be strictly 0 in Restricted Mode');
      details.push(`Restricted Mode blocked all 5 entry classes; totalBrokerSpawnCount=${getTotalBrokerSpawnCount()}.`);
      return 6;
    }
  );

  // -------------------------------------------------------------------------
  // B02: Remote／virtual／不支援架構：在共同入口拒絕；沒有 fallback
  // -------------------------------------------------------------------------
  await runCase(
    'B02',
    'Remote／virtual／不支援架構：在共同入口拒絕；沒有 fallback',
    async (details) => {
      resetTotalBrokerSpawnCountForTests();
      const remoteUnspecified = verifyLaunchAdmission(makeHostDesc(repoRoot, { isRemote: true }));
      assert.strictEqual(remoteUnspecified.ok, false);

      const remoteSsh = verifyLaunchAdmission(
        makeHostDesc(repoRoot, { isRemote: true, remoteName: 'ssh-remote' })
      );
      assert.strictEqual(remoteSsh.ok, false);

      const remoteCodespaces = verifyLaunchAdmission(
        makeHostDesc(repoRoot, { isRemote: true, remoteName: 'codespaces' })
      );
      assert.strictEqual(remoteCodespaces.ok, false);

      const remoteTunnel = verifyLaunchAdmission(
        makeHostDesc(repoRoot, { isRemote: true, remoteName: 'tunnel' })
      );
      assert.strictEqual(remoteTunnel.ok, false);

      if (ACTIVE_PLATFORM === 'linux') {
        const wslOk = verifyLaunchAdmission(
          makeHostDesc(repoRoot, { isRemote: true, remoteName: 'wsl' })
        );
        assert.strictEqual(wslOk.ok, true, 'WSL remote workspace on linux/x64 must be admitted');
        cleanupIsolatedRunDirectory(wslOk.value.isolatedTempDir, true);

        const devContainerOk = verifyLaunchAdmission(
          makeHostDesc(repoRoot, { isRemote: true, remoteName: 'dev-container' })
        );
        assert.strictEqual(
          devContainerOk.ok,
          true,
          'Dev Container remote workspace on linux/x64 must be admitted'
        );
        cleanupIsolatedRunDirectory(devContainerOk.value.isolatedTempDir, true);
      } else {
        const wslOnWinHost = verifyLaunchAdmission(
          makeHostDesc(repoRoot, { isRemote: true, remoteName: 'wsl' })
        );
        assert.strictEqual(
          wslOnWinHost.ok,
          false,
          'WSL remoteName on win32 host must be rejected (WSL workspace host runs on linux/x64)'
        );
      }

      const virtualFs = verifyLaunchAdmission(
        makeHostDesc(repoRoot, { isVirtualWorkspace: true, workspaceScheme: 'vscode-vfs' })
      );
      assert.strictEqual(virtualFs.ok, false);

      const virtualWsl = verifyLaunchAdmission(
        makeHostDesc(repoRoot, {
          isRemote: true,
          remoteName: 'wsl',
          isVirtualWorkspace: true,
          workspaceScheme: 'vscode-vfs'
        })
      );
      assert.strictEqual(virtualWsl.ok, false);

      const badOs = verifyLaunchAdmission(makeHostDesc(repoRoot, { platform: 'darwin', arch: 'x64' }));
      assert.strictEqual(badOs.ok, false);

      const badArch = verifyLaunchAdmission(
        makeHostDesc(repoRoot, { platform: ACTIVE_PLATFORM, arch: 'arm64' })
      );
      assert.strictEqual(badArch.ok, false);

      assert.strictEqual(getTotalBrokerSpawnCount(), 0);
      details.push(
        `Unsupported remotes (ssh-remote, codespaces, tunnel, unspecified), virtual (vscode-vfs), darwin/x64, and ${ACTIVE_PLATFORM}/arm64 rejected at common admission gate with zero spawns (supported linux/x64 wsl/dev-container verified).`
      );
      return 10;
    }
  );

  // -------------------------------------------------------------------------
  // B03: PYTHONPATH、site customization 污染：Sentinel 未執行，且 bundled 真實靜態 fixture 分析成功
  // -------------------------------------------------------------------------
  await runCase(
    'B03',
    'PYTHONPATH、site customization 污染：Sentinel 未執行，且 bundled 真實靜態 fixture 分析成功',
    async (details) => {
      const poisonDir = path.join(tmpBase, 'poison-pythonpath');
      fs.mkdirSync(poisonDir, { recursive: true });
      const sentinelFile = path.join(tmpBase, 'b03-sentinel-triggered.txt');

      const poisonCode = [
        'import pathlib',
        `pathlib.Path(${JSON.stringify(sentinelFile)}).write_text("POISON_EXECUTED", encoding="utf-8")`,
        'raise RuntimeError("sitecustomize poison executed!")'
      ].join('\n');
      fs.writeFileSync(path.join(poisonDir, 'sitecustomize.py'), poisonCode, 'utf8');
      fs.writeFileSync(path.join(poisonDir, 'usercustomize.py'), poisonCode, 'utf8');
      fs.writeFileSync(path.join(repoRoot, 'sitecustomize.py'), poisonCode, 'utf8');

      const runner = new UnifiedProcessRunner();
      const pollutedDesc = makeHostDesc(repoRoot, {
        inheritedEnv: {
          ...process.env,
          PYTHONPATH: [poisonDir, repoRoot].join(path.delimiter),
          PYTHONSTARTUP: path.join(poisonDir, 'sitecustomize.py'),
          PYTHONHOME: poisonDir
        }
      });

      try {
        const scan = await runner.runCommittedCheckwashScan(pollutedDesc, `${baseOid}..${headOid}`);
        assert.strictEqual(fs.existsSync(sentinelFile), false, 'Sentinel file must NOT exist');
        assert.strictEqual(scan.state, 'Pass', `Expected Pass state, got ${scan.state} (${scan.errorReason ?? ''})`);
        assert.strictEqual(scan.joinedReport?.scanIdentity.effectiveBaseOid, baseOid);
        assert.strictEqual(scan.joinedReport?.scanIdentity.effectiveHeadOid, headOid);
        details.push(`Poisoned PYTHONPATH/PYTHONSTARTUP/repo sitecustomize.py ignored under -I -S -B; scan state=${scan.state}, sentinelExists=false.`);
      } finally {
        fs.rmSync(path.join(repoRoot, 'sitecustomize.py'), { force: true });
      }
      return 4;
    }
  );

  // -------------------------------------------------------------------------
  // B04: 專案同名 Git／Python／Checkwash：未被啟動；實際程序身分符合固定 runtime
  // -------------------------------------------------------------------------
  await runCase(
    'B04',
    '專案同名 Git／Python／Checkwash：未被啟動；實際程序身分符合固定 runtime',
    async (details) => {
      const decoySentinel = path.join(tmpBase, 'b04-decoy-triggered.txt');
      const decoyNames = IS_WIN32
        ? ['git.cmd', 'git.bat', 'python.cmd', 'checkwash.cmd']
        : ['git', 'python3', 'python', 'checkwash'];
      for (const name of decoyNames) {
        writeExecutableDecoyScript(path.join(repoRoot, name), decoySentinel, 99);
      }
      const repoPyName = IS_WIN32 ? 'python.exe' : 'python3-bin';
      const repoGitName = IS_WIN32 ? 'git.exe' : 'git-bin';
      const repoPyPath = path.join(repoRoot, repoPyName);
      const repoGitPath = path.join(repoRoot, repoGitName);
      copyExecutablePreservingMode(BROKER_EXE, repoPyPath);
      copyExecutablePreservingMode(BROKER_EXE, repoGitPath);

      try {
        // 1) Configured Python or Git inside target repo is rejected by verifyLaunchAdmission
        const badPyAdmission = verifyLaunchAdmission(
          makeHostDesc(repoRoot, { configuredPythonPath: repoPyPath })
        );
        assert.strictEqual(badPyAdmission.ok, false);

        const badGitAdmission = verifyLaunchAdmission(
          makeHostDesc(repoRoot, { configuredGitPath: repoGitPath })
        );
        assert.strictEqual(badGitAdmission.ok, false);

        // 2) Bare 'git' vs verified Git identity cases (Issue #10 & Phase 0 B04):
        // 2a: Configured git-new in a directory that ALSO contains git -> blocked before analysis
        const gitDualDir = path.join(tmpBase, 'b04-git-dual');
        fs.mkdirSync(gitDualDir, { recursive: true });
        const gitNewDual = path.join(gitDualDir, IS_WIN32 ? 'git-new.exe' : 'git-new');
        const gitStdDual = path.join(gitDualDir, IS_WIN32 ? 'git.exe' : 'git');
        copyExecutablePreservingMode(GIT_EXE, gitNewDual);
        copyExecutablePreservingMode(GIT_EXE, gitStdDual);
        const dualAdmission = verifyLaunchAdmission(
          makeHostDesc(repoRoot, { configuredGitPath: gitNewDual })
        );
        assert.strictEqual(dualAdmission.ok, false, 'git-new alongside git must be blocked');

        // 2b: Configured git-only-custom where bare 'git' resolves differently or is missing -> blocked before analysis
        const gitMissingBareDir = path.join(tmpBase, 'b04-git-no-bare');
        fs.mkdirSync(gitMissingBareDir, { recursive: true });
        const gitOnlyCustom = path.join(gitMissingBareDir, IS_WIN32 ? 'git-new.exe' : 'git-new');
        copyExecutablePreservingMode(GIT_EXE, gitOnlyCustom);
        const noBareAdmission = verifyLaunchAdmission(
          makeHostDesc(repoRoot, { configuredGitPath: gitOnlyCustom })
        );
        assert.strictEqual(noBareAdmission.ok, false, 'git-new without matching bare git must be blocked');

        // 2c: Another git earlier in OS search order -> blocked before analysis
        if (IS_WIN32) {
          const fakeWinRoot = path.join(tmpBase, 'b04-fake-winroot');
          fs.mkdirSync(path.join(fakeWinRoot, 'System32'), { recursive: true });
          copyExecutablePreservingMode(GIT_EXE, path.join(fakeWinRoot, 'System32', 'git.exe'));
          const shadowedAdmission = verifyLaunchAdmission(
            makeHostDesc(repoRoot, {
              configuredGitPath: GIT_EXE,
              inheritedEnv: { ...process.env, SystemRoot: fakeWinRoot }
            })
          );
          assert.strictEqual(shadowedAdmission.ok, false, 'Shadowed git.exe earlier in search order must be blocked');
        } else {
          const shadowGitDir = path.join(tmpBase, 'b04-shadow-git-dir');
          fs.mkdirSync(shadowGitDir, { recursive: true });
          copyExecutablePreservingMode(GIT_EXE, path.join(shadowGitDir, 'git'));
          const shadowedBareRes = verifyBareGitResolutionForProcessLaunch({
            callingExecutables: [fs.realpathSync.native(PYTHON_EXE)],
            canonicalGitPath: fs.realpathSync.native(GIT_EXE),
            cwd: tmpBase,
            env: {
              PATH: [shadowGitDir, path.dirname(GIT_EXE), '/usr/bin', '/bin'].join(':'),
            },
            platform: 'linux',
          });
          assert.strictEqual(shadowedBareRes.ok, false, 'Shadowed git earlier in POSIX PATH must be blocked');
        }

        // 3) Full committed scan with decoy git/python inside repoRoot never executes decoys,
        //    AND configured Git, probe Git, and descendant bare 'git' share identical canonical path & SHA-256
        const crypto = require('crypto') as typeof import('crypto');
        const sha256File = (p: string) =>
          crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');

        const runner = new UnifiedProcessRunner();
        const validDesc = makeHostDesc(repoRoot);
        const validAdm = verifyLaunchAdmission(validDesc);
        if (!validAdm.ok) assert.fail(validAdm.error);

        const configuredCanonGit = fs.realpathSync.native(GIT_EXE);
        const configuredGitSha = sha256File(configuredCanonGit);
        const probeGitRes = await runner.probeTrustedRuntimeVersions(validDesc);
        if (!probeGitRes.ok) assert.fail(probeGitRes.error);

        const descendantCheckScript = buildDescendantGitIdentityProbeScript();

        const descGitRes = await runner.executeGatedProcess({
          hostDesc: validDesc,
          executableSelector: (ctx) => ctx.canonicalPythonPath,
          argsBuilder: () => ['-I', '-S', '-B', '-c', descendantCheckScript],
          timeoutMs: 15_000
        });
        if (!descGitRes.ok) assert.fail(descGitRes.error);
        const descGitInfo = JSON.parse(descGitRes.value.outcome.stdoutText.trim());
        assert.strictEqual(descGitInfo.ok, true);
        assert.strictEqual(
          normalizePlatformLookupKey(descGitInfo.imagePath),
          normalizePlatformLookupKey(configuredCanonGit),
          'Descendant bare git OS image path must match configured canonical Git'
        );
        assert.strictEqual(
          normalizePlatformLookupKey(probeGitRes.value.admission.canonicalGitPath),
          normalizePlatformLookupKey(configuredCanonGit),
          'Probe canonical Git path must match configured canonical Git'
        );
        assert.strictEqual(descGitInfo.sha256, configuredGitSha, 'Descendant bare git SHA-256 must match configured Git');

        const scan = await runner.runCommittedCheckwashScan(validDesc, `${baseOid}..${headOid}`);

        assert.strictEqual(fs.existsSync(decoySentinel), false, 'Decoy sentinel must never be created');
        assert.strictEqual(scan.state, 'Pass');
        assert.strictEqual(
          normalizePlatformLookupKey(fs.realpathSync.native(scan.joinedReport!.scanIdentity.pythonExecutable)),
          normalizePlatformLookupKey(fs.realpathSync.native(PYTHON_EXE))
        );
        assert.strictEqual(
          normalizePlatformLookupKey(path.resolve(scan.joinedReport!.scanIdentity.gitExecutable)),
          normalizePlatformLookupKey(configuredCanonGit)
        );
        details.push(
          `Blocked git-new+git, missing-bare-git, and shadowed-git before analysis; verified configured/probe/descendant bare git identity=${configuredCanonGit} (sha256=${configuredGitSha.slice(0, 16)}...); repo decoys untouched.`
        );
      } finally {
        for (const name of [...decoyNames, repoPyName, repoGitName]) {
          fs.rmSync(path.join(repoRoot, name), { force: true });
        }
      }
      return 16;
    }
  );

  // -------------------------------------------------------------------------
  // B05: 路徑含空白、中文及 shell 字元：真實 argv 保持原值，沒有 shell fallback
  // -------------------------------------------------------------------------
  await runCase(
    'B05',
    '路徑含空白、中文及 shell 字元：真實 argv 保持原值，沒有 shell fallback',
    async (details) => {
      const runner = new UnifiedProcessRunner();
      const desc = makeHostDesc(repoRoot);
      const trickyArgs = [
        '-I',
        '-S',
        '-B',
        '-X',
        'utf8',
        '-c',
        'import sys, json; print(json.dumps(sys.argv[1:], ensure_ascii=False))',
        'C:\\路徑 含空白\\中文 測試\\file.py',
        '%PATH%',
        'a & b | c > d ^ e "quoted" \'single\'',
        '--only=m0001; calc.exe'
      ];

      const execRes = await runner.executeGatedProcess({
        hostDesc: desc,
        executableSelector: (ctx) => ctx.canonicalPythonPath,
        argsBuilder: () => trickyArgs,
        timeoutMs: 15_000
      });
      assert.strictEqual(execRes.ok, true);
      assert.strictEqual(execRes.value.outcome.exitCode, 0);

      const echoedArgv = JSON.parse(execRes.value.outcome.stdoutText.trim());
      assert.deepStrictEqual(echoedArgv, trickyArgs.slice(7));
      details.push(`Verbatim argv verified under -I -S -B -X utf8 without shell expansion: ${JSON.stringify(echoedArgv)}`);
      return 3;
    }
  );

  // -------------------------------------------------------------------------
  // B06: 父、子、孫程序正常／取消／逾時／溢位：全部受管理，收尾後 Job 無 active processes
  // -------------------------------------------------------------------------
  await runCase(
    'B06',
    '父、子、孫程序正常／取消／逾時／溢位：全部受管理，收尾後 Job 無 active processes',
    async (details) => {
      const runner = new UnifiedProcessRunner();
      const desc = makeHostDesc(repoRoot);

      const treeScriptPath = path.join(tmpBase, 'tree_helper.py');
      fs.writeFileSync(
        treeScriptPath,
        [
          'import subprocess, sys, time',
          'mode = sys.argv[1]',
          'pid_file = sys.argv[2]',
          'grandchild_code = "import time; time.sleep(60)"',
          'child_code = f"import subprocess, pathlib, time; p = subprocess.Popen([r\'{sys.executable}\', \'-I\', \'-S\', \'-B\', \'-c\', \'{grandchild_code}\']); pathlib.Path(r\'{pid_file}\').write_text(str(p.pid)); time.sleep(60)"',
          'if mode == "normal":',
          '    p = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", "print(\'grandchild_ok\')"])',
          '    p.wait()',
          '    sys.exit(0)',
          'p = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", child_code])',
          'for _ in range(50):',
          '    try:',
          '        with open(pid_file, "r") as f:',
          '            if f.read().strip(): break',
          '    except Exception:',
          '        pass',
          '    time.sleep(0.05)',
          'if mode == "overflow":',
          '    sys.stdout.write("X" * (2 * 1024 * 1024))',
          '    sys.stdout.flush()',
          'time.sleep(60)'
        ].join('\n'),
        'utf8'
      );

      // 1) Normal completion
      const normalPidFile = path.join(tmpBase, 'b06-normal.pid');
      const normalRes = await runner.executeGatedProcess({
        hostDesc: desc,
        executableSelector: (ctx) => ctx.canonicalPythonPath,
        argsBuilder: () => ['-I', '-S', '-B', treeScriptPath, 'normal', normalPidFile],
        timeoutMs: 10_000
      });
      assert.strictEqual(normalRes.ok, true);
      assert.strictEqual(normalRes.value.outcome.status, 'completed');
      assert.strictEqual(normalRes.value.outcome.cleanupConfirmed, true);
      assert.strictEqual(normalRes.value.outcome.activeProcessesRemaining, 0);

      // 2) User cancellation
      const cancelPidFile = path.join(tmpBase, 'b06-cancel.pid');
      const abortController = new AbortController();
      setTimeout(() => abortController.abort(), 800);
      const cancelRes = await runner.executeGatedProcess({
        hostDesc: desc,
        executableSelector: (ctx) => ctx.canonicalPythonPath,
        argsBuilder: () => ['-I', '-S', '-B', treeScriptPath, 'hang', cancelPidFile],
        timeoutMs: 30_000,
        abortSignal: abortController.signal
      });
      assert.strictEqual(cancelRes.ok, true);
      assert.strictEqual(cancelRes.value.outcome.status, 'cancelled');
      assert.strictEqual(cancelRes.value.outcome.cleanupConfirmed, true);
      assert.strictEqual(cancelRes.value.outcome.activeProcessesRemaining, 0);
      const cancelGrandchildPid = Number(fs.readFileSync(cancelPidFile, 'utf8').trim());
      assert.strictEqual(cancelGrandchildPid > 0, true);
      assert.strictEqual(isPidAlive(cancelGrandchildPid), false, 'Cancelled grandchild PID must be dead');

      // 3) Timeout expiry
      const timeoutPidFile = path.join(tmpBase, 'b06-timeout.pid');
      const timeoutRes = await runner.executeGatedProcess({
        hostDesc: desc,
        executableSelector: (ctx) => ctx.canonicalPythonPath,
        argsBuilder: () => ['-I', '-S', '-B', treeScriptPath, 'hang', timeoutPidFile],
        timeoutMs: 1200
      });
      assert.strictEqual(timeoutRes.ok, true);
      assert.strictEqual(timeoutRes.value.outcome.status, 'timed_out');
      assert.strictEqual(timeoutRes.value.outcome.cleanupConfirmed, true);
      assert.strictEqual(timeoutRes.value.outcome.activeProcessesRemaining, 0);
      const timeoutGrandchildPid = Number(fs.readFileSync(timeoutPidFile, 'utf8').trim());
      assert.strictEqual(isPidAlive(timeoutGrandchildPid), false, 'Timed-out grandchild PID must be dead');

      // 4) Output overflow
      const overflowPidFile = path.join(tmpBase, 'b06-overflow.pid');
      const overflowRes = await runner.executeGatedProcess({
        hostDesc: desc,
        executableSelector: (ctx) => ctx.canonicalPythonPath,
        argsBuilder: () => ['-I', '-S', '-B', treeScriptPath, 'overflow', overflowPidFile],
        timeoutMs: 15_000,
        maxStdoutBytes: 64 * 1024
      });
      assert.strictEqual(overflowRes.ok, true);
      assert.strictEqual(overflowRes.value.outcome.status, 'stdout_overflow');
      assert.strictEqual(overflowRes.value.outcome.cleanupConfirmed, true);
      assert.strictEqual(overflowRes.value.outcome.activeProcessesRemaining, 0);
      const overflowGrandchildPid = Number(fs.readFileSync(overflowPidFile, 'utf8').trim());
      assert.strictEqual(isPidAlive(overflowGrandchildPid), false, 'Overflowed grandchild PID must be dead');

      // 5) Real cancel/timeout race on broker: grandchild reaped cleanly with 0 active processes
      const racePidFile = path.join(tmpBase, 'b06-race.pid');
      const raceAbort = new AbortController();
      setTimeout(() => raceAbort.abort(), 950);
      const raceRes = await runner.executeGatedProcess({
        hostDesc: desc,
        executableSelector: (ctx) => ctx.canonicalPythonPath,
        argsBuilder: () => ['-I', '-S', '-B', treeScriptPath, 'hang', racePidFile],
        timeoutMs: 1000,
        abortSignal: raceAbort.signal
      });
      assert.strictEqual(raceRes.ok, true);
      assert.strictEqual(raceRes.value.outcome.cleanupConfirmed, true);
      assert.strictEqual(raceRes.value.outcome.activeProcessesRemaining, 0);
      const raceGrandchildPid = Number(fs.readFileSync(racePidFile, 'utf8').trim());
      assert.strictEqual(isPidAlive(raceGrandchildPid), false, 'Cancel/timeout race grandchild PID must be dead');

      // 6) Unconfirmed cleanup during cancellation: never claims confirmed stopped; blocks subsequent runs
      const unconfirmedRunner = new UnifiedProcessRunner();
      let releaseMockHang!: () => void;
      const mockHangGate = new Promise<void>((r) => {
        releaseMockHang = r;
      });
      let mockStarted!: () => void;
      const mockStartedPromise = new Promise<void>((r) => {
        mockStarted = r;
      });
      unconfirmedRunner.setCustomBrokerExecutorForTests(async (_req, sig) => {
        mockStarted();
        if (sig && !sig.aborted) {
          await new Promise<void>((r) => sig.addEventListener('abort', () => r(), { once: true }));
        }
        await mockHangGate;
        return {
          status: 'cancelled',
          exitCode: null,
          childPid: 99999,
          stdoutRaw: Buffer.alloc(0),
          stderrRaw: Buffer.alloc(0),
          stdoutUtf8Valid: true,
          stderrUtf8Valid: true,
          stdoutText: '',
          stderrText: '',
          cleanupConfirmed: false,
          activeProcessesRemaining: 1,
          brokerErrorDetail: 'Simulated unconfirmed Job Object cleanup'
        };
      });
      const unconfirmedScanPromise = unconfirmedRunner.runCommittedCheckwashScan(desc, `${baseOid}..${headOid}`);
      await mockStartedPromise;
      const cancelStopPromise = unconfirmedRunner.cancelActiveRunAndConfirmStop();
      releaseMockHang();
      const [stopOutcome, scanOutcome] = await Promise.all([cancelStopPromise, unconfirmedScanPromise]);
      assert.strictEqual(stopOutcome.cleanupConfirmed, false);
      assert.strictEqual(stopOutcome.stopped, false, 'stopped must be false when cleanupConfirmed is false');
      assert.strictEqual(scanOutcome.state, 'Error', 'Unconfirmed cleanup must yield Error, never Not Run');
      assert.strictEqual(
        (scanOutcome.errorReason ?? '').includes('confirmed stopped'),
        false,
        'Error reason must never claim confirmed stopped'
      );
      const blockedFollowup = await unconfirmedRunner.runCommittedCheckwashScan(desc, `${baseOid}..${headOid}`);
      assert.strictEqual(blockedFollowup.state, 'Error', 'Subsequent scan must remain blocked after unconfirmed cleanup');

      details.push(
        `Confirmed 0 active processes across normal, cancel (PID=${cancelGrandchildPid}), timeout (PID=${timeoutGrandchildPid}), overflow (PID=${overflowGrandchildPid}), and cancel/timeout race (PID=${raceGrandchildPid}); unconfirmed cleanup yielded stopped=false, state=Error, and blocked subsequent runs.`
      );
      return 30;
    }
  );

  // -------------------------------------------------------------------------
  // B07: Job assignment 失敗：Suspended child 已終止，沒有殘留
  // -------------------------------------------------------------------------
  await runCase(
    'B07',
    'Job assignment 失敗：Suspended child 已終止，沒有殘留',
    async (details) => {
      const b07Sentinel = path.join(tmpBase, 'b07-should-never-exist.txt');
      const res = await executeViaWindowsBroker({
        brokerExecutablePath: BROKER_EXE,
        executable: PYTHON_EXE,
        args: [
          '-I',
          '-S',
          '-B',
          '-c',
          `import pathlib; pathlib.Path(${JSON.stringify(b07Sentinel)}).write_text("RAN")`
        ],
        cwd: emptyCwd,
        env: getMinimalBrokerEnv(),
        timeoutMs: 10_000,
        maxStdoutBytes: 1024 * 1024,
        maxStderrBytes: 1024 * 1024,
        simulateAssignFailure: true
      });

      assert.strictEqual(res.status, 'assign_failed');
      assert.strictEqual(res.suspendedChildTerminated, true, 'Suspended child must be terminated before resume');
      assert.strictEqual(res.cleanupConfirmed, true, 'Cleanup of suspended child must be confirmed');
      assert.strictEqual(res.activeProcessesRemaining, 0);
      assert.strictEqual(fs.existsSync(b07Sentinel), false, 'Suspended child code must never execute');
      details.push('Simulated AssignProcessToJobObject failure terminated suspended child before ResumeThread; sentinelExists=false.');
      return 5;
    }
  );

  // -------------------------------------------------------------------------
  // B08: Node IPC pipe EOF & standalone mock-host SIGKILL Job Object 收尾驗證
  // -------------------------------------------------------------------------
  await runCase(
    'B08',
    'Node IPC pipe EOF 與獨立 mock-host SIGKILL：Broker Job Object 收尾有效，無殘留程序（真實 VS Code Desktop host crash/reload UI 為 NOT_RUN）',
    async (details) => {
      // Subtest 1: Extension host reload / abrupt life-support pipe disconnect (stdin EOF)
      const reloadGrandchildPidFile = path.join(tmpBase, 'b08-reload-grandchild.pid');
      const reloadTrackFile = path.join(tmpBase, 'b08-reload-track.pid');
      const reloadTreeScript = path.join(tmpBase, 'b08_reload_tree.py');
      fs.writeFileSync(
        reloadTreeScript,
        [
          'import subprocess, sys, time, pathlib',
          'p = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", "import time; time.sleep(60)"])',
          `pathlib.Path(${JSON.stringify(reloadGrandchildPidFile)}).write_text(str(p.pid))`,
          'time.sleep(60)'
        ].join('\n'),
        'utf8'
      );

      const reloadReqLine = buildBrokerRequestLine({
        brokerExecutablePath: BROKER_EXE,
        executable: PYTHON_EXE,
        args: ['-I', '-S', '-B', reloadTreeScript],
        cwd: emptyCwd,
        env: getMinimalBrokerEnv(),
        timeoutMs: 60_000,
        maxStdoutBytes: 1024 * 1024,
        maxStderrBytes: 1024 * 1024,
        pidTrackFilePath: reloadTrackFile
      });

      const brkProc = spawn(BROKER_EXE, [], {
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true
      });
      brkProc.stdin.write(reloadReqLine);

      let reloadGrandchildPid = 0;
      for (let i = 0; i < 60; i++) {
        if (fs.existsSync(reloadGrandchildPidFile)) {
          const content = fs.readFileSync(reloadGrandchildPidFile, 'utf8').trim();
          if (content) {
            reloadGrandchildPid = Number(content);
            break;
          }
        }
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.strictEqual(reloadGrandchildPid > 0, true, 'Reload grandchild PID must be recorded');
      assert.strictEqual(isPidAlive(reloadGrandchildPid), true, 'Reload grandchild must be alive before disconnect');

      // Abruptly sever the life-support stdin pipe (simulating host reload / uncaught exit without dispose)
      brkProc.stdin.destroy();

      let reloadTrackContent = '';
      for (let i = 0; i < 30; i++) {
        if (fs.existsSync(reloadTrackFile)) {
          reloadTrackContent = fs.readFileSync(reloadTrackFile, 'utf8').trim();
          if (reloadTrackContent.endsWith(':CLEANED') && !isPidAlive(reloadGrandchildPid)) {
            break;
          }
        }
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.strictEqual(reloadTrackContent.endsWith(':CLEANED'), true, `Expected :CLEANED marker, got '${reloadTrackContent}'`);
      assert.strictEqual(isPidAlive(reloadGrandchildPid), false, 'Reload grandchild must be terminated on pipe EOF');

      // Subtest 2: Abrupt hard SIGKILL of an intermediate Extension Host process
      const crashGrandchildPidFile = path.join(tmpBase, 'b08-crash-grandchild.pid');
      const crashTrackFile = path.join(tmpBase, 'b08-crash-track.pid');
      const crashTreeScript = path.join(tmpBase, 'b08_crash_tree.py');
      fs.writeFileSync(
        crashTreeScript,
        [
          'import subprocess, sys, time, pathlib',
          'p = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", "import time; time.sleep(60)"])',
          `pathlib.Path(${JSON.stringify(crashGrandchildPidFile)}).write_text(str(p.pid))`,
          'time.sleep(60)'
        ].join('\n'),
        'utf8'
      );

      const crashReqLine = buildBrokerRequestLine({
        brokerExecutablePath: BROKER_EXE,
        executable: PYTHON_EXE,
        args: ['-I', '-S', '-B', crashTreeScript],
        cwd: emptyCwd,
        env: getMinimalBrokerEnv(),
        timeoutMs: 60_000,
        maxStdoutBytes: 1024 * 1024,
        maxStderrBytes: 1024 * 1024,
        pidTrackFilePath: crashTrackFile
      });

      const mockHostScript = path.join(tmpBase, 'b08_mock_host.js');
      fs.writeFileSync(
        mockHostScript,
        [
          'const { spawn } = require("child_process");',
          `const child = spawn(${JSON.stringify(BROKER_EXE)}, [], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });`,
          `child.stdin.write(${JSON.stringify(crashReqLine)});`,
          'setInterval(() => {}, 1000);'
        ].join('\n'),
        'utf8'
      );

      const hostProc = spawn(process.execPath, [mockHostScript], {
        stdio: ['ignore', 'ignore', 'ignore'],
        windowsHide: true
      });

      let crashChildPid = 0;
      let crashGrandchildPid = 0;
      try {
        for (let i = 0; i < 60; i++) {
          if (fs.existsSync(crashGrandchildPidFile) && fs.existsSync(crashTrackFile)) {
            const content = fs.readFileSync(crashGrandchildPidFile, 'utf8').trim();
            if (content) {
              crashGrandchildPid = Number(content);
              break;
            }
          }
          await new Promise((r) => setTimeout(r, 100));
        }
        crashChildPid = Number(fs.readFileSync(crashTrackFile, 'utf8').split(':')[0]);
        assert.strictEqual(crashGrandchildPid > 0 && crashChildPid > 0, true);
        assert.strictEqual(isPidAlive(crashGrandchildPid), true);

        // Abruptly kill the mock Extension Host process with SIGKILL
        hostProc.kill('SIGKILL');
      } finally {
        try {
          hostProc.kill('SIGKILL');
        } catch {
          // already terminated
        }
      }

      for (let i = 0; i < 30; i++) {
        if (!isPidAlive(crashChildPid) && !isPidAlive(crashGrandchildPid)) {
          break;
        }
        await new Promise((r) => setTimeout(r, 100));
      }

      assert.strictEqual(isPidAlive(crashChildPid), false, 'Child process must be dead after host SIGKILL');
      assert.strictEqual(isPidAlive(crashGrandchildPid), false, 'Grandchild process must be dead after host SIGKILL');
      details.push(
        `Reload pipe EOF reaped grandchild PID=${reloadGrandchildPid} with '${reloadTrackContent}'; hard host SIGKILL (PID=${hostProc.pid}) reaped child PID=${crashChildPid} & grandchild PID=${crashGrandchildPid} via KILL_ON_JOB_CLOSE.`
      );
      return 9;
    }
  );

  // -------------------------------------------------------------------------
  // B09: Broker／Job 能力失敗：執行功能一致停用；離線檢視可用
  // -------------------------------------------------------------------------
  await runCase(
    'B09',
    'Broker／Job 能力失敗：執行功能一致停用；離線檢視可用',
    async (details) => {
      const runner = new UnifiedProcessRunner();
      runner.forceBrokerFailureForTest('Simulated Job Object capability failure');
      const desc = makeHostDesc(repoRoot);

      const scanWhenDisabled = await runner.runCommittedCheckwashScan(desc, `${baseOid}..${headOid}`);
      assert.strictEqual(scanWhenDisabled.state, 'Not Run');

      const missingProbe = await probeWindowsBroker(path.join(tmpBase, 'nonexistent-broker.exe'));
      assert.strictEqual(missingProbe.ok, false);

      // Offline report inspection remains fully available without broker
      const offlineFindings = validateFindingsJsonV2(
        fs.readFileSync(path.join(FIXTURES_DIR, 'a01-block.findings.json'), 'utf8')
      );
      const offlineProve = validateProveReportJson(
        fs.readFileSync(path.join(FIXTURES_DIR, 'a11-prove-protection-loss.json'), 'utf8')
      );
      assert.strictEqual(offlineFindings.ok, true);
      assert.strictEqual(offlineProve.ok, true);
      details.push('Broker capability failure disables execution consistently while offline JSON v2 and Prove report viewing remain operational.');
      return 4;
    }
  );

  // -------------------------------------------------------------------------
  // B10: 成品 hash、輸出限額、UTF-8 錯誤：明確失敗，不載入截斷或舊報告
  // -------------------------------------------------------------------------
  await runCase(
    'B10',
    '成品 hash、輸出限額、UTF-8 錯誤：明確失敗，不載入截斷或舊報告',
    async (details) => {
      // 1) Corrupted checkwash.pyz hash in a temp extension root -> scan returns Error state
      const fakeExtRoot = path.join(tmpBase, 'fake-ext-root');
      fs.mkdirSync(path.join(fakeExtRoot, 'bundled'), { recursive: true });
      fs.copyFileSync(path.join(ROOT, 'bundled', 'manifest.json'), path.join(fakeExtRoot, 'bundled', 'manifest.json'));
      copyExecutablePreservingMode(BROKER_EXE, path.join(fakeExtRoot, 'bundled', BROKER_FILENAME));
      fs.writeFileSync(path.join(fakeExtRoot, 'bundled', 'checkwash.pyz'), 'corrupted-bytes', 'utf8');

      const runner = new UnifiedProcessRunner();
      const badPyzDesc = makeHostDesc(repoRoot, { extensionRootPath: fakeExtRoot });
      const badPyzScan = await runner.runCommittedCheckwashScan(badPyzDesc, `${baseOid}..${headOid}`);
      assert.strictEqual(badPyzScan.state, 'Error');
      assert.strictEqual(badPyzScan.joinedReport, null);

      // 2) Invalid UTF-8 bytes in stdout -> flagged as stdoutUtf8Valid=false
      const validDesc = makeHostDesc(repoRoot);
      const badUtf8Exec = await runner.executeGatedProcess({
        hostDesc: validDesc,
        executableSelector: (ctx) => ctx.canonicalPythonPath,
        argsBuilder: () => ['-I', '-S', '-B', '-c', 'import sys; sys.stdout.buffer.write(b"\\xff\\xfeinvalid_utf8")'],
        timeoutMs: 10_000
      });
      assert.strictEqual(badUtf8Exec.ok, true);
      assert.strictEqual(badUtf8Exec.value.outcome.stdoutUtf8Valid, false);

      // 3) Output exceeding limit -> status === 'stdout_overflow', never parsed as truncated JSON
      const overflowExec = await runner.executeGatedProcess({
        hostDesc: validDesc,
        executableSelector: (ctx) => ctx.canonicalPythonPath,
        argsBuilder: () => [
          '-I',
          '-S',
          '-B',
          '-c',
          'import sys; sys.stdout.write("{\\"version\\":2,\\"findings\\":[" + "1," * 100000 + "1]}")'
        ],
        timeoutMs: 10_000,
        maxStdoutBytes: 32 * 1024
      });
      assert.strictEqual(overflowExec.ok, true);
      assert.strictEqual(overflowExec.value.outcome.status, 'stdout_overflow');

      details.push('Corrupted checkwash.pyz SHA-256, invalid UTF-8 bytes (0xFF 0xFE), and output overflow explicitly flagged and rejected without loading truncated/stale reports.');
      return 6;
    }
  );

  // Clean up temporary directory
  fs.rmSync(tmpBase, { recursive: true, force: true });

  const passedCount = results.filter((r) => r.status === 'PASS').length;
  const failedCount = results.filter((r) => r.status === 'FAIL').length;

  let sourceSha = 'unknown';
  try {
    sourceSha = execFileSync(GIT_EXE, ['-C', ROOT, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch {
    // Fallback if outside git checkout
  }

  const execMeta = getPlatformExecutionMetadata();
  const platformLabel = IS_WIN32 ? 'Windows' : 'Linux';
  const reportPayload = {
    phase: `Phase 0B — ${platformLabel} Execution Boundary Verification (Node Integration Suite)`,
    testLayer: 'node-integration',
    realVsCodeDesktopHostCrashReloadUi: 'B08 here verifies broker stdin pipe EOF & standalone Node mock-host SIGKILL; real VS Code Desktop B01 + B08-A reloadWindow + B08-B Extension Host crash are verified separately in installed_vsix_real_vscode_runner',
    evidenceTag: execMeta.evidenceTag,
    executionEnvironment: execMeta.executionEnvironment,
    hostname: execMeta.hostname,
    hostMachineHostname: execMeta.hostMachineHostname,
    containerHostname: execMeta.containerHostname,
    platform: process.platform,
    arch: process.arch,
    sourceSha,
    osRelease: `${os.type()} ${os.release()} (${os.arch()})`,
    nodeVersion: process.version,
    executedAt: new Date().toISOString(),
    exitCode: failedCount === 0 ? 0 : 1,
    totalCases: results.length,
    passed: passedCount,
    failed: failedCount,
    skipped: 0,
    cases: results
  };

  fs.writeFileSync(path.join(EVIDENCE_DIR, 'phase0b-report.json'), JSON.stringify(reportPayload, null, 2), 'utf8');

  const mdLines = [
    `# Phase 0B Report — ${platformLabel} Execution Boundary Verification (B01–B10)`,
    '',
    `- **Host**: \`${reportPayload.hostname}\` (\`${reportPayload.evidenceTag}\`)`,
    `- **OS**: \`${reportPayload.osRelease}\``,
    `- **Executed At**: \`${reportPayload.executedAt}\``,
    `- **Summary**: **${passedCount} / ${results.length} PASS**, **${failedCount} FAIL**, **0 SKIP**`,
    '',
    '| Case ID | Description | Status | Assertions | Details |',
    '| --- | --- | --- | --- | --- |',
    ...results.map(
      (r) =>
        `| \`${r.id}\` | ${r.description} | **${r.status}** | ${r.assertionsCount} | ${r.details.join('; ')}${
          r.error ? ` (ERROR: ${r.error})` : ''
        } |`
    ),
    ''
  ];
  fs.writeFileSync(path.join(EVIDENCE_DIR, 'PHASE0B-REPORT.md'), mdLines.join('\n'), 'utf8');

  console.log(`Phase 0B completed: ${passedCount}/${results.length} PASS, ${failedCount} FAIL.`);
  if (failedCount > 0) {
    process.exitCode = 1;
  }
}

void runPhase0B();
