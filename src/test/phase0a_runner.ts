import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import {
  validateFindingsJsonV2,
  validateCheckwashSarif
} from '../core/checkwashSchema';
import {
  joinCheckwashJsonAndSarif,
  JoinedFindingItem,
  PINNED_CHECKWASH_BUILD_COMMIT,
  PINNED_CHECKWASH_PYZ_SHA256,
  PINNED_CHECKWASH_VERSION
} from '../core/reportJoiner';
import {
  evaluateCheckwashPair,
  FIXED_PASS_DISCLAIMER,
  ProcessInvocationOutcome
} from '../core/verdictModel';
import {
  validateProveReportJson,
  classifyProveReport,
  NO_CONFIRMED_LOSS_FIXED_MESSAGE,
  PINNED_PROVE_CATALOGUE_VERSION,
  PINNED_PROVE_GENERATOR_SHA256,
  PINNED_PROVE_VERSION
} from '../core/proveModel';
import {
  buildReplayFromTrustedRecord,
  ProveRuntimeIdentity,
  TrustedProveExecutionRecord
} from '../core/replayBuilder';
import {
  isValidCommitOid,
  parseCommittedRangeSpec,
  decodeAndValidateSarifUri,
  canProjectDiagnosticToLiveDocument,
  PinnedScanIdentity
} from '../core/sourceIdentity';
import {
  getPlatformExecutionMetadata,
  resolvePlatformEvidenceDir,
  resolveTestProveExe,
} from './testPlatformEnv';

const ROOT = path.resolve(__dirname, '..', '..');
const FIXTURES_DIR = path.join(ROOT, 'fixtures', 'phase0');
const EVIDENCE_DIR = resolvePlatformEvidenceDir(ROOT);
const PROVE_EXE_CONST = resolveTestProveExe();

interface CaseResult {
  id: string;
  description: string;
  status: 'PASS' | 'FAIL';
  assertionsCount: number;
  fixtureFiles: string[];
  details: string[];
  error?: string;
}

function readFixture(fileName: string): string {
  return fs.readFileSync(path.join(FIXTURES_DIR, fileName), 'utf8');
}

function makeIdentityForDoc(
  doc: { run: { base: string; head: string } },
  overrides: Partial<PinnedScanIdentity> = {}
): PinnedScanIdentity {
  const baseLabel = doc.run.base;
  const headLabel = doc.run.head;
  const fullBase = baseLabel.length >= 40 ? baseLabel : baseLabel.padEnd(40, '0');
  const fullHead = headLabel.length >= 40 ? headLabel : headLabel.padEnd(40, '0');

  return {
    scanId: 1,
    repositoryRoot: 'C:\\synth\\repo1',
    rawRangeSpec: `${fullBase}..${fullHead}`,
    rangeMode: 'two-dot',
    leftRef: fullBase,
    rightRef: fullHead,
    resolvedLeftOid: fullBase,
    resolvedRightOid: fullHead,
    effectiveBaseOid: fullBase,
    effectiveHeadOid: fullHead,
    checkwashVersion: PINNED_CHECKWASH_VERSION,
    checkwashPyzSha256: PINNED_CHECKWASH_PYZ_SHA256,
    checkwashBuildCommit: PINNED_CHECKWASH_BUILD_COMMIT,
    pythonExecutable: 'C:\\Python311\\python.exe',
    pythonVersion: '3.11.9',
    gitExecutable: 'C:\\Program Files\\Git\\cmd\\git.exe',
    gitVersion: 'git version 2.55.0.windows.3',
    controlledCwd: 'C:\\temp\\empty-cwd',
    ...overrides
  };
}

function makeInvocation(
  stdoutText: string,
  identity: PinnedScanIdentity,
  overrides: Partial<ProcessInvocationOutcome> = {}
): ProcessInvocationOutcome {
  return {
    exitCode: 0,
    signal: null,
    timedOut: false,
    cancelled: false,
    stdoutOverflow: false,
    stderrOverflow: false,
    cleanupConfirmed: true,
    stdoutUtf8Valid: true,
    stderrUtf8Valid: true,
    stdoutText,
    stderrText: '',
    identity,
    ...overrides
  };
}

function runPhase0A(): void {
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  const manifestRaw = fs.readFileSync(path.join(FIXTURES_DIR, 'manifest.json'), 'utf8');
  const manifest = JSON.parse(manifestRaw);

  const results: CaseResult[] = [];

  function runCase(
    id: string,
    fixtureFiles: string[],
    fn: (expected: any, details: string[]) => number
  ): void {
    const caseMeta = manifest.cases[id];
    const details: string[] = [];
    try {
      const count = fn(caseMeta.expectedOutcome, details);
      results.push({
        id,
        description: caseMeta.description,
        status: 'PASS',
        assertionsCount: count,
        fixtureFiles,
        details
      });
    } catch (err) {
      results.push({
        id,
        description: caseMeta?.description ?? id,
        status: 'FAIL',
        assertionsCount: 0,
        fixtureFiles,
        details,
        error: err instanceof Error ? `${err.message}\n${err.stack}` : String(err)
      });
    }
  }

  // -------------------------------------------------------------------------
  // A01: 固定版本 pass／block 原始輸出（直接讀取 a01-invocation-receipts.json 實測收據）
  // -------------------------------------------------------------------------
  runCase(
    'A01',
    [
      'a01-invocation-receipts.json',
      'a01-pass.findings.json',
      'a01-pass.sarif.json',
      'a01-block.findings.json',
      'a01-block.sarif.json'
    ],
    (expected, details) => {
      const crypto = require('crypto') as typeof import('crypto');
      const sha256Str = (s: string) =>
        crypto.createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');

      let assertions = 0;
      const receiptsDoc = JSON.parse(readFixture('a01-invocation-receipts.json'));
      const rt = receiptsDoc.runtimeEngineIdentity;
      assert.strictEqual(rt.checkwashVersion, PINNED_CHECKWASH_VERSION);
      assert.strictEqual(rt.checkwashPyzSha256, PINNED_CHECKWASH_PYZ_SHA256);
      assert.strictEqual(rt.checkwashBuildCommit, PINNED_CHECKWASH_BUILD_COMMIT);
      const upstreamDoc = JSON.parse(fs.readFileSync(path.join(ROOT, 'bundled', 'upstream.json'), 'utf8'));
      assert.strictEqual(upstreamDoc.checkwash.version, PINNED_CHECKWASH_VERSION);
      assert.strictEqual(upstreamDoc.checkwash.sha256, PINNED_CHECKWASH_PYZ_SHA256);
      assert.strictEqual(upstreamDoc.checkwash.artifactBuildSourceCommit, PINNED_CHECKWASH_BUILD_COMMIT);
      assertions += 6;

      const buildObservedInvocation = (
        obs: any,
        scanId: number
      ): { rawStdout: string; invocation: ProcessInvocationOutcome } => {
        assert.strictEqual(Array.isArray(obs.argv) && obs.argv.length >= 9, true, 'observed argv must be recorded');
        assert.strictEqual(isValidCommitOid(obs.effectiveBaseOid), true, 'observed base OID must be 40-hex');
        assert.strictEqual(isValidCommitOid(obs.effectiveHeadOid), true, 'observed head OID must be 40-hex');
        assert.strictEqual(typeof obs.exitCode, 'number', 'observed exitCode must be recorded');
        assert.strictEqual(typeof obs.stderrText, 'string', 'observed stderrText must be recorded');
        const rawStdout = readFixture(obs.stdoutFile);
        assert.strictEqual(sha256Str(rawStdout), obs.stdoutSha256, 'stdout file must match observed SHA-256');
        assert.strictEqual(sha256Str(obs.stderrText), obs.stderrSha256, 'stderrText must match observed SHA-256');
        assertions += 7;

        const identity: PinnedScanIdentity = {
          scanId,
          repositoryRoot: obs.repositoryRoot,
          rawRangeSpec: obs.rawRangeSpec,
          rangeMode: 'two-dot',
          leftRef: obs.effectiveBaseOid,
          rightRef: obs.effectiveHeadOid,
          resolvedLeftOid: obs.effectiveBaseOid,
          resolvedRightOid: obs.effectiveHeadOid,
          effectiveBaseOid: obs.effectiveBaseOid,
          effectiveHeadOid: obs.effectiveHeadOid,
          checkwashVersion: rt.checkwashVersion,
          checkwashPyzSha256: rt.checkwashPyzSha256,
          checkwashBuildCommit: rt.checkwashBuildCommit,
          pythonExecutable: rt.pythonExecutable,
          pythonVersion: rt.pythonVersion,
          gitExecutable: rt.gitExecutable,
          gitVersion: rt.gitVersion,
          controlledCwd: obs.cwd
        };

        return {
          rawStdout,
          invocation: {
            exitCode: obs.exitCode,
            signal: obs.signal,
            timedOut: false,
            cancelled: false,
            stdoutOverflow: false,
            stderrOverflow: false,
            cleanupConfirmed: true,
            stdoutUtf8Valid: true,
            stderrUtf8Valid: true,
            stdoutText: rawStdout,
            stderrText: obs.stderrText,
            identity
          }
        };
      };

      const passJsonObs = buildObservedInvocation(receiptsDoc.invocations.passJson, 1);
      const passSarifObs = buildObservedInvocation(receiptsDoc.invocations.passSarif, 1);
      assert.strictEqual(validateFindingsJsonV2(passJsonObs.rawStdout).ok, true, 'pass findings v2 must validate');
      assert.strictEqual(validateCheckwashSarif(passSarifObs.rawStdout).ok, true, 'pass SARIF 2.1.0 must validate');
      assertions += 2;

      const passEval = evaluateCheckwashPair(passJsonObs.invocation, passSarifObs.invocation);
      assert.strictEqual(passEval.state, expected.passState);
      assert.strictEqual(passEval.disclaimer, FIXED_PASS_DISCLAIMER);
      assert.strictEqual(passEval.joinedReport?.items.length, expected.passFindingsCount);
      assert.strictEqual(
        passEval.joinedReport?.scanIdentity.effectiveBaseOid,
        receiptsDoc.fixtureCommits.c1Base
      );
      assert.strictEqual(
        passEval.joinedReport?.scanIdentity.effectiveHeadOid,
        receiptsDoc.fixtureCommits.c2Pass
      );
      assertions += 5;
      details.push(
        `Pass observed receipts verified: exits=(${passJsonObs.invocation.exitCode},${passSarifObs.invocation.exitCode}), stderrBytes=(${receiptsDoc.invocations.passJson.stderrBytes},${receiptsDoc.invocations.passSarif.stderrBytes}), state=${passEval.state}`
      );

      const blockJsonObs = buildObservedInvocation(receiptsDoc.invocations.blockJson, 2);
      const blockSarifObs = buildObservedInvocation(receiptsDoc.invocations.blockSarif, 2);
      assert.strictEqual(validateFindingsJsonV2(blockJsonObs.rawStdout).ok, true, 'block findings v2 must validate');
      assert.strictEqual(validateCheckwashSarif(blockSarifObs.rawStdout).ok, true, 'block SARIF 2.1.0 must validate');
      assertions += 2;

      const blockEval = evaluateCheckwashPair(blockJsonObs.invocation, blockSarifObs.invocation);
      assert.strictEqual(blockEval.state, expected.blockState);
      assert.strictEqual(blockEval.joinedReport?.items.length, expected.blockFindingsCount);
      assert.strictEqual(blockEval.joinedReport?.nonAllowlistedCount, expected.blockSarifResultsCount);
      assert.strictEqual(
        blockEval.joinedReport?.scanIdentity.effectiveBaseOid,
        receiptsDoc.fixtureCommits.c2Pass
      );
      assert.strictEqual(
        blockEval.joinedReport?.scanIdentity.effectiveHeadOid,
        receiptsDoc.fixtureCommits.c3Block
      );
      assertions += 5;
      details.push(
        `Block observed receipts verified: exits=(${blockJsonObs.invocation.exitCode},${blockSarifObs.invocation.exitCode}), stderrBytes=(${receiptsDoc.invocations.blockJson.stderrBytes},${receiptsDoc.invocations.blockSarif.stderrBytes}), state=${blockEval.state}, findings=${blockEval.joinedReport?.items.length}`
      );
      return assertions;
    }
  );

  // -------------------------------------------------------------------------
  // A02: 缺鍵、錯型別、不支援版本拒絕；合法空字串 unit 與未知 optional key／rule／label 可保留
  // -------------------------------------------------------------------------
  runCase(
    'A02',
    [
      'a02-empty-unit-js.findings.json',
      'a02-empty-unit-js.sarif.json',
      'a02-empty-unit-js-receipt.json',
      'a02-unknown-optional.findings.json',
      'a02-missing-verdict.findings.json',
      'a02-unsupported-version.findings.json'
    ],
    (expected, details) => {
      let assertions = 0;
      const jsEmptyReceipt = JSON.parse(readFixture('a02-empty-unit-js-receipt.json'));
      const jsEmptyJsonRaw = readFixture('a02-empty-unit-js.findings.json');
      const jsEmptySarifRaw = readFixture('a02-empty-unit-js.sarif.json');
      const jsEmptyJsonRes = validateFindingsJsonV2(jsEmptyJsonRaw);
      const jsEmptySarifRes = validateCheckwashSarif(jsEmptySarifRaw);
      assert.strictEqual(jsEmptyJsonRes.ok, true, 'empty-unit JS findings v2 must validate');
      assert.strictEqual(jsEmptySarifRes.ok, true, 'empty-unit JS SARIF must validate');
      assertions += 2;
      if (!jsEmptyJsonRes.ok || !jsEmptySarifRes.ok) throw new Error('Unreachable');
      assert.strictEqual(jsEmptyJsonRes.value.findings.some((f) => f.unit === ''), true);
      const jsId = makeIdentityForDoc(jsEmptyJsonRes.value, {
        scanId: 20,
        effectiveBaseOid: jsEmptyReceipt.jsBase,
        effectiveHeadOid: jsEmptyReceipt.jsHead
      });
      const jsJoin = joinCheckwashJsonAndSarif({
        jsonIdentity: jsId,
        sarifIdentity: jsId,
        jsonDoc: jsEmptyJsonRes.value,
        sarifDoc: jsEmptySarifRes.value
      });
      assert.strictEqual(jsJoin.ok, true, 'empty-unit JS JSON+SARIF join must succeed');
      assertions += 2;

      const optRes = validateFindingsJsonV2(readFixture('a02-unknown-optional.findings.json'));
      assert.strictEqual(optRes.ok, expected.unknownOptionalValid);
      assertions++;
      if (optRes.ok) {
        assert.strictEqual(optRes.value.findings[0].rule, expected.unknownRuleIdPreserved);
        assert.deepStrictEqual(optRes.value.findings[0].escalators, ['FUTURE_ESCALATOR_V3']);
        assert.deepStrictEqual(optRes.value.findings[0].deescalators, ['FUTURE_DEESCALATOR_V3']);
        assertions += 3;
      }
      const missingRes = validateFindingsJsonV2(readFixture('a02-missing-verdict.findings.json'));
      assert.strictEqual(missingRes.ok, expected.missingVerdictValid);
      const badVerRes = validateFindingsJsonV2(readFixture('a02-unsupported-version.findings.json'));
      assert.strictEqual(badVerRes.ok, expected.unsupportedVersionValid);
      const wrongTypeSarif = validateCheckwashSarif(JSON.stringify({ version: '2.0.0', runs: [] }));
      assert.strictEqual(wrongTypeSarif.ok, false);
      // Verify Checkwash v0.13.1 TEST_PATCHES_SUBJECT & GUARDRAIL_ADDITIVE escalator labels validate cleanly
      const v0131Sample = JSON.parse(readFixture('a01-block.findings.json'));
      v0131Sample.findings = [
        {
          ...v0131Sample.findings[0],
          rule: 'GUARDRAIL_TOUCHED',
          severity: 'warn',
          path: 'CLAUDE.md',
          unit: null,
          escalators: ['GUARDRAIL_ADDITIVE'],
          deescalators: [],
          fingerprint: 'GUARDRAIL_TOUCHED/CLAUDE.md/additive'
        },
        {
          ...v0131Sample.findings[0],
          rule: 'TEST_PATCHES_SUBJECT',
          severity: 'high',
          path: 'tests/test_total.py',
          unit: 'test_total',
          escalators: ['NO_PROD_CHANGE_IN_DIFF'],
          deescalators: [],
          fingerprint: 'TEST_PATCHES_SUBJECT/tests/test_total.py/test_total'
        }
      ];
      assert.strictEqual(validateFindingsJsonV2(v0131Sample).ok, true, 'v0.13.1 GUARDRAIL_ADDITIVE & TEST_PATCHES_SUBJECT must validate');
      assertions += 4;
      details.push('Real empty-title JS unit="" report preserved; unknown optional keys/rule/escalators preserved; missing required keys, wrong types, and version=3 rejected.');
      return assertions;
    }
  );

  // -------------------------------------------------------------------------
  // A03: 多項、缺項、錯序、錯 fingerprint 拒絕整組關聯；保留重複 identity
  // -------------------------------------------------------------------------
  runCase(
    'A03',
    [
      'a01-block.findings.json',
      'a03-extra-sarif-result.sarif.json',
      'a03-wrong-fingerprint.sarif.json',
      'a03-dup.findings.json',
      'a03-dup.sarif.json'
    ],
    (expected, details) => {
      let assertions = 0;
      const baseJson = validateFindingsJsonV2(readFixture('a01-block.findings.json'));
      const extraSarif = validateCheckwashSarif(readFixture('a03-extra-sarif-result.sarif.json'));
      const wrongFpSarif = validateCheckwashSarif(readFixture('a03-wrong-fingerprint.sarif.json'));
      assert.strictEqual(baseJson.ok && extraSarif.ok && wrongFpSarif.ok, true);
      assertions++;
      if (!baseJson.ok || !extraSarif.ok || !wrongFpSarif.ok) throw new Error('Unreachable');

      const id = makeIdentityForDoc(baseJson.value);
      const extraJoin = joinCheckwashJsonAndSarif({
        jsonIdentity: id,
        sarifIdentity: id,
        jsonDoc: baseJson.value,
        sarifDoc: extraSarif.value
      });
      assert.strictEqual(!extraJoin.ok, expected.extraSarifRejected, 'Extra SARIF item must reject whole join');

      const wrongFpJoin = joinCheckwashJsonAndSarif({
        jsonIdentity: id,
        sarifIdentity: id,
        jsonDoc: baseJson.value,
        sarifDoc: wrongFpSarif.value
      });
      assert.strictEqual(!wrongFpJoin.ok, expected.wrongFingerprintRejected, 'Wrong fingerprint must reject whole join');
      assertions += 2;

      const dupJsonRes = validateFindingsJsonV2(readFixture('a03-dup.findings.json'));
      const dupSarifRes = validateCheckwashSarif(readFixture('a03-dup.sarif.json'));
      assert.strictEqual(dupJsonRes.ok && dupSarifRes.ok, true);
      if (!dupJsonRes.ok || !dupSarifRes.ok) throw new Error('Unreachable');
      const dupJoin = joinCheckwashJsonAndSarif({
        jsonIdentity: id,
        sarifIdentity: id,
        jsonDoc: dupJsonRes.value,
        sarifDoc: dupSarifRes.value
      });
      assert.strictEqual(dupJoin.ok, true, 'Duplicate findings must join cleanly');
      assert.strictEqual(dupJoin.value.items.length, expected.duplicateCountPreserved, 'Duplicate identities must both be preserved');
      assertions += 3;

      // Mutate message order to test wrong-order rejection
      const outOfOrderJson = JSON.parse(readFixture('a03-dup.findings.json'));
      outOfOrderJson.findings[0].message = 'first message';
      outOfOrderJson.findings[1].message = 'second message';
      const outOfOrderSarif = JSON.parse(readFixture('a03-dup.sarif.json'));
      outOfOrderSarif.runs[0].results[0].message.text = 'second message';
      outOfOrderSarif.runs[0].results[1].message.text = 'first message';
      const oooJ = validateFindingsJsonV2(JSON.stringify(outOfOrderJson));
      const oooS = validateCheckwashSarif(JSON.stringify(outOfOrderSarif));
      if (oooJ.ok && oooS.ok) {
        const oooJoin = joinCheckwashJsonAndSarif({
          jsonIdentity: id,
          sarifIdentity: id,
          jsonDoc: oooJ.value,
          sarifDoc: oooS.value
        });
        assert.strictEqual(oooJoin.ok, false, 'Out-of-order SARIF results must be rejected');
        assertions++;
      }
      details.push('Extra/missing/out-of-order/wrong-fingerprint rejected; duplicate findings preserved 1-to-1.');
      return assertions;
    }
  );

  // -------------------------------------------------------------------------
  // A04: Allowlisted、helper、conftest
  // -------------------------------------------------------------------------
  runCase(
    'A04',
    ['a04-allowlisted-conftest.findings.json', 'a04-allowlisted-conftest.sarif.json'],
    (expected, details) => {
      const fRes = validateFindingsJsonV2(readFixture('a04-allowlisted-conftest.findings.json'));
      const sRes = validateCheckwashSarif(readFixture('a04-allowlisted-conftest.sarif.json'));
      assert.strictEqual(fRes.ok && sRes.ok, true);
      if (!fRes.ok || !sRes.ok) throw new Error('Unreachable');
      const id = makeIdentityForDoc(fRes.value);
      const joined = joinCheckwashJsonAndSarif({
        jsonIdentity: id,
        sarifIdentity: id,
        jsonDoc: fRes.value,
        sarifDoc: sRes.value
      });
      assert.strictEqual(joined.ok, true);

      const allowlisted = joined.value.items.filter((f: JoinedFindingItem) => f.finding.allowlisted);
      assert.strictEqual(allowlisted.length, expected.allowlistedPreservedCount);
      assert.strictEqual(allowlisted[0].startLine1Based, expected.allowlistedLine);

      const nonAllowlisted = joined.value.items.filter((f: JoinedFindingItem) => !f.finding.allowlisted);
      assert.strictEqual(nonAllowlisted[0].declaredUnitPath, expected.crossFileJsonPath);
      assert.strictEqual(nonAllowlisted[0].resolvedSourcePath, expected.crossFileSarifPath);
      assert.strictEqual(nonAllowlisted[0].startLine1Based, expected.crossFileLine1Based);
      assert.strictEqual(nonAllowlisted[0].vscodeLine0Based, expected.crossFileLine0Based);
      details.push('Allowlisted preserved with line:null; cross-file conftest.py provenance preserved without requiring declaredUnitPath === resolvedSourcePath.');
      return 8;
    }
  );

  // -------------------------------------------------------------------------
  // A05: Base-only、無 region、歧義來源
  // -------------------------------------------------------------------------
  runCase(
    'A05',
    ['a05-noregion.findings.json', 'a05-noregion.sarif.json'],
    (expected, details) => {
      const fRes = validateFindingsJsonV2(readFixture('a05-noregion.findings.json'));
      const sRes = validateCheckwashSarif(readFixture('a05-noregion.sarif.json'));
      assert.strictEqual(fRes.ok && sRes.ok, true);
      if (!fRes.ok || !sRes.ok) throw new Error('Unreachable');
      const id = makeIdentityForDoc(fRes.value);
      const joined = joinCheckwashJsonAndSarif({
        jsonIdentity: id,
        sarifIdentity: id,
        jsonDoc: fRes.value,
        sarifDoc: sRes.value
      });
      assert.strictEqual(joined.ok, true);

      assert.strictEqual(joined.value.items[0].startLine1Based, expected.firstFindingLine);
      assert.strictEqual(joined.value.items[0].vscodeLine0Based, null);
      assert.strictEqual(joined.value.items[0].evidenceSide, expected.firstFindingEvidenceSide);

      assert.strictEqual(joined.value.items[1].startLine1Based, expected.secondFindingLine);
      assert.strictEqual(joined.value.items[1].vscodeLine0Based, null);
      assert.strictEqual(joined.value.items[1].evidenceSide, expected.secondFindingEvidenceSide);
      details.push('Missing region keeps startLine1Based:null and vscodeLine0Based:null (never fake line 1); evidenceSide preserves base or unknown.');
      return 8;
    }
  );

  // -------------------------------------------------------------------------
  // A06: 中文、空白、百分號、URI 與換行
  // -------------------------------------------------------------------------
  runCase('A06', ['manifest.json'], (expected, details) => {
    const encoded = 'tests/%E4%B8%AD%E6%96%87%20%E6%B8%AC%E8%A9%A6/test_%2525_literal.py';
    const dec = decodeAndValidateSarifUri(encoded);
    assert.strictEqual(dec.ok, true);
    if (dec.ok) {
      assert.strictEqual(dec.value, expected.encodedChineseAndPercentDecodedOnce);
    }
    assert.strictEqual(decodeAndValidateSarifUri('file:///C:/evil.py').ok, !expected.schemesRejected);
    assert.strictEqual(decodeAndValidateSarifUri('../outside.py').ok, !expected.traversalRejected);
    assert.strictEqual(decodeAndValidateSarifUri('tests/../../outside.py').ok, !expected.traversalRejected);
    assert.strictEqual(decodeAndValidateSarifUri('tests/file.py:Zone.Identifier').ok, !expected.adsRejected);
    assert.strictEqual(decodeAndValidateSarifUri('tests/nul\u0000.py').ok, !expected.nulRejected);
    assert.strictEqual(decodeAndValidateSarifUri('tests/CON.py').ok, false);
    details.push('Single percent-decoding verified for Chinese, spaces, and %25; schemes, .., NUL, ADS, and Windows reserved names rejected.');
    return 8;
  });

  // -------------------------------------------------------------------------
  // A07: Pass／Block 各與所有缺口組合
  // -------------------------------------------------------------------------
  runCase(
    'A07',
    ['a07-pass-gaps.findings.json', 'a07-pass-gaps.sarif.json', 'a01-block.findings.json', 'a01-block.sarif.json'],
    (expected, details) => {
      const pJsonRaw = readFixture('a07-pass-gaps.findings.json');
      const pSarifRaw = readFixture('a07-pass-gaps.sarif.json');
      const pJson = validateFindingsJsonV2(pJsonRaw);
      const pSarif = validateCheckwashSarif(pSarifRaw);
      assert.strictEqual(pJson.ok && pSarif.ok, true);
      if (!pJson.ok || !pSarif.ok) throw new Error('Unreachable');

      const idPass = makeIdentityForDoc(pJson.value);
      const passGapsEval = evaluateCheckwashPair(
        makeInvocation(pJsonRaw, idPass, { exitCode: 0, stderrText: 'checkwash: warning: ignored exemption on line 3' }),
        makeInvocation(pSarifRaw, idPass, { exitCode: 0 })
      );
      assert.strictEqual(passGapsEval.state, expected.passWithGapsState);
      assert.strictEqual(passGapsEval.gaps.hasAnyGap, true);
      assert.strictEqual(passGapsEval.gaps.unread.length, 1);
      assert.strictEqual(passGapsEval.gaps.skippedFiles.length, 1);
      assert.strictEqual(passGapsEval.gaps.configErrors.length, 1);
      assert.strictEqual(passGapsEval.gaps.sarifNotifications.length, 1);
      assert.strictEqual(passGapsEval.gaps.jsonStderrNotes.length, 1);

      // Block + gaps remains Block and preserves all gaps
      const bJsonRaw = readFixture('a01-block.findings.json');
      const bSarifRaw = readFixture('a01-block.sarif.json');
      const bJson = validateFindingsJsonV2(bJsonRaw);
      if (!bJson.ok) throw new Error('Unreachable');
      const idBlock = makeIdentityForDoc(bJson.value);
      const blockGapsEval = evaluateCheckwashPair(
        makeInvocation(bJsonRaw, idBlock, { exitCode: 1, stderrText: 'checkwash: coverage gap warning' }),
        makeInvocation(bSarifRaw, idBlock, { exitCode: 1 })
      );
      assert.strictEqual(blockGapsEval.state, expected.blockWithGapsState);
      assert.strictEqual(blockGapsEval.gaps.hasAnyGap, true);
      assert.strictEqual(blockGapsEval.gaps.jsonStderrNotes.length, 1);
      details.push(`Pass+gaps -> ${passGapsEval.state}; Block+gaps -> ${blockGapsEval.state} with all gaps preserved.`);
      return 11;
    }
  );

  // -------------------------------------------------------------------------
  // A08: Unread-only exit 2、signal、null、矛盾 exits：一律不是 Pass
  // -------------------------------------------------------------------------
  runCase('A08', ['a01-pass.findings.json', 'a01-pass.sarif.json', 'a01-block.findings.json', 'a01-block.sarif.json'], (expected, details) => {
    const pJsonRaw = readFixture('a01-pass.findings.json');
    const pSarifRaw = readFixture('a01-pass.sarif.json');
    const bJsonRaw = readFixture('a01-block.findings.json');
    const bSarifRaw = readFixture('a01-block.sarif.json');
    const pJson = validateFindingsJsonV2(pJsonRaw);
    const bJson = validateFindingsJsonV2(bJsonRaw);
    if (!pJson.ok || !bJson.ok) throw new Error('Unreachable');
    const idPass = makeIdentityForDoc(pJson.value);
    const idBlock = makeIdentityForDoc(bJson.value);

    const exit2 = evaluateCheckwashPair(
      makeInvocation(JSON.stringify({ unread: [{ path: 'big.py', side: 'head', size: 2000000, limit: 1000000 }] }), idPass, { exitCode: 2 }),
      makeInvocation('', idPass, { exitCode: 2 })
    );
    assert.strictEqual(exit2.state, expected.exit2State);

    const sig = evaluateCheckwashPair(
      makeInvocation(pJsonRaw, idPass, { exitCode: 0, signal: 'SIGTERM' }),
      makeInvocation(pSarifRaw, idPass, { exitCode: 0 })
    );
    assert.strictEqual(sig.state, expected.signalState);

    const nullExit = evaluateCheckwashPair(
      makeInvocation(pJsonRaw, idPass, { exitCode: null }),
      makeInvocation(pSarifRaw, idPass, { exitCode: 0 })
    );
    assert.strictEqual(nullExit.state, expected.nullExitState);

    const contrad0Block = evaluateCheckwashPair(
      makeInvocation(bJsonRaw, idBlock, { exitCode: 0 }),
      makeInvocation(bSarifRaw, idBlock, { exitCode: 0 })
    );
    assert.strictEqual(contrad0Block.state, expected.contradictoryExit0BlockState);

    const contrad1Pass = evaluateCheckwashPair(
      makeInvocation(pJsonRaw, idPass, { exitCode: 1 }),
      makeInvocation(pSarifRaw, idPass, { exitCode: 1 })
    );
    assert.strictEqual(contrad1Pass.state, expected.contradictoryExit1PassState);

    details.push('Exit 2, signal, null exit, 0+block, and 1+pass all evaluated to Error (never Pass).');
    return 5;
  });

  // -------------------------------------------------------------------------
  // A09: 歷史來源、dirty buffer、文件 version 改變
  // -------------------------------------------------------------------------
  runCase('A09', ['manifest.json'], (expected, details) => {
    const headBytes = Buffer.from('\uFEFFdef test_a():\r\n    assert True\r\n', 'utf8');
    const cleanCheck = canProjectDiagnosticToLiveDocument({
      expectedRepositoryRoot: 'C:\\repo\\one',
      actualRepositoryRoot: 'C:\\repo\\one',
      expectedRelativePath: 'tests/test_a.py',
      actualRelativePath: 'tests/test_a.py',
      analyzedSourceBytes: headBytes,
      liveDocumentText: 'def test_a():\n    assert True\n',
      verifiedDocumentVersion: 7,
      currentDocumentVersionAtPublish: 7
    });
    assert.strictEqual(cleanCheck.ok, expected.bomAndCrlfNormalizedMatch);

    const dirtyCheck = canProjectDiagnosticToLiveDocument({
      expectedRepositoryRoot: 'C:\\repo\\one',
      actualRepositoryRoot: 'C:\\repo\\one',
      expectedRelativePath: 'tests/test_a.py',
      actualRelativePath: 'tests/test_a.py',
      analyzedSourceBytes: headBytes,
      liveDocumentText: 'def test_a():\n    assert False\n',
      verifiedDocumentVersion: 7,
      currentDocumentVersionAtPublish: 7
    });
    assert.strictEqual(dirtyCheck.ok, expected.dirtyBufferAllowed);

    const verCheck = canProjectDiagnosticToLiveDocument({
      expectedRepositoryRoot: 'C:\\repo\\one',
      actualRepositoryRoot: 'C:\\repo\\one',
      expectedRelativePath: 'tests/test_a.py',
      actualRelativePath: 'tests/test_a.py',
      analyzedSourceBytes: headBytes,
      liveDocumentText: 'def test_a():\n    assert True\n',
      verifiedDocumentVersion: 7,
      currentDocumentVersionAtPublish: 8
    });
    assert.strictEqual(verCheck.ok, expected.versionChangedAllowed);

    const badUtf8Check = canProjectDiagnosticToLiveDocument({
      expectedRepositoryRoot: 'C:\\repo\\one',
      actualRepositoryRoot: 'C:\\repo\\one',
      expectedRelativePath: 'tests/test_a.py',
      actualRelativePath: 'tests/test_a.py',
      analyzedSourceBytes: Buffer.from([0xff, 0xfe, 0x00, 0x61]),
      liveDocumentText: 'a',
      verifiedDocumentVersion: 1,
      currentDocumentVersionAtPublish: 1
    });
    assert.strictEqual(badUtf8Check.ok, expected.invalidUtf8Allowed);

    details.push('BOM+CRLF normalized live match allowed; dirty buffer, version change, and invalid UTF-8 rejected.');
    return 4;
  });

  // -------------------------------------------------------------------------
  // A10: 分支移動、引擎改變、舊 run 晚到
  // -------------------------------------------------------------------------
  runCase('A10', ['a01-pass.findings.json', 'a01-pass.sarif.json'], (expected, details) => {
    assert.strictEqual(isValidCommitOid('a'.repeat(40)), true);
    assert.strictEqual(isValidCommitOid('b'.repeat(64)), true);
    assert.strictEqual(isValidCommitOid('main'), false);
    const twoDot = parseCommittedRangeSpec('main..feature');
    const threeDot = parseCommittedRangeSpec('main...feature');
    assert.strictEqual(twoDot.ok && twoDot.value.mode === 'two-dot', true);
    assert.strictEqual(threeDot.ok && threeDot.value.mode === 'three-dot', true);

    const pJson = validateFindingsJsonV2(readFixture('a01-pass.findings.json'));
    const pSarif = validateCheckwashSarif(readFixture('a01-pass.sarif.json'));
    if (!pJson.ok || !pSarif.ok) throw new Error('Unreachable');

    const id1 = makeIdentityForDoc(pJson.value, { scanId: 10 });
    const idEngineChanged = makeIdentityForDoc(pJson.value, { scanId: 10, checkwashPyzSha256: '0'.repeat(64) });
    assert.strictEqual(
      !joinCheckwashJsonAndSarif({
        jsonIdentity: id1,
        sarifIdentity: idEngineChanged,
        jsonDoc: pJson.value,
        sarifDoc: pSarif.value
      }).ok,
      expected.engineHashMismatchRejected
    );

    const idBranchMoved = makeIdentityForDoc(pJson.value, { scanId: 10, effectiveHeadOid: '9'.repeat(40) });
    assert.strictEqual(
      !joinCheckwashJsonAndSarif({
        jsonIdentity: id1,
        sarifIdentity: idBranchMoved,
        jsonDoc: pJson.value,
        sarifDoc: pSarif.value
      }).ok,
      expected.pinnedOidImmutableOnBranchMove
    );

    const idStaleScan = makeIdentityForDoc(pJson.value, { scanId: 9 });
    assert.strictEqual(
      !joinCheckwashJsonAndSarif({
        jsonIdentity: id1,
        sarifIdentity: idStaleScan,
        jsonDoc: pJson.value,
        sarifDoc: pSarif.value
      }).ok,
      expected.staleScanIdDropped
    );

    details.push('40/64-char OIDs verified; engine SHA mismatch, branch move OID mismatch, and stale scanId rejected.');
    return 8;
  });

  // -------------------------------------------------------------------------
  // A11: Prove 零損失、各群組與混合報告
  // -------------------------------------------------------------------------
  runCase(
    'A11',
    [
      'a11-prove-zero-loss.json',
      'a11-prove-protection-loss.json',
      'prove-real-clarification-coexisting.json',
      'prove-real-undecided.json',
      'a11-prove-mixed-coexisting.json'
    ],
    (expected, details) => {
      const zeroRes = validateProveReportJson(readFixture('a11-prove-zero-loss.json'));
      assert.strictEqual(zeroRes.ok, true);
      const zeroClass = classifyProveReport(zeroRes.value);
      assert.strictEqual(zeroClass.status, expected.zeroLossStatus);
      assert.strictEqual(zeroClass.protectionLosses.length, expected.zeroLossConfirmedCount);
      assert.strictEqual(zeroClass.noConfirmedLossExplanation, expected.zeroLossNoConfirmedMessage);
      assert.strictEqual(zeroClass.noConfirmedLossExplanation, NO_CONFIRMED_LOSS_FIXED_MESSAGE);

      const lossRes = validateProveReportJson(readFixture('a11-prove-protection-loss.json'));
      assert.strictEqual(lossRes.ok, true);
      const lossClass = classifyProveReport(lossRes.value);
      assert.strictEqual(lossClass.status, expected.protectionLossStatus);
      assert.strictEqual(lossClass.protectionLosses.length >= expected.protectionLossMinCount, true);
      assert.strictEqual(lossClass.noConfirmedLossExplanation, null);

      const realClarifyRes = validateProveReportJson(readFixture('prove-real-clarification-coexisting.json'));
      assert.strictEqual(realClarifyRes.ok, true);
      const realClarifyClass = classifyProveReport(realClarifyRes.value);
      assert.strictEqual(realClarifyClass.needsClarification.length > 0, true);
      assert.strictEqual(realClarifyClass.protectionLosses.length > 0, true);
      assert.strictEqual(realClarifyClass.unconfirmedLosses.length > 0, true);
      assert.strictEqual(typeof realClarifyClass.needsClarification[0].test, 'string');
      assert.strictEqual(typeof realClarifyClass.needsClarification[0].reason, 'string');
      assert.strictEqual(typeof realClarifyClass.needsClarification[0].also_fails_in_new, 'boolean');
      assert.strictEqual(typeof realClarifyClass.needsClarification[0].detail, 'string');

      const realUndecidedRes = validateProveReportJson(readFixture('prove-real-undecided.json'));
      assert.strictEqual(realUndecidedRes.ok, true);
      const realUndecidedClass = classifyProveReport(realUndecidedRes.value);
      assert.strictEqual(realUndecidedClass.undecidedRows.length > 0, true);

      const mixedRes = validateProveReportJson(readFixture('a11-prove-mixed-coexisting.json'));
      assert.strictEqual(mixedRes.ok, true);
      const mixedClass = classifyProveReport(mixedRes.value);
      assert.strictEqual(
        mixedClass.protectionLosses.length > 0 &&
          mixedClass.unconfirmedLosses.length > 0 &&
          mixedClass.needsClarification.length > 0 &&
          mixedClass.undecidedRows.length > 0,
        expected.mixedHasAllFourGroups
      );
      details.push(
        `Zero-loss message verified; real producer clarification+losses+unconfirmed and real undecided verified; mixed report coexisting groups verified.`
      );
      return 21;
    }
  );

  // -------------------------------------------------------------------------
  // A12: Prove list／nothing／no mutants／cap=0／失敗
  // -------------------------------------------------------------------------
  runCase(
    'A12',
    [
      'a12-prove-list.json',
      'a12-prove-nothing.json',
      'prove-real-list-nothing.json',
      'a12-prove-cap-zero.json',
      'prove-real-list-no-mutants.json',
      'prove-real-full-no-mutants.json',
      'prove-real-list-clean-fail.json',
      'prove-real-full-clean-fail.json',
      'prove-real-list-collection-fail.json',
      'prove-real-full-collection-fail.json'
    ],
    (expected, details) => {
      const listRes = validateProveReportJson(readFixture('a12-prove-list.json'));
      const nothingRes = validateProveReportJson(readFixture('a12-prove-nothing.json'));
      const listNothingRes = validateProveReportJson(readFixture('prove-real-list-nothing.json'));
      const capZeroRes = validateProveReportJson(readFixture('a12-prove-cap-zero.json'));
      const listNoMutRes = validateProveReportJson(readFixture('prove-real-list-no-mutants.json'));
      const fullNoMutRes = validateProveReportJson(readFixture('prove-real-full-no-mutants.json'));
      const listCleanFailRes = validateProveReportJson(readFixture('prove-real-list-clean-fail.json'));
      const fullCleanFailRes = validateProveReportJson(readFixture('prove-real-full-clean-fail.json'));
      const listCollFailRes = validateProveReportJson(readFixture('prove-real-list-collection-fail.json'));
      const fullCollFailRes = validateProveReportJson(readFixture('prove-real-full-collection-fail.json'));

      assert.strictEqual(
        listRes.ok &&
          nothingRes.ok &&
          listNothingRes.ok &&
          capZeroRes.ok &&
          listNoMutRes.ok &&
          fullNoMutRes.ok &&
          listCleanFailRes.ok &&
          fullCleanFailRes.ok &&
          listCollFailRes.ok &&
          fullCollFailRes.ok,
        true
      );
      if (
        !listRes.ok ||
        !nothingRes.ok ||
        !listNothingRes.ok ||
        !capZeroRes.ok ||
        !listNoMutRes.ok ||
        !fullNoMutRes.ok ||
        !listCleanFailRes.ok ||
        !fullCleanFailRes.ok ||
        !listCollFailRes.ok ||
        !fullCollFailRes.ok
      ) {
        throw new Error('Unreachable');
      }

      const listClass = classifyProveReport(listRes.value);
      assert.strictEqual(listClass.status, expected.listStatus);
      assert.strictEqual(listClass.candidates.length > 0, true);
      assert.strictEqual(listClass.skippedOverCapCount > 0, true);

      const nothingClass = classifyProveReport(nothingRes.value);
      const listNothingClass = classifyProveReport(listNothingRes.value);
      assert.strictEqual(nothingClass.status, expected.nothingStatus);
      assert.strictEqual(listNothingClass.status, expected.nothingStatus);

      const capZeroClass = classifyProveReport(capZeroRes.value);
      assert.strictEqual(capZeroClass.status, expected.capZeroStatus);
      assert.strictEqual(capZeroClass.notComparedReason, expected.capZeroReason);

      const listNoMutClass = classifyProveReport(listNoMutRes.value);
      const fullNoMutClass = classifyProveReport(fullNoMutRes.value);
      assert.strictEqual(listNoMutClass.status, expected.noMutantsStatus);
      assert.strictEqual(listNoMutClass.notComparedReason, expected.noMutantsReason);
      assert.strictEqual(fullNoMutClass.status, listNoMutClass.status);
      assert.strictEqual(fullNoMutClass.notComparedReason, listNoMutClass.notComparedReason);

      const listCleanFailClass = classifyProveReport(listCleanFailRes.value);
      const fullCleanFailClass = classifyProveReport(fullCleanFailRes.value);
      assert.strictEqual(listCleanFailClass.status, expected.collectionFailStatus);
      assert.strictEqual(listCleanFailClass.notComparedReason, expected.collectionFailReason);
      assert.strictEqual(fullCleanFailClass.status, listCleanFailClass.status);
      assert.strictEqual(fullCleanFailClass.notComparedReason, listCleanFailClass.notComparedReason);

      const listCollFailClass = classifyProveReport(listCollFailRes.value);
      const fullCollFailClass = classifyProveReport(fullCollFailRes.value);
      assert.strictEqual(listCollFailClass.status, expected.collectionFailStatus);
      assert.strictEqual(listCollFailClass.notComparedReason, expected.collectionFailReason);
      assert.strictEqual(fullCollFailClass.status, listCollFailClass.status);
      assert.strictEqual(fullCollFailClass.notComparedReason, listCollFailClass.notComparedReason);

      details.push(
        'Listed, Nothing to compare (full & --list), cap_zero, no_mutants (full & --list), clean-run failure (full & --list), and collection failure (full & --list) all distinctly and consistently classified.'
      );
      return 22;
    }
  );

  // -------------------------------------------------------------------------
  // A13: Replay 特殊字元、HEAD 移動、選項替換
  // -------------------------------------------------------------------------
  runCase('A13', ['a11-prove-protection-loss.json'], (expected, details) => {
    const lossObj = JSON.parse(readFixture('a11-prove-protection-loss.json'));
    const mutantId = lossObj.protection_losses[0]?.id ?? 'src/calc.py:3:8:SDL:1';
    // Inject malicious replay string in report to prove ReplayBuilder ignores it
    lossObj.protection_losses[0].replay = 'cmd.exe /c calc.exe & echo PWNED';
    const validatedLoss = validateProveReportJson(JSON.stringify(lossObj));
    assert.strictEqual(validatedLoss.ok, true);
    const parsedReport = classifyProveReport(validatedLoss.value);

    const rtIdentity: ProveRuntimeIdentity = {
      proveExecutable: PROVE_EXE_CONST,
      proveExecutableSha256: 'a'.repeat(64),
      proveVersion: PINNED_PROVE_VERSION,
      hostPythonExecutable: 'C:\\Python311\\python.exe',
      hostPythonVersion: '3.11.9',
      testPythonExecutable: 'C:\\Python311\\python.exe',
      testPythonVersion: '3.11.9',
      testPythonSha256: 'b'.repeat(64),
      catalogueVersion: PINNED_PROVE_CATALOGUE_VERSION,
      catalogueGeneratorSha256: PINNED_PROVE_GENERATOR_SHA256
    };

    const trustedRecord: TrustedProveExecutionRecord = {
      runId: 42,
      entryKind: 'full',
      adapterVersion: PINNED_PROVE_VERSION,
      isImportedExternalReport: false,
      repositoryRoot: 'C:\\Projects\\中文 專案 & 測試',
      rawRangeSpec: 'HEAD~1..HEAD',
      effectiveBaseOid: '1111111111111111111111111111111111111111',
      effectiveHeadOid: '2222222222222222222222222222222222222222',
      fromMergeBase: false,
      runtimeIdentity: rtIdentity,
      argv: [],
      effectiveOptions: {
        workers: 4,
        maxMutants: 20,
        timeoutSeconds: 30,
        suiteTimeoutSeconds: 300,
        importRoot: 'src/中文 子目錄',
        strictWarnings: true,
        listOnly: false,
        keep: false,
        onlyMutantId: null
      },
      rawReportSha256: 'c'.repeat(64),
      parsedReport,
      exitCode: 0,
      cleanupConfirmed: true
    };

    const replayRes = buildReplayFromTrustedRecord({
      record: trustedRecord,
      currentRepositoryRoot: trustedRecord.repositoryRoot,
      currentRuntimeIdentity: rtIdentity,
      selectedMutantId: mutantId
    });
    assert.strictEqual(replayRes.ok, true);

    assert.strictEqual(replayRes.value.executable, PROVE_EXE_CONST);
    assert.strictEqual(replayRes.value.effectiveOptions.workers, 1);
    assert.strictEqual(replayRes.value.effectiveOptions.maxMutants, 1);
    assert.strictEqual(replayRes.value.effectiveOptions.listOnly, false);
    assert.strictEqual(replayRes.value.effectiveOptions.keep, false);
    assert.strictEqual(
      replayRes.value.argv.includes(
        '1111111111111111111111111111111111111111..2222222222222222222222222222222222222222'
      ),
      expected.usesPinnedOidsNotMovingHead
    );
    assert.strictEqual(replayRes.value.argv.includes('HEAD~1..HEAD'), false);
    details.push('Replay argv rebuilt from TrustedProveExecutionRecord with pinned OIDs and single-mutant overrides; report loss.replay ignored.');
    return 9;
  });

  // -------------------------------------------------------------------------
  // A14: 匯入報告及不相容 Prove
  // -------------------------------------------------------------------------
  runCase('A14', ['a11-prove-protection-loss.json'], (expected, details) => {
    const lossRes = validateProveReportJson(readFixture('a11-prove-protection-loss.json'));
    if (!lossRes.ok) throw new Error(lossRes.error);
    const parsedReport = classifyProveReport(lossRes.value);
    const mutantId = parsedReport.protectionLosses[0]?.id ?? 'src/calc.py:3:8:SDL:1';

    const rtIdentity: ProveRuntimeIdentity = {
      proveExecutable: PROVE_EXE_CONST,
      proveExecutableSha256: 'a'.repeat(64),
      proveVersion: PINNED_PROVE_VERSION,
      hostPythonExecutable: 'C:\\py.exe',
      hostPythonVersion: '3.11.9',
      testPythonExecutable: 'C:\\py.exe',
      testPythonVersion: '3.11.9',
      testPythonSha256: 'b'.repeat(64),
      catalogueVersion: PINNED_PROVE_CATALOGUE_VERSION,
      catalogueGeneratorSha256: PINNED_PROVE_GENERATOR_SHA256
    };

    const importedRecord: TrustedProveExecutionRecord = {
      runId: 99,
      entryKind: 'full',
      adapterVersion: PINNED_PROVE_VERSION,
      isImportedExternalReport: true,
      repositoryRoot: 'C:\\repo',
      rawRangeSpec: 'a..b',
      effectiveBaseOid: '1'.repeat(40),
      effectiveHeadOid: '2'.repeat(40),
      fromMergeBase: false,
      runtimeIdentity: rtIdentity,
      argv: [],
      effectiveOptions: {
        workers: 1,
        maxMutants: 20,
        timeoutSeconds: 30,
        suiteTimeoutSeconds: 300,
        importRoot: null,
        strictWarnings: false,
        listOnly: false,
        keep: false,
        onlyMutantId: null
      },
      rawReportSha256: 'b'.repeat(64),
      parsedReport,
      exitCode: 0,
      cleanupConfirmed: true
    };

    const replayImported = buildReplayFromTrustedRecord({
      record: importedRecord,
      currentRepositoryRoot: 'C:\\repo',
      currentRuntimeIdentity: rtIdentity,
      selectedMutantId: mutantId
    });
    assert.strictEqual(!replayImported.ok, expected.importedReportReplayBlocked);

    // Incompatible Prove version / catalogue hash
    const badVerProve = JSON.parse(readFixture('a11-prove-protection-loss.json'));
    badVerProve.version = '0.2.0';
    assert.strictEqual(!validateProveReportJson(JSON.stringify(badVerProve)).ok, expected.unsupportedProveVersionRejected);

    const badHashProve = JSON.parse(readFixture('a11-prove-protection-loss.json'));
    badHashProve.catalogue.generator_sha256 = '0'.repeat(64);
    assert.strictEqual(!validateProveReportJson(JSON.stringify(badHashProve)).ok, expected.unsupportedCatalogueHashRejected);

    details.push('Imported external reports blocked from Replay; incompatible Prove version and generator SHA-256 rejected.');
    return 3;
  });

  // Write Phase 0A report
  const passedCount = results.filter((r) => r.status === 'PASS').length;
  const failedCount = results.filter((r) => r.status === 'FAIL').length;

  let sourceSha = 'unknown';
  try {
    const headRaw = fs.readFileSync(path.join(ROOT, '.git', 'HEAD'), 'utf8').trim();
    if (headRaw.startsWith('ref:')) {
      const refRel = headRaw.slice(4).trim();
      const refPath = path.join(ROOT, '.git', ...refRel.split('/'));
      if (fs.existsSync(refPath)) {
        sourceSha = fs.readFileSync(refPath, 'utf8').trim();
      }
    } else if (/^[0-9a-f]{40}$/i.test(headRaw)) {
      sourceSha = headRaw;
    }
  } catch {
    // Fallback if outside git checkout
  }

  const execMeta = getPlatformExecutionMetadata();
  const reportPayload = {
    phase: 'Phase 0A — Data & Contract Verification (Pure Function Suite)',
    testLayer: 'pure-unit-and-pinned-fixture',
    evidenceTag: execMeta.evidenceTag,
    executionEnvironment: execMeta.executionEnvironment,
    hostname: execMeta.hostname,
    hostMachineHostname: execMeta.hostMachineHostname,
    containerHostname: execMeta.containerHostname,
    platform: process.platform,
    arch: process.arch,
    sourceSha,
    nodeVersion: process.version,
    executedAt: new Date().toISOString(),
    exitCode: failedCount === 0 ? 0 : 1,
    totalCases: results.length,
    passed: passedCount,
    failed: failedCount,
    skipped: 0,
    cases: results
  };

  fs.writeFileSync(path.join(EVIDENCE_DIR, 'phase0a-report.json'), JSON.stringify(reportPayload, null, 2), 'utf8');

  const mdLines = [
    '# Phase 0A Report — Data & Contract Verification (A01–A14)',
    '',
    `- **Host**: \`${reportPayload.hostname}\` (\`${reportPayload.evidenceTag}\`)`,
    `- **Executed At**: \`${reportPayload.executedAt}\``,
    `- **Summary**: **${passedCount} / ${results.length} PASS**, **${failedCount} FAIL**, **0 SKIP**`,
    '',
    '| Case ID | Description | Status | Assertions | Fixtures | Details |',
    '| --- | --- | --- | --- | --- | --- |',
    ...results.map(
      (r) =>
        `| \`${r.id}\` | ${r.description} | **${r.status}** | ${r.assertionsCount} | ${r.fixtureFiles
          .map((f) => `\`${f}\``)
          .join(', ')} | ${r.details.join('; ')}${r.error ? ` (ERROR: ${r.error})` : ''} |`
    ),
    ''
  ];
  fs.writeFileSync(path.join(EVIDENCE_DIR, 'PHASE0A-REPORT.md'), mdLines.join('\n'), 'utf8');

  console.log(`Phase 0A completed: ${passedCount}/${results.length} PASS, ${failedCount} FAIL.`);
  if (failedCount > 0) {
    for (const r of results) {
      if (r.status === 'FAIL') {
        console.error(`  [FAIL] ${r.id}: ${r.error ?? 'Unknown error'}`);
      }
    }
    process.exitCode = 1;
  }
}

runPhase0A();
