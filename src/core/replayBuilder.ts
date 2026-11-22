/**
 * core/replayBuilder.ts
 *
 * Builds verified Prove execution argv and single-mutant Replay plans strictly
 * from extension-owned TrustedProveExecutionRecord objects.
 * Zero VS Code UI dependency; never spawns processes.
 *
 * Enforces Rev 3 §9.2, §9.3, §9.5 (A13, A14):
 * - Report data (including loss.replay, report.python, report.options) NEVER overrides
 *   the extension's trusted execution record or specifies executables.
 * - External imported reports are strictly read-only and cannot build a Replay.
 * - Replay binds the pinned effectiveBaseOid..effectiveHeadOid from the trusted record,
 *   so subsequent branch/HEAD movements never alter the replayed commits.
 * - Forces single-mutant replay adjustments:
 *   workers=1, max-mutants=1, list_only=false, keep=false, --only <verifiedMutantId>.
 * - Rejects replay if runtime/Prove/Python/repository identity changed since the record was created.
 */

import * as crypto from "crypto";
import { ValidationResult } from "./checkwashSchema";
import {
  ParsedProveReport,
  PINNED_PROVE_CATALOGUE_VERSION,
  PINNED_PROVE_GENERATOR_SHA256,
  PINNED_PROVE_VERSION,
} from "./proveModel";
import {
  decodeAndValidateSarifUri,
  isValidCommitOid,
  sanitizeUntrustedDisplayString,
} from "./sourceIdentity";

export const DEFAULT_PROVE_WORKERS = 1;
export const DEFAULT_PROVE_MAX_MUTANTS = 20;
export const DEFAULT_PROVE_MUTANT_TIMEOUT_S = 30;
export const DEFAULT_PROVE_SUITE_TIMEOUT_S = 300;
export const DEFAULT_PROVE_WALL_CLOCK_BUDGET_MS = 30 * 60 * 1000; // 30 minutes

export type ProveEntryKind = "list" | "full" | "replay";

export interface BoundedProveOptions {
  workers: number;
  maxMutants: number;
  timeoutSeconds: number;
  suiteTimeoutSeconds: number;
  importRoot: string | null;
  strictWarnings: boolean;
  listOnly: boolean;
  keep: false;
  onlyMutantId: string | null;
}

export interface ProveRuntimeIdentity {
  proveExecutable: string;
  proveExecutableSha256: string;
  proveVersion: string;
  hostPythonExecutable: string;
  hostPythonVersion: string;
  hostPythonSha256?: string;
  hostGitExecutable?: string;
  hostGitVersion?: string;
  hostGitSha256?: string;
  testPythonExecutable: string;
  testPythonVersion: string;
  testPythonSha256: string;
  catalogueVersion: string;
  catalogueGeneratorSha256: string;
}

export interface PreparedProveExecutionPlanFields {
  readonly planId: string;
  readonly entryKind: ProveEntryKind;
  readonly repositoryRoot: string;
  readonly rawRangeSpec: string;
  readonly effectiveBaseOid: string;
  readonly effectiveHeadOid: string;
  readonly fromMergeBase: boolean;
  readonly recordRunId: number | null;
  readonly selectedMutantId: string | null;
  readonly runtimeIdentity: Readonly<ProveRuntimeIdentity>;
  readonly effectiveOptions: Readonly<BoundedProveOptions>;
  readonly argv: readonly string[];
  readonly wallClockBudgetMs: number;
}

export interface PreparedProveExecutionPlan extends PreparedProveExecutionPlanFields {
  readonly planDigest: string;
  readonly confirmationDetailsText: string;
}

export function computePreparedProvePlanDigest(plan: PreparedProveExecutionPlanFields): string {
  const canonicalPayload = JSON.stringify({
    planId: plan.planId,
    entryKind: plan.entryKind,
    repositoryRoot: plan.repositoryRoot,
    rawRangeSpec: plan.rawRangeSpec,
    effectiveBaseOid: plan.effectiveBaseOid,
    effectiveHeadOid: plan.effectiveHeadOid,
    fromMergeBase: plan.fromMergeBase,
    recordRunId: plan.recordRunId,
    selectedMutantId: plan.selectedMutantId,
    runtimeIdentity: {
      proveExecutable: plan.runtimeIdentity.proveExecutable,
      proveExecutableSha256: plan.runtimeIdentity.proveExecutableSha256,
      proveVersion: plan.runtimeIdentity.proveVersion,
      hostPythonExecutable: plan.runtimeIdentity.hostPythonExecutable,
      hostPythonVersion: plan.runtimeIdentity.hostPythonVersion,
      hostPythonSha256: plan.runtimeIdentity.hostPythonSha256 ?? "",
      hostGitExecutable: plan.runtimeIdentity.hostGitExecutable ?? "",
      hostGitVersion: plan.runtimeIdentity.hostGitVersion ?? "",
      hostGitSha256: plan.runtimeIdentity.hostGitSha256 ?? "",
      testPythonExecutable: plan.runtimeIdentity.testPythonExecutable,
      testPythonVersion: plan.runtimeIdentity.testPythonVersion,
      testPythonSha256: plan.runtimeIdentity.testPythonSha256,
      catalogueVersion: plan.runtimeIdentity.catalogueVersion,
      catalogueGeneratorSha256: plan.runtimeIdentity.catalogueGeneratorSha256,
    },
    effectiveOptions: {
      workers: plan.effectiveOptions.workers,
      maxMutants: plan.effectiveOptions.maxMutants,
      timeoutSeconds: plan.effectiveOptions.timeoutSeconds,
      suiteTimeoutSeconds: plan.effectiveOptions.suiteTimeoutSeconds,
      importRoot: plan.effectiveOptions.importRoot,
      strictWarnings: plan.effectiveOptions.strictWarnings,
      listOnly: plan.effectiveOptions.listOnly,
      keep: plan.effectiveOptions.keep,
      onlyMutantId: plan.effectiveOptions.onlyMutantId,
    },
    argv: [...plan.argv],
    wallClockBudgetMs: plan.wallClockBudgetMs,
  });
  return crypto.createHash("sha256").update(Buffer.from(canonicalPayload, "utf8")).digest("hex");
}

export function formatProvePlanConfirmationDetails(plan: PreparedProveExecutionPlanFields): string {
  const safeMutantId =
    plan.selectedMutantId !== null
      ? sanitizeUntrustedDisplayString(String(plan.selectedMutantId), { maxLen: 256 })
      : null;
  const safeRepoRoot = sanitizeUntrustedDisplayString(plan.repositoryRoot, { maxLen: 512 });
  const safeRawRange = sanitizeUntrustedDisplayString(plan.rawRangeSpec, { maxLen: 256 });
  const safeProveExe = sanitizeUntrustedDisplayString(plan.runtimeIdentity.proveExecutable, {
    maxLen: 512,
  });
  const safeTestPyExe = sanitizeUntrustedDisplayString(plan.runtimeIdentity.testPythonExecutable, {
    maxLen: 512,
  });

  const modeLabel =
    plan.entryKind === "list"
      ? "List Candidate Mutants (--list)"
      : plan.entryKind === "full"
        ? "Full Prove Mutation Analysis"
        : `Single-Mutant Replay (record #${String(plan.recordRunId)}, mutant ${String(safeMutantId)})`;

  const lines: string[] = [
    `Mode: ${modeLabel}`,
    `Repository: ${safeRepoRoot}`,
    `Requested Range: ${safeRawRange}${plan.fromMergeBase ? " (merge-base resolved)" : ""}`,
    `Pinned Commits: ${plan.effectiveBaseOid}..${plan.effectiveHeadOid}`,
  ];
  if (safeMutantId !== null) {
    lines.push(`Pinned Mutant ID: ${safeMutantId}`);
  }
  lines.push(
    `Prove Binary: ${safeProveExe} (v${plan.runtimeIdentity.proveVersion}, sha256:${plan.runtimeIdentity.proveExecutableSha256.slice(0, 12)})`,
    `Test Python: ${safeTestPyExe} (${plan.runtimeIdentity.testPythonVersion}, sha256:${plan.runtimeIdentity.testPythonSha256.slice(0, 12)})`,
    `Limits: workers=${plan.effectiveOptions.workers}, maxMutants=${plan.effectiveOptions.maxMutants}, timeout=${plan.effectiveOptions.timeoutSeconds}s, suiteTimeout=${plan.effectiveOptions.suiteTimeoutSeconds}s, wallBudget=${Math.round(plan.wallClockBudgetMs / 1000)}s`
  );
  return lines.join("\n");
}

export function createFrozenPreparedProvePlan(
  fields: PreparedProveExecutionPlanFields
): PreparedProveExecutionPlan {
  const frozenRuntime = Object.freeze({ ...fields.runtimeIdentity });
  const frozenOptions = Object.freeze({ ...fields.effectiveOptions });
  const frozenArgv = Object.freeze([...fields.argv]);
  const normalizedFields: PreparedProveExecutionPlanFields = {
    ...fields,
    runtimeIdentity: frozenRuntime,
    effectiveOptions: frozenOptions,
    argv: frozenArgv,
  };
  const planDigest = computePreparedProvePlanDigest(normalizedFields);
  const confirmationDetailsText = formatProvePlanConfirmationDetails(normalizedFields);
  return Object.freeze({
    ...normalizedFields,
    planDigest,
    confirmationDetailsText,
  });
}

export interface TrustedProveExecutionRecord {
  readonly runId: number;
  readonly entryKind: ProveEntryKind;
  readonly adapterVersion: string;
  readonly isImportedExternalReport: boolean;
  readonly repositoryRoot: string;
  readonly rawRangeSpec: string;
  readonly effectiveBaseOid: string;
  readonly effectiveHeadOid: string;
  readonly fromMergeBase: boolean;
  readonly runtimeIdentity: ProveRuntimeIdentity;
  readonly argv: readonly string[];
  readonly effectiveOptions: Readonly<BoundedProveOptions>;
  readonly rawReportSha256: string;
  readonly parsedReport: ParsedProveReport;
  readonly exitCode: number;
  readonly cleanupConfirmed: boolean;
}

export interface ReplayBuildResult {
  executable: string;
  argv: string[];
  effectiveRangeArg: string;
  effectiveOptions: BoundedProveOptions;
  adjustmentsDisclosedToUser: string[];
  confirmationSummary: {
    repositoryRoot: string;
    originalRangeSpec: string;
    pinnedCommitRange: string;
    proveExecutable: string;
    hostPython: string;
    testPython: string;
    mutantId: string;
    wallClockBudgetMs: number;
  };
}

export function validateBoundedProveOptions(
  opts: Partial<BoundedProveOptions>
): ValidationResult<BoundedProveOptions> {
  const workers = opts.workers ?? DEFAULT_PROVE_WORKERS;
  const maxMutants = opts.maxMutants ?? DEFAULT_PROVE_MAX_MUTANTS;
  const timeoutSeconds = opts.timeoutSeconds ?? DEFAULT_PROVE_MUTANT_TIMEOUT_S;
  const suiteTimeoutSeconds = opts.suiteTimeoutSeconds ?? DEFAULT_PROVE_SUITE_TIMEOUT_S;
  const importRoot = opts.importRoot ?? null;
  const strictWarnings = opts.strictWarnings ?? false;
  const listOnly = opts.listOnly ?? false;
  const onlyMutantId = opts.onlyMutantId ?? null;

  if (!Number.isInteger(workers) || workers < 1 || workers > 16) {
    return { ok: false, error: `workers must be an integer between 1 and 16, got ${String(workers)}` };
  }
  if (!Number.isInteger(maxMutants) || maxMutants < 0 || maxMutants > 5000) {
    return { ok: false, error: `maxMutants must be an integer between 0 and 5000, got ${String(maxMutants)}` };
  }
  if (typeof timeoutSeconds !== "number" || !Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0 || timeoutSeconds > 3600) {
    return { ok: false, error: `timeoutSeconds must be in (0, 3600], got ${String(timeoutSeconds)}` };
  }
  if (
    typeof suiteTimeoutSeconds !== "number" ||
    !Number.isFinite(suiteTimeoutSeconds) ||
    suiteTimeoutSeconds <= 0 ||
    suiteTimeoutSeconds > 7200
  ) {
    return { ok: false, error: `suiteTimeoutSeconds must be in (0, 7200], got ${String(suiteTimeoutSeconds)}` };
  }
  if (opts.keep !== undefined && opts.keep !== false) {
    return { ok: false, error: "keep=true is not permitted in Checkwash Lens v1" };
  }
  if (importRoot !== null) {
    if (typeof importRoot !== "string" || importRoot.length === 0 || importRoot.startsWith("-")) {
      return { ok: false, error: "importRoot must be a safe relative directory path" };
    }
    const encoded = importRoot
      .split("/")
      .map((s) => encodeURIComponent(s))
      .join("/");
    const pathCheck = decodeAndValidateSarifUri(encoded);
    if (!pathCheck.ok || pathCheck.value !== importRoot) {
      return { ok: false, error: `Invalid importRoot '${importRoot}': ${pathCheck.ok ? "not normalized" : pathCheck.error}` };
    }
  }
  if (onlyMutantId !== null) {
    if (
      typeof onlyMutantId !== "string" ||
      onlyMutantId.length === 0 ||
      onlyMutantId.startsWith("-") ||
      /[\0\r\n]/.test(onlyMutantId)
    ) {
      return { ok: false, error: "Invalid onlyMutantId" };
    }
  }

  return {
    ok: true,
    value: {
      workers,
      maxMutants,
      timeoutSeconds,
      suiteTimeoutSeconds,
      importRoot,
      strictWarnings,
      listOnly,
      keep: false,
      onlyMutantId,
    },
  };
}

/**
 * Builds the exact argument array for checkwash-prove (never shell-interpolated).
 * Uses stdout (--format json) as the single official report source (never --out).
 */
export function buildProveArgv(params: {
  effectiveBaseOid: string;
  effectiveHeadOid: string;
  repositoryRoot: string;
  testPythonExecutable: string;
  options: BoundedProveOptions;
}): ValidationResult<string[]> {
  if (!isValidCommitOid(params.effectiveBaseOid) || !isValidCommitOid(params.effectiveHeadOid)) {
    return { ok: false, error: "Effective base and head must be pinned 40/64-char commit OIDs" };
  }
  if (!params.repositoryRoot || /[\0\r\n]/.test(params.repositoryRoot)) {
    return { ok: false, error: "Invalid repositoryRoot" };
  }
  if (!params.testPythonExecutable || /[\0\r\n]/.test(params.testPythonExecutable)) {
    return { ok: false, error: "Invalid testPythonExecutable" };
  }

  const optsCheck = validateBoundedProveOptions(params.options);
  if (!optsCheck.ok) return optsCheck;
  const opts = optsCheck.value;

  // Since effectiveBaseOid is already resolved (including merge-base when A...B was used),
  // effectiveBaseOid..effectiveHeadOid pins the exact two trees deterministically.
  const pinnedRange = `${params.effectiveBaseOid}..${params.effectiveHeadOid}`;
  const argv: string[] = [
    pinnedRange,
    "--repo",
    params.repositoryRoot,
    "--format",
    "json",
    "--python",
    params.testPythonExecutable,
    "--workers",
    String(opts.workers),
    "--max-mutants",
    String(opts.maxMutants),
    "--timeout",
    String(opts.timeoutSeconds),
    "--suite-timeout",
    String(opts.suiteTimeoutSeconds),
  ];

  if (opts.importRoot !== null) {
    argv.push("--import-root", opts.importRoot);
  }
  if (opts.strictWarnings) {
    argv.push("--strict-warnings");
  }
  if (opts.listOnly) {
    argv.push("--list");
  }
  if (opts.onlyMutantId !== null) {
    argv.push("--only", opts.onlyMutantId);
  }

  return { ok: true, value: argv };
}

function mutantExistsInReport(report: ParsedProveReport, mutantId: string): boolean {
  if (report.protectionLosses.some((item) => item.id === mutantId)) return true;
  if (report.unconfirmedLosses.some((item) => item.id === mutantId)) return true;
  if (report.candidates.some((item) => item.id === mutantId)) return true;
  if (report.undecidedRows.some((item) => item.id === mutantId)) return true;
  return false;
}

export function boundedProveOptionsEqual(
  a: Readonly<BoundedProveOptions>,
  b: Readonly<BoundedProveOptions>
): boolean {
  return (
    a.workers === b.workers &&
    a.maxMutants === b.maxMutants &&
    a.timeoutSeconds === b.timeoutSeconds &&
    a.suiteTimeoutSeconds === b.suiteTimeoutSeconds &&
    a.importRoot === b.importRoot &&
    a.strictWarnings === b.strictWarnings &&
    a.listOnly === b.listOnly &&
    a.keep === b.keep &&
    a.onlyMutantId === b.onlyMutantId
  );
}

export function runtimeIdentitiesMatch(
  a: Readonly<ProveRuntimeIdentity>,
  b: Readonly<ProveRuntimeIdentity>
): ValidationResult<true> {
  if (
    a.proveVersion !== PINNED_PROVE_VERSION ||
    b.proveVersion !== PINNED_PROVE_VERSION ||
    a.catalogueVersion !== PINNED_PROVE_CATALOGUE_VERSION ||
    b.catalogueVersion !== PINNED_PROVE_CATALOGUE_VERSION ||
    a.catalogueGeneratorSha256.toLowerCase() !== PINNED_PROVE_GENERATOR_SHA256 ||
    b.catalogueGeneratorSha256.toLowerCase() !== PINNED_PROVE_GENERATOR_SHA256
  ) {
    return { ok: false, error: "Prove version or catalogue identity is not the pinned v0.1.0 / v0.5-m2 contract" };
  }
  if (
    a.proveExecutable !== b.proveExecutable ||
    a.proveExecutableSha256 !== b.proveExecutableSha256 ||
    a.hostPythonExecutable !== b.hostPythonExecutable ||
    a.hostPythonVersion !== b.hostPythonVersion ||
    (a.hostPythonSha256 ?? "") !== (b.hostPythonSha256 ?? "") ||
    (a.hostGitExecutable ?? "") !== (b.hostGitExecutable ?? "") ||
    (a.hostGitVersion ?? "") !== (b.hostGitVersion ?? "") ||
    (a.hostGitSha256 ?? "") !== (b.hostGitSha256 ?? "") ||
    a.testPythonExecutable !== b.testPythonExecutable ||
    a.testPythonVersion !== b.testPythonVersion ||
    a.testPythonSha256 !== b.testPythonSha256
  ) {
    return {
      ok: false,
      error: "Runtime or Prove executable identity has changed since the execution plan or record was created; a new Prove confirmation is required",
    };
  }
  return { ok: true, value: true };
}

/**
 * Reconstructs a single-mutant Replay argv strictly from a TrustedProveExecutionRecord.
 * Never reads executables, paths, or options from the report JSON or loss.replay string.
 */
export function buildReplayFromTrustedRecord(params: {
  record: TrustedProveExecutionRecord;
  currentRepositoryRoot: string;
  currentRuntimeIdentity: ProveRuntimeIdentity;
  selectedMutantId: string;
}): ValidationResult<ReplayBuildResult> {
  const { record, currentRepositoryRoot, currentRuntimeIdentity, selectedMutantId } = params;

  if (record.isImportedExternalReport) {
    return {
      ok: false,
      error: "Imported external Prove reports are strictly read-only and cannot trigger Replay execution",
    };
  }
  if (!record.cleanupConfirmed || record.exitCode !== 0) {
    return {
      ok: false,
      error: "Cannot replay from an incomplete or unconfirmed Prove execution record",
    };
  }
  if (record.adapterVersion !== PINNED_PROVE_VERSION) {
    return {
      ok: false,
      error: `Incompatible Prove adapter version '${record.adapterVersion}'`,
    };
  }
  if (record.repositoryRoot !== currentRepositoryRoot) {
    return {
      ok: false,
      error: "Active repository root does not match the execution record's repository root",
    };
  }

  const rtCheck = runtimeIdentitiesMatch(record.runtimeIdentity, currentRuntimeIdentity);
  if (!rtCheck.ok) {
    return rtCheck;
  }

  if (!mutantExistsInReport(record.parsedReport, selectedMutantId)) {
    return {
      ok: false,
      error: `Selected mutant ID '${selectedMutantId}' does not belong to execution record #${record.runId}`,
    };
  }

  const replayOptions: BoundedProveOptions = {
    workers: 1,
    maxMutants: 1,
    timeoutSeconds: record.effectiveOptions.timeoutSeconds,
    suiteTimeoutSeconds: record.effectiveOptions.suiteTimeoutSeconds,
    importRoot: record.effectiveOptions.importRoot,
    strictWarnings: record.effectiveOptions.strictWarnings,
    listOnly: false,
    keep: false,
    onlyMutantId: selectedMutantId,
  };

  const argvRes = buildProveArgv({
    effectiveBaseOid: record.effectiveBaseOid,
    effectiveHeadOid: record.effectiveHeadOid,
    repositoryRoot: record.repositoryRoot,
    testPythonExecutable: record.runtimeIdentity.testPythonExecutable,
    options: replayOptions,
  });
  if (!argvRes.ok) {
    return argvRes;
  }

  const adjustments: string[] = [
    `Pinned commits: ${record.effectiveBaseOid}..${record.effectiveHeadOid} (from record #${record.runId}, unaffected by current HEAD)`,
    `Target mutant: --only ${selectedMutantId}`,
    "Single-mutant overrides forced: --workers 1, --max-mutants 1, list_only=false, keep=false",
  ];

  return {
    ok: true,
    value: {
      executable: record.runtimeIdentity.proveExecutable,
      argv: argvRes.value,
      effectiveRangeArg: `${record.effectiveBaseOid}..${record.effectiveHeadOid}`,
      effectiveOptions: replayOptions,
      adjustmentsDisclosedToUser: adjustments,
      confirmationSummary: {
        repositoryRoot: record.repositoryRoot,
        originalRangeSpec: record.rawRangeSpec,
        pinnedCommitRange: `${record.effectiveBaseOid}..${record.effectiveHeadOid}`,
        proveExecutable: record.runtimeIdentity.proveExecutable,
        hostPython: `${record.runtimeIdentity.hostPythonExecutable} (${record.runtimeIdentity.hostPythonVersion})`,
        testPython: `${record.runtimeIdentity.testPythonExecutable} (${record.runtimeIdentity.testPythonVersion})`,
        mutantId: selectedMutantId,
        wallClockBudgetMs: DEFAULT_PROVE_WALL_CLOCK_BUDGET_MS,
      },
    },
  };
}
