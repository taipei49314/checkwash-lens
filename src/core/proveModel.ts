/**
 * core/proveModel.ts
 *
 * Pinned checkwash-prove v0.1.0 report parser and status classifier.
 * Zero VS Code UI dependency; never spawns processes.
 *
 * Enforces Rev 3 §9.1, §9.4, §9.5 (A11, A12, A14):
 * - Validates pinned tool ("checkwash-prove"), catalogue version ("v0.5-m2"),
 *   and generator SHA-256 ("67096f7340a281585aaeaf801ae0ac29c4eb1a777c358ee973f02058cc7f4e14").
 * - Classifies execution/comparison status separately from findings:
 *   - Not Run / Cancelled
 *   - Running
 *   - Listed (candidates, rank, within_cap; explicitly states mutants were not executed)
 *   - Nothing to compare (preserves raw status & notes)
 *   - Not compared (distinguishes no_mutants, cap_zero, collection_clean_or_trace)
 *   - Compared (generated, run, skipped_over_cap, notes)
 *   - Execution error
 * - Preserves all 4 coexisting groups simultaneously:
 *   - protection_losses
 *   - unconfirmed_losses
 *   - needs_clarification
 *   - undecided rows in mutation
 * - When Compared with 0 protection_losses, surfaces the exact fixed disclaimer:
 *   "本次有限範圍內未觀察到已確認的保護損失；不代表變更安全或沒有損失。"
 * - Never provides a green Pass state and never alters Checkwash static verdict.
 */

import { parseBoundedJson, ValidationResult } from "./checkwashSchema";

export const PINNED_PROVE_VERSION = "0.1.0";
export const PINNED_PROVE_SOURCE_COMMIT = "582f1339ea48f4db48b4414648ca21316aeb0713";
export const PINNED_PROVE_CATALOGUE_VERSION = "v0.5-m2";
export const PINNED_PROVE_GENERATOR_SHA256 =
  "67096f7340a281585aaeaf801ae0ac29c4eb1a777c358ee973f02058cc7f4e14";

export const NO_CONFIRMED_LOSS_FIXED_MESSAGE =
  "本次有限範圍內未觀察到已確認的保護損失；不代表變更安全或沒有損失。";

export type ProveExecutionStatus =
  | "Not Run / Cancelled"
  | "Running"
  | "Listed"
  | "Nothing to compare"
  | "Not compared"
  | "Compared"
  | "Execution error";

export type ProveNotComparedReason =
  | "no_mutants"
  | "cap_zero"
  | "collection_clean_or_trace";

export interface ProveLossItem {
  id: string;
  op: string;
  path: string;
  line: number;
  before: string;
  after: string;
  what?: string;
  old_caught_by: string[];
  why?: string;
  /** Display-only string from report; NEVER executed or passed to shell (§9.5) */
  replay: string;
}

export interface ProveClarificationItem {
  test: string;
  reason: string;
  also_fails_in_new: boolean;
  detail: string;
  [key: string]: unknown;
}

export interface ProveCandidateItem {
  id: string;
  rank: number;
  within_cap: boolean;
  path: string;
  line: number;
  op: string;
  before: string;
  after: string;
  what?: string;
}

export interface ProveUndecidedItem {
  id: string;
  op?: string;
  path?: string;
  line?: number;
  reason?: string;
  category?: string;
  [key: string]: unknown;
}

export interface RawProveReportV010 {
  tool: "checkwash-prove";
  version?: string;
  experimental: boolean;
  catalogue: {
    version: string;
    generator_sha256: string;
  };
  range: string;
  base: string;
  head: string;
  from_merge_base: boolean;
  python: string;
  host_python: string;
  options: {
    workers: number;
    timeout: number;
    suite_timeout: number;
    max_mutants: number;
    import_root: string | null;
    strict_warnings: boolean;
    only?: string | null;
    keep: boolean;
    list_only: boolean;
  };
  needs_clarification: ProveClarificationItem[];
  protection_losses: ProveLossItem[];
  unconfirmed_losses: ProveLossItem[];
  notes: string[];
  mutation: {
    generated?: number;
    run?: number;
    skipped_over_cap?: number;
    categories?: Record<string, number>;
    rows?: Array<Record<string, unknown>>;
    candidates?: ProveCandidateItem[];
    undecided?: ProveUndecidedItem[];
  };
  compared: boolean;
  nothing_to_compare: boolean;
  status: string;
  seconds?: number;
  [extraKey: string]: unknown;
}

export interface ParsedProveReport {
  raw: RawProveReportV010;
  status: ProveExecutionStatus;
  notComparedReason: ProveNotComparedReason | null;
  rawStatusText: string;
  notes: string[];
  generatedCount: number;
  runCount: number;
  skippedOverCapCount: number;
  protectionLosses: ProveLossItem[];
  unconfirmedLosses: ProveLossItem[];
  needsClarification: ProveClarificationItem[];
  candidates: ProveCandidateItem[];
  undecidedRows: ProveUndecidedItem[];
  noConfirmedLossExplanation: string | null;
}

function isPlainObject(val: unknown): val is Record<string, unknown> {
  return typeof val === "object" && val !== null && !Array.isArray(val);
}

export function validateProveReportJson(
  rawInput: string | unknown
): ValidationResult<RawProveReportV010> {
  let doc: unknown = rawInput;
  if (typeof rawInput === "string") {
    const parsed = parseBoundedJson(rawInput);
    if (!parsed.ok) return parsed;
    doc = parsed.value;
  }

  if (!isPlainObject(doc)) {
    return { ok: false, error: "Prove JSON root must be an object" };
  }
  if (doc.tool !== "checkwash-prove") {
    return { ok: false, error: `Unsupported Prove tool identifier: ${String(doc.tool)}` };
  }
  if ("version" in doc && doc.version !== undefined && doc.version !== PINNED_PROVE_VERSION) {
    return {
      ok: false,
      error: `Unsupported checkwash-prove report version '${String(doc.version)}' (expected '${PINNED_PROVE_VERSION}')`,
    };
  }
  if (!isPlainObject(doc.catalogue)) {
    return { ok: false, error: "Prove report is missing 'catalogue' object" };
  }
  if (doc.catalogue.version !== PINNED_PROVE_CATALOGUE_VERSION) {
    return {
      ok: false,
      error: `Unsupported Prove catalogue version '${String(doc.catalogue.version)}' (expected '${PINNED_PROVE_CATALOGUE_VERSION}')`,
    };
  }
  if (
    typeof doc.catalogue.generator_sha256 !== "string" ||
    doc.catalogue.generator_sha256.toLowerCase() !== PINNED_PROVE_GENERATOR_SHA256
  ) {
    return {
      ok: false,
      error: `Unsupported Prove catalogue generator_sha256 '${String(doc.catalogue.generator_sha256)}'`,
    };
  }
  if (
    typeof doc.range !== "string" ||
    typeof doc.base !== "string" ||
    typeof doc.head !== "string" ||
    typeof doc.from_merge_base !== "boolean" ||
    typeof doc.compared !== "boolean" ||
    typeof doc.nothing_to_compare !== "boolean" ||
    typeof doc.status !== "string"
  ) {
    return { ok: false, error: "Prove report is missing required top-level execution metadata fields" };
  }
  if (!isPlainObject(doc.options)) {
    return { ok: false, error: "Prove report is missing 'options' object" };
  }
  if (
    typeof doc.options.workers !== "number" ||
    !Number.isFinite(doc.options.workers) ||
    typeof doc.options.timeout !== "number" ||
    !Number.isFinite(doc.options.timeout) ||
    typeof doc.options.suite_timeout !== "number" ||
    !Number.isFinite(doc.options.suite_timeout) ||
    typeof doc.options.max_mutants !== "number" ||
    !Number.isFinite(doc.options.max_mutants) ||
    typeof doc.options.strict_warnings !== "boolean" ||
    typeof doc.options.keep !== "boolean" ||
    typeof doc.options.list_only !== "boolean" ||
    (doc.options.import_root !== undefined &&
      doc.options.import_root !== null &&
      typeof doc.options.import_root !== "string") ||
    (doc.options.only !== undefined &&
      doc.options.only !== null &&
      typeof doc.options.only !== "string")
  ) {
    return { ok: false, error: "Prove report 'options' contains invalid or missing required fields" };
  }
  if (
    !Array.isArray(doc.protection_losses) ||
    !Array.isArray(doc.unconfirmed_losses) ||
    !Array.isArray(doc.needs_clarification) ||
    !Array.isArray(doc.notes) ||
    !isPlainObject(doc.mutation)
  ) {
    return { ok: false, error: "Prove report is missing required findings/mutation collections" };
  }

  const validateLossArray = (arr: unknown[], fieldName: string): ValidationResult<true> => {
    for (let i = 0; i < arr.length; i++) {
      const item = arr[i];
      if (!isPlainObject(item)) {
        return { ok: false, error: `Prove report '${fieldName}[${i}]' must be an object` };
      }
      if (
        typeof item.id !== "string" ||
        item.id.length === 0 ||
        typeof item.op !== "string" ||
        typeof item.path !== "string" ||
        typeof item.line !== "number" ||
        !Number.isFinite(item.line) ||
        typeof item.before !== "string" ||
        typeof item.after !== "string" ||
        typeof item.replay !== "string" ||
        (item.why !== undefined && typeof item.why !== "string") ||
        !Array.isArray(item.old_caught_by) ||
        !item.old_caught_by.every((x) => typeof x === "string")
      ) {
        return {
          ok: false,
          error: `Prove report '${fieldName}[${i}]' is missing required loss fields (id, op, path, line, before, after, old_caught_by, replay)`,
        };
      }
    }
    return { ok: true, value: true };
  };

  const plCheck = validateLossArray(doc.protection_losses, "protection_losses");
  if (!plCheck.ok) return plCheck;

  const ulCheck = validateLossArray(doc.unconfirmed_losses, "unconfirmed_losses");
  if (!ulCheck.ok) return ulCheck;

  for (let i = 0; i < doc.needs_clarification.length; i++) {
    const nc = doc.needs_clarification[i];
    if (!isPlainObject(nc)) {
      return { ok: false, error: `Prove report 'needs_clarification[${i}]' must be an object` };
    }
    if (
      typeof nc.test !== "string" ||
      nc.test.length === 0 ||
      typeof nc.reason !== "string" ||
      nc.reason.length === 0 ||
      typeof nc.also_fails_in_new !== "boolean" ||
      typeof nc.detail !== "string"
    ) {
      return {
        ok: false,
        error: `Prove report 'needs_clarification[${i}]' is missing required fields (test, reason, also_fails_in_new, detail) or has invalid field types`,
      };
    }
  }

  for (let i = 0; i < doc.notes.length; i++) {
    if (typeof doc.notes[i] !== "string") {
      return { ok: false, error: `Prove report 'notes[${i}]' must be a string` };
    }
  }

  if (
    (doc.mutation.generated !== undefined &&
      (typeof doc.mutation.generated !== "number" || !Number.isFinite(doc.mutation.generated))) ||
    (doc.mutation.run !== undefined &&
      (typeof doc.mutation.run !== "number" || !Number.isFinite(doc.mutation.run))) ||
    (doc.mutation.skipped_over_cap !== undefined &&
      (typeof doc.mutation.skipped_over_cap !== "number" ||
        !Number.isFinite(doc.mutation.skipped_over_cap)))
  ) {
    return {
      ok: false,
      error: "Prove report 'mutation' numeric counters must be finite numbers",
    };
  }

  if (doc.mutation.candidates !== undefined) {
    if (!Array.isArray(doc.mutation.candidates)) {
      return { ok: false, error: "Prove report 'mutation.candidates' must be an array" };
    }
    for (let i = 0; i < doc.mutation.candidates.length; i++) {
      const c = doc.mutation.candidates[i];
      if (
        !isPlainObject(c) ||
        typeof c.id !== "string" ||
        c.id.length === 0 ||
        typeof c.rank !== "number" ||
        !Number.isFinite(c.rank) ||
        typeof c.within_cap !== "boolean" ||
        typeof c.path !== "string" ||
        typeof c.line !== "number" ||
        !Number.isFinite(c.line) ||
        typeof c.op !== "string" ||
        typeof c.before !== "string" ||
        typeof c.after !== "string"
      ) {
        return {
          ok: false,
          error: `Prove report 'mutation.candidates[${i}]' is malformed`,
        };
      }
    }
  }

  const hasValidUndecidedOptionalFields = (obj: Record<string, unknown>): boolean =>
    (obj.path === undefined || typeof obj.path === "string") &&
    (obj.line === undefined || (typeof obj.line === "number" && Number.isFinite(obj.line))) &&
    (obj.reason === undefined || typeof obj.reason === "string") &&
    (obj.status === undefined || typeof obj.status === "string") &&
    (obj.op === undefined || typeof obj.op === "string") &&
    (obj.before === undefined || typeof obj.before === "string") &&
    (obj.after === undefined || typeof obj.after === "string");

  if (doc.mutation.undecided !== undefined) {
    if (!Array.isArray(doc.mutation.undecided)) {
      return { ok: false, error: "Prove report 'mutation.undecided' must be an array" };
    }
    for (let i = 0; i < doc.mutation.undecided.length; i++) {
      const u = doc.mutation.undecided[i];
      if (
        !isPlainObject(u) ||
        typeof u.id !== "string" ||
        u.id.length === 0 ||
        !hasValidUndecidedOptionalFields(u)
      ) {
        return {
          ok: false,
          error: `Prove report 'mutation.undecided[${i}]' must be an object with non-empty string 'id' and primitive string/number fields`,
        };
      }
    }
  }

  if (doc.mutation.rows !== undefined) {
    if (!Array.isArray(doc.mutation.rows)) {
      return { ok: false, error: "Prove report 'mutation.rows' must be an array" };
    }
    for (let i = 0; i < doc.mutation.rows.length; i++) {
      const r = doc.mutation.rows[i];
      if (!isPlainObject(r)) {
        return { ok: false, error: `Prove report 'mutation.rows[${i}]' must be an object` };
      }
      if (
        (r.category !== undefined && typeof r.category !== "string") ||
        (r.id !== undefined && (typeof r.id !== "string" || r.id.length === 0)) ||
        !hasValidUndecidedOptionalFields(r)
      ) {
        return {
          ok: false,
          error: `Prove report 'mutation.rows[${i}]' has invalid field types`,
        };
      }
      if (r.category === "undecided" && (typeof r.id !== "string" || r.id.length === 0)) {
        return {
          ok: false,
          error: `Prove report 'mutation.rows[${i}]' (undecided) must have a non-empty string 'id'`,
        };
      }
    }
  }

  return {
    ok: true,
    value: doc as unknown as RawProveReportV010,
  };
}

export function classifyProveReport(raw: RawProveReportV010): ParsedProveReport {
  const generatedCount = typeof raw.mutation.generated === "number" ? raw.mutation.generated : 0;
  const runCount = typeof raw.mutation.run === "number" ? raw.mutation.run : 0;

  const candidates: ProveCandidateItem[] = Array.isArray(raw.mutation.candidates)
    ? [...raw.mutation.candidates]
    : [];

  const skippedOverCapCount =
    typeof raw.mutation.skipped_over_cap === "number"
      ? raw.mutation.skipped_over_cap
      : candidates.length > 0
      ? candidates.filter((c) => c.within_cap === false).length
      : 0;

  const undecidedRows: ProveUndecidedItem[] = [];
  if (Array.isArray(raw.mutation.undecided)) {
    undecidedRows.push(...raw.mutation.undecided);
  }
  if (Array.isArray(raw.mutation.rows)) {
    for (const row of raw.mutation.rows) {
      if (isPlainObject(row) && row.category === "undecided" && typeof row.id === "string") {
        undecidedRows.push(row as unknown as ProveUndecidedItem);
      }
    }
  }

  let status: ProveExecutionStatus;
  let notComparedReason: ProveNotComparedReason | null = null;

  if (raw.nothing_to_compare === true) {
    status = "Nothing to compare";
  } else if (raw.compared === true) {
    status = "Compared";
  } else if (
    raw.options.list_only === true &&
    Array.isArray(raw.mutation.candidates) &&
    raw.status.startsWith("listed")
  ) {
    status = "Listed";
  } else {
    status = "Not compared";
    if (
      raw.status.includes("--max-mutants 0") ||
      (!raw.options.list_only &&
        raw.options.max_mutants === 0 &&
        typeof raw.mutation.generated === "number" &&
        raw.mutation.generated > 0)
    ) {
      notComparedReason = "cap_zero";
    } else if (
      raw.status.startsWith("no mutants:") ||
      (raw.mutation.generated === 0 &&
        raw.needs_clarification.length === 0 &&
        (raw.status.includes("no mutant") || raw.notes.length === 0))
    ) {
      notComparedReason = "no_mutants";
    } else {
      notComparedReason = "collection_clean_or_trace";
    }
  }

  const protectionLosses = [...raw.protection_losses];
  const unconfirmedLosses = [...raw.unconfirmed_losses];
  const needsClarification = [...raw.needs_clarification];

  const noConfirmedLossExplanation =
    status === "Compared" && protectionLosses.length === 0
      ? NO_CONFIRMED_LOSS_FIXED_MESSAGE
      : null;

  return {
    raw,
    status,
    notComparedReason,
    rawStatusText: raw.status,
    notes: [...raw.notes],
    generatedCount,
    runCount,
    skippedOverCapCount,
    protectionLosses,
    unconfirmedLosses,
    needsClarification,
    candidates,
    undecidedRows,
    noConfirmedLossExplanation,
  };
}
