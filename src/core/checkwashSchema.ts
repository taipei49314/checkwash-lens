/**
 * core/checkwashSchema.ts
 *
 * Strict structural and type validator for Checkwash findings JSON v2 and SARIF 2.1.0.
 * Zero VS Code UI dependency; never spawns processes.
 *
 * Enforces Rev 3 §5.1 & §7.4:
 * - Max report size (16 MiB), max JSON nesting depth (32), max findings/results count (50,000).
 * - Requires all mandatory JSON v2 fields and types (does not substitute defaults for missing required fields).
 * - Tolerates unknown optional keys, new rule IDs, and new escalator/deescalator labels.
 * - Strictly validates fixed-contract enums (severity, verdict, unread.side, span).
 * - Validates SARIF 2.1.0 projection (single run, driver name === "checkwash", pinned version, properties, results).
 */

export const MAX_REPORT_BYTES = 16 * 1024 * 1024; // 16 MiB
export const MAX_JSON_DEPTH = 32;
export const MAX_FINDINGS_COUNT = 50_000;

export type CheckwashSeverity = "info" | "warn" | "high" | "critical";
export type CheckwashVerdict = "pass" | "block";
export type UnreadSideKind = "base" | "head" | "worktree";
export type SarifLevel = "note" | "warning" | "error";

export const SEVERITY_TO_SARIF_LEVEL: Record<CheckwashSeverity, SarifLevel> = {
  info: "note",
  warn: "warning",
  high: "error",
  critical: "error",
};

export interface CheckwashEvidence {
  text: string;
  span: [number, number];
}

export interface CheckwashFinding {
  rule: string;
  severity: CheckwashSeverity;
  message: string;
  path: string;
  unit: string | null;
  before: CheckwashEvidence | null;
  after: CheckwashEvidence | null;
  escalators: string[];
  deescalators: string[];
  fingerprint: string;
  allowlisted: boolean;
  strength_drop: number | null;
  strength_after: number | null;
  subject_changed: boolean | null;
  shape: string | null;
  [extraKey: string]: unknown;
}

export interface CheckwashUnreadEntry {
  path: string;
  side: UnreadSideKind;
  size: number;
  limit: number;
}

export interface CheckwashSummary {
  info: number;
  warn: number;
  high: number;
  critical: number;
}

export interface CheckwashFindingsDocumentV2 {
  checkwash_findings_version: 2;
  run: {
    base: string;
    head: string;
    checkwash_version: string;
  };
  findings: CheckwashFinding[];
  summary: CheckwashSummary;
  skipped_files: string[];
  config_errors: string[];
  verdict: CheckwashVerdict;
  unread?: CheckwashUnreadEntry[];
  [extraKey: string]: unknown;
}

export interface SarifPhysicalLocation {
  artifactLocation: {
    uri: string;
  };
  region?: {
    startLine: number;
    startColumn?: number;
  };
}

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: {
    text: string;
  };
  locations: Array<{
    physicalLocation: SarifPhysicalLocation;
  }>;
  partialFingerprints: {
    "checkwash/v1"?: string;
    "checkwash/v2"?: string;
    [key: string]: string | undefined;
  };
  properties?: {
    "checkwash.evidenceSide"?: "head" | "base";
    "checkwash.evidenceText"?: string;
    [key: string]: unknown;
  };
}

export interface SarifNotification {
  level: string;
  message: {
    text: string;
  };
  properties?: {
    "checkwash.path"?: string;
    "checkwash.side"?: string;
    "checkwash.line"?: number;
    "checkwash.column"?: number;
    "checkwash.size"?: number;
    "checkwash.limit"?: number;
    [key: string]: unknown;
  };
  locations?: Array<{
    physicalLocation: SarifPhysicalLocation;
  }>;
}

export interface CheckwashSarifDocument {
  version: "2.1.0";
  runs: [
    {
      tool: {
        driver: {
          name: "checkwash";
          semanticVersion: string;
          informationUri?: string;
          rules?: Array<{ id: string; name?: string }>;
        };
      };
      properties: {
        "checkwash.base": string;
        "checkwash.head": string;
        [key: string]: unknown;
      };
      results: SarifResult[];
      invocations?: Array<{
        executionSuccessful: boolean;
        toolExecutionNotifications?: SarifNotification[];
      }>;
    }
  ];
}

export type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

const LABEL_REGEX = /^[A-Z][A-Z0-9_]*$/;
const FINGERPRINT_REGEX = /^[A-Z][A-Z0-9_]*\/.+/s;
const VALID_SEVERITIES = new Set<string>(["info", "warn", "high", "critical"]);
const VALID_VERDICTS = new Set<string>(["pass", "block"]);
const VALID_UNREAD_SIDES = new Set<string>(["base", "head", "worktree"]);
const VALID_SARIF_LEVELS = new Set<string>(["note", "warning", "error"]);

function isPlainObject(val: unknown): val is Record<string, unknown> {
  return typeof val === "object" && val !== null && !Array.isArray(val);
}

function isNonNegativeInteger(val: unknown): val is number {
  return typeof val === "number" && Number.isInteger(val) && val >= 0;
}

function isNonEmptyString(val: unknown): val is string {
  return typeof val === "string" && val.length > 0;
}

export function checkJsonDepthAndItemCount(
  val: unknown,
  maxDepth: number = MAX_JSON_DEPTH,
  maxItems: number = MAX_FINDINGS_COUNT
): ValidationResult<true> {
  let totalItems = 0;
  const stack: Array<{ node: unknown; depth: number }> = [{ node: val, depth: 0 }];

  while (stack.length > 0) {
    const { node, depth } = stack.pop()!;
    if (depth > maxDepth) {
      return { ok: false, error: `JSON nesting depth exceeds maximum (${maxDepth})` };
    }
    if (Array.isArray(node)) {
      totalItems += node.length;
      if (totalItems > maxItems * 4) {
        return { ok: false, error: `JSON array item count exceeds safety limit` };
      }
      for (let i = 0; i < node.length; i++) {
        stack.push({ node: node[i], depth: depth + 1 });
      }
    } else if (isPlainObject(node)) {
      const keys = Object.keys(node);
      totalItems += keys.length;
      if (totalItems > maxItems * 8) {
        return { ok: false, error: `JSON object property count exceeds safety limit` };
      }
      for (const k of keys) {
        stack.push({ node: node[k], depth: depth + 1 });
      }
    }
  }
  return { ok: true, value: true };
}

export function parseBoundedJson(
  rawText: string,
  maxBytes: number = MAX_REPORT_BYTES
): ValidationResult<unknown> {
  const byteLen = Buffer.byteLength(rawText, "utf-8");
  if (byteLen > maxBytes) {
    return { ok: false, error: `Report byte length (${byteLen}) exceeds limit (${maxBytes})` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    return { ok: false, error: `Invalid JSON: ${err instanceof Error ? err.message : String(err)}` };
  }
  const depthCheck = checkJsonDepthAndItemCount(parsed);
  if (!depthCheck.ok) {
    return depthCheck;
  }
  return { ok: true, value: parsed };
}

function validateEvidence(val: unknown, fieldPath: string): ValidationResult<CheckwashEvidence | null> {
  if (val === null) {
    return { ok: true, value: null };
  }
  if (!isPlainObject(val)) {
    return { ok: false, error: `${fieldPath} must be an object or null` };
  }
  if (typeof val.text !== "string") {
    return { ok: false, error: `${fieldPath}.text must be a string` };
  }
  if (
    !Array.isArray(val.span) ||
    val.span.length !== 2 ||
    !isNonNegativeInteger(val.span[0]) ||
    !isNonNegativeInteger(val.span[1])
  ) {
    return { ok: false, error: `${fieldPath}.span must be a [start, end] pair of non-negative integers` };
  }
  return {
    ok: true,
    value: {
      text: val.text,
      span: [val.span[0], val.span[1]],
    },
  };
}

function validateFinding(val: unknown, idx: number): ValidationResult<CheckwashFinding> {
  const prefix = `findings[${idx}]`;
  if (!isPlainObject(val)) {
    return { ok: false, error: `${prefix} must be an object` };
  }
  const requiredKeys = [
    "rule",
    "severity",
    "message",
    "path",
    "unit",
    "before",
    "after",
    "escalators",
    "deescalators",
    "fingerprint",
    "allowlisted",
    "strength_drop",
    "strength_after",
    "subject_changed",
    "shape",
  ];
  for (const key of requiredKeys) {
    if (!(key in val)) {
      return { ok: false, error: `${prefix} is missing required key '${key}'` };
    }
  }
  if (!isNonEmptyString(val.rule) || !LABEL_REGEX.test(val.rule)) {
    return { ok: false, error: `${prefix}.rule must be an uppercase label` };
  }
  if (typeof val.severity !== "string" || !VALID_SEVERITIES.has(val.severity)) {
    return { ok: false, error: `${prefix}.severity is invalid: ${String(val.severity)}` };
  }
  if (typeof val.message !== "string") {
    return { ok: false, error: `${prefix}.message must be a string` };
  }
  if (!isNonEmptyString(val.path)) {
    return { ok: false, error: `${prefix}.path must be a non-empty string` };
  }
  if (val.unit !== null && typeof val.unit !== "string") {
    return { ok: false, error: `${prefix}.unit must be a string or null` };
  }
  const beforeRes = validateEvidence(val.before, `${prefix}.before`);
  if (!beforeRes.ok) return beforeRes;
  const afterRes = validateEvidence(val.after, `${prefix}.after`);
  if (!afterRes.ok) return afterRes;

  if (
    !Array.isArray(val.escalators) ||
    !val.escalators.every((item) => isNonEmptyString(item) && LABEL_REGEX.test(item))
  ) {
    return { ok: false, error: `${prefix}.escalators must be an array of uppercase labels` };
  }
  if (
    !Array.isArray(val.deescalators) ||
    !val.deescalators.every((item) => isNonEmptyString(item) && LABEL_REGEX.test(item))
  ) {
    return { ok: false, error: `${prefix}.deescalators must be an array of uppercase labels` };
  }
  if (!isNonEmptyString(val.fingerprint) || !FINGERPRINT_REGEX.test(val.fingerprint)) {
    return { ok: false, error: `${prefix}.fingerprint is invalid` };
  }
  if (typeof val.allowlisted !== "boolean") {
    return { ok: false, error: `${prefix}.allowlisted must be a boolean` };
  }
  if (val.strength_drop !== null && !isNonNegativeInteger(val.strength_drop)) {
    return { ok: false, error: `${prefix}.strength_drop must be a non-negative integer or null` };
  }
  if (
    val.strength_after !== null &&
    (!isNonNegativeInteger(val.strength_after) || val.strength_after > 100)
  ) {
    return { ok: false, error: `${prefix}.strength_after must be an integer in 0..100 or null` };
  }
  if (val.subject_changed !== null && typeof val.subject_changed !== "boolean") {
    return { ok: false, error: `${prefix}.subject_changed must be a boolean or null` };
  }
  if (val.shape !== null && !isNonEmptyString(val.shape)) {
    return { ok: false, error: `${prefix}.shape must be a non-empty string or null` };
  }

  return {
    ok: true,
    value: val as unknown as CheckwashFinding,
  };
}

export function validateFindingsJsonV2(rawInput: string | unknown): ValidationResult<CheckwashFindingsDocumentV2> {
  let doc: unknown = rawInput;
  if (typeof rawInput === "string") {
    const parsed = parseBoundedJson(rawInput);
    if (!parsed.ok) return parsed;
    doc = parsed.value;
  } else {
    const depthCheck = checkJsonDepthAndItemCount(doc);
    if (!depthCheck.ok) return depthCheck;
  }

  if (!isPlainObject(doc)) {
    return { ok: false, error: "Checkwash JSON root must be an object" };
  }

  const requiredTopKeys = [
    "checkwash_findings_version",
    "run",
    "findings",
    "summary",
    "skipped_files",
    "config_errors",
    "verdict",
  ];
  for (const key of requiredTopKeys) {
    if (!(key in doc)) {
      return { ok: false, error: `Checkwash JSON is missing required top-level key '${key}'` };
    }
  }

  if (doc.checkwash_findings_version !== 2) {
    return {
      ok: false,
      error: `Unsupported checkwash_findings_version: ${String(doc.checkwash_findings_version)} (expected 2)`,
    };
  }

  if (!isPlainObject(doc.run)) {
    return { ok: false, error: "run must be an object" };
  }
  if (
    !isNonEmptyString(doc.run.base) ||
    !isNonEmptyString(doc.run.head) ||
    !isNonEmptyString(doc.run.checkwash_version)
  ) {
    return { ok: false, error: "run.base, run.head, and run.checkwash_version must be non-empty strings" };
  }

  if (!Array.isArray(doc.findings)) {
    return { ok: false, error: "findings must be an array" };
  }
  if (doc.findings.length > MAX_FINDINGS_COUNT) {
    return { ok: false, error: `findings length (${doc.findings.length}) exceeds limit (${MAX_FINDINGS_COUNT})` };
  }

  const validatedFindings: CheckwashFinding[] = [];
  for (let i = 0; i < doc.findings.length; i++) {
    const fRes = validateFinding(doc.findings[i], i);
    if (!fRes.ok) return fRes;
    validatedFindings.push(fRes.value);
  }

  if (!isPlainObject(doc.summary)) {
    return { ok: false, error: "summary must be an object" };
  }
  for (const sev of ["info", "warn", "high", "critical"]) {
    if (!(sev in doc.summary) || !isNonNegativeInteger(doc.summary[sev])) {
      return { ok: false, error: `summary.${sev} must be a non-negative integer` };
    }
  }

  if (!Array.isArray(doc.skipped_files) || !doc.skipped_files.every(isNonEmptyString)) {
    return { ok: false, error: "skipped_files must be an array of non-empty strings" };
  }
  if (!Array.isArray(doc.config_errors) || !doc.config_errors.every(isNonEmptyString)) {
    return { ok: false, error: "config_errors must be an array of non-empty strings" };
  }
  if (typeof doc.verdict !== "string" || !VALID_VERDICTS.has(doc.verdict)) {
    return { ok: false, error: `verdict must be 'pass' or 'block', got ${String(doc.verdict)}` };
  }

  if ("unread" in doc && doc.unread !== undefined) {
    if (!Array.isArray(doc.unread) || doc.unread.length === 0) {
      return { ok: false, error: "unread, when present, must be a non-empty array" };
    }
    for (let i = 0; i < doc.unread.length; i++) {
      const item = doc.unread[i];
      if (!isPlainObject(item)) {
        return { ok: false, error: `unread[${i}] must be an object` };
      }
      if (
        !isNonEmptyString(item.path) ||
        typeof item.side !== "string" ||
        !VALID_UNREAD_SIDES.has(item.side) ||
        !isNonNegativeInteger(item.size) ||
        !isNonNegativeInteger(item.limit) ||
        item.limit < 1
      ) {
        return { ok: false, error: `unread[${i}] has invalid fields` };
      }
    }
  }

  return {
    ok: true,
    value: doc as unknown as CheckwashFindingsDocumentV2,
  };
}

export function validateCheckwashSarif(rawInput: string | unknown): ValidationResult<CheckwashSarifDocument> {
  let doc: unknown = rawInput;
  if (typeof rawInput === "string") {
    const parsed = parseBoundedJson(rawInput);
    if (!parsed.ok) return parsed;
    doc = parsed.value;
  } else {
    const depthCheck = checkJsonDepthAndItemCount(doc);
    if (!depthCheck.ok) return depthCheck;
  }

  if (!isPlainObject(doc)) {
    return { ok: false, error: "SARIF root must be an object" };
  }
  if (doc.version !== "2.1.0") {
    return { ok: false, error: `Unsupported SARIF version: ${String(doc.version)} (expected '2.1.0')` };
  }
  if (!Array.isArray(doc.runs) || doc.runs.length !== 1 || !isPlainObject(doc.runs[0])) {
    return { ok: false, error: "SARIF must contain exactly 1 run object" };
  }

  const run = doc.runs[0];
  if (!isPlainObject(run.tool) || !isPlainObject(run.tool.driver)) {
    return { ok: false, error: "SARIF run.tool.driver is missing" };
  }
  const driver = run.tool.driver;
  if (driver.name !== "checkwash" || !isNonEmptyString(driver.semanticVersion)) {
    return { ok: false, error: "SARIF driver must be 'checkwash' with a non-empty semanticVersion" };
  }

  if (
    !isPlainObject(run.properties) ||
    !isNonEmptyString(run.properties["checkwash.base"]) ||
    !isNonEmptyString(run.properties["checkwash.head"])
  ) {
    return { ok: false, error: "SARIF run.properties must carry checkwash.base and checkwash.head" };
  }

  if (!Array.isArray(run.results)) {
    return { ok: false, error: "SARIF run.results must be an array" };
  }
  if (run.results.length > MAX_FINDINGS_COUNT) {
    return { ok: false, error: `SARIF results length (${run.results.length}) exceeds limit (${MAX_FINDINGS_COUNT})` };
  }

  for (let i = 0; i < run.results.length; i++) {
    const res = run.results[i];
    const prefix = `SARIF results[${i}]`;
    if (!isPlainObject(res)) {
      return { ok: false, error: `${prefix} must be an object` };
    }
    if (!isNonEmptyString(res.ruleId) || !LABEL_REGEX.test(res.ruleId)) {
      return { ok: false, error: `${prefix}.ruleId is invalid` };
    }
    if (typeof res.level !== "string" || !VALID_SARIF_LEVELS.has(res.level)) {
      return { ok: false, error: `${prefix}.level is invalid: ${String(res.level)}` };
    }
    if (!isPlainObject(res.message) || typeof res.message.text !== "string") {
      return { ok: false, error: `${prefix}.message.text must be a string` };
    }
    if (
      !Array.isArray(res.locations) ||
      res.locations.length < 1 ||
      !isPlainObject(res.locations[0]) ||
      !isPlainObject(res.locations[0].physicalLocation) ||
      !isPlainObject(res.locations[0].physicalLocation.artifactLocation) ||
      !isNonEmptyString(res.locations[0].physicalLocation.artifactLocation.uri)
    ) {
      return { ok: false, error: `${prefix}.locations[0].physicalLocation.artifactLocation.uri is required` };
    }
    const region = res.locations[0].physicalLocation.region;
    if (region !== undefined) {
      if (!isPlainObject(region) || !isNonNegativeInteger(region.startLine) || region.startLine < 1) {
        return { ok: false, error: `${prefix} region.startLine must be a positive integer >= 1` };
      }
    }
    if (!isPlainObject(res.partialFingerprints)) {
      return { ok: false, error: `${prefix}.partialFingerprints must be an object` };
    }
    const fp = res.partialFingerprints["checkwash/v2"] ?? res.partialFingerprints["checkwash/v1"];
    if (!isNonEmptyString(fp)) {
      return { ok: false, error: `${prefix}.partialFingerprints must contain checkwash/v1 or checkwash/v2` };
    }
  }

  if ("invocations" in run && run.invocations !== undefined) {
    if (!Array.isArray(run.invocations)) {
      return { ok: false, error: "SARIF run.invocations must be an array when present" };
    }
    for (let i = 0; i < run.invocations.length; i++) {
      const inv = run.invocations[i];
      if (!isPlainObject(inv) || typeof inv.executionSuccessful !== "boolean") {
        return { ok: false, error: `SARIF invocations[${i}] is invalid` };
      }
      if (inv.toolExecutionNotifications !== undefined) {
        if (!Array.isArray(inv.toolExecutionNotifications)) {
          return { ok: false, error: `SARIF invocations[${i}].toolExecutionNotifications must be an array` };
        }
        for (let j = 0; j < inv.toolExecutionNotifications.length; j++) {
          const n = inv.toolExecutionNotifications[j];
          if (!isPlainObject(n) || !isPlainObject(n.message) || typeof n.message.text !== "string") {
            return { ok: false, error: `SARIF notification[${j}] is invalid` };
          }
        }
      }
    }
  }

  return {
    ok: true,
    value: doc as unknown as CheckwashSarifDocument,
  };
}
