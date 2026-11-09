export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

const FILE_ROLES = [
  "browserCode",
  "serverCode",
  "edgeFunction",
  "unknownCode",
  "migration",
  "envFile",
  "buildOutput",
  "other",
] as const;
export type FileRole = (typeof FILE_ROLES)[number];

const RLS_STATUSES = ["enabled", "disabled", "unknown"] as const;
export type RlsStatus = (typeof RLS_STATUSES)[number];

const POLICY_COMMANDS = ["all", "select", "insert", "update", "delete"] as const;
export type PolicyCommand = (typeof POLICY_COMMANDS)[number];

const SECRET_KINDS = [
  "supabaseServiceRoleKey",
  "supabaseSecretKey",
  "databaseUrl",
  "stripeSecretKey",
  "openAiApiKey",
  "anthropicApiKey",
  "awsAccessKeyId",
  "githubToken",
  "privateKey",
] as const;
export type SecretKind = (typeof SECRET_KINDS)[number];

export const EDGE_KINDS = ["defines", "guardedBy", "queries", "writes", "reads", "contains"] as const;
export type EdgeKind = (typeof EDGE_KINDS)[number];

export interface Location {
  path: string;
  line: number;
  column: number;
}

export type NodeKind =
  | { type: "file"; role: FileRole }
  | { type: "table"; schema: string; rls: RlsStatus }
  | { type: "policy"; command: PolicyCommand; roles: string[]; unrestricted: boolean }
  | { type: "envVar"; exposedToBrowser: boolean }
  | { type: "secret"; secretKind: SecretKind; masked: string };

export interface ReportNode {
  id: string;
  label: string;
  kind: NodeKind;
  location?: Location;
}

export interface ReportEdge {
  from: string;
  to: string;
  kind: EdgeKind;
}

export interface LocalizedText {
  en: string;
  ko: string;
}

export interface Finding {
  id: string;
  rule: string;
  severity: Severity;
  title: LocalizedText;
  explanation: LocalizedText;
  node: string;
  location?: Location;
  fixPrompt?: string;
}

export const SCHEMA_VERSION = 2;

export interface ScanReport {
  schemaVersion: typeof SCHEMA_VERSION;
  tool: { name: string; version: string };
  target: { name: string; filesScanned: number; filesSkipped: number; truncated: boolean };
  summary: Record<Severity, number>;
  nodes: ReportNode[];
  edges: ReportEdge[];
  findings: Finding[];
}

const MAX_NODES = 5000;
const MAX_EDGES = 20000;
const MAX_FINDINGS = 5000;
const MAX_TEXT = 20000;

export class ReportError extends Error {
  override name = "ReportError";
}

type Json = Record<string, unknown>;

function fail(path: string, expected: string): never {
  throw new ReportError(`${path}: ${expected}`);
}

function object(value: unknown, path: string, keys: readonly string[]): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(path, "object expected");
  }
  const record = value as Json;
  for (const key of Object.keys(record)) {
    if (!keys.includes(key)) fail(`${path}.${key}`, "unknown field");
  }
  return record;
}

function text(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length > MAX_TEXT) fail(path, "string expected");
  return value;
}

function count(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail(path, "non-negative integer expected");
  }
  return value;
}

function flag(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") fail(path, "boolean expected");
  return value;
}

function oneOf<T extends string>(value: unknown, path: string, allowed: readonly T[]): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
    fail(path, `one of ${allowed.join(", ")} expected`);
  }
  return value as T;
}

function list(value: unknown, path: string, max: number): unknown[] {
  if (!Array.isArray(value) || value.length > max) fail(path, `array of at most ${max} items expected`);
  return value;
}

function localized(value: unknown, path: string): LocalizedText {
  const o = object(value, path, ["en", "ko"]);
  return { en: text(o.en, `${path}.en`), ko: text(o.ko, `${path}.ko`) };
}

function location(value: unknown, path: string): Location {
  const o = object(value, path, ["path", "line", "column"]);
  return { path: text(o.path, `${path}.path`), line: count(o.line, `${path}.line`), column: count(o.column, `${path}.column`) };
}

function nodeKind(value: unknown, path: string): NodeKind {
  const tag = object(value, path, ["type", "role", "schema", "rls", "command", "roles", "unrestricted", "exposedToBrowser", "secretKind", "masked"]).type;
  switch (tag) {
    case "file": {
      const o = object(value, path, ["type", "role"]);
      return { type: "file", role: oneOf(o.role, `${path}.role`, FILE_ROLES) };
    }
    case "table": {
      const o = object(value, path, ["type", "schema", "rls"]);
      return { type: "table", schema: text(o.schema, `${path}.schema`), rls: oneOf(o.rls, `${path}.rls`, RLS_STATUSES) };
    }
    case "policy": {
      const o = object(value, path, ["type", "command", "roles", "unrestricted"]);
      return {
        type: "policy",
        command: oneOf(o.command, `${path}.command`, POLICY_COMMANDS),
        roles: list(o.roles, `${path}.roles`, 64).map((role, i) => text(role, `${path}.roles[${i}]`)),
        unrestricted: flag(o.unrestricted, `${path}.unrestricted`),
      };
    }
    case "envVar": {
      const o = object(value, path, ["type", "exposedToBrowser"]);
      return { type: "envVar", exposedToBrowser: flag(o.exposedToBrowser, `${path}.exposedToBrowser`) };
    }
    case "secret": {
      const o = object(value, path, ["type", "secretKind", "masked"]);
      return {
        type: "secret",
        secretKind: oneOf(o.secretKind, `${path}.secretKind`, SECRET_KINDS),
        masked: text(o.masked, `${path}.masked`),
      };
    }
    default:
      return fail(`${path}.type`, "known node type expected");
  }
}

export function parseScanReport(input: unknown): ScanReport {
  const root = object(input, "report", ["schemaVersion", "tool", "target", "summary", "nodes", "edges", "findings"]);
  if (root.schemaVersion !== SCHEMA_VERSION) fail("report.schemaVersion", `version ${SCHEMA_VERSION} expected`);

  const tool = object(root.tool, "report.tool", ["name", "version"]);
  const target = object(root.target, "report.target", ["name", "filesScanned", "filesSkipped", "truncated"]);
  const summary = object(root.summary, "report.summary", SEVERITIES);

  const nodes = list(root.nodes, "report.nodes", MAX_NODES).map((value, i): ReportNode => {
    const path = `report.nodes[${i}]`;
    const o = object(value, path, ["id", "label", "kind", "location"]);
    const node: ReportNode = { id: text(o.id, `${path}.id`), label: text(o.label, `${path}.label`), kind: nodeKind(o.kind, `${path}.kind`) };
    if (o.location !== undefined) node.location = location(o.location, `${path}.location`);
    return node;
  });
  const ids = new Set(nodes.map((node) => node.id));
  if (ids.size !== nodes.length) fail("report.nodes", "unique ids expected");
  const known = (value: unknown, path: string): string => {
    const id = text(value, path);
    if (!ids.has(id)) fail(path, "reference to a known node expected");
    return id;
  };

  const edges = list(root.edges, "report.edges", MAX_EDGES).map((value, i): ReportEdge => {
    const path = `report.edges[${i}]`;
    const o = object(value, path, ["from", "to", "kind"]);
    return { from: known(o.from, `${path}.from`), to: known(o.to, `${path}.to`), kind: oneOf(o.kind, `${path}.kind`, EDGE_KINDS) };
  });

  const findings = list(root.findings, "report.findings", MAX_FINDINGS).map((value, i): Finding => {
    const path = `report.findings[${i}]`;
    const o = object(value, path, ["id", "rule", "severity", "title", "explanation", "node", "location", "fixPrompt"]);
    const finding: Finding = {
      id: text(o.id, `${path}.id`),
      rule: text(o.rule, `${path}.rule`),
      severity: oneOf(o.severity, `${path}.severity`, SEVERITIES),
      title: localized(o.title, `${path}.title`),
      explanation: localized(o.explanation, `${path}.explanation`),
      node: known(o.node, `${path}.node`),
    };
    if (o.location !== undefined) finding.location = location(o.location, `${path}.location`);
    if (o.fixPrompt !== undefined) finding.fixPrompt = text(o.fixPrompt, `${path}.fixPrompt`);
    return finding;
  });

  return {
    schemaVersion: SCHEMA_VERSION,
    tool: { name: text(tool.name, "report.tool.name"), version: text(tool.version, "report.tool.version") },
    target: {
      name: text(target.name, "report.target.name"),
      filesScanned: count(target.filesScanned, "report.target.filesScanned"),
      filesSkipped: count(target.filesSkipped, "report.target.filesSkipped"),
      truncated: flag(target.truncated, "report.target.truncated"),
    },
    summary: {
      critical: count(summary.critical, "report.summary.critical"),
      high: count(summary.high, "report.summary.high"),
      medium: count(summary.medium, "report.summary.medium"),
      low: count(summary.low, "report.summary.low"),
      info: count(summary.info, "report.summary.info"),
    },
    nodes,
    edges,
    findings,
  };
}

export function worstSeverity(findings: readonly Finding[]): Severity | undefined {
  let worst: Severity | undefined;
  for (const finding of findings) {
    if (worst === undefined || SEVERITIES.indexOf(finding.severity) < SEVERITIES.indexOf(worst)) {
      worst = finding.severity;
    }
  }
  return worst;
}

export function edgeKindsIn(report: Pick<ScanReport, "edges">): EdgeKind[] {
  const present = new Set(report.edges.map((edge) => edge.kind));
  return EDGE_KINDS.filter((kind) => present.has(kind));
}
