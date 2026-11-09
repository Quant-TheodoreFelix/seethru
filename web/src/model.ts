export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ["certain", "likely", "review"] as const;
export type Confidence = (typeof CONFIDENCES)[number];

export const ZONES = ["client", "server", "database", "device", "buildTime", "thirdParty", "unknown"] as const;
export type Zone = (typeof ZONES)[number];

const RUNTIMES = ["browser", "server", "edge", "mobile", "native", "firmware", "database", "build", "unknown"] as const;
export type Runtime = (typeof RUNTIMES)[number];

const ARTIFACTS = ["source", "buildOutput", "migration", "config", "binary", "other"] as const;
export type Artifact = (typeof ARTIFACTS)[number];

const UNITS = ["file", "function", "image"] as const;
export type Unit = (typeof UNITS)[number];

const BASES = ["path", "directive", "imports", "buildOutput", "engine", "dynamic"] as const;
export type Basis = (typeof BASES)[number];

const CHANNELS = ["httpRoute", "serverAction", "rpc", "cli", "ipc", "queue", "schedule", "serial", "ble", "socket"] as const;
export type Channel = (typeof CHANNELS)[number];

const EXPOSURES = ["public", "authenticated", "internal", "unknown"] as const;
export type Exposure = (typeof EXPOSURES)[number];

const RULE_SCOPES = ["open", "conditional", "unknown"] as const;
export type RuleScope = (typeof RULE_SCOPES)[number];

const STRENGTHS = ["verified", "weak", "unknown"] as const;
export type Strength = (typeof STRENGTHS)[number];

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

export const EDGE_KINDS = [
  "imports",
  "calls",
  "builtFrom",
  "invokes",
  "reads",
  "writes",
  "usesConfig",
  "defines",
  "guardedBy",
  "actsAs",
  "appliesTo",
  "contains",
  "unlocks",
  "connectsTo",
] as const;
export type EdgeKind = (typeof EDGE_KINDS)[number];

const ECOSYSTEMS = ["next", "vite", "supabase"] as const;
export type Ecosystem = (typeof ECOSYSTEMS)[number];

const INPUT_KINDS = ["source"] as const;
export type InputKind = (typeof INPUT_KINDS)[number];

export const LIMITATION_CODES = ["buildOutputNotRead", "dashboardPoliciesUnseen"] as const;
export type LimitationCode = (typeof LIMITATION_CODES)[number];

export interface Location {
  path: string;
  line: number;
  column: number;
}

export type DataStoreDetail = { type: "postgresTable"; schema: string; rls: RlsStatus };
export type AccessRuleDetail = { type: "postgresPolicy"; command: PolicyCommand; roles: string[] };
export type ConfigDetail = { type: "envVar"; exposedToClient: boolean };
export type CredentialDetail = { type: "secret"; secretKind: SecretKind; masked: string };

export type NodeKind =
  | { type: "component"; runtime: Runtime; artifact: Artifact; unit: Unit; basis: Basis }
  | { type: "entryPoint"; channel: Channel; exposure: Exposure }
  | { type: "dataStore"; detail?: DataStoreDetail }
  | { type: "accessRule"; scope: RuleScope; strength?: Strength; detail?: AccessRuleDetail }
  | { type: "principal" }
  | { type: "credential"; detail: CredentialDetail }
  | { type: "config"; detail?: ConfigDetail }
  | { type: "service" };

export interface ReportNode {
  id: string;
  label: string;
  kind: NodeKind;
  zone: Zone;
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

export interface Acceptance {
  reason: string;
}

export interface EvidenceStep {
  label: string;
  via?: EdgeKind;
  node?: string;
  location?: Location;
}

export interface Origin {
  engine: string;
  inputs: InputKind[];
  rule?: string;
}

export interface Finding {
  id: string;
  rule: string;
  severity: Severity;
  confidence: Confidence;
  title: LocalizedText;
  explanation: LocalizedText;
  node: string;
  location?: Location;
  evidence: EvidenceStep[];
  origin: Origin;
  cwe: number[];
  proof?: string;
  fixPrompt?: LocalizedText;
  accepted?: Acceptance;
}

export interface Limitation {
  code: LimitationCode;
  text: LocalizedText;
}

export const SCHEMA_VERSION = 4;

export interface ScanReport {
  schemaVersion: typeof SCHEMA_VERSION;
  tool: { name: string; version: string };
  target: {
    name: string;
    filesScanned: number;
    filesSkipped: number;
    filesExcluded: number;
    truncated: boolean;
    configFile?: string;
    ecosystems: Ecosystem[];
    inputs: { type: InputKind }[];
    limitations: Limitation[];
  };
  summary: Record<Severity, number> & { accepted: number };
  nodes: ReportNode[];
  edges: ReportEdge[];
  findings: Finding[];
}

const MAX_NODES = 5000;
const MAX_EDGES = 20000;
const MAX_FINDINGS = 5000;
const MAX_TEXT = 20000;
const MAX_ROLES = 64;
const MAX_STEPS = 64;
const MAX_CWE = 16;
const MAX_LIST = 64;

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

function tagOf(value: unknown, path: string): string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(path, "object expected");
  const tag = (value as Json).type;
  if (typeof tag !== "string") fail(`${path}.type`, "string expected");
  return tag;
}

function dataStoreDetail(value: unknown, path: string): DataStoreDetail {
  if (tagOf(value, path) !== "postgresTable") fail(`${path}.type`, "known detail type expected");
  const o = object(value, path, ["type", "schema", "rls"]);
  return { type: "postgresTable", schema: text(o.schema, `${path}.schema`), rls: oneOf(o.rls, `${path}.rls`, RLS_STATUSES) };
}

function accessRuleDetail(value: unknown, path: string): AccessRuleDetail {
  if (tagOf(value, path) !== "postgresPolicy") fail(`${path}.type`, "known detail type expected");
  const o = object(value, path, ["type", "command", "roles"]);
  return {
    type: "postgresPolicy",
    command: oneOf(o.command, `${path}.command`, POLICY_COMMANDS),
    roles: list(o.roles, `${path}.roles`, MAX_ROLES).map((role, i) => text(role, `${path}.roles[${i}]`)),
  };
}

function configDetail(value: unknown, path: string): ConfigDetail {
  if (tagOf(value, path) !== "envVar") fail(`${path}.type`, "known detail type expected");
  const o = object(value, path, ["type", "exposedToClient"]);
  return { type: "envVar", exposedToClient: flag(o.exposedToClient, `${path}.exposedToClient`) };
}

function credentialDetail(value: unknown, path: string): CredentialDetail {
  if (tagOf(value, path) !== "secret") fail(`${path}.type`, "known detail type expected");
  const o = object(value, path, ["type", "secretKind", "masked"]);
  return {
    type: "secret",
    secretKind: oneOf(o.secretKind, `${path}.secretKind`, SECRET_KINDS),
    masked: text(o.masked, `${path}.masked`),
  };
}

function nodeKind(value: unknown, path: string): NodeKind {
  switch (tagOf(value, path)) {
    case "component": {
      const o = object(value, path, ["type", "runtime", "artifact", "unit", "basis"]);
      return {
        type: "component",
        runtime: oneOf(o.runtime, `${path}.runtime`, RUNTIMES),
        artifact: oneOf(o.artifact, `${path}.artifact`, ARTIFACTS),
        unit: oneOf(o.unit, `${path}.unit`, UNITS),
        basis: oneOf(o.basis, `${path}.basis`, BASES),
      };
    }
    case "entryPoint": {
      const o = object(value, path, ["type", "channel", "exposure"]);
      return {
        type: "entryPoint",
        channel: oneOf(o.channel, `${path}.channel`, CHANNELS),
        exposure: oneOf(o.exposure, `${path}.exposure`, EXPOSURES),
      };
    }
    case "dataStore": {
      const o = object(value, path, ["type", "detail"]);
      return o.detail === undefined ? { type: "dataStore" } : { type: "dataStore", detail: dataStoreDetail(o.detail, `${path}.detail`) };
    }
    case "accessRule": {
      const o = object(value, path, ["type", "scope", "strength", "detail"]);
      const kind: NodeKind = { type: "accessRule", scope: oneOf(o.scope, `${path}.scope`, RULE_SCOPES) };
      if (o.strength !== undefined) kind.strength = oneOf(o.strength, `${path}.strength`, STRENGTHS);
      if (o.detail !== undefined) kind.detail = accessRuleDetail(o.detail, `${path}.detail`);
      return kind;
    }
    case "principal":
      object(value, path, ["type"]);
      return { type: "principal" };
    case "credential": {
      const o = object(value, path, ["type", "detail"]);
      return { type: "credential", detail: credentialDetail(o.detail, `${path}.detail`) };
    }
    case "config": {
      const o = object(value, path, ["type", "detail"]);
      return o.detail === undefined ? { type: "config" } : { type: "config", detail: configDetail(o.detail, `${path}.detail`) };
    }
    case "service":
      object(value, path, ["type"]);
      return { type: "service" };
    default:
      return fail(`${path}.type`, "known node type expected");
  }
}

export function parseScanReport(input: unknown): ScanReport {
  const root = object(input, "report", ["schemaVersion", "tool", "target", "summary", "nodes", "edges", "findings"]);
  if (root.schemaVersion !== SCHEMA_VERSION) fail("report.schemaVersion", `version ${SCHEMA_VERSION} expected`);

  const tool = object(root.tool, "report.tool", ["name", "version"]);
  const target = object(root.target, "report.target", [
    "name",
    "filesScanned",
    "filesSkipped",
    "filesExcluded",
    "truncated",
    "configFile",
    "ecosystems",
    "inputs",
    "limitations",
  ]);
  const summary = object(root.summary, "report.summary", [...SEVERITIES, "accepted"]);

  const nodes = list(root.nodes, "report.nodes", MAX_NODES).map((value, i): ReportNode => {
    const path = `report.nodes[${i}]`;
    const o = object(value, path, ["id", "label", "kind", "zone", "location"]);
    const node: ReportNode = {
      id: text(o.id, `${path}.id`),
      label: text(o.label, `${path}.label`),
      kind: nodeKind(o.kind, `${path}.kind`),
      zone: oneOf(o.zone, `${path}.zone`, ZONES),
    };
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
    const o = object(value, path, [
      "id",
      "rule",
      "severity",
      "confidence",
      "title",
      "explanation",
      "node",
      "location",
      "evidence",
      "origin",
      "cwe",
      "proof",
      "fixPrompt",
      "accepted",
    ]);
    const origin = object(o.origin, `${path}.origin`, ["engine", "inputs", "rule"]);
    const finding: Finding = {
      id: text(o.id, `${path}.id`),
      rule: text(o.rule, `${path}.rule`),
      severity: oneOf(o.severity, `${path}.severity`, SEVERITIES),
      confidence: oneOf(o.confidence, `${path}.confidence`, CONFIDENCES),
      title: localized(o.title, `${path}.title`),
      explanation: localized(o.explanation, `${path}.explanation`),
      node: known(o.node, `${path}.node`),
      evidence: list(o.evidence, `${path}.evidence`, MAX_STEPS).map((value, j): EvidenceStep => {
        const stepPath = `${path}.evidence[${j}]`;
        const s = object(value, stepPath, ["label", "via", "node", "location"]);
        const step: EvidenceStep = { label: text(s.label, `${stepPath}.label`) };
        if (s.via !== undefined) step.via = oneOf(s.via, `${stepPath}.via`, EDGE_KINDS);
        if (s.node !== undefined) step.node = known(s.node, `${stepPath}.node`);
        if (s.location !== undefined) step.location = location(s.location, `${stepPath}.location`);
        return step;
      }),
      origin: {
        engine: text(origin.engine, `${path}.origin.engine`),
        inputs: list(origin.inputs, `${path}.origin.inputs`, MAX_LIST).map((value, j) =>
          oneOf(value, `${path}.origin.inputs[${j}]`, INPUT_KINDS),
        ),
        ...(origin.rule === undefined ? {} : { rule: text(origin.rule, `${path}.origin.rule`) }),
      },
      cwe: list(o.cwe, `${path}.cwe`, MAX_CWE).map((value, j) => count(value, `${path}.cwe[${j}]`)),
    };
    if (o.location !== undefined) finding.location = location(o.location, `${path}.location`);
    if (o.proof !== undefined) finding.proof = text(o.proof, `${path}.proof`);
    if (o.fixPrompt !== undefined) finding.fixPrompt = localized(o.fixPrompt, `${path}.fixPrompt`);
    if (o.accepted !== undefined) {
      const accepted = object(o.accepted, `${path}.accepted`, ["reason"]);
      finding.accepted = { reason: text(accepted.reason, `${path}.accepted.reason`) };
    }
    return finding;
  });

  return {
    schemaVersion: SCHEMA_VERSION,
    tool: { name: text(tool.name, "report.tool.name"), version: text(tool.version, "report.tool.version") },
    target: {
      name: text(target.name, "report.target.name"),
      filesScanned: count(target.filesScanned, "report.target.filesScanned"),
      filesSkipped: count(target.filesSkipped, "report.target.filesSkipped"),
      filesExcluded: count(target.filesExcluded, "report.target.filesExcluded"),
      truncated: flag(target.truncated, "report.target.truncated"),
      ...(target.configFile === undefined ? {} : { configFile: text(target.configFile, "report.target.configFile") }),
      ecosystems: list(target.ecosystems, "report.target.ecosystems", MAX_LIST).map((value, i) =>
        oneOf(value, `report.target.ecosystems[${i}]`, ECOSYSTEMS),
      ),
      inputs: list(target.inputs, "report.target.inputs", MAX_LIST).map((value, i) => {
        const o = object(value, `report.target.inputs[${i}]`, ["type"]);
        return { type: oneOf(o.type, `report.target.inputs[${i}].type`, INPUT_KINDS) };
      }),
      limitations: list(target.limitations, "report.target.limitations", MAX_LIST).map((value, i): Limitation => {
        const path = `report.target.limitations[${i}]`;
        const o = object(value, path, ["code", "text"]);
        return { code: oneOf(o.code, `${path}.code`, LIMITATION_CODES), text: localized(o.text, `${path}.text`) };
      }),
    },
    summary: {
      critical: count(summary.critical, "report.summary.critical"),
      high: count(summary.high, "report.summary.high"),
      medium: count(summary.medium, "report.summary.medium"),
      low: count(summary.low, "report.summary.low"),
      info: count(summary.info, "report.summary.info"),
      accepted: count(summary.accepted, "report.summary.accepted"),
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
