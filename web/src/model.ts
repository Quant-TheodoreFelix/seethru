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

const UNITS = ["file", "function", "image", "package"] as const;
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

const BUCKET_VISIBILITIES = ["public", "private", "unknown"] as const;
export type BucketVisibility = (typeof BUCKET_VISIBILITIES)[number];

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

const ECOSYSTEMS = ["next", "vite", "supabase", "espIdf", "zephyr", "platformIo", "arduino", "cargo"] as const;
export type Ecosystem = (typeof ECOSYSTEMS)[number];

const INPUT_KINDS = ["source", "buildOutput", "sarif", "compileDatabase", "compiledOutput", "binary", "probe"] as const;
export type InputKind = (typeof INPUT_KINDS)[number];

const PROBE_ENVIRONMENTS = ["staging", "production"] as const;
export type ProbeEnvironment = (typeof PROBE_ENVIRONMENTS)[number];

const BINARY_FORMATS = ["elf", "machO"] as const;
export type BinaryFormat = (typeof BINARY_FORMATS)[number];

export interface ToolUse {
  name: string;
  version: string;
}

const BUILD_TOOLS = ["vite", "next"] as const;
export type BuildTool = (typeof BUILD_TOOLS)[number];

export type TargetInput =
  | { type: "source" }
  | { type: "buildOutput"; path: string; tool: BuildTool }
  | { type: "sarif"; path: string; engine: string; results: number; dropped: number }
  | { type: "compileDatabase"; path: string; files: number }
  | { type: "compiledOutput"; path: string; files: number; functions: number; machineCode: boolean }
  | { type: "binary"; path: string; format: BinaryFormat; tools: ToolUse[]; lines: number }
  | { type: "probe"; environment: ProbeEnvironment; tools: ToolUse[]; requests: number };

export const LIMITATION_CODES = ["buildOutputNotRead", "buildOutputStale", "buildOutputWithoutSourceMaps", "dashboardPoliciesUnseen", "externalNotVerified", "externalResultsDropped", "firmwareProtectionNotChecked", "nativeCodePartlyRead", "projectKindNotRecognized", "compiledOutputNotRead", "compiledChecksPartial", "compiledOutputWithoutMachineCode", "compiledOutputNotOptimized", "compiledOutputPartlyRead", "compiledOutputWithoutWipes", "outsideEntriesNotFound", "machineCodeProcessorNotKnown", "assemblyOutsideFunctionsNotRead", "binaryToolNotPermitted", "binaryToolFailed", "binaryNotFound", "binaryWithoutLineInfo", "binaryWipesNotConfirmed", "binaryChecksPartial", "probeToolNotPermitted", "probeToolFailed", "ownershipNotVerified", "probeTargetNotResponding", "probeStoppedBySeethru", "probeRedirectedOutside", "probePageNotRead", "probeChecksPartial"] as const;
export type LimitationCode = (typeof LIMITATION_CODES)[number];

export interface Location {
  path: string;
  line: number;
  column: number;
}

export type DataStoreDetail =
  | { type: "postgresTable"; schema: string; rls: RlsStatus }
  | { type: "postgresView"; schema: string; securityInvoker: boolean; materialized: boolean }
  | { type: "storageBucket"; visibility: BucketVisibility };
export type AccessRuleDetail = { type: "postgresPolicy"; command: PolicyCommand; roles: string[] };
export type ConfigDetail = { type: "envVar"; exposedToClient: boolean } | { type: "buildOption"; value: string };
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
  tools?: string[];
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

export interface DivisionLine {
  path: string;
  line: number;
  secret: boolean;
  assembly: boolean;
}

export interface AssemblyLine {
  path: string;
  line: number;
  divides: boolean;
  branches: boolean;
  secret: boolean;
}

export interface MachineCode {
  divisions: number;
  divisionsWithoutLine: number;
  divisionLines: DivisionLine[];
  assemblyBlocks: number;
  assemblyBlocksWithoutLine: number;
  assemblyLines: AssemblyLine[];
}

export const SCHEMA_VERSION = 12;

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
    inputs: TargetInput[];
    limitations: Limitation[];
    machineCode?: MachineCode;
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
const MAX_LINES = 500;

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
  switch (tagOf(value, path)) {
    case "postgresTable": {
      const o = object(value, path, ["type", "schema", "rls"]);
      return { type: "postgresTable", schema: text(o.schema, `${path}.schema`), rls: oneOf(o.rls, `${path}.rls`, RLS_STATUSES) };
    }
    case "postgresView": {
      const o = object(value, path, ["type", "schema", "securityInvoker", "materialized"]);
      return {
        type: "postgresView",
        schema: text(o.schema, `${path}.schema`),
        securityInvoker: flag(o.securityInvoker, `${path}.securityInvoker`),
        materialized: flag(o.materialized, `${path}.materialized`),
      };
    }
    case "storageBucket": {
      const o = object(value, path, ["type", "visibility"]);
      return { type: "storageBucket", visibility: oneOf(o.visibility, `${path}.visibility`, BUCKET_VISIBILITIES) };
    }
    default:
      return fail(`${path}.type`, "known detail type expected");
  }
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
  const tag = tagOf(value, path);
  if (tag === "buildOption") {
    const o = object(value, path, ["type", "value"]);
    return { type: "buildOption", value: text(o.value, `${path}.value`) };
  }
  if (tag !== "envVar") fail(`${path}.type`, "known detail type expected");
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

function machineCode(value: unknown, path: string): MachineCode {
  const o = object(value, path, [
    "divisions",
    "divisionsWithoutLine",
    "divisionLines",
    "assemblyBlocks",
    "assemblyBlocksWithoutLine",
    "assemblyLines",
  ]);
  return {
    divisions: count(o.divisions, `${path}.divisions`),
    divisionsWithoutLine: count(o.divisionsWithoutLine, `${path}.divisionsWithoutLine`),
    divisionLines: list(o.divisionLines, `${path}.divisionLines`, MAX_LINES).map((entry, i): DivisionLine => {
      const linePath = `${path}.divisionLines[${i}]`;
      const l = object(entry, linePath, ["path", "line", "secret", "assembly"]);
      return {
        path: text(l.path, `${linePath}.path`),
        line: count(l.line, `${linePath}.line`),
        secret: flag(l.secret, `${linePath}.secret`),
        assembly: flag(l.assembly, `${linePath}.assembly`),
      };
    }),
    assemblyBlocks: count(o.assemblyBlocks, `${path}.assemblyBlocks`),
    assemblyBlocksWithoutLine: count(o.assemblyBlocksWithoutLine, `${path}.assemblyBlocksWithoutLine`),
    assemblyLines: list(o.assemblyLines, `${path}.assemblyLines`, MAX_LINES).map((entry, i): AssemblyLine => {
      const linePath = `${path}.assemblyLines[${i}]`;
      const l = object(entry, linePath, ["path", "line", "divides", "branches", "secret"]);
      return {
        path: text(l.path, `${linePath}.path`),
        line: count(l.line, `${linePath}.line`),
        divides: flag(l.divides, `${linePath}.divides`),
        branches: flag(l.branches, `${linePath}.branches`),
        secret: flag(l.secret, `${linePath}.secret`),
      };
    }),
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
    "machineCode",
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
    const origin = object(o.origin, `${path}.origin`, ["engine", "inputs", "rule", "tools"]);
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
        ...(origin.tools === undefined
          ? {}
          : {
              tools: list(origin.tools, `${path}.origin.tools`, MAX_LIST).map((value, j) =>
                text(value, `${path}.origin.tools[${j}]`),
              ),
            }),
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
      inputs: list(target.inputs, "report.target.inputs", MAX_LIST).map((value, i): TargetInput => {
        const path = `report.target.inputs[${i}]`;
        const kind = oneOf(tagOf(value, path), `${path}.type`, INPUT_KINDS);
        if (kind === "source") {
          object(value, path, ["type"]);
          return { type: "source" };
        }
        if (kind === "compileDatabase") {
          const o = object(value, path, ["type", "path", "files"]);
          return { type: "compileDatabase", path: text(o.path, `${path}.path`), files: count(o.files, `${path}.files`) };
        }
        if (kind === "compiledOutput") {
          const o = object(value, path, ["type", "path", "files", "functions", "machineCode"]);
          return {
            type: "compiledOutput",
            path: text(o.path, `${path}.path`),
            files: count(o.files, `${path}.files`),
            functions: count(o.functions, `${path}.functions`),
            machineCode: flag(o.machineCode, `${path}.machineCode`),
          };
        }
        if (kind === "binary") {
          const o = object(value, path, ["type", "path", "format", "tools", "lines"]);
          return {
            type: "binary",
            path: text(o.path, `${path}.path`),
            format: oneOf(o.format, `${path}.format`, BINARY_FORMATS),
            tools: list(o.tools, `${path}.tools`, MAX_LIST).map((entry, j): ToolUse => {
              const toolPath = `${path}.tools[${j}]`;
              const t = object(entry, toolPath, ["name", "version"]);
              return { name: text(t.name, `${toolPath}.name`), version: text(t.version, `${toolPath}.version`) };
            }),
            lines: count(o.lines, `${path}.lines`),
          };
        }
        if (kind === "probe") {
          const o = object(value, path, ["type", "environment", "tools", "requests"]);
          return {
            type: "probe",
            environment: oneOf(o.environment, `${path}.environment`, PROBE_ENVIRONMENTS),
            tools: list(o.tools, `${path}.tools`, MAX_LIST).map((entry, j): ToolUse => {
              const toolPath = `${path}.tools[${j}]`;
              const t = object(entry, toolPath, ["name", "version"]);
              return { name: text(t.name, `${toolPath}.name`), version: text(t.version, `${toolPath}.version`) };
            }),
            requests: count(o.requests, `${path}.requests`),
          };
        }
        if (kind === "sarif") {
          const o = object(value, path, ["type", "path", "engine", "results", "dropped"]);
          return {
            type: "sarif",
            path: text(o.path, `${path}.path`),
            engine: text(o.engine, `${path}.engine`),
            results: count(o.results, `${path}.results`),
            dropped: count(o.dropped, `${path}.dropped`),
          };
        }
        const o = object(value, path, ["type", "path", "tool"]);
        return { type: "buildOutput", path: text(o.path, `${path}.path`), tool: oneOf(o.tool, `${path}.tool`, BUILD_TOOLS) };
      }),
      limitations: list(target.limitations, "report.target.limitations", MAX_LIST).map((value, i): Limitation => {
        const path = `report.target.limitations[${i}]`;
        const o = object(value, path, ["code", "text"]);
        return { code: oneOf(o.code, `${path}.code`, LIMITATION_CODES), text: localized(o.text, `${path}.text`) };
      }),
      ...(target.machineCode === undefined ? {} : { machineCode: machineCode(target.machineCode, "report.target.machineCode") }),
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

export const LIST_VIEWS = [...SEVERITIES, "accepted", "limitations", "machineCode"] as const;
export type ListView = (typeof LIST_VIEWS)[number];

export function isSeverity(view: ListView): view is Severity {
  return view !== "accepted" && view !== "limitations" && view !== "machineCode";
}

export function viewOf(finding: Pick<Finding, "severity" | "accepted">): ListView {
  return finding.accepted ? "accepted" : finding.severity;
}

export function findingsIn(report: Pick<ScanReport, "findings">, view: ListView): Finding[] {
  return report.findings.filter((finding) => viewOf(finding) === view);
}

export function viewCount(report: Pick<ScanReport, "summary" | "target">, view: ListView): number {
  if (view === "limitations") return report.target.limitations.length;
  if (view === "machineCode") {
    const machine = report.target.machineCode;
    return machine ? machine.divisionLines.length + machine.assemblyLines.length : 0;
  }
  return report.summary[view];
}
