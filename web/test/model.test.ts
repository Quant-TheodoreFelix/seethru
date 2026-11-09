import assert from "node:assert/strict";
import { test } from "node:test";
import { ReportError, edgeKindsIn, parseScanReport, worstSeverity } from "../src/model.ts";

function validReport(): Record<string, unknown> {
  return {
    schemaVersion: 4,
    tool: { name: "seethru", version: "0.1.0" },
    target: {
      name: "app",
      filesScanned: 2,
      filesSkipped: 0,
      filesExcluded: 0,
      truncated: false,
      ecosystems: ["supabase"],
      inputs: [{ type: "source" }],
      limitations: [{ code: "dashboardPoliciesUnseen", text: { en: "l", ko: "한계" } }],
    },
    summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0, accepted: 0 },
    nodes: [
      {
        id: "file:a.sql",
        label: "a.sql",
        kind: { type: "component", runtime: "database", artifact: "migration", unit: "file", basis: "path" },
        zone: "database",
      },
      {
        id: "table:public.todos",
        label: "todos",
        kind: { type: "dataStore", detail: { type: "postgresTable", schema: "public", rls: "disabled" } },
        zone: "database",
        location: { path: "a.sql", line: 1, column: 1 },
      },
    ],
    edges: [{ from: "file:a.sql", to: "table:public.todos", kind: "defines" }],
    findings: [
      {
        id: "supabase-rls-disabled:table:public.todos",
        rule: "supabase-rls-disabled",
        severity: "critical",
        confidence: "certain",
        title: { en: "t", ko: "제목" },
        explanation: { en: "e", ko: "설명" },
        node: "table:public.todos",
        evidence: [
          { label: "a.sql", node: "file:a.sql", location: { path: "a.sql", line: 1, column: 1 } },
          { label: "todos", via: "defines", node: "table:public.todos", location: { path: "a.sql", line: 1, column: 1 } },
        ],
        origin: { engine: "seethru", inputs: ["source"] },
        cwe: [862],
        fixPrompt: { en: "p", ko: "프롬프트" },
      },
    ],
  };
}

test("accepts a valid report", () => {
  const report = parseScanReport(validReport());
  assert.equal(report.nodes.length, 2);
  assert.equal(report.findings[0]?.severity, "critical");
  assert.equal(report.findings[0]?.confidence, "certain");
  assert.equal(report.findings[0]?.evidence.length, 2);
  assert.deepEqual(report.findings[0]?.cwe, [862]);
  assert.deepEqual(report.target.ecosystems, ["supabase"]);
  assert.equal(report.target.limitations[0]?.code, "dashboardPoliciesUnseen");
  assert.equal(report.nodes[1]?.zone, "database");
  assert.equal(worstSeverity(report.findings), "critical");
});

test("accepts every node kind and rejects extra fields inside kind and detail", () => {
  const kinds = [
    { type: "component", runtime: "browser", artifact: "source", unit: "file", basis: "imports" },
    { type: "entryPoint", channel: "httpRoute", exposure: "unknown" },
    { type: "dataStore" },
    { type: "accessRule", scope: "open", strength: "weak", detail: { type: "postgresPolicy", command: "select", roles: ["anon"] } },
    { type: "principal" },
    { type: "credential", detail: { type: "secret", secretKind: "stripeSecretKey", masked: "sk_live_****" } },
    { type: "config", detail: { type: "envVar", exposedToClient: true } },
    { type: "service" },
  ];
  const report = validReport();
  report.nodes = kinds.map((kind, i) => ({ id: `n${i}`, label: "n", kind, zone: "unknown" }));
  report.edges = [];
  report.findings = [];
  assert.equal(parseScanReport(report).nodes.length, kinds.length);

  const extraInKind = validReport();
  extraInKind.nodes = [{ id: "x", label: "x", kind: { type: "principal", extra: 1 }, zone: "unknown" }];
  extraInKind.edges = [];
  extraInKind.findings = [];
  assert.throws(() => parseScanReport(extraInKind), /kind\.extra/);

  const extraInDetail = validReport();
  extraInDetail.nodes = [
    { id: "x", label: "x", kind: { type: "dataStore", detail: { type: "postgresTable", schema: "public", rls: "enabled", extra: 1 } }, zone: "database" },
  ];
  extraInDetail.edges = [];
  extraInDetail.findings = [];
  assert.throws(() => parseScanReport(extraInDetail), /detail\.extra/);

  const noZone = validReport();
  noZone.nodes = [{ id: "x", label: "x", kind: { type: "service" } }];
  noZone.edges = [];
  noZone.findings = [];
  assert.throws(() => parseScanReport(noZone), /zone/);
});

test("rejects evidence steps that point at missing nodes", () => {
  const report = validReport();
  const finding = (report.findings as Record<string, unknown>[])[0];
  report.findings = [{ ...finding, evidence: [{ label: "ghost", node: "ghost" }] }];
  assert.throws(() => parseScanReport(report), /known node/);
});

test("rejects unknown fields", () => {
  const report = validReport();
  report.extra = true;
  assert.throws(() => parseScanReport(report), ReportError);
});

test("reads finding texts in both languages and rejects anything else", () => {
  const report = parseScanReport(validReport());
  assert.deepEqual(report.findings[0]?.title, { en: "t", ko: "제목" });
  assert.deepEqual(report.findings[0]?.fixPrompt, { en: "p", ko: "프롬프트" });

  const finding = (validReport().findings as Record<string, unknown>[])[0];
  for (const title of ["t", { en: "t" }, { en: "t", ko: "제목", ja: "x" }, { en: "t", ko: 1 }]) {
    const broken = validReport();
    broken.findings = [{ ...finding, title }];
    assert.throws(() => parseScanReport(broken), ReportError);
  }
  const plainPrompt = validReport();
  plainPrompt.findings = [{ ...finding, fixPrompt: "p" }];
  assert.throws(() => parseScanReport(plainPrompt), /fixPrompt/);
});

test("reads accepted findings and the config that accepted them", () => {
  const input = validReport();
  input.target = { ...(input.target as object), filesExcluded: 4, configFile: "seethru.toml" };
  const finding = (input.findings as Record<string, unknown>[])[0];
  input.findings = [{ ...finding, accepted: { reason: "Public on purpose" } }];
  const report = parseScanReport(input);
  assert.equal(report.target.configFile, "seethru.toml");
  assert.equal(report.target.filesExcluded, 4);
  assert.deepEqual(report.findings[0]?.accepted, { reason: "Public on purpose" });

  const broken = validReport();
  broken.findings = [{ ...finding, accepted: { reason: "x", by: "someone" } }];
  assert.throws(() => parseScanReport(broken), /accepted\.by/);
});

test("rejects edges and findings that point at missing nodes", () => {
  const dangling = validReport();
  dangling.edges = [{ from: "file:a.sql", to: "table:public.ghost", kind: "defines" }];
  assert.throws(() => parseScanReport(dangling), /known node/);

  const orphan = validReport();
  orphan.findings = [{ ...(validReport().findings as object[])[0], node: "ghost" }];
  assert.throws(() => parseScanReport(orphan), /known node/);
});

test("rejects unknown enum values and node types", () => {
  const badSeverity = validReport();
  badSeverity.summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, accepted: 0, extreme: 1 };
  assert.throws(() => parseScanReport(badSeverity), ReportError);

  const badKind = validReport();
  badKind.nodes = [{ id: "x", label: "x", kind: { type: "script", src: "https://example.invalid/x.js" }, zone: "unknown" }];
  assert.throws(() => parseScanReport(badKind), ReportError);
});

test("rejects wrong schema versions and non objects", () => {
  assert.throws(() => parseScanReport({ ...validReport(), schemaVersion: 3 }), /version 4 expected/);
  assert.throws(() => parseScanReport({ ...validReport(), schemaVersion: 5 }), ReportError);
  assert.throws(() => parseScanReport(null), ReportError);
  assert.throws(() => parseScanReport([]), ReportError);
});

test("rejects duplicate node ids and negative counts", () => {
  const duplicate = validReport();
  duplicate.nodes = [...(validReport().nodes as object[]), (validReport().nodes as object[])[0]];
  assert.throws(() => parseScanReport(duplicate), /unique/);

  const negative = validReport();
  negative.target = { ...(validReport().target as object), filesScanned: -1 };
  assert.throws(() => parseScanReport(negative), ReportError);
});

test("lists each edge kind in the report once in a fixed order", () => {
  const edges = [
    { from: "a", to: "b", kind: "usesConfig" },
    { from: "a", to: "c", kind: "defines" },
    { from: "b", to: "c", kind: "reads" },
  ] as const;
  assert.deepEqual(edgeKindsIn({ edges: [...edges] }), ["reads", "usesConfig", "defines"]);
  assert.deepEqual(edgeKindsIn({ edges: [] }), []);
});
