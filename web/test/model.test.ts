import assert from "node:assert/strict";
import { test } from "node:test";
import { ReportError, edgeKindsIn, parseScanReport, worstSeverity } from "../src/model.ts";

function validReport(): Record<string, unknown> {
  return {
    schemaVersion: 2,
    tool: { name: "seethru", version: "0.1.0" },
    target: { name: "app", filesScanned: 2, filesSkipped: 0, truncated: false },
    summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    nodes: [
      { id: "file:a.sql", label: "a.sql", kind: { type: "file", role: "migration" } },
      {
        id: "table:public.todos",
        label: "todos",
        kind: { type: "table", schema: "public", rls: "disabled" },
        location: { path: "a.sql", line: 1, column: 1 },
      },
    ],
    edges: [{ from: "file:a.sql", to: "table:public.todos", kind: "defines" }],
    findings: [
      {
        id: "supabase-rls-disabled:table:public.todos",
        rule: "supabase-rls-disabled",
        severity: "critical",
        title: { en: "t", ko: "제목" },
        explanation: { en: "e", ko: "설명" },
        node: "table:public.todos",
        fixPrompt: { en: "p", ko: "프롬프트" },
      },
    ],
  };
}

test("accepts a valid report", () => {
  const report = parseScanReport(validReport());
  assert.equal(report.nodes.length, 2);
  assert.equal(report.findings[0]?.severity, "critical");
  assert.equal(worstSeverity(report.findings), "critical");
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
  badSeverity.summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, extreme: 1 };
  assert.throws(() => parseScanReport(badSeverity), ReportError);

  const badKind = validReport();
  badKind.nodes = [{ id: "x", label: "x", kind: { type: "script", src: "https://example.invalid/x.js" } }];
  assert.throws(() => parseScanReport(badKind), ReportError);
});

test("rejects wrong schema versions and non objects", () => {
  assert.throws(() => parseScanReport({ ...validReport(), schemaVersion: 1 }), /version 2 expected/);
  assert.throws(() => parseScanReport({ ...validReport(), schemaVersion: 3 }), ReportError);
  assert.throws(() => parseScanReport(null), ReportError);
  assert.throws(() => parseScanReport([]), ReportError);
});

test("rejects duplicate node ids and negative counts", () => {
  const duplicate = validReport();
  duplicate.nodes = [...(validReport().nodes as object[]), (validReport().nodes as object[])[0]];
  assert.throws(() => parseScanReport(duplicate), /unique/);

  const negative = validReport();
  negative.target = { name: "app", filesScanned: -1, filesSkipped: 0, truncated: false };
  assert.throws(() => parseScanReport(negative), ReportError);
});

test("lists each edge kind in the report once in a fixed order", () => {
  const edges = [
    { from: "a", to: "b", kind: "reads" },
    { from: "a", to: "c", kind: "defines" },
    { from: "b", to: "c", kind: "reads" },
  ] as const;
  assert.deepEqual(edgeKindsIn({ edges: [...edges] }), ["defines", "reads"]);
  assert.deepEqual(edgeKindsIn({ edges: [] }), []);
});
