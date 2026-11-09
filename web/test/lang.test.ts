import assert from "node:assert/strict";
import { test } from "node:test";
import { pageLang, parseLang } from "../src/lang.ts";
import { MESSAGES, kindLabel } from "../src/messages.ts";

test("accepts only the two known languages", () => {
  assert.equal(parseLang("en"), "en");
  assert.equal(parseLang("ko"), "ko");
  assert.equal(parseLang("KO"), undefined);
  assert.equal(parseLang("ja"), undefined);
  assert.equal(parseLang(undefined), undefined);
});

test("starts in the language the page was written in", () => {
  assert.equal(pageLang("ko"), "ko");
  assert.equal(pageLang("ko-KR"), "ko");
  assert.equal(pageLang(" EN "), "en");
  assert.equal(pageLang("ja"), "en");
  assert.equal(pageLang(""), "en");
  assert.equal(pageLang(null), "en");
});

function strings(value: unknown, path: string): [string, string][] {
  if (typeof value === "string") return [[path, value]];
  if (typeof value === "function") {
    const target = { name: "app", filesScanned: 2, filesSkipped: 0, filesExcluded: 1, truncated: true };
    return [[path, String(value.length === 1 && path.endsWith("scanned") ? value(target) : value("x"))]];
  }
  return Object.entries(value as Record<string, unknown>).flatMap(([key, inner]) => strings(inner, `${path}.${key}`));
}

test("both languages fill every message", () => {
  const en = strings(MESSAGES.en, "en");
  const ko = strings(MESSAGES.ko, "ko");
  assert.deepEqual(
    en.map(([path]) => path.slice(3)),
    ko.map(([path]) => path.slice(3)),
  );
  for (const [path, text] of [...en, ...ko]) {
    assert.ok(text.trim().length > 0, path);
    assert.ok(!text.includes("—"), path);
  }
  const target = { name: "app", filesScanned: 1, filesSkipped: 0, filesExcluded: 0, truncated: false };
  assert.equal(MESSAGES.en.scanned(target), "1 file scanned");
  assert.equal(
    MESSAGES.en.scanned({ ...target, filesScanned: 3, filesExcluded: 2, truncated: true, configFile: "seethru.toml" }),
    "3 files scanned, 2 excluded by seethru.toml, stopped early",
  );
  assert.equal(MESSAGES.ko.scanned({ ...target, filesScanned: 3, filesExcluded: 2 }), "파일 3개 검사, seethru.toml로 2개 제외");
});

test("labels graph nodes in the chosen language", () => {
  const policy = { type: "policy", command: "update", roles: ["authenticated"], unrestricted: true } as const;
  assert.equal(kindLabel(policy, MESSAGES.en), "Policy · Update · authenticated");
  assert.equal(kindLabel(policy, MESSAGES.ko), "정책 · 수정 · authenticated");
  const table = { type: "table", schema: "public", rls: "disabled" } as const;
  assert.equal(kindLabel(table, MESSAGES.en), "Table · RLS off");
  assert.equal(kindLabel(table, MESSAGES.ko), "테이블 · RLS 꺼짐");
});
