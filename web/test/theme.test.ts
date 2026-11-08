import assert from "node:assert/strict";
import { test } from "node:test";
import { parseTheme, readStoredTheme, storeTheme, systemTheme } from "../src/theme.ts";

function memoryStorage(initial?: string) {
  const values = new Map<string, string>();
  if (initial !== undefined) values.set("seethru-theme", initial);
  return {
    values,
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => void values.set(key, value),
  };
}

const brokenStorage = {
  getItem: (): string | null => {
    throw new Error("blocked");
  },
  setItem: (): void => {
    throw new Error("blocked");
  },
};

test("accepts only the two known themes", () => {
  assert.equal(parseTheme("light"), "light");
  assert.equal(parseTheme("dark"), "dark");
  assert.equal(parseTheme("Dark"), undefined);
  assert.equal(parseTheme("<script>"), undefined);
  assert.equal(parseTheme(null), undefined);
});

test("reads a stored choice and ignores anything else", () => {
  assert.equal(readStoredTheme(memoryStorage("dark")), "dark");
  assert.equal(readStoredTheme(memoryStorage("blue")), undefined);
  assert.equal(readStoredTheme(memoryStorage()), undefined);
  assert.equal(readStoredTheme(undefined), undefined);
});

test("blocked storage never breaks the page", () => {
  assert.equal(readStoredTheme(brokenStorage), undefined);
  assert.doesNotThrow(() => storeTheme(brokenStorage, "dark"));
  assert.doesNotThrow(() => storeTheme(undefined, "dark"));
});

test("stores the chosen theme", () => {
  const storage = memoryStorage();
  storeTheme(storage, "dark");
  assert.equal(storage.values.get("seethru-theme"), "dark");
});

test("follows the system preference when nothing is stored", () => {
  assert.equal(systemTheme({ matches: true }), "dark");
  assert.equal(systemTheme({ matches: false }), "light");
  assert.equal(systemTheme(undefined), "light");
});
