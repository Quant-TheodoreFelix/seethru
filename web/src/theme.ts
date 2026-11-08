export type Theme = "light" | "dark";

export const THEMES: readonly Theme[] = ["light", "dark"];

const STORAGE_KEY = "seethru-theme";

type ThemeStorage = Pick<Storage, "getItem" | "setItem">;

export function parseTheme(value: unknown): Theme | undefined {
  return value === "light" || value === "dark" ? value : undefined;
}

export function readStoredTheme(storage: ThemeStorage | undefined): Theme | undefined {
  try {
    return parseTheme(storage?.getItem(STORAGE_KEY));
  } catch {
    return undefined;
  }
}

export function storeTheme(storage: ThemeStorage | undefined, theme: Theme): void {
  try {
    storage?.setItem(STORAGE_KEY, theme);
  } catch {
    return;
  }
}

export function themeStorage(): ThemeStorage | undefined {
  try {
    return globalThis.localStorage;
  } catch {
    return undefined;
  }
}

export function systemTheme(query: Pick<MediaQueryList, "matches"> | undefined): Theme {
  return query?.matches ? "dark" : "light";
}
