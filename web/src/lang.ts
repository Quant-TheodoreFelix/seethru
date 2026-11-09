export type Lang = "en" | "ko";

export const LANGS: readonly Lang[] = ["en", "ko"];

export function parseLang(value: unknown): Lang | undefined {
  return value === "en" || value === "ko" ? value : undefined;
}

export function pageLang(value: string | null | undefined): Lang {
  const primary = (value ?? "").trim().toLowerCase().split("-")[0];
  return parseLang(primary) ?? "en";
}
