import { useCallback, useEffect, useState } from "react";
import { readStoredTheme, storeTheme, systemTheme, themeStorage, type Theme } from "./theme";

const DARK_QUERY = "(prefers-color-scheme: dark)";

function darkQuery(): MediaQueryList | undefined {
  return typeof window.matchMedia === "function" ? window.matchMedia(DARK_QUERY) : undefined;
}

export function useTheme(): [Theme, (theme: Theme) => void] {
  const [chosen, setChosen] = useState(() => readStoredTheme(themeStorage()));
  const [system, setSystem] = useState(() => systemTheme(darkQuery()));

  useEffect(() => {
    const query = darkQuery();
    if (!query) return;
    const onChange = () => setSystem(systemTheme(query));
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);

  const theme = chosen ?? system;

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  const choose = useCallback((next: Theme) => {
    storeTheme(themeStorage(), next);
    setChosen(next);
  }, []);

  return [theme, choose];
}
