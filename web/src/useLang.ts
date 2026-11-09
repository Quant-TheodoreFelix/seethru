import { createContext, useContext, useEffect, useState } from "react";
import { pageLang, type Lang } from "./lang";
import { MESSAGES, type Messages } from "./messages";

export const LangContext = createContext<Lang>("en");

export function useCurrentLang(): Lang {
  return useContext(LangContext);
}

export function useMessages(): Messages {
  return MESSAGES[useContext(LangContext)];
}

export function useLang(): [Lang, (lang: Lang) => void] {
  const [lang, setLang] = useState(() => pageLang(document.documentElement.lang));

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  return [lang, setLang];
}
