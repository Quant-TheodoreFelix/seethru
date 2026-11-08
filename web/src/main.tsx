import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./theme.css";
import "./shell.css";
import "./graph.css";

document.addEventListener("securitypolicyviolation", (event) => {
  const root = document.documentElement;
  const seen = root.dataset.cspViolations ? `${root.dataset.cspViolations} ` : "";
  root.dataset.cspViolations = `${seen}${event.effectiveDirective}`;
});

const container = document.getElementById("root");

if (container) {
  createRoot(container).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
