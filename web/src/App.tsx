import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { AnimatePresence, MotionConfig, motion } from "motion/react";
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import { InlineText } from "./InlineText";
import { layoutReport, type GraphNode } from "./layout";
import { readEmbeddedReport, readReportFile } from "./loadReport";
import { SEVERITIES, edgeKindsIn, type EdgeKind, type Finding, type ScanReport, type Severity } from "./model";
import { ReportNodeView } from "./ReportNodeView";
import { LANGS, type Lang } from "./lang";
import { MESSAGES } from "./messages";
import { THEMES, type Theme } from "./theme";
import { LangContext, useCurrentLang, useLang, useMessages } from "./useLang";
import { useTheme } from "./useTheme";

const nodeTypes: NodeTypes = { report: ReportNodeView };

const PANEL_WIDTH = 420;
const MINIMAP_MIN_NODES = 40;
const WIDE_SCREEN = "(min-width: 861px)";

type Loaded = { state: "empty" } | { state: "error"; message: string } | { state: "ready"; report: ScanReport };

function initialState(): Loaded {
  try {
    const report = readEmbeddedReport();
    return report ? { state: "ready", report } : { state: "empty" };
  } catch (error) {
    return { state: "error", message: error instanceof Error ? error.message : "unknown error" };
  }
}

export function App() {
  const [loaded, setLoaded] = useState<Loaded>(initialState);
  const [theme, setTheme] = useTheme();
  const [lang, setLang] = useLang();
  const m = MESSAGES[lang];

  const onFile = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    readReportFile(file).then(
      (report) => setLoaded({ state: "ready", report }),
      (error: unknown) => setLoaded({ state: "error", message: error instanceof Error ? error.message : "unknown error" }),
    );
  }, []);

  const report = loaded.state === "ready" ? loaded.report : undefined;

  return (
    <LangContext value={lang}>
      <MotionConfig reducedMotion="user">
        <div className="shell">
          <header className="navbar">
            <div className="navbar-start">
              {report ? (
                <>
                  <span className="target-name" title={report.target.name}>
                    {report.target.name}
                  </span>
                  <span className="target-meta">{m.scanned(report.target)}</span>
                </>
              ) : null}
            </div>
            <p className="logo">Seethru</p>
            <div className="navbar-end">
              <ThemeSwitch theme={theme} onChange={setTheme} />
              <LangSwitch lang={lang} onChange={setLang} />
            </div>
          </header>
          {report ? (
            <ReactFlowProvider>
              <ReportView report={report} theme={theme} />
            </ReactFlowProvider>
          ) : (
            <main className="landing">
              <h1>{m.openTitle}</h1>
              <p>
                <InlineText text={m.openBody} />
              </p>
              <label className="file-button button">
                {m.openButton}
                <input type="file" accept="application/json,.json" onChange={onFile} />
              </label>
              {loaded.state === "error" ? <p className="error">{m.readError(loaded.message)}</p> : null}
            </main>
          )}
        </div>
      </MotionConfig>
    </LangContext>
  );
}

function ThemeSwitch({ theme, onChange }: { theme: Theme; onChange: (theme: Theme) => void }) {
  const m = useMessages();
  return (
    <ul className="switch" aria-label={m.colorTheme}>
      {THEMES.map((option) => (
        <li key={option}>
          <button type="button" aria-pressed={theme === option} onClick={() => onChange(option)}>
            {m.theme[option]}
          </button>
        </li>
      ))}
    </ul>
  );
}

const LANG_NAME: Record<Lang, string> = { en: "English", ko: "한국어" };

function LangSwitch({ lang, onChange }: { lang: Lang; onChange: (lang: Lang) => void }) {
  const m = useMessages();
  return (
    <ul className="switch" aria-label={m.languageSwitch}>
      {LANGS.map((option) => (
        <li key={option}>
          <button
            type="button"
            lang={option}
            title={LANG_NAME[option]}
            aria-pressed={lang === option}
            onClick={() => onChange(option)}
          >
            {m.language[option]}
          </button>
        </li>
      ))}
    </ul>
  );
}

function SeverityTag({ severity }: { severity: Severity }) {
  const m = useMessages();
  return <span className={`tag sev-${severity}`}>{m.severity[severity]}</span>;
}

function minimapClass(node: GraphNode) {
  return node.data.severity ? `sev-${node.data.severity}` : "";
}

function Legend({ kinds }: { kinds: EdgeKind[] }) {
  const m = useMessages();
  if (kinds.length === 0) return null;
  return (
    <Panel position="top-left" className="legend" aria-label={m.lineStyles}>
      <ul>
        {kinds.map((kind) => (
          <li key={kind}>
            <svg width="28" height="8" aria-hidden="true">
              <line className={`legend-line edge-${kind}`} x1="0" y1="4" x2="28" y2="4" />
            </svg>
            {m.edge[kind]}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function px(value: number) {
  return `${value}px` as const;
}

function overviewPadding() {
  return { top: px(72), bottom: px(32), left: px(72), right: px(32) };
}

function focusPadding() {
  const wide = typeof window.matchMedia === "function" && window.matchMedia(WIDE_SCREEN).matches;
  return { top: px(64), bottom: px(64), left: px(72), right: px(wide ? PANEL_WIDTH + 64 : 64) };
}

function ReportView({ report, theme }: { report: ScanReport; theme: Theme }) {
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [layoutError, setLayoutError] = useState<string>();
  const [selectedId, setSelectedId] = useState<string>();
  const list = useRef<HTMLDivElement>(null);
  const flow = useReactFlow<GraphNode>();
  const lang = useCurrentLang();
  const m = useMessages();

  useEffect(() => {
    let active = true;
    layoutReport(report).then(
      (layout) => {
        if (!active) return;
        setNodes(layout.nodes);
        setEdges(layout.edges);
        requestAnimationFrame(() => void flow.fitView({ padding: overviewPadding() }));
      },
      (error: unknown) => {
        if (active) setLayoutError(error instanceof Error ? error.message : "layout failed");
      },
    );
    return () => {
      active = false;
    };
  }, [report, flow]);

  useEffect(() => {
    if (!selectedId) return;
    list.current
      ?.querySelector(`[data-finding="${CSS.escape(selectedId)}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [selectedId]);

  const selected = useMemo(() => report.findings.find((finding) => finding.id === selectedId), [report, selectedId]);
  const open = useMemo(() => report.findings.filter((finding) => !finding.accepted), [report]);
  const accepted = useMemo(() => report.findings.filter((finding) => finding.accepted), [report]);
  const edgeKinds = useMemo(() => edgeKindsIn(report), [report]);

  const focus = useCallback(
    (finding: Finding) => {
      setSelectedId(finding.id);
      setNodes((current) => current.map((node) => ({ ...node, selected: node.id === finding.node })));
      void flow.fitView({ nodes: [{ id: finding.node }], duration: 400, maxZoom: 1.1, padding: focusPadding() });
    },
    [flow],
  );

  const clear = useCallback(() => {
    setSelectedId(undefined);
    setNodes((current) => current.map((node) => ({ ...node, selected: false })));
  }, []);

  return (
    <div className="workspace">
      <aside className="sidebar" aria-label={m.findings}>
        <div className="sidebar-head">
          <h2>{m.findings}</h2>
          <span className="sidebar-count">{open.length}</span>
        </div>
        {open.length === 0 ? <p className="empty">{m.noProblems}</p> : null}
        <div ref={list}>
          <ol className="findings">
            {open.map((finding, index) => (
              <FindingRow
                key={finding.id}
                finding={finding}
                label={String(index + 1).padStart(2, "0")}
                active={finding.id === selectedId}
                onSelect={focus}
              />
            ))}
          </ol>
          {accepted.length > 0 ? (
            <section className="accepted" aria-label={m.acceptedTitle}>
              <div className="accepted-head">
                <h3>{m.acceptedTitle}</h3>
                <span className="sidebar-count">{accepted.length}</span>
              </div>
              <p className="accepted-note">{m.acceptedNote(report.target.configFile ?? "seethru.toml")}</p>
              <ol className="findings">
                {accepted.map((finding) => (
                  <FindingRow
                    key={finding.id}
                    finding={finding}
                    label={m.acceptedLabel}
                    active={finding.id === selectedId}
                    onSelect={focus}
                  />
                ))}
              </ol>
            </section>
          ) : null}
        </div>
      </aside>
      <main className="stage">
        <dl className="summary">
          {SEVERITIES.map((severity) => {
            const count = report.summary[severity];
            return (
              <div key={severity} className={`summary-cell sev-${severity} ${count > 0 ? "has-findings" : "is-zero"}`}>
                <dt className="tag">{m.severity[severity]}</dt>
                <dd>{count}</dd>
              </div>
            );
          })}
        </dl>
        <div className="canvas">
          {layoutError ? <p className="error">{m.layoutError(layoutError)}</p> : null}
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            colorMode={theme}
            nodesConnectable={false}
            minZoom={0.1}
            proOptions={{ hideAttribution: true }}
            onNodeClick={(_, node) => {
              const finding = report.findings.find((item) => item.node === node.id);
              if (finding) focus(finding);
            }}
          >
            <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} />
            <Controls position="top-left" showInteractive={false} />
            {report.nodes.length > MINIMAP_MIN_NODES ? (
              <MiniMap<GraphNode> position="bottom-left" nodeClassName={minimapClass} pannable zoomable />
            ) : null}
            <Legend kinds={edgeKinds} />
          </ReactFlow>
          <AnimatePresence mode="wait">
            {selected ? (
              <motion.section
                key={selected.id}
                className="fix-panel"
                aria-label={m.selectedFinding}
                initial={{ opacity: 0, x: 16 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 16 }}
                transition={{ duration: 0.16, ease: "easeOut" }}
              >
                <div className="fix-panel-head">
                  <SeverityTag severity={selected.severity} />
                  <button type="button" className="button quiet" onClick={clear}>
                    {m.close}
                  </button>
                </div>
                <h3>
                  <InlineText text={selected.title[lang]} />
                </h3>
                {selected.location ? (
                  <p className="where">
                    {selected.location.path}:{selected.location.line}
                  </p>
                ) : null}
                {selected.accepted ? (
                  <p className="accepted-reason">
                    <span>{m.acceptedLabel}</span> {selected.accepted.reason}
                  </p>
                ) : null}
                <p className="finding-id">
                  <span>{m.findingId}</span>
                  <code>{selected.id}</code>
                </p>
                {selected.fixPrompt ? <FixPrompt key={`${selected.id}:${lang}`} prompt={selected.fixPrompt[lang]} /> : null}
              </motion.section>
            ) : null}
          </AnimatePresence>
        </div>
      </main>
    </div>
  );
}

function FindingRow({
  finding,
  label,
  active,
  onSelect,
}: {
  finding: Finding;
  label: string;
  active: boolean;
  onSelect: (finding: Finding) => void;
}) {
  const lang = useCurrentLang();
  const m = useMessages();
  return (
    <li data-finding={finding.id}>
      <button
        type="button"
        className={`finding ${active ? "is-active" : ""} ${finding.accepted ? "is-accepted" : ""}`}
        aria-current={active ? "true" : undefined}
        onClick={() => onSelect(finding)}
      >
        <span className="finding-meta">
          <span className="finding-index">{label}</span>
          <SeverityTag severity={finding.severity} />
        </span>
        <span className="finding-title">
          <InlineText text={finding.title[lang]} />
        </span>
        {finding.accepted ? (
          <span className="finding-reason">
            {m.reason} {finding.accepted.reason}
          </span>
        ) : (
          <span className="finding-text">
            <InlineText text={finding.explanation[lang]} />
          </span>
        )}
        {finding.location ? (
          <span className="finding-where">
            {finding.location.path}:{finding.location.line}
          </span>
        ) : null}
      </button>
    </li>
  );
}

type CopyState = "idle" | "copied" | "manual";

function FixPrompt({ prompt }: { prompt: string }) {
  const area = useRef<HTMLTextAreaElement>(null);
  const [state, setState] = useState<CopyState>("idle");
  const m = useMessages();

  const copy = useCallback(() => {
    const selectForManualCopy = () => {
      area.current?.focus();
      area.current?.select();
      setState("manual");
    };
    if (!navigator.clipboard) {
      selectForManualCopy();
      return;
    }
    navigator.clipboard.writeText(prompt).then(() => setState("copied"), selectForManualCopy);
  }, [prompt]);

  return (
    <div className="fix">
      <div className="fix-head">
        <h4>{m.fixTitle}</h4>
        <button type="button" className={`button copy ${state === "copied" ? "is-done" : ""}`} onClick={copy}>
          {state === "copied" ? m.copied : m.copy}
        </button>
      </div>
      <p>{m.fixHint}</p>
      <textarea
        ref={area}
        className="fix-prompt"
        aria-label={m.fixPrompt}
        readOnly
        value={prompt}
        rows={10}
        spellCheck={false}
      />
      {state === "manual" ? <p>{m.copyBlocked}</p> : null}
    </div>
  );
}
