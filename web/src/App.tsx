import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { AnimatePresence, motion } from "motion/react";
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import { InlineText } from "./InlineText";
import { SEVERITY_LABEL } from "./labels";
import { layoutReport, type GraphNode } from "./layout";
import { readEmbeddedReport, readReportFile } from "./loadReport";
import { SEVERITIES, type Finding, type ScanReport } from "./model";
import { ReportNodeView } from "./ReportNodeView";

const nodeTypes: NodeTypes = { report: ReportNodeView };

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

  const onFile = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    readReportFile(file).then(
      (report) => setLoaded({ state: "ready", report }),
      (error: unknown) => setLoaded({ state: "error", message: error instanceof Error ? error.message : "unknown error" }),
    );
  }, []);

  if (loaded.state !== "ready") {
    return (
      <main className="landing">
        <h1>seethru</h1>
        <p>
          Open a report file made with <code>seethru scan --json</code>.
        </p>
        <label className="file-button">
          Open report file
          <input type="file" accept="application/json,.json" onChange={onFile} />
        </label>
        {loaded.state === "error" ? <p className="error">Could not read the report file ({loaded.message})</p> : null}
      </main>
    );
  }

  return (
    <ReactFlowProvider>
      <ReportView report={loaded.report} />
    </ReactFlowProvider>
  );
}

function ReportView({ report }: { report: ScanReport }) {
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [layoutError, setLayoutError] = useState<string>();
  const [selectedId, setSelectedId] = useState<string>();
  const flow = useReactFlow<GraphNode>();

  useEffect(() => {
    let active = true;
    layoutReport(report).then(
      (layout) => {
        if (!active) return;
        setNodes(layout.nodes);
        setEdges(layout.edges);
        requestAnimationFrame(() => void flow.fitView({ padding: 0.15 }));
      },
      (error: unknown) => {
        if (active) setLayoutError(error instanceof Error ? error.message : "layout failed");
      },
    );
    return () => {
      active = false;
    };
  }, [report, flow]);

  const selected = useMemo(() => report.findings.find((finding) => finding.id === selectedId), [report, selectedId]);

  const focus = useCallback(
    (finding: Finding) => {
      setSelectedId(finding.id);
      setNodes((current) => current.map((node) => ({ ...node, selected: node.id === finding.node })));
      void flow.fitView({ nodes: [{ id: finding.node }], duration: 450, maxZoom: 1.25, padding: 0.6 });
    },
    [flow],
  );

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          seethru <span className="target">{report.target.name}</span>
        </div>
        <ul className="counts">
          {SEVERITIES.map((severity) => (
            <li key={severity} className={`count sev-${severity}`}>
              {SEVERITY_LABEL[severity]} <strong>{report.summary[severity]}</strong>
            </li>
          ))}
        </ul>
      </header>
      <main className="canvas">
        {layoutError ? <p className="error">Could not draw the graph ({layoutError})</p> : null}
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          colorMode="system"
          nodesConnectable={false}
          minZoom={0.1}
          proOptions={{ hideAttribution: true }}
          onNodeClick={(_, node) => {
            const finding = report.findings.find((item) => item.node === node.id);
            if (finding) focus(finding);
          }}
        >
          <Background />
          <Controls showInteractive={false} />
          <MiniMap pannable zoomable />
        </ReactFlow>
      </main>
      <aside className="sidebar">
        <h2>Findings ({report.findings.length})</h2>
        {report.findings.length === 0 ? <p className="muted">No problems found.</p> : null}
        <ol className="findings">
          {report.findings.map((finding) => (
            <li key={finding.id}>
              <button
                type="button"
                className={`finding sev-${finding.severity} ${finding.id === selectedId ? "is-active" : ""}`}
                onClick={() => focus(finding)}
              >
                <span className="finding-severity">{SEVERITY_LABEL[finding.severity]}</span>
                <span className="finding-title">
                  <InlineText text={finding.title} />
                </span>
              </button>
            </li>
          ))}
        </ol>
        <AnimatePresence mode="wait">
          {selected ? (
            <motion.section
              key={selected.id}
              className="detail"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.2 }}
            >
              <h3>
                <InlineText text={selected.title} />
              </h3>
              <p>
                <InlineText text={selected.explanation} />
              </p>
              {selected.location ? (
                <p className="where">
                  <code>
                    {selected.location.path}:{selected.location.line}
                  </code>
                </p>
              ) : null}
              {selected.fixPrompt ? <FixPrompt key={selected.id} prompt={selected.fixPrompt} /> : null}
            </motion.section>
          ) : null}
        </AnimatePresence>
      </aside>
    </div>
  );
}

type CopyState = "idle" | "copied" | "manual";

function FixPrompt({ prompt }: { prompt: string }) {
  const area = useRef<HTMLTextAreaElement>(null);
  const [state, setState] = useState<CopyState>("idle");

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
        <h4>Ask your AI to fix it</h4>
        <button type="button" className="copy" onClick={copy}>
          {state === "copied" ? "Copied" : "Copy prompt"}
        </button>
      </div>
      <p className="muted">Paste it as is into an AI coding tool such as Cursor, Claude or Lovable.</p>
      <textarea ref={area} className="fix-prompt" readOnly value={prompt} rows={9} spellCheck={false} />
      {state === "manual" ? <p className="muted">The browser blocked copying. The prompt is selected, so copy it yourself.</p> : null}
    </div>
  );
}
