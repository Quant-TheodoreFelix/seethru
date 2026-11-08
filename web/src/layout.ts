import { MarkerType, type Edge, type Node } from "@xyflow/react";
import ELK from "elkjs/lib/elk.bundled.js";
import type { ElkNode } from "elkjs/lib/elk-api";
import { worstSeverity, type Finding, type ReportNode, type ScanReport, type Severity } from "./model";

export type GraphNodeData = {
  node: ReportNode;
  severity: Severity | undefined;
  findingCount: number;
};

export type GraphNode = Node<GraphNodeData, "report">;

const NODE_WIDTH = 248;
const NODE_HEIGHT = 72;

const elk = new ELK();

const LAYOUT_OPTIONS: Record<string, string> = {
  "elk.algorithm": "layered",
  "elk.direction": "RIGHT",
  "elk.layered.spacing.nodeNodeBetweenLayers": "96",
  "elk.spacing.nodeNode": "28",
  "elk.spacing.componentComponent": "64",
  "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
  "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
};

export async function layoutReport(report: ScanReport): Promise<{ nodes: GraphNode[]; edges: Edge[] }> {
  const findingsByNode = new Map<string, Finding[]>();
  for (const finding of report.findings) {
    const bucket = findingsByNode.get(finding.node);
    if (bucket) bucket.push(finding);
    else findingsByNode.set(finding.node, [finding]);
  }

  const graph: ElkNode = {
    id: "root",
    layoutOptions: LAYOUT_OPTIONS,
    children: report.nodes.map((node) => ({ id: node.id, width: NODE_WIDTH, height: NODE_HEIGHT })),
    edges: report.edges.map((edge, index) => ({ id: `edge-${index}`, sources: [edge.from], targets: [edge.to] })),
  };
  const laidOut = await elk.layout(graph);
  const positions = new Map((laidOut.children ?? []).map((child) => [child.id, { x: child.x ?? 0, y: child.y ?? 0 }]));

  const nodes = report.nodes.map((node): GraphNode => {
    const findings = findingsByNode.get(node.id) ?? [];
    return {
      id: node.id,
      type: "report",
      position: positions.get(node.id) ?? { x: 0, y: 0 },
      data: { node, severity: worstSeverity(findings), findingCount: findings.length },
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
    };
  });

  const edges = report.edges.map(
    (edge, index): Edge => ({
      id: `edge-${index}`,
      source: edge.from,
      target: edge.to,
      className: `edge edge-${edge.kind}`,
      animated: edge.kind === "queries" || edge.kind === "reads",
      markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
    }),
  );

  return { nodes, edges };
}
