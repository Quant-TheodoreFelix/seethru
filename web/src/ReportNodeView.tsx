import { Handle, Position, type NodeProps } from "@xyflow/react";
import { SEVERITY_LABEL, kindLabel } from "./labels";
import type { GraphNode } from "./layout";

export function ReportNodeView({ data, selected }: NodeProps<GraphNode>) {
  const { node, severity, findingCount } = data;
  const classes = ["node", `node-${node.kind.type}`];
  if (severity) classes.push(`sev-${severity}`);
  if (selected) classes.push("is-selected");
  if (node.kind.type === "table") classes.push(`rls-${node.kind.rls}`);

  return (
    <div className={classes.join(" ")}>
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="node-kind">{kindLabel(node.kind)}</div>
      <div className="node-label" title={node.label}>
        {node.label}
      </div>
      {severity ? (
        <span className="node-badge">
          {SEVERITY_LABEL[severity]}
          {findingCount > 1 ? ` ${findingCount}` : ""}
        </span>
      ) : null}
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  );
}
