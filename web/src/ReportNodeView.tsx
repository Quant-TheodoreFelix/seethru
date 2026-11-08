import { Handle, Position, type NodeProps } from "@xyflow/react";
import { SEVERITY_LABEL, kindLabel } from "./labels";
import type { GraphNode } from "./layout";

export function ReportNodeView({ data, selected }: NodeProps<GraphNode>) {
  const { node, severity, findingCount } = data;
  const classes = ["node", `node-${node.kind.type}`];
  if (severity) classes.push("has-finding", `sev-${severity}`);
  if (selected) classes.push("is-selected");

  return (
    <div className={classes.join(" ")}>
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="node-kind">{kindLabel(node.kind)}</div>
      <div className="node-label" title={node.label}>
        {node.label}
      </div>
      {severity ? (
        <span className={`node-badge tag sev-${severity}`}>
          {SEVERITY_LABEL[severity]}
          {findingCount > 1 ? ` ${findingCount}` : ""}
        </span>
      ) : null}
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  );
}
