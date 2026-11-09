import { Handle, Position, type NodeProps } from "@xyflow/react";
import { kindLabel } from "./messages";
import type { GraphNode } from "./layout";
import { useMessages } from "./useLang";

export function ReportNodeView({ data, selected }: NodeProps<GraphNode>) {
  const { node, severity, findingCount } = data;
  const m = useMessages();
  const classes = ["node", `node-${node.kind.type}`];
  if (severity) classes.push("has-finding", `sev-${severity}`);
  if (selected) classes.push("is-selected");

  return (
    <div className={classes.join(" ")}>
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="node-head">
        <span className="node-kind">{kindLabel(node.kind, m)}</span>
        {severity ? (
          <span className={`node-badge tag sev-${severity}`}>
            {m.severity[severity]}
            {findingCount > 1 ? ` ${findingCount}` : ""}
          </span>
        ) : null}
      </div>
      <div className="node-label" title={node.label}>
        {node.label}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  );
}
