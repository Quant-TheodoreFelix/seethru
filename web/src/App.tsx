import { Background, Controls, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

export function App() {
  return (
    <main className="canvas">
      <ReactFlow nodes={[]} edges={[]} colorMode="system" fitView>
        <Background />
        <Controls />
      </ReactFlow>
    </main>
  );
}
