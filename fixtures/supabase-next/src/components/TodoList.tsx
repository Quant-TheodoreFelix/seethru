"use client";

import { addTodo } from "../app/actions";
import { browserClient } from "@/lib/supabase-browser";
import { purgeTodos } from "@/lib/admin";

export function TodoList({ total }: { total: number }) {
  async function load() {
    return browserClient.from("todos").select("*");
  }
  return (
    <div>
      <p>{total}</p>
      <button onClick={() => addTodo("new")}>Add</button>
      <button onClick={() => purgeTodos()}>Purge</button>
      <button onClick={() => load()}>Load</button>
    </div>
  );
}
