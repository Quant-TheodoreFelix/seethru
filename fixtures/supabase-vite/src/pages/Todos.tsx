import { supabase } from "../integrations/supabase/client";

export async function loadTodos() {
  const { data } = await supabase.from("todos").select("*").order("id");
  return data ?? [];
}

export async function addTodo(title: string) {
  return supabase.from("todos").insert({ title });
}
