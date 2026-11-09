"use server";

import { createClient } from "@supabase/supabase-js";

const server = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function addTodo(title: string) {
  await server.from("todos").insert({ title });
}
