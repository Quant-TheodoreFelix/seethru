import { adminClient } from "./admin-server";

export async function countTodos() {
  const { count } = await adminClient.from("todos").select("*", { count: "exact", head: true });
  return count ?? 0;
}
