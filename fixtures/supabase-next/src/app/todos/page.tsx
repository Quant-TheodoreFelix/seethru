import { TodoList } from "@/components/TodoList";
import { countTodos } from "@/lib/stats";

export default async function TodosPage() {
  const total = await countTodos();
  return <TodoList total={total} />;
}
