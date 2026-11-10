import { requireUser } from "@/lib/auth";
import { countTodos } from "@/lib/stats";

export async function GET() {
  await requireUser();
  return Response.json({ total: await countTodos() });
}
