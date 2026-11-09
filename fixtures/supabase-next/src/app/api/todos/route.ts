import { adminClient } from "@/lib/admin-server";

export async function DELETE(request: Request) {
  const { id } = await request.json();
  return Response.json(await adminClient.from("todos").delete().eq("id", id));
}
