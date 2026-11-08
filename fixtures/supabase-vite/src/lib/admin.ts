import { createClient } from "@supabase/supabase-js";

export const admin = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY,
);

export async function deleteUserPosts(userId: string) {
  return admin.from("posts").delete().eq("author_id", userId);
}
