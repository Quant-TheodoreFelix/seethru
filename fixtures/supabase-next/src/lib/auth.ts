import "server-only";
import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

export async function requireUser() {
  const store = await cookies();
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
    { cookies: { getAll: () => store.getAll() } },
  );
  const { data } = await supabase.auth.getUser();
  if (!data.user) throw new Error("Sign in first");
  return data.user;
}
