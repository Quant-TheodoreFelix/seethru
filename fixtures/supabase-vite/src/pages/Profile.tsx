import { supabase } from "../integrations/supabase/client";

export async function loadProfile(id: string) {
  return supabase.from("profiles").select("display_name, email").eq("id", id).single();
}

export async function loadNotes() {
  return supabase.from("notes").select("*");
}
