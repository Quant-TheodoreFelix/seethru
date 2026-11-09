import { createClient } from "@supabase/supabase-js";

const seed = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

await seed.from("todos").insert([{ title: "first" }]);
