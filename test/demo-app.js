// A small, deliberately leaky app used for the sample output in the README. Every key-shaped value
// is synthetic and assembled at runtime, so this file itself contains nothing a scanner would flag.
const j = (...parts) => parts.join("");
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const serviceRole = j(b64({ alg: "HS256", typ: "JWT" }), ".", b64({ role: "service_role", ref: "xyzcompany" }), ".", "c2lnbmF0dXJlX3BsYWNlaG9sZGVy");
const stripe = j("sk_live_", "51H8xWpackedFAKEkey1234567890abcdEF");
const V = "VITE_";

/** Map of relative path -> file content. */
export const demoApp = {
  "package.json": '{ "name": "my-app", "dependencies": { "@supabase/supabase-js": "^2.0.0" } }\n',
  ".gitignore": "node_modules\ndist\n",
  ".env": `VITE_SUPABASE_URL=https://xyzcompany.supabase.co\nSTRIPE_SECRET_KEY=${stripe}\n`,
  "src/lib/admin.ts": `import { createClient } from "@supabase/supabase-js";\n\nexport const admin = createClient(url, "${serviceRole}");\n`,
  "src/lib/ai.ts": `export const openaiKey = import.meta.env.${V}OPENAI_API_KEY;\n`,
  "supabase/migrations/001_init.sql": [
    "create table public.profiles (id uuid primary key, user_id uuid, bio text);",
    "alter table public.profiles enable row level security;",
    'create policy "Users manage profiles" on public.profiles for all to authenticated using (true) with check (true);',
    "",
    "create table public.invoices (id uuid primary key, user_id uuid, amount int);",
    "",
  ].join("\n"),
};
