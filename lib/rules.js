// Caelo rules. Every check here is a deterministic pattern match over file text and file names:
// provider key formats, secrets behind browser-public variable names, open Firebase rules,
// permissive or missing Postgres row-level security in Supabase migrations, and env files that git
// tracks. Nothing here executes project code, calls a network service, or uses a model.
//
// Scope is deliberate: these are the widely known, pattern-detectable leaks. Logic bugs (broken
// auth, tenancy, data flow, billing) need a human or a deeper tool, and Caelo does not claim them.
//
// Safety: secret VALUES are redacted at the point of detection. Nothing here ever returns a raw
// secret; callers receive only the masked form.

/**
 * Text that came from the scanned folder (a file path, a matched line, a name), made safe to print:
 * control, bidirectional and zero-width characters become a visible \uXXXX escape, and the length is
 * bounded. A path or value can then never add a line to the report, send an escape sequence to the
 * terminal, or hide text from a reader. Applied to every finding in scanDir (lib/scan.js).
 */
export function clean(value, max = 400) {
  const t = String(value).replace(
    /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
  return t.length > max ? t.slice(0, max) + "…" : t;
}

/** Mask a secret so it is recognizable but not usable: first 4 + last 4, with length. */
export function redact(secret) {
  const s = String(secret);
  if (s.length <= 10) return `**** (${s.length} chars)`;
  return `${s.slice(0, 4)}…${s.slice(-4)} (${s.length} chars)`;
}

// Provider secret patterns. `B` stops a match from starting in the middle of a longer token
// (so "task-…" or a base64 blob does not look like a key).
const B = "(?<![A-Za-z0-9_-])";
const SECRET_PATTERNS = [
  { id: "stripe-secret", title: "Stripe live secret key", sev: "critical", re: new RegExp(B + "sk_live_[0-9a-zA-Z]{20,}", "g") },
  { id: "stripe-restricted", title: "Stripe live restricted key", sev: "critical", re: new RegExp(B + "rk_live_[0-9a-zA-Z]{20,}", "g") },
  // Legacy keys are one long alphanumeric run; project, service-account and admin keys also use "-" and "_".
  { id: "openai", title: "OpenAI API key", sev: "critical", re: new RegExp(B + "sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|[A-Za-z0-9]{40,})", "g") },
  { id: "anthropic", title: "Anthropic API key", sev: "critical", re: new RegExp(B + "sk-ant-[A-Za-z0-9_-]{30,}", "g") },
  { id: "aws-akia", title: "AWS access key id", sev: "critical", re: new RegExp(B + "AKIA[0-9A-Z]{16}(?![0-9A-Za-z])", "g") },
  { id: "github-pat", title: "GitHub personal access token", sev: "critical", re: new RegExp(B + "(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})", "g") },
  { id: "github-oauth", title: "GitHub OAuth token", sev: "high", re: new RegExp(B + "gho_[A-Za-z0-9]{36}", "g") },
  { id: "sendgrid", title: "SendGrid API key", sev: "critical", re: new RegExp(B + "SG\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{30,}", "g") },
  { id: "slack", title: "Slack token", sev: "high", re: new RegExp(B + "xox[baprs]-[A-Za-z0-9-]{10,}", "g") },
  { id: "google-api", title: "Google API key", sev: "high", re: new RegExp(B + "AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])", "g") },
  // Require key material after the header, so code that merely strips a PEM header is not flagged.
  { id: "private-key", title: "Private key block", sev: "critical", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----(?:\\r|\\n|[\s"'`+])*[A-Za-z0-9+/=]{40,}/g },
  { id: "supabase-secret", title: "Supabase secret key (sb_secret_)", sev: "critical", re: new RegExp(B + "sb_secret_[A-Za-z0-9_-]{20,}", "g") },
];

// Documentation placeholders ("sk_live_xxxxxxxx", "sb_secret_your_key_here", AWS's ...EXAMPLE key)
// have the right shape but are not secrets. A value with almost no variety is also a placeholder.
const PLACEHOLDER_RE = /your|example|placeholder|change_?me|replace|dummy|redacted|sample|insert|x{4,}|\*{3,}|\.{3}|here$/i;
export function looksPlaceholder(value) {
  const v = String(value);
  return PLACEHOLDER_RE.test(v) || new Set(v.slice(-24)).size < 6;
}

function lineOf(text, index) {
  let line = 1;
  for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) line++;
  return line;
}

function lineAt(text, index) {
  const start = text.lastIndexOf("\n", index - 1) + 1;
  const end = text.indexOf("\n", index);
  return text.slice(start, end === -1 ? text.length : end);
}

/** Decode a JWT payload without verifying. Returns the parsed object or null. */
function decodeJwtPayload(jwt) {
  try {
    const part = jwt.split(".")[1];
    const json = Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

// A match starts only at a token boundary and every segment is bounded, so scanning stays linear.
// Without the boundary, a file of repeated "eyJ" made every occurrence a fresh start (quadratic time).
const JWT_RE = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,2000}\.[A-Za-z0-9_-]{30,6000}\.[A-Za-z0-9_-]{10,2000}/g;

// ---- Browser-public variable names ---------------------------------------------------------------
// Frameworks inline any variable with these prefixes into the JavaScript every visitor downloads.
const PUBLIC_VAR_RE = /\b(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)[A-Z0-9_]+/g;
// Names that say "secret" outright.
const SECRET_WORD_RE = /SERVICE_ROLE|SECRET|PRIVATE|PASSWORD$|PASSWD$/;
// "KEY" in the sense of a lookup key, not a credential.
const NOT_A_CREDENTIAL_RE = /(?:STORAGE|CACHE|QUERY|SORT|PRIMARY|FOREIGN|PARTITION|IDEMPOTENCY)_KEY$/;
// Keys that are designed to ship to the browser. Flagging these would be noise on almost every app.
const PUBLIC_BY_DESIGN_RE =
  /ANON|PUBLISHABLE|PUBLIC_KEY|PUBLIC_API_KEY|SITE_?KEY|CLIENT_ID|CLIENT_KEY|VAPID|FIREBASE|POSTHOG|SENTRY|MAPBOX|MAPS|RECAPTCHA|TURNSTILE|HCAPTCHA|PUSHER|ALGOLIA_SEARCH|MIXPANEL|AMPLITUDE|SEGMENT|ONESIGNAL|REVENUECAT|RAZORPAY_KEY_ID|LOGO_DEV|CRISP|INTERCOM|GTM|ANALYTICS|MEASUREMENT/;
// Providers whose API keys are server-only; there is no browser-safe variant.
const SERVER_ONLY_RE =
  /(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|MISTRAL|COHERE|REPLICATE|ELEVENLABS|DEEPSEEK|OPENROUTER|PERPLEXITY|HUGGINGFACE|RESEND|SENDGRID|MAILGUN|POSTMARK|TWILIO|BREVO|BEEHIIV|AWS|GITHUB|SLACK|TELEGRAM|NOTION|AIRTABLE)[A-Z0-9_]*(?:KEY|TOKEN|KEY_ID)$/;
const GENERIC_KEY_RE = /(?:_KEY|APIKEY|_TOKEN)$/;

/** Classify a browser-public variable name: "secret" | "server-only" | "unclear" | null (fine). */
export function classifyPublicVar(name) {
  if (SECRET_WORD_RE.test(name)) return "secret";
  if (PUBLIC_BY_DESIGN_RE.test(name) || NOT_A_CREDENTIAL_RE.test(name)) return null;
  if (SERVER_ONLY_RE.test(name)) return "server-only";
  if (GENERIC_KEY_RE.test(name)) return "unclear";
  return null;
}

// ---- Firebase ------------------------------------------------------------------------------------
// `allow <ops>: if true;` and the bare `allow <ops>;` both mean "no condition".
const FIREBASE_ALLOW_RE =
  /\ballow\s+((?:read|write|get|list|create|update|delete)(?:\s*,\s*(?:read|write|get|list|create|update|delete))*)\s*(?::\s*if\s+true\s*)?(?=;|\}|$)/gm;
const RTDB_OPEN_RE = /"\.(read|write)"\s*:\s*(?:true|"true")/g;

/** Blank out comments but keep every character offset and newline, so line numbers stay right. */
function blank(text, re) {
  return text.replace(re, (m) => m.replace(/[^\n]/g, " "));
}

// ---- SQL (Postgres row-level security, as used by Supabase) ---------------------------------------
const sqlCode = (text) => blank(blank(text, /\/\*[\s\S]*?\*\//g), /--[^\n]*/g);
const sqlName = (raw) => raw.replace(/"/g, "").replace(/^public\./i, "").toLowerCase();

/** Scan one file's text. Returns findings (already redacted). */
export function scanContent(relPath, text, opts = {}) {
  const findings = [];
  const add = (f) => findings.push({ file: relPath, ...f });

  if (!opts.skipSecrets) {
    const firebaseConfigFile = /authDomain|firebaseapp\.com|messagingSenderId/.test(text);
    for (const p of SECRET_PATTERNS) {
      p.re.lastIndex = 0;
      let m;
      const seen = new Set();
      while ((m = p.re.exec(text)) !== null) {
        const val = m[0];
        if (seen.has(val)) continue;
        seen.add(val);
        if (p.id !== "private-key" && looksPlaceholder(val)) continue;
        const base = {
          ruleId: `secrets.${p.id}`,
          title: `${p.title} in source`,
          severity: p.sev,
          line: lineOf(text, m.index),
          value: p.id === "private-key" ? "(private key material)" : redact(val),
          why: `Matches the ${p.title} format.`,
          fix: "Revoke this key in the provider dashboard now (assume it is compromised), issue a new one, keep it only in server-side environment variables, and purge it from git history.",
          confidence: "confirmed",
        };
        // Firebase web config keys share the Google key format and are public by design.
        if (p.id === "google-api" && (firebaseConfigFile || /firebase/i.test(lineAt(text, m.index)))) {
          Object.assign(base, {
            title: "Google API key (looks like a Firebase web config key)",
            severity: "low",
            why: "Firebase web API keys are meant to be public; they identify the project and do not grant access. The same key format is also used by Maps and Gemini keys, which are not public.",
            fix: "If this is the Firebase web key, no action is needed beyond restricting it by HTTP referrer in Google Cloud. If it can call Maps, Gemini or another billed API, restrict or roll it.",
            confidence: "needs_review",
          });
        }
        add(base);
      }
    }

    // Supabase service-role JWT (anon keys are public and fine; only service_role is the problem).
    JWT_RE.lastIndex = 0;
    let j;
    const seenJwt = new Set();
    while ((j = JWT_RE.exec(text)) !== null) {
      if (seenJwt.has(j[0])) continue;
      seenJwt.add(j[0]);
      const payload = decodeJwtPayload(j[0]);
      // iss "supabase-demo" is the fixed key every local `supabase start` uses; it is not a secret.
      if (payload && payload.role === "service_role" && payload.iss !== "supabase-demo") {
        add({
          ruleId: "secrets.supabase-service-role",
          title: "Supabase service-role key in source",
          severity: "critical",
          line: lineOf(text, j.index),
          // `ref` comes from inside the token, so the scanned repository controls it: print it only
          // when it looks like a Supabase project ref.
          value: `service_role JWT (ref ${typeof payload.ref === "string" && /^[a-z0-9]{1,40}$/.test(payload.ref) ? payload.ref : "?"})`,
          why: "A JWT with role=service_role bypasses row-level security. The anon key is fine; this one is not.",
          fix: "Roll the service-role key in Supabase, remove it from client-reachable code, and use it only in server-side code (API route, server action, edge function).",
          confidence: "confirmed",
        });
      }
    }
  }

  // Secret-sounding name behind a browser-public prefix. Prose is skipped: a name that only shows
  // up in documentation is not being shipped to anyone.
  PUBLIC_VAR_RE.lastIndex = 0;
  let b;
  const seenBrowser = new Set();
  const prose = /\.(?:md|mdx|markdown|txt|rst)$/i.test(relPath);
  while (!prose && (b = PUBLIC_VAR_RE.exec(text)) !== null) {
    const name = b[0];
    if (seenBrowser.has(name)) continue;
    seenBrowser.add(name);
    const kind = classifyPublicVar(name);
    if (!kind) continue;
    const why = {
      secret: `${name} has a browser-public prefix and a secret-sounding name. Anything behind that prefix is bundled into the JavaScript every visitor downloads.`,
      "server-only": `${name} has a browser-public prefix, so its value is bundled into the JavaScript every visitor downloads. This provider's keys are server-only; there is no browser-safe version.`,
      unclear: `${name} has a browser-public prefix, so its value is bundled into the JavaScript every visitor downloads. That is fine for a publishable key and a leak for a secret one. Caelo cannot tell which from the name.`,
    }[kind];
    add({
      ruleId: "browser.public-secret-name",
      title: { secret: "Secret-named value exposed to the browser", "server-only": "Server-only key exposed to the browser", unclear: "Key exposed to the browser (check that it is a public one)" }[kind],
      severity: kind === "unclear" ? "medium" : "high",
      line: lineOf(text, b.index),
      value: name,
      why,
      fix: "Keep only publishable or anon keys behind a public prefix. Move secret work to server-only code (API route, server action, edge function), rename the variable without the prefix, then roll the key.",
      confidence: "needs_review",
    });
  }

  // Open Firestore / Storage security rules.
  if (/\.rules$/.test(relPath) || /service\s+(?:cloud\.firestore|firebase\.storage)|rules_version/.test(text)) {
    const code = blank(text, /\/\/[^\n]*/g);
    FIREBASE_ALLOW_RE.lastIndex = 0;
    let fr;
    while ((fr = FIREBASE_ALLOW_RE.exec(code)) !== null) {
      const ops = fr[1].split(",").map((s) => s.trim());
      const writes = ops.some((o) => ["write", "create", "update", "delete"].includes(o));
      // A recursive wildcard such as `match /{document=**}` opens the whole database, not one collection.
      const mi = code.lastIndexOf("match ", fr.index);
      const everything = mi !== -1 && /=\*\*\}/.test(lineAt(code, mi));
      add({
        ruleId: "firebase.open-rule",
        title: writes ? "Firebase rule lets anyone write" : "Firebase rule lets anyone read",
        severity: writes ? "critical" : everything ? "high" : "medium",
        line: lineOf(code, fr.index),
        value: fr[0].replace(/\s+/g, " ").trim(),
        why: writes
          ? "There is no condition, so any visitor can write this data without signing in."
          : "There is no condition, so any visitor can read this data without signing in. That is right for public content and a leak for anything private.",
        fix: "Replace the open rule with a real condition (request.auth != null plus an ownership check).",
        confidence: writes ? "confirmed" : "needs_review",
      });
    }
  }

  // Open Realtime Database rules (database.rules.json).
  if (/\.json$/.test(relPath) && /"rules"\s*:/.test(text)) {
    RTDB_OPEN_RE.lastIndex = 0;
    let rt;
    while ((rt = RTDB_OPEN_RE.exec(text)) !== null) {
      const writes = rt[1] === "write";
      add({
        ruleId: "firebase.open-rule",
        title: writes ? "Firebase rule lets anyone write" : "Firebase rule lets anyone read",
        severity: writes ? "critical" : "high",
        line: lineOf(text, rt.index),
        value: rt[0].replace(/\s+/g, " "),
        why: writes
          ? "`.write: true` lets any visitor change or delete this data without signing in."
          : "`.read: true` lets any visitor read this data without signing in. That is right for public content and a leak for anything private.",
        fix: 'Replace `true` with a real condition such as "auth != null" plus an ownership check.',
        confidence: writes ? "confirmed" : "needs_review",
      });
    }
  }

  return findings;
}

// ---- Env files -----------------------------------------------------------------------------------
const baseOf = (rel) => rel.split("/").pop();
export function isEnvFile(rel) {
  const base = baseOf(rel);
  return /^\.env(\.[A-Za-z0-9_-]+)*$/.test(base) && !/\.(example|sample|template|dist|defaults?)$/i.test(base);
}

const SECRETISH_NAME_RE = /SECRET|PASSWORD|PASSWD|PRIVATE|SERVICE_ROLE|TOKEN|API_?KEY|ACCESS_KEY|CREDENTIAL|_KEY$/;
const PLACEHOLDER_VALUE_RE = /^(?:your|xxx|change_?me|todo|example|placeholder|<|\.\.\.|\$\{)|your[-_]/i;

/** Parse KEY=value lines. Returns { real: number of real values, secretNames: [names] }. */
export function readEnv(text) {
  let real = 0;
  const secretNames = [];
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(raw);
    if (!m) continue;
    const name = m[1];
    const value = m[2].trim().replace(/^(["'])(.*)\1$/, "$2");
    if (!value || PLACEHOLDER_VALUE_RE.test(value)) continue;
    real++;
    const upper = name.toUpperCase();
    const credsInUrl = /:\/\/[^\s:@/]+:[^\s@/]+@/.test(value);
    if (credsInUrl || (SECRETISH_NAME_RE.test(upper) && !PUBLIC_BY_DESIGN_RE.test(upper))) secretNames.push(name);
  }
  return { real, secretNames };
}

/**
 * Decide what an env file is, from git facts ({ tracked: true | false | null, ignored }):
 * "tracked"   git tracks it (committed or staged)
 * "local"     not tracked and ignored, or ignored with no git data: an ordinary local env file
 * "unignored" a repo is present, the file is not tracked, and nothing ignores it
 * "unknown"   no git data and nothing ignores it
 */
export function envStatus({ tracked, ignored }) {
  if (tracked === true) return "tracked";
  if (ignored) return "local";
  return tracked === false ? "unignored" : "unknown";
}

const SQL_ID = String.raw`((?:[\w"]+\.)?[\w"]+)`;
const SQL_STMT_RE = new RegExp(
  [
    String.raw`\b(create|alter)\s+policy\s+("[^"]*"|\S+)\s+on\s+${SQL_ID}([^;]*)`, // 1 verb, 2 policy, 3 table, 4 rest
    String.raw`\bdrop\s+policy\s+(?:if\s+exists\s+)?("[^"]*"|\S+)\s+on\s+${SQL_ID}`, // 5 policy, 6 table
    String.raw`\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?${SQL_ID}`, // 7 table
    String.raw`\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${SQL_ID}\s+(?:enable|force)\s+row\s+level\s+security`, // 8 table
    String.raw`\bdrop\s+table\s+(?:if\s+exists\s+)?${SQL_ID}`, // 9 table
  ].join("|"),
  "gi",
);
// Files that describe test data or the way back out of a migration, not the live schema.
const SQL_NOT_SCHEMA_RE = /(^|\/)(tests?|rollbacks?|seeds?)\/|\.down\.sql$|(^|\/)seed\.sql$/i;
const policyKey = (table, policy) => `${sqlName(table)}|${policy.replace(/"/g, "").toLowerCase()}`;
const listNames = (names, max) => names.slice(0, max).join(", ") + (names.length > max ? `, +${names.length - max} more` : "");

/**
 * SQL checks. Migrations are replayed in path order, so a policy that a later migration drops or
 * rewrites, or a table that gets row-level security three files later, is judged on its final state.
 */
function scanSql(files, ctx, findings) {
  let sqlFiles = files.filter((f) => f.text && /\.sql$/i.test(f.relPath) && !SQL_NOT_SCHEMA_RE.test(f.relPath));
  // When the project has a supabase/ folder, that is the schema Supabase serves. Other .sql files
  // (a Cloudflare D1 worker, a Neon export) are different databases with different rules.
  const inSupabaseDir = sqlFiles.filter((f) => /(^|\/)supabase\//.test(f.relPath));
  if (inSupabaseDir.length) sqlFiles = inSupabaseDir;

  const tables = new Map(); // name -> { file, line, rls }
  const policies = new Map(); // "table|policy" -> { file, line, table, cmd, roles }
  const inPublic = (raw) => !raw.includes(".") || /^"?public"?\./i.test(raw);

  for (const f of sqlFiles) {
    const code = sqlCode(f.text);
    SQL_STMT_RE.lastIndex = 0;
    let m;
    while ((m = SQL_STMT_RE.exec(code)) !== null) {
      if (m[1]) {
        const key = policyKey(m[3], m[2]);
        const rest = m[4];
        const prev = policies.get(key);
        const cmd = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest)?.[1] || prev?.cmd || "all").toLowerCase();
        // USING picks the rows a role may touch; WITH CHECK validates the new row. A policy is only
        // wide open when the clause that applies to its command is literally true and the other
        // clause does not narrow it. Restrictive policies can only narrow access, never grant it.
        const usingTrue = /\busing\s*\(\s*true\s*\)/i.test(rest);
        const checkTrue = /\bwith\s+check\s*\(\s*true\s*\)/i.test(rest);
        const hasUsing = /\busing\s*\(/i.test(rest);
        const hasCheck = /\bwith\s+check\s*\(/i.test(rest);
        const open =
          !/\bas\s+restrictive\b/i.test(rest) &&
          (cmd === "insert"
            ? checkTrue
            : cmd === "select" || cmd === "delete"
              ? usingTrue
              : (usingTrue || checkTrue) && (usingTrue || !hasUsing) && (checkTrue || !hasCheck));
        if (!open) {
          // A rewrite with a real condition replaces whatever was there; a bare rename does not.
          if (m[1].toLowerCase() === "create" || hasUsing || hasCheck) policies.delete(key);
          continue;
        }
        const roles = (/\bto\s+([a-z_,\s"]+?)(?=\s+(?:using|with)\b|\s*$)/i.exec(rest)?.[1] || prev?.roles || "public")
          .replace(/["\s]/g, "")
          .toLowerCase();
        policies.set(key, { file: f.relPath, line: lineOf(code, m.index), table: sqlName(m[3]), cmd, roles });
      } else if (m[5]) {
        policies.delete(policyKey(m[6], m[5]));
      } else if (m[7]) {
        // Only the public schema is served by the Supabase API.
        const name = sqlName(m[7]);
        if (inPublic(m[7]) && !tables.has(name)) tables.set(name, { file: f.relPath, line: lineOf(code, m.index), rls: false });
      } else if (m[8]) {
        const t = tables.get(sqlName(m[8]));
        if (t) t.rls = true;
      } else if (m[9]) {
        const name = sqlName(m[9]);
        tables.delete(name);
        for (const key of [...policies.keys()]) if (key.startsWith(name + "|")) policies.delete(key);
      }
    }
  }

  const reads = [];
  for (const p of policies.values()) {
    // service_role bypasses RLS anyway, so a `true` policy scoped to it grants nothing new.
    if (p.roles.split(",").every((r) => r === "service_role" || r === "postgres" || r === "supabase_admin")) continue;
    if (p.cmd === "select") {
      reads.push(p);
      continue;
    }
    const insert = p.cmd === "insert";
    findings.push({
      file: p.file,
      ruleId: "supabase.permissive-policy",
      title: insert ? "RLS policy lets the role insert any row" : `RLS policy lets the role ${p.cmd === "all" ? "read and write" : p.cmd} every row`,
      severity: insert ? "medium" : "high",
      line: p.line,
      value: `${p.table}: for ${p.cmd} to ${p.roles}, condition is (true)`,
      why: insert
        ? `Any "${p.roles}" client can insert rows into ${p.table} with whatever values it likes. That is fine for something like a public contact form and a problem for anything else.`
        : `The condition is literally true, so any "${p.roles}" client can ${p.cmd === "all" ? "read, change and delete" : p.cmd} every row in ${p.table}, not only its own.`,
      fix: "Scope the policy to the signed-in user, e.g. `using (auth.uid() = user_id)` and the same in `with check`.",
      confidence: "needs_review",
    });
  }
  if (reads.length) {
    reads.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
    const tablesRead = [...new Set(reads.map((p) => p.table))];
    findings.push({
      file: reads[0].file,
      ruleId: "supabase.public-read-policy",
      title: `RLS policies let the role read every row of ${tablesRead.length} table${tablesRead.length > 1 ? "s" : ""}`,
      severity: "low",
      line: reads[0].line,
      value: `select using (true) on: ${listNames(tablesRead, 12)}`,
      why: "Reading every row is right for public content (posts, products) and wrong for per-user data (profiles, orders, messages). Caelo cannot tell which these are.",
      fix: "For per-user tables, scope the select policy, e.g. `using (auth.uid() = user_id)`.",
      confidence: "needs_review",
    });
  }

  // Tables that never get `enable row level security`. Only for Supabase projects: plain Postgres,
  // MySQL or SQLite schemas are not exposed through a public API.
  if (!ctx.supabase) return;
  const byFile = new Map();
  for (const [name, t] of tables) {
    if (t.rls) continue;
    if (!byFile.has(t.file)) byFile.set(t.file, { line: t.line, names: [] });
    byFile.get(t.file).names.push(name);
  }
  for (const [file, { line, names }] of byFile) {
    findings.push({
      file,
      ruleId: "supabase.rls-not-enabled",
      title: names.length > 1 ? `${names.length} tables created without row-level security` : "Table created without row-level security",
      severity: "high",
      line,
      value: `no \`enable row level security\` for: ${listNames(names, 8)}`,
      why: "No SQL file in this project turns on row-level security for these tables. In Supabase, a public-schema table with RLS off can be read and written by anyone holding the anon key. RLS switched on by hand in the dashboard would not show up here.",
      fix: "Add `alter table <name> enable row level security;` plus policies that scope rows to their owner, then confirm the live state in the Supabase dashboard.",
      confidence: "needs_review",
    });
  }
}

/** Project-level checks: env files, and SQL policies and tables judged on their final state. */
export function scanProject(files, ctx = {}) {
  // files: [{ relPath, text|null }], ctx.env: Map relPath -> status (see envStatus)
  const findings = [];
  const notes = [];
  const env = ctx.env || new Map();

  const local = [];
  for (const f of files) {
    const status = env.get(f.relPath);
    if (!status || !f.text) continue;
    const { real, secretNames } = readEnv(f.text);
    if (!real) continue;
    const base = baseOf(f.relPath);
    if (status === "local") { local.push(f.relPath); continue; }
    const names = secretNames.slice(0, 5).join(", ") + (secretNames.length > 5 ? `, +${secretNames.length - 5} more` : "");
    if (status === "tracked") {
      findings.push({
        file: f.relPath,
        ruleId: "env.committed",
        title: secretNames.length ? "Env file with secret-looking values is tracked by git" : "Env file is tracked by git (only public-looking values found)",
        severity: secretNames.length ? "high" : "low",
        line: 1,
        value: secretNames.length ? `(${base} sets ${names})` : `(${base})`,
        why: secretNames.length
          ? "Git tracks this file, so its values are in the repository for anyone with access, and stay in history after you delete the file."
          : "Git tracks this file. The values in it look like public configuration, which some frameworks expect you to commit. Check that nothing in it is secret.",
        fix: "Remove it from the repo and its history (git rm --cached, then a history rewrite), add it to .gitignore, rotate every secret it held, and commit a .env.example with placeholders instead.",
        confidence: secretNames.length ? "confirmed" : "needs_review",
      });
    } else {
      // "unignored": a repo is here and does not track the file yet. "unknown": no git data at all.
      findings.push({
        file: f.relPath,
        ruleId: "env.not-ignored",
        title: secretNames.length ? "Env file with secret-looking values is not git-ignored" : "Env file is not git-ignored",
        severity: secretNames.length ? "high" : "low",
        line: 1,
        value: secretNames.length ? `(${base} sets ${names})` : `(${base})`,
        why:
          status === "unignored"
            ? "Git does not track this file today, but no .gitignore rule excludes it, so the next `git add .` commits it."
            : "There is no git metadata in this folder, so Caelo cannot tell whether this file is committed. No .gitignore rule excludes it, and if this folder was exported or downloaded from a repository, the file was in that repository.",
        fix: "Add `.env*` and `!.env.example` to the root .gitignore. If the file was ever committed, remove it from history and rotate every secret it held.",
        confidence: status === "unignored" ? "confirmed" : "needs_review",
      });
    }
  }
  if (local.length) {
    const shown = local.slice(0, 4).join(", ") + (local.length > 4 ? `, +${local.length - 4} more` : "");
    notes.push(`${local.length} git-ignored env file${local.length > 1 ? "s" : ""} (${shown}): the secret values inside were not flagged, since an ignored local env file is where secrets belong.`);
  }

  scanSql(files, ctx, findings);

  return { findings, notes };
}
