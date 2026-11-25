// Irth Labs Roast: free-tier rules (commodity checks only).
//
// This file intentionally contains ONLY the obvious, widely-known checks that any scanner gives
// away free: exposed provider keys, secrets shipped to the browser, open Firebase rules, committed
// .env files, and permissive Supabase policies. The deep, logic-level, app-aware rules (auth gaps,
// tenancy, data-flow, billing logic) are NOT here; they live in the private Irth Labs engine and
// are part of the paid Health Check. Keep it that way: never port a proprietary rule into this file.
//
// Safety: secret VALUES are redacted at the point of detection. Nothing here ever returns a raw
// secret; callers receive only the masked form.

/** Mask a secret so it is recognizable but not usable: first 4 + last 4, with length. */
export function redact(secret) {
  const s = String(secret);
  if (s.length <= 10) return `**** (${s.length} chars)`;
  return `${s.slice(0, 4)}…${s.slice(-4)} (${s.length} chars)`;
}

// Provider secret patterns. Tightened to avoid false positives (e.g. CSS tokens like "sk-image-x").
const SECRET_PATTERNS = [
  { id: "stripe-secret", title: "Stripe live secret key", sev: "critical", re: /sk_live_[0-9a-zA-Z]{20,}/g },
  { id: "stripe-restricted", title: "Stripe live restricted key", sev: "critical", re: /rk_live_[0-9a-zA-Z]{20,}/g },
  { id: "openai", title: "OpenAI API key", sev: "critical", re: /sk-(?:proj-)?[A-Za-z0-9]{40,}/g },
  { id: "anthropic", title: "Anthropic API key", sev: "critical", re: /sk-ant-[A-Za-z0-9_-]{30,}/g },
  { id: "aws-akia", title: "AWS access key id", sev: "critical", re: /AKIA[0-9A-Z]{16}/g },
  { id: "github-pat", title: "GitHub personal access token", sev: "critical", re: /ghp_[A-Za-z0-9]{36}/g },
  { id: "github-oauth", title: "GitHub OAuth token", sev: "high", re: /gho_[A-Za-z0-9]{36}/g },
  { id: "sendgrid", title: "SendGrid API key", sev: "critical", re: /SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}/g },
  { id: "slack", title: "Slack token", sev: "high", re: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { id: "google-api", title: "Google API key", sev: "high", re: /AIza[0-9A-Za-z_-]{35}/g },
  { id: "private-key", title: "Private key block", sev: "critical", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
];

function lineOf(text, index) {
  return text.slice(0, index).split(/\r?\n/).length;
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

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{10,}/g;
const BROWSER_PREFIX = /\b(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_)[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE|_KEY\b)/g;
const FIREBASE_OPEN_RE = /allow\s+(?:read|write|read\s*,\s*write)\s*:\s*if\s+true\b/g;
const SUPABASE_PERMISSIVE_RE = /\b(?:using|with\s+check)\s*\(\s*true\s*\)/gi;

/** Scan one file's text. Returns findings (already redacted). */
export function scanContent(relPath, text) {
  const findings = [];
  const add = (f) => findings.push({ file: relPath, ...f });

  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    let m;
    const seen = new Set();
    while ((m = p.re.exec(text)) !== null) {
      const val = m[0];
      if (seen.has(val)) continue;
      seen.add(val);
      add({
        ruleId: `secrets.${p.id}`,
        title: `${p.title} in source`,
        severity: p.sev,
        line: lineOf(text, m.index),
        value: p.id === "private-key" ? "(private key material)" : redact(val),
        why: `Matches the ${p.title} format.`,
        fix: "Revoke this key in the provider dashboard now (assume it is compromised), issue a new one, keep it only in server-side environment variables, and purge it from git history.",
        confidence: "confirmed",
      });
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
    if (payload && payload.role === "service_role") {
      add({
        ruleId: "secrets.supabase-service-role",
        title: "Supabase service-role key in source",
        severity: "critical",
        line: lineOf(text, j.index),
        value: `service_role JWT (ref ${payload.ref || "?"})`,
        why: "A JWT with role=service_role bypasses row-level security. The anon key is fine; this one is not.",
        fix: "Roll the service-role key in Supabase, remove it from client-reachable code, and use it only in server-side code (API route, server action, edge function).",
        confidence: "confirmed",
      });
    }
  }

  // Secret shipped to the browser via a public-prefixed variable name.
  BROWSER_PREFIX.lastIndex = 0;
  let b;
  const seenBrowser = new Set();
  while ((b = BROWSER_PREFIX.exec(text)) !== null) {
    if (seenBrowser.has(b[0])) continue;
    seenBrowser.add(b[0]);
    add({
      ruleId: "browser.public-secret-name",
      title: "Secret-named value exposed to the browser",
      severity: "high",
      line: lineOf(text, b.index),
      value: b[0],
      why: `The variable ${b[0]} has a browser-public prefix (NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_/REACT_APP_) but a secret-sounding name, so it ships to every visitor.`,
      fix: "Never put a secret behind a public prefix. Use the anon/publishable key in the browser and rely on RLS; move secret work to server-only code, then roll the key.",
      confidence: "needs_review",
    });
  }

  // Open Firebase security rules.
  if (/\.rules$/.test(relPath) || /service\s+cloud\.firestore|rules_version/.test(text)) {
    FIREBASE_OPEN_RE.lastIndex = 0;
    let fr;
    while ((fr = FIREBASE_OPEN_RE.exec(text)) !== null) {
      add({
        ruleId: "firebase.open-rule",
        title: "Firebase rule allows anyone to read or write",
        severity: "critical",
        line: lineOf(text, fr.index),
        value: fr[0].replace(/\s+/g, " "),
        why: "`if true` lets any visitor read or write this data with no auth.",
        fix: "Replace `if true` with a real condition (request.auth != null plus ownership checks).",
        confidence: "confirmed",
      });
    }
  }

  // Permissive Supabase policies in SQL migrations.
  if (/\.sql$/.test(relPath)) {
    SUPABASE_PERMISSIVE_RE.lastIndex = 0;
    let sp;
    while ((sp = SUPABASE_PERMISSIVE_RE.exec(text)) !== null) {
      add({
        ruleId: "supabase.permissive-policy",
        title: "Supabase policy with a `true` condition",
        severity: "high",
        line: lineOf(text, sp.index),
        value: sp[0].replace(/\s+/g, " "),
        why: "A policy that is `using (true)` or `with check (true)` applies to every row, which usually defeats the point of RLS.",
        fix: "Scope the policy to the signed-in user, e.g. `using (auth.uid() = user_id)`.",
        confidence: "needs_review",
      });
    }
    // create table with no row-level security anywhere in the file (light heuristic).
    if (/create\s+table/i.test(text) && !/enable\s+row\s+level\s+security/i.test(text)) {
      add({
        ruleId: "supabase.rls-not-enabled",
        title: "Table created without row-level security in this file",
        severity: "high",
        line: lineOf(text, text.search(/create\s+table/i)),
        value: "(no `enable row level security` in this migration)",
        why: "A Supabase table with RLS off is readable and writable by any authenticated user through the public API.",
        fix: "Add `alter table <name> enable row level security;` and policies that scope rows to their owner. Confirm the final state in the Supabase dashboard.",
        confidence: "needs_review",
      });
    }
  }

  return findings;
}

/** Project-level checks over the file list (names + a few contents). */
export function scanProject(files) {
  // files: [{ relPath, text|null }]
  const findings = [];
  const names = files.map((f) => f.relPath.replace(/\\/g, "/"));

  const isCommittedEnv = (n) => {
    const base = n.split("/").pop();
    return /^\.env(\.[A-Za-z0-9]+)?$/.test(base) && !/\.(example|sample|template|dist)$/i.test(base);
  };
  for (const f of files) {
    const base = f.relPath.replace(/\\/g, "/").split("/").pop();
    if (isCommittedEnv(f.relPath) && f.text && /^[A-Z0-9_]+\s*=\s*\S/m.test(f.text)) {
      findings.push({
        file: f.relPath,
        ruleId: "env.committed",
        title: ".env file with real values is committed",
        severity: "high",
        line: 1,
        value: `(committed ${base})`,
        why: "A committed env file puts secrets in git history, visible to anyone with repo access.",
        fix: "Remove it from the repo and its history, add it to .gitignore, rotate every secret it held, and commit a .env.example with placeholders instead.",
        confidence: "confirmed",
      });
    }
  }

  const gitignore = files.find((f) => /(^|\/)\.gitignore$/.test(f.relPath.replace(/\\/g, "/")));
  const hasEnvFiles = names.some((n) => isCommittedEnv(n));
  if (hasEnvFiles) {
    const covered = gitignore && gitignore.text && /(^|\n)\s*\.env/.test(gitignore.text);
    if (!covered) {
      findings.push({
        file: gitignore ? gitignore.relPath : ".gitignore",
        ruleId: "env.gitignore-missing",
        title: ".gitignore does not exclude .env files",
        severity: "low",
        line: 1,
        value: gitignore ? "(no .env pattern in .gitignore)" : "(no .gitignore)",
        why: "Without a .gitignore rule, the next commit can add a real .env again.",
        fix: "Add `.env*` and `!.env.example` to the root .gitignore.",
        confidence: "confirmed",
      });
    }
  }

  return findings;
}
