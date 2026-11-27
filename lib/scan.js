// File walker + scan orchestration. Reads files as data only; never executes anything.
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { scanContent, scanProject, isEnvFile, envStatus } from "./rules.js";
import { createGitLookup } from "./git.js";

const EXCLUDE_DIRS = new Set([
  "node_modules", ".git", ".next", "dist", "build", "out", "coverage", ".cache",
  ".turbo", ".vercel", ".netlify", "vendor", "__pycache__", ".venv", "venv", ".idea", ".svelte-kit",
  ".nuxt", ".output", ".expo", ".angular", ".parcel-cache", ".wrangler", ".terraform", ".gradle",
  ".dart_tool", ".yarn", ".pnpm-store", ".tox", ".pytest_cache", ".mypy_cache", "bower_components", "Pods",
]);
const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar", ".mp4",
  ".mov", ".mp3", ".wav", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".wasm", ".exe", ".dll", ".so",
  ".dylib", ".bin", ".node", ".lock", ".map",
]);
// Lockfiles are machine-written hashes; scanning them only produces chance matches.
const SKIP_NAMES = new Set(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "bun.lockb", "bun.lock"]);
const MAX_FILE_BYTES = 1_500_000;
const MAX_FILES = 20_000;

/** Decode a file to text, or return null when it is binary. Handles UTF-8 and UTF-16 with a BOM. */
function decode(buf) {
  // Windows PowerShell's `>` writes UTF-16, so a .env made with `echo KEY=... > .env` lands here.
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return buf.toString("utf16le", 2);
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const body = Buffer.from(buf.subarray(2, 2 + ((buf.length - 2) & ~1)));
    return body.swap16().toString("utf16le");
  }
  const n = Math.min(buf.length, 4096);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return null;
  const text = buf.toString("utf8");
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function walk(root) {
  const out = [];
  let truncated = false;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue; // never follow symlinks
      if (e.isDirectory()) {
        if (EXCLUDE_DIRS.has(e.name)) continue;
        stack.push(full);
      } else if (e.isFile()) {
        if (out.length >= MAX_FILES) { truncated = true; continue; }
        out.push(full);
      }
    }
  }
  return { files: out, truncated };
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export function scanDir(root) {
  const resolved = path.resolve(root);
  const { files: paths, truncated } = walk(resolved);
  const records = [];
  let examined = 0;
  let skipped = 0;

  for (const full of paths) {
    // Forward slashes on every platform, so reports and JSON read the same everywhere.
    const rel = (path.relative(resolved, full) || path.basename(full)).split(path.sep).join("/");
    const ext = path.extname(full).toLowerCase();
    if (BINARY_EXT.has(ext) || SKIP_NAMES.has(path.basename(full))) { skipped++; continue; }
    let text;
    try {
      const st = statSync(full);
      if (st.size > MAX_FILE_BYTES) { skipped++; continue; }
      text = decode(readFileSync(full));
    } catch {
      skipped++; continue;
    }
    if (text === null) { skipped++; continue; }
    records.push({ relPath: rel, text });
    examined++;
  }
  records.sort((a, b) => (a.relPath < b.relPath ? -1 : a.relPath > b.relPath ? 1 : 0));

  // Env files: work out whether git tracks each one before deciding what to say about it.
  const gitLookup = createGitLookup(resolved);
  const env = new Map();
  for (const r of records) if (isEnvFile(r.relPath)) env.set(r.relPath, envStatus(gitLookup(path.join(resolved, r.relPath))));

  const supabase = records.some(
    (r) => /(^|\/)supabase\//.test(r.relPath) || (r.relPath.split("/").pop() === "package.json" && r.text.includes('"@supabase/')),
  );

  const findings = [];
  for (const r of records) {
    // A git-ignored local env file is where secrets are supposed to live; do not flag its values.
    findings.push(...scanContent(r.relPath, r.text, { skipSecrets: env.get(r.relPath) === "local" }));
  }
  const project = scanProject(records, { env, supabase });
  findings.push(...project.findings);

  findings.sort(
    (a, b) =>
      SEV_ORDER[a.severity] - SEV_ORDER[b.severity] ||
      (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) ||
      (a.line || 0) - (b.line || 0) ||
      (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0),
  );

  // De-dup: identical findings, and one finding per browser-exposed variable name across the
  // project (a name used in 30 files is one problem, not 30).
  const seen = new Map();
  const deduped = [];
  for (const f of findings) {
    const key = f.ruleId === "browser.public-secret-name" ? `${f.ruleId}|${f.value}` : `${f.ruleId}|${f.file}|${f.line}|${f.value}`;
    const first = seen.get(key);
    if (first) {
      // Each file reports a name at most once, so this counts the files that use it.
      if (f.ruleId === "browser.public-secret-name") first.occurrences = (first.occurrences || 1) + 1;
      continue;
    }
    seen.set(key, f);
    deduped.push(f);
  }

  return {
    target: root,
    examined,
    skipped,
    truncated,
    findings: deduped,
    notes: project.notes,
  };
}

const PENALTY = { critical: 25, high: 12, medium: 5, low: 2 };
export function score(findings) {
  const total = findings.reduce((s, f) => s + (PENALTY[f.severity] || 0), 0);
  return Math.max(0, 100 - total);
}
export function grade(s) {
  if (s >= 90) return "Solid";
  if (s >= 70) return "Needs work";
  if (s >= 40) return "At risk";
  return "Critical";
}
