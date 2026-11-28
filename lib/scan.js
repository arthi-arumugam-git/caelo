// File walker + scan orchestration. Reads files as data only; never executes anything.
import { opendirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { scanContent, scanProject, isEnvFile, envStatus, clean } from "./rules.js";
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

export const SCAN_LIMITS = { files: 20_000, entries: 100_000, directories: 10_000, milliseconds: 30_000, projectBytes: 16_000_000 };

function walk(root, limits, started) {
  const files = [];
  const gaps = {};
  const stack = [root];
  let entries = 0;
  let directories = 0;
  const gap = (reason) => { gaps[reason] = (gaps[reason] || 0) + 1; };
  outer: while (stack.length) {
    if (++directories > limits.directories) { gap("directory_limit"); break; }
    let dir;
    try { dir = opendirSync(stack.pop()); } catch { gap("directory_read"); continue; }
    try {
      for (;;) {
        if (performance.now() - started > limits.milliseconds) { gap("time_limit"); break outer; }
        if (entries >= limits.entries) { gap("entry_limit"); break outer; }
        const e = dir.readSync();
        if (!e) break;
        entries++;
        const full = path.join(dir.path, e.name);
        if (e.isSymbolicLink()) continue;
        if (e.isDirectory()) {
          if (!EXCLUDE_DIRS.has(e.name)) stack.push(full);
        } else if (e.isFile()) {
          if (files.length >= limits.files) { gap("file_limit"); break outer; }
          files.push(full);
        }
      }
    } catch { gap("directory_read"); }
    finally { dir.closeSync(); }
  }
  return { files, gaps };
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export function scanDir(root, options = {}) {
  const limits = { ...SCAN_LIMITS, ...options.limits };
  const started = performance.now();
  const resolved = path.resolve(root);
  const { files: paths, gaps } = walk(resolved, limits, started);
  const gap = (reason) => { gaps[reason] = (gaps[reason] || 0) + 1; };
  let projectBytes = 0;
  const gitLookup = createGitLookup(resolved);
  const findings = [];
  // Text kept for the project-level checks: env files and SQL files only. Every other file is dropped
  // as soon as its own scan is done, so memory follows the largest file, not the size of the folder.
  const records = [];
  const env = new Map();
  let supabase = false;
  let examined = 0;
  let skipped = 0;

  for (const full of paths) {
    if (performance.now() - started > limits.milliseconds) { gap("time_limit"); break; }
    // Forward slashes on every platform, so reports and JSON read the same everywhere.
    const rel = (path.relative(resolved, full) || path.basename(full)).split(path.sep).join("/");
    const ext = path.extname(full).toLowerCase();
    const base = path.basename(full);
    if (BINARY_EXT.has(ext) || SKIP_NAMES.has(base)) { skipped++; continue; }
    let text;
    try {
      const st = statSync(full);
      if (st.size > MAX_FILE_BYTES) { skipped++; gap("file_size"); continue; }
      text = decode(readFileSync(full));
    } catch {
      skipped++; gap("file_read"); continue;
    }
    if (text === null) { skipped++; continue; }
    examined++;

    // Env files: work out whether git tracks this one before deciding what to say about it.
    const isEnv = isEnvFile(rel);
    if (isEnv) env.set(rel, envStatus(gitLookup(full)));
    if (/(^|\/)supabase\//.test(rel) || (base === "package.json" && text.includes('"@supabase/'))) supabase = true;

    // A git-ignored local env file is where secrets are supposed to live; do not flag its values.
    // One file can return more findings than a call can take arguments, so no push(...spread) here.
    for (const f of scanContent(rel, text, { skipSecrets: env.get(rel) === "local" })) findings.push(f);
    if (isEnv || /\.sql$/i.test(rel)) {
      const bytes = Buffer.byteLength(text, "utf8");
      if (bytes > limits.projectBytes - projectBytes) gap("project_bytes_limit");
      else { records.push({ relPath: rel, text }); projectBytes += bytes; }
    }
  }
  records.sort((a, b) => (a.relPath < b.relPath ? -1 : a.relPath > b.relPath ? 1 : 0));

  const project = scanProject(records, { env, supabase });
  for (const f of project.findings) findings.push(f);

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

  // Every string below can carry text from the scanned folder (paths, matched lines, names). Clean it
  // here, once, so no output mode (text, --json, MCP) and no future rule can print it raw.
  const safe = (f) => Object.fromEntries(Object.entries(f).map(([k, v]) => [k, typeof v === "string" ? clean(v, k === "why" || k === "fix" ? 2000 : 400) : v]));
  return {
    target: clean(root, 1000),
    examined,
    skipped,
    truncated: Object.keys(gaps).length > 0,
    status: Object.keys(gaps).length ? "partial" : "completed",
    coverage: { gaps, projectBytes },
    findings: deduped.map(safe),
    notes: (project.notes || []).map((n) => clean(n, 2000)),
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
