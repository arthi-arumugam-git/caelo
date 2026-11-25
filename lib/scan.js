// File walker + scan orchestration. Reads files as data only; never executes anything.
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { scanContent, scanProject } from "./rules.js";

const EXCLUDE_DIRS = new Set([
  "node_modules", ".git", ".next", "dist", "build", "out", "coverage", ".cache",
  ".turbo", ".vercel", ".netlify", "vendor", "__pycache__", ".venv", "venv", ".idea", ".svelte-kit",
]);
const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar", ".mp4",
  ".mov", ".mp3", ".wav", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".wasm", ".exe", ".dll", ".so",
  ".dylib", ".bin", ".node", ".lock", ".map",
]);
const MAX_FILE_BYTES = 1_500_000;
const MAX_FILES = 20_000;

function looksBinary(buf) {
  const n = Math.min(buf.length, 4096);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
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

export function scanDir(root) {
  const resolved = path.resolve(root);
  const { files: paths, truncated } = walk(resolved);
  const records = [];
  let examined = 0;
  let skipped = 0;

  for (const full of paths) {
    const rel = path.relative(resolved, full) || path.basename(full);
    const ext = path.extname(full).toLowerCase();
    if (BINARY_EXT.has(ext)) { skipped++; continue; }
    let buf;
    try {
      const st = statSync(full);
      if (st.size > MAX_FILE_BYTES) { skipped++; records.push({ relPath: rel, text: null }); continue; }
      buf = readFileSync(full);
    } catch {
      skipped++; continue;
    }
    if (looksBinary(buf)) { skipped++; records.push({ relPath: rel, text: null }); continue; }
    const text = buf.toString("utf8");
    records.push({ relPath: rel, text });
    examined++;
  }

  const findings = [];
  for (const r of records) if (r.text) findings.push(...scanContent(r.relPath, r.text));
  findings.push(...scanProject(records));

  // de-dup identical findings (same rule+file+line)
  const seen = new Set();
  const deduped = [];
  for (const f of findings) {
    const key = `${f.ruleId}|${f.file}|${f.line}|${f.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(f);
  }

  return {
    target: root,
    examined,
    skipped,
    truncated,
    findings: deduped,
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
