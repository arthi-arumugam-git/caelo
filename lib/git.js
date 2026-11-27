// Read-only git awareness. Caelo never runs `git`; it reads the index file as data so it can tell
// "this .env is tracked (committed or staged)" apart from "this .env is a normal local file".
// Anything unexpected (no repo, unknown index version, split or sparse index, sha256 repo) yields
// "unknown", and callers fall back to .gitignore with more cautious wording.
import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

/** Walk up from `start` to the enclosing repo. Returns { gitDir, workTree } or null. */
export function findGitDir(start) {
  // Same meaning as in git: never look for a repository in or above these directories.
  const ceilings = (process.env.GIT_CEILING_DIRECTORIES || "").split(path.delimiter).filter(Boolean).map((c) => path.resolve(c));
  let dir = path.resolve(start);
  for (;;) {
    if (ceilings.includes(dir)) return null;
    const dotGit = path.join(dir, ".git");
    try {
      if (existsSync(dotGit)) {
        if (statSync(dotGit).isDirectory()) return { gitDir: dotGit, workTree: dir };
        // Worktrees and submodules use a `.git` file that points at the real git dir.
        const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotGit, "utf8"));
        if (m) return { gitDir: path.resolve(dir, m[1].trim()), workTree: dir };
        return null;
      }
    } catch {
      return null;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/** Parse a git index (v2, v3, v4). Returns a Set of tracked paths (forward slashes) or null. */
export function parseIndex(buf) {
  try {
    if (buf.length < 12 || buf.toString("latin1", 0, 4) !== "DIRC") return null;
    const version = buf.readUInt32BE(4);
    if (version < 2 || version > 4) return null;
    const count = buf.readUInt32BE(8);
    const tracked = new Set();
    let pos = 12;
    let prev = "";
    for (let i = 0; i < count; i++) {
      const start = pos;
      const flags = buf.readUInt16BE(pos + 60); // 40 bytes of stat data, 20 of sha1, then flags
      pos += 62;
      if (version >= 3 && flags & 0x4000) pos += 2; // extended flags
      let name;
      if (version === 4) {
        // Prefix compression: drop N bytes from the previous path, then append a NUL-terminated suffix.
        let c = buf[pos++];
        let strip = c & 0x7f;
        while (c & 0x80) {
          c = buf[pos++];
          strip = ((strip + 1) << 7) | (c & 0x7f);
        }
        const end = buf.indexOf(0, pos);
        if (end < 0) return null;
        const prevBytes = Buffer.from(prev, "utf8");
        if (strip > prevBytes.length) return null;
        name = Buffer.concat([prevBytes.subarray(0, prevBytes.length - strip), buf.subarray(pos, end)]).toString("utf8");
        pos = end + 1;
      } else {
        const end = buf.indexOf(0, pos);
        if (end < 0) return null;
        name = buf.toString("utf8", pos, end);
        pos = start + Math.ceil((end - start + 1) / 8) * 8; // entries are NUL-padded to 8 bytes
      }
      if (!name || pos > buf.length) return null;
      tracked.add(name);
      prev = name;
    }
    // Extensions follow the entries. A split index ("link") or sparse index ("sdir") means the
    // entries above are not the whole story, so refuse to answer rather than answer wrongly.
    while (pos + 8 <= buf.length - 20) {
      const sig = buf.toString("latin1", pos, pos + 4);
      if (sig === "link" || sig === "sdir") return null;
      pos += 8 + buf.readUInt32BE(pos + 4);
    }
    return tracked;
  } catch {
    return null;
  }
}

/**
 * Minimal .gitignore matcher for a single file name. Returns true (ignored), false (explicitly
 * re-included with "!") or null (no pattern matches). Last matching pattern wins, as in git.
 */
export function gitignoreVerdict(gitignoreText, baseName) {
  let verdict = null;
  for (const raw of String(gitignoreText || "").split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const negate = line.startsWith("!");
    if (negate) line = line.slice(1);
    line = line.replace(/^(\*\*\/|\/)+/, "").replace(/\/+$/, "");
    if (!line || line.includes("/")) continue; // path patterns are out of scope for a name check
    const re = new RegExp("^" + line.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*+/g, ".*").replace(/\?/g, ".") + "$");
    if (re.test(baseName)) verdict = !negate;
  }
  return verdict;
}

export const gitignoreCovers = (gitignoreText, baseName) => gitignoreVerdict(gitignoreText, baseName) === true;

/**
 * Per-file git facts, with caching. A scanned folder can sit inside a repo, be a repo, or hold
 * several repos, so the enclosing repo is resolved from each file's own directory.
 *
 *   lookup(fullPath) -> { tracked: true | false | null, ignored: boolean }
 *
 * `tracked` is null when there is no readable index. `ignored` comes from the .gitignore files
 * between the file and the repo root (or `fallbackRoot` when there is no repo), then
 * .git/info/exclude. Global excludes are not read.
 */
export function createGitLookup(fallbackRoot) {
  const repoByDir = new Map();
  const indexByGitDir = new Map();
  const ignoreFiles = new Map();
  const readIgnore = (file) => {
    if (!ignoreFiles.has(file)) {
      let text = null;
      try {
        text = readFileSync(file, "utf8");
      } catch {
        // no ignore file at this level
      }
      ignoreFiles.set(file, text);
    }
    return ignoreFiles.get(file);
  };
  const trackedSet = (repo) => {
    if (!indexByGitDir.has(repo.gitDir)) {
      let set = null;
      const indexFile = path.join(repo.gitDir, "index");
      try {
        // A fresh repo with nothing staged has no index file yet: it tracks nothing.
        set = existsSync(indexFile) ? parseIndex(readFileSync(indexFile)) : new Set();
      } catch {
        set = null;
      }
      indexByGitDir.set(repo.gitDir, set);
    }
    return indexByGitDir.get(repo.gitDir);
  };

  return function lookup(fullPath) {
    const dir = path.dirname(fullPath);
    const base = path.basename(fullPath);
    if (!repoByDir.has(dir)) repoByDir.set(dir, findGitDir(dir));
    const repo = repoByDir.get(dir);

    let tracked = null;
    if (repo) {
      const set = trackedSet(repo);
      if (set) tracked = set.has(path.relative(repo.workTree, fullPath).split(path.sep).join("/"));
    }

    // The nearest .gitignore with an opinion about this name wins, as in git.
    const stop = repo ? repo.workTree : path.resolve(fallbackRoot);
    let ignored = false;
    for (let d = dir; ; d = path.dirname(d)) {
      const verdict = gitignoreVerdict(readIgnore(path.join(d, ".gitignore")), base);
      if (verdict !== null) {
        ignored = verdict;
        break;
      }
      if (d === stop || path.dirname(d) === d) {
        if (repo) ignored = gitignoreVerdict(readIgnore(path.join(repo.gitDir, "info", "exclude")), base) === true;
        break;
      }
    }
    return { tracked, ignored };
  };
}
