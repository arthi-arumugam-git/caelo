// Read-only git awareness. Caelo never runs `git`; it reads the index file as data so it can tell
// "this .env is tracked (committed or staged)" apart from "this .env is a normal local file".
// Anything unexpected (no repo, unknown index version, split or sparse index, sha256 repo) yields
// "unknown", and callers fall back to .gitignore with more cautious wording.
import { existsSync, readFileSync, statSync, lstatSync, realpathSync } from "node:fs";
import path from "node:path";

/** Walk up from `start` to the enclosing repo. Returns { gitDir, workTree } or null. */
export function findGitDir(start, ceiling) {
  // Same meaning as in git: never look for a repository in or above these directories.
  const ceilings = (process.env.GIT_CEILING_DIRECTORIES || "").split(path.delimiter).filter(Boolean).map((c) => path.resolve(c));
  let dir = path.resolve(start);
  for (;;) {
    if (ceilings.includes(dir)) return null;
    const dotGit = path.join(dir, ".git");
    try {
      if (existsSync(dotGit)) {
        if (lstatSync(dotGit).isSymbolicLink()) return null;
        if (statSync(dotGit).isDirectory()) return { gitDir: dotGit, workTree: dir };
        if (statSync(dotGit).size > 4096) return null;
        // Worktrees and submodules use a `.git` file that points at the real git dir.
        const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotGit, "utf8"));
        if (m) {
          const gitDir = realpathSync(path.resolve(dir, m[1].trim()));
          const relative = path.relative(path.resolve(ceiling || dir), gitDir);
          const inside = relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative);
          if (!inside) {
            // Linked worktree metadata must independently point back at this worktree.
            const back = path.join(gitDir, "gitdir");
            if (statSync(back).size > 4096 || realpathSync(readFileSync(back, "utf8").trim()) !== realpathSync(dotGit)) return null;
          }
          return { gitDir, workTree: dir };
        }
        return null;
      }
    } catch {
      return null;
    }
    if (ceiling && dir === path.resolve(ceiling)) return null;
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
 * `*` and `?` glob match without a regex. It backtracks only to the last star, so the work is at most
 * pattern length x name length. A regex built from the pattern backtracked exponentially on a line
 * such as `*a*a*a*a*!`, which let a scanned repository stall the scan.
 */
export function globMatch(pattern, name) {
  let p = 0, i = 0, star = -1, mark = 0;
  while (i < name.length) {
    if (p < pattern.length && (pattern[p] === "?" || pattern[p] === name[i])) { p++; i++; }
    else if (p < pattern.length && pattern[p] === "*") { star = p++; mark = i; }
    else if (star !== -1) { p = star + 1; i = ++mark; }
    else return false;
  }
  while (pattern[p] === "*") p++;
  return p === pattern.length;
}

/** No real ignore rule is longer than this; longer lines are skipped. */
const MAX_IGNORE_LINE = 256;
/** No real ignore file is larger than this; a larger one is not read. */
const MAX_IGNORE_BYTES = 1_000_000;
/** Rule comparisons allowed in one scan. Past this, files are reported rather than assumed ignored. */
const MAX_IGNORE_CHECKS = 5_000_000;

/**
 * Parse an ignore file into rules, in file order. Supported: plain names, `*`, `?`, `**`, a leading
 * or inner `/` (the rule is then relative to the folder that holds the ignore file), a trailing `/`
 * (folders only) and `!` (re-include). Character classes (`[ab]`) and backslash escapes are not
 * interpreted, so such a line matches nothing and the file it was meant to cover gets reported.
 */
export function parseIgnore(text) {
  const rules = [];
  let previous;
  for (const raw of String(text || "").split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith("#") || line.length > MAX_IGNORE_LINE) continue;
    if (line === previous) continue;
    previous = line;
    const negate = line.startsWith("!");
    if (negate) line = line.slice(1);
    // `dir/**` covers everything inside dir, which is what ignoring the folder itself does.
    const dirOnly = /\/(\*\*)?$/.test(line);
    line = line.replace(/(\/\*\*)+$/, "").replace(/\/+$/, "");
    const anchored = line.includes("/");
    const segs = line.split("/").filter(Boolean).map((seg) => (seg === "**" ? seg : seg.replace(/\*+/g, "*")));
    if (segs.length) rules.push({ negate, dirOnly, anchored, segs });
  }
  return rules;
}

/** Match path segments against rule segments, where a `**` segment stands for any number of folders. */
function matchSegments(pats, segs) {
  let p = 0, i = 0, star = -1, mark = 0;
  while (i < segs.length) {
    if (p < pats.length && pats[p] === "**") { star = p++; mark = i; }
    else if (p < pats.length && globMatch(pats[p], segs[i])) { p++; i++; }
    else if (star !== -1) { p = star + 1; i = ++mark; }
    else return false;
  }
  while (pats[p] === "**") p++;
  return p === pats.length;
}

/**
 * What a list of rules says about one path. `rel` is relative to the folder that holds the ignore
 * file, with forward slashes; `isDir` says whether it names a folder. Returns true (ignored), false
 * (re-included with "!") or null (no rule matches). The last matching rule wins, as in git.
 */
function rulesVerdict(rules, rel, isDir) {
  const segs = rel.split("/");
  let verdict = null;
  for (const r of rules) {
    if (r.dirOnly && !isDir) continue;
    // A rule without a slash is a name that matches at any depth; one with a slash is a path.
    if (r.anchored ? matchSegments(r.segs, segs) : globMatch(r.segs[0], segs[segs.length - 1])) verdict = !r.negate;
  }
  return verdict;
}

export const gitignoreVerdict = (gitignoreText, rel, isDir = false) => rulesVerdict(parseIgnore(gitignoreText), rel, isDir);

export const gitignoreCovers = (gitignoreText, baseName) => gitignoreVerdict(gitignoreText, baseName) === true;

/**
 * Per-file git facts, with caching. A scanned folder can sit inside a repo, be a repo, or hold
 * several repos, so the enclosing repo is resolved from each file's own directory.
 *
 *   lookup(fullPath) -> { tracked: true | false | null, ignored: boolean }
 *
 * `tracked` is null when there is no readable index. `ignored` comes from the .gitignore files
 * between the file and the repo root (or `fallbackRoot` when there is no repo), then
 * .git/info/exclude. A file inside an ignored folder is ignored, as in git. Global excludes are not
 * read.
 */
export function createGitLookup(fallbackRoot) {
  const repoByDir = new Map();
  const indexByGitDir = new Map();
  const ignoredDirs = new Map();
  const ignoreFiles = new Map();
  const readIgnore = (file) => {
    if (!ignoreFiles.has(file)) {
      let rules = [];
      try {
        if (statSync(file).size <= MAX_IGNORE_BYTES) rules = parseIgnore(readFileSync(file, "utf8"));
      } catch {
        // no ignore file at this level
      }
      ignoreFiles.set(file, rules);
    }
    return ignoreFiles.get(file);
  };
  // The scanned folder chooses how many ignore rules and env files there are, so the work is capped.
  let checksLeft = MAX_IGNORE_CHECKS;
  const verdict = (ignoreFile, from, target, isDir) => {
    const rules = readIgnore(ignoreFile);
    if (!rules.length || (checksLeft -= rules.length) < 0) return null;
    return rulesVerdict(rules, path.relative(from, target).split(path.sep).join("/"), isDir);
  };
  const trackedSet = (repo) => {
    if (!indexByGitDir.has(repo.gitDir)) {
      let set = null;
      const indexFile = path.join(repo.gitDir, "index");
      try {
        // A fresh repo with nothing staged has no index file yet: it tracks nothing. A `.git` file
        // that points at a folder that is not there (a copied worktree or submodule) says nothing.
        set = existsSync(indexFile) ? parseIndex(readFileSync(indexFile)) : existsSync(repo.gitDir) ? new Set() : null;
      } catch {
        set = null;
      }
      indexByGitDir.set(repo.gitDir, set);
    }
    return indexByGitDir.get(repo.gitDir);
  };

  return function lookup(fullPath) {
    const dir = path.dirname(fullPath);
    if (!repoByDir.has(dir)) repoByDir.set(dir, findGitDir(dir, fallbackRoot));
    const repo = repoByDir.get(dir);

    let tracked = null;
    if (repo) {
      const set = trackedSet(repo);
      if (set) tracked = set.has(path.relative(repo.workTree, fullPath).split(path.sep).join("/"));
    }

    const stop = repo ? repo.workTree : path.resolve(fallbackRoot);
    // The nearest .gitignore with an opinion about a path wins, as in git; .git/info/exclude is last.
    const ignores = (target, isDir) => {
      for (let d = path.dirname(target); ; d = path.dirname(d)) {
        const v = verdict(path.join(d, ".gitignore"), d, target, isDir);
        if (v !== null) return v;
        if (d === stop || path.dirname(d) === d) {
          return repo ? verdict(path.join(repo.gitDir, "info", "exclude"), repo.workTree, target, isDir) === true : false;
        }
      }
    };
    // Git does not look inside an ignored folder, so a file in one is ignored whatever else matches.
    const dirIgnored = (d) => {
      if (d === stop || path.dirname(d) === d) return false;
      if (!ignoredDirs.has(d)) ignoredDirs.set(d, dirIgnored(path.dirname(d)) || ignores(d, true));
      return ignoredDirs.get(d);
    };
    const ignored = dirIgnored(dir) || ignores(fullPath, false);
    return { tracked, ignored };
  };
}
