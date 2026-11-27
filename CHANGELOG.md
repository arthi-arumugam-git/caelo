# Changelog

## 0.1.3 (unreleased)

Security fixes. A repository being scanned is untrusted input; before this release a crafted one could
stall Caelo or write its own text into the report. Upgrade if you run Caelo on code you did not write
(pull requests, CI, an AI agent's MCP tool).

- A `.gitignore` line with many `*` could make the scan hang (exponential regex backtracking). Ignore
  lines are now matched with a linear glob matcher.
- A file of repeated `eyJ` made the JWT check quadratic (20 s at 160 KB). The pattern is now linear.
- Four more inputs took minutes or did not finish, each from a single file under the 1.5 MB size limit:
  a `.sql` file of unclosed `/*` comments, a policy with a very long `to` role list, a Firebase rules
  file with thousands of `allow` lines, and any file with tens of thousands of findings (line numbers
  were counted from the top of the file for each one). All four are now linear.
- One file with about 125,000 findings ended the scan with `internal error: Maximum call stack size
  exceeded` (exit code 2) and no report. It is now scanned like any other file.
- Memory: Caelo kept the text of every file until the end of the scan (about 1 GB for 700 files of
  1.4 MB). It now keeps only env and SQL files, which the project-level checks need, so memory follows
  the largest file instead of the size of the folder.
- Env checks now respect anchored and nested ignore rules and ignored folders. A copied worktree
  whose git directory is missing is reported with cautious wording. Oversized ignore files and
  excessive rule comparisons are bounded rather than allowing a scan to stall.
- File paths, matched lines and the `ref` inside a Supabase JWT were printed as they were, so a crafted
  repository could add lines such as "No findings" to the report or send escape codes to the terminal.
  Control, bidirectional and zero-width characters are now shown as visible escapes in every output mode.
- MCP: the tool result begins with a notice that paths and values are data, not instructions. The tool
  refuses a drive root or a home folder.
- `package.json` now has `repository`, `bugs` and `author`.

## 0.1.2

Fewer false positives, git-aware env checks, `--json`, honest output.
