# Changelog

## 0.1.3 (unreleased)

Security fixes. A repository being scanned is untrusted input; before this release a crafted one could
stall Caelo or write its own text into the report. Upgrade if you run Caelo on code you did not write
(pull requests, CI, an AI agent's MCP tool).

- A `.gitignore` line with many `*` could make the scan hang (exponential regex backtracking). Ignore
  lines are now matched with a linear glob matcher.
- A file of repeated `eyJ` made the JWT check quadratic (20 s at 160 KB). The pattern is now linear.
- File paths, matched lines and the `ref` inside a Supabase JWT were printed as they were, so a crafted
  repository could add lines such as "No findings" to the report or send escape codes to the terminal.
  Control, bidirectional and zero-width characters are now shown as visible escapes in every output mode.
- MCP: the tool result begins with a notice that paths and values are data, not instructions. The tool
  refuses a drive root or a home folder.
- `package.json` now has `repository`, `bugs` and `author`.

## 0.1.2

Fewer false positives, git-aware env checks, `--json`, honest output.
