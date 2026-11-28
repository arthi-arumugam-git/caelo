---
description: Run a free, local Caelo security scan on the project
argument-hint: "[path]"
---

Run a Caelo security scan on the path in $ARGUMENTS, or on the current project root if no path is given.

Caelo is a free, local developer security scanner (made by Irth Labs). It reads files only, uploads nothing, and redacts every secret value it reports.

How to run it:

- If the Caelo MCP scanner tools (`mcp__plugin_caelo_scanner__*`) are available in this session, use them.
- Otherwise run the CLI from the target directory: `npx -y caelo .` (the `-y` lets npx fetch caelo from npm; the trailing dot scans the current folder). If unsure of the syntax, run `npx -y caelo --help` first.

Then read Caelo's actual printed report and relay it:

- Lead with the overall grade and a count of issues by severity, highest first.
- For each finding, give the file, the rule, why it matters, and the fix Caelo suggests. Keep secrets redacted exactly as Caelo already redacts them.
- Group findings by severity so the most serious come first. If the report is clean, say so plainly and note what was checked.
- Some matches may be test fixtures or already-rotated keys. Point that out where likely, but still tell the user to confirm.

Do not modify any files. If the user wants the fixes applied, confirm each change with them first.
