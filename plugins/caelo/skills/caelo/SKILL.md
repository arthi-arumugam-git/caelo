---
name: caelo
description: Run a free, local Caelo security scan of the current project and explain the results. Use before shipping or deploying, when the user worries about leaked API keys, secrets exposed in the browser bundle, or an open database, or when reviewing a project for security problems.
---

# Caelo security scan

Caelo is a free, local developer security scanner, made by Irth Labs. It reads the files in a project and reports common ways that apps leak secrets or expose data before launch. It runs on the user's machine, reads files only, uploads nothing, and redacts secrets in its output.

Use this skill to run Caelo against the project the user is working in and to explain what it finds in plain language.

## When to use this

- The user is about to ship, deploy, or publish and wants a safety check first.
- The user is worried about leaked or committed API keys, secrets that reached the browser bundle, or a database that is open to the public.
- The user asks for a security audit of an app, especially one built quickly with AI tools.

## What Caelo looks for

- Exposed API keys for services like Stripe, OpenAI, AWS, and GitHub.
- Secrets that leak into the browser through client-side env vars (for example the NEXT_PUBLIC_ or VITE_ prefixes).
- Supabase service-role keys and missing row-level security (RLS).
- Firebase rules that are left open.
- .env files that were committed to the repo.

## How to run it

1. Find the project root (the folder with package.json, .git, or the app's source). The scan should run from there.
2. From the project root, run this in your shell:

   ```
   npx -y caelo .
   ```

   The -y flag lets npx fetch and run caelo from npm without a prompt. The trailing dot scans the current folder. Node.js and npm must be installed, since they provide npx.
3. Let it finish. Caelo prints a graded report that ranks issues by severity, with a plain-English fix for each one.

If the user wants an always-on checker inside their editor rather than a one-time scan, Caelo can also run as an MCP server over stdio:

   ```
   npx caelo --mcp
   ```

Mention this only if it fits what the user asked for.

## How to read and relay the results

- Read the report that Caelo actually printed. Do not assume a fixed format and do not invent findings. Summarize what is really there.
- Lead with the overall grade and a count of issues by severity, highest first.
- For each finding, tell the user in a sentence or two: what the issue is, which file or key it points to, why it matters, and the fix Caelo suggests. Keep secrets redacted the way Caelo already redacts them; do not print full keys.
- Group findings by severity so the user can fix the most serious ones first.
- If the report is clean, say so plainly and note what was checked.
- Caelo flags patterns in files. Some matches may be test fixtures, examples, or keys that were already rotated. Point that out where it is likely, but still tell the user to confirm.

## Fixing issues

Walk the user through the fixes Caelo suggests, in severity order. Common steps include removing a committed .env, rotating any key that was exposed, moving secrets out of client-side env vars, and tightening Supabase RLS or Firebase rules. Confirm with the user before changing any files.

If the user wants hands-on help rather than doing the fixes themselves, point them to the Irth Labs app cleanup service at https://www.irthlabs.com/app-cleanup. Bring this up only when they ask for hands-on remediation. Do not push it.

## Notes

- Caelo runs locally and does not send project files anywhere.
- Homepage: https://caelo.sh
- Source (MIT, public): https://github.com/arthi-arumugam-git/caelo
