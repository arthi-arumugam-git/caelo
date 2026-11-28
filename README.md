# Caelo

[![npm version](https://img.shields.io/npm/v/caelo)](https://www.npmjs.com/package/caelo)
[![license](https://img.shields.io/npm/l/caelo)](LICENSE)
[![node](https://img.shields.io/node/v/caelo)](https://nodejs.org)

**See straight to the bottom of your code.**

Caelo by [Irth Labs](https://www.irthlabs.com/) is a free local security scanner for AI-built apps, with a CLI and MCP server. It checks project files for exposed keys, permissive access rules and configuration issues. It is MIT-licensed and prints a plain-English fix for each finding.

Irth Labs reviews AI-built products and cleans up business data for AI. Those are separate human services. Caelo reads project files; it does not clean or change business data.

```bash
npx caelo .
```

It runs entirely on your machine. It reads your files as data, never executes your code, makes no
network calls, and uses no AI model: every check is a fixed pattern, so the same folder always gives
the same report. Secret values are redacted before they are printed (you see `[redacted] (43 chars)`,
never the key).

## What the output looks like

This is the real output for a small, deliberately leaky demo app (the fixture is in
[`test/demo-app.js`](test/demo-app.js), and a test fails if this block drifts from what the code prints):

<!-- sample-output:start -->
```text
Caelo roast: /home/you/my-app
6 files examined, 0 skipped
findings: 2 critical, 4 high, 0 medium, 0 low
grade: Critical (2/100)

CRITICAL (2)
- Stripe live secret key in source
    .env:2  (secrets.stripe-secret)
    value: [redacted] (43 chars)
    why: Matches the Stripe live secret key format.
    fix: Revoke this key in the provider dashboard now (assume it is compromised), issue a new one, keep it only in server-side environment variables, and purge it from git history.
- Supabase service-role key in source
    src/lib/admin.ts:3  (secrets.supabase-service-role)
    value: service_role JWT (ref xyzcompany)
    why: A JWT with role=service_role bypasses row-level security. The anon key is fine; this one is not.
    fix: Roll the service-role key in Supabase, remove it from client-reachable code, and use it only in server-side code (API route, server action, edge function).

HIGH (4)
- Env file with secret-looking values is not git-ignored [needs review]
    .env:1  (env.not-ignored)
    value: (.env sets STRIPE_SECRET_KEY)
    why: There is no git metadata in this folder, so Caelo cannot tell whether this file is committed. No .gitignore rule excludes it, and if this folder was exported or downloaded from a repository, the file was in that repository.
    fix: Add `.env*` and `!.env.example` to the root .gitignore. If the file was ever committed, remove it from history and rotate every secret it held.
- Server-only key exposed to the browser [needs review]
    src/lib/ai.ts:1  (browser.public-secret-name)
    value: VITE_OPENAI_API_KEY
    why: VITE_OPENAI_API_KEY has a browser-public prefix, so its value is bundled into the JavaScript every visitor downloads. This provider's keys are server-only; there is no browser-safe version.
    fix: Keep only publishable or anon keys behind a public prefix. Move secret work to server-only code (API route, server action, edge function), rename the variable without the prefix, then roll the key.
- RLS policy lets the role read and write every row [needs review]
    supabase/migrations/001_init.sql:3  (supabase.permissive-policy)
    value: profiles: for all to authenticated, condition is (true)
    why: The condition is literally true, so any "authenticated" client can read, change and delete every row in profiles, not only its own.
    fix: Scope the policy to the signed-in user, e.g. `using (auth.uid() = user_id)` and the same in `with check`.
- Table created without row-level security [needs review]
    supabase/migrations/001_init.sql:5  (supabase.rls-not-enabled)
    value: no `enable row level security` for: invoices
    why: No SQL file in this project turns on row-level security for these tables. In Supabase, a public-schema table with RLS off can be read and written by anyone holding the anon key. RLS switched on by hand in the dashboard would not show up here.
    fix: Add `alter table <name> enable row level security;` plus policies that scope rows to their owner, then confirm the live state in the Supabase dashboard.

Caelo matches known leak patterns in files. It does not run your app, so a clean scan is not proof the app is secure.
Want a human to check these findings? App Health Check, $490: https://caelo.sh
```
<!-- sample-output:end -->

`[needs review]` marks a finding where the pattern is clear but the intent is not: a policy that lets
everyone read a table is correct for blog posts and a leak for invoices. Findings without the tag are
format matches Caelo is confident about.

## What it checks

| Check | Rule id | Severity |
| --- | --- | --- |
| Provider keys in files: Stripe live and restricted, OpenAI, Anthropic, AWS access key id, GitHub, SendGrid, Slack, Google, private key blocks, Supabase `sb_secret_` | `secrets.*` | critical or high |
| A Supabase `service_role` JWT (decoded locally; the anon key is not flagged) | `secrets.supabase-service-role` | critical |
| A secret-sounding or server-only key behind a browser-public prefix (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `NUXT_PUBLIC_`, `GATSBY_`, `PUBLIC_`) | `browser.public-secret-name` | high or medium |
| Firestore, Storage and Realtime Database rules with no condition (`allow write: if true`, `".write": true`) | `firebase.open-rule` | critical for writes, lower for reads |
| Postgres row-level-security policies whose condition is literally `true` | `supabase.permissive-policy`, `supabase.public-read-policy` | high, medium or low |
| Supabase tables that no migration ever enables row-level security on | `supabase.rls-not-enabled` | high |
| Env files that git tracks, or that nothing git-ignores | `env.committed`, `env.not-ignored` | high or low |

The grade starts at 100 and loses 25 per critical, 12 per high, 5 per medium and 2 per low finding:
90 and up is `Solid`, 70 and up `Needs work`, 40 and up `At risk`, below that `Critical`.

## What it deliberately does not flag

- Keys that are meant to be public: Supabase anon and `sb_publishable_` keys, Stripe publishable keys,
  Firebase web config, PostHog, Sentry, Maps and similar.
- A local `.env` that is git-ignored. That is where secrets belong, so Caelo reports that it saw the
  file and does not flag the values inside. To know whether a file is tracked, Caelo reads `.git/index`
  as data. It never runs `git`.
- Placeholders such as `sk_live_xxxxxxxx` or `your_key_here`, and the fixed `service_role` key that every
  local `supabase start` uses.
- A browser-public variable name that only appears in prose (`.md`, `.txt`). Documentation does not ship
  to the browser.
- SQL policies that a later migration drops or rewrites. Migrations are replayed in path order and judged
  on their final state.

## Limits

Caelo is a pattern scanner, and it is honest about that:

- A clean scan is not proof the app is secure. Caelo does not understand your auth or business logic.
- It cannot see your live database. Row-level security that was switched on by hand in the Supabase
  dashboard does not appear in your files, so the SQL checks can be wrong in both directions.
- It reads the working tree, not git history. A key you deleted last week is still in history.
- It will sometimes flag a test fixture or an already-rotated key, and it will miss a secret that has
  no recognizable format (a database password, a custom token).
- It skips `node_modules`, `.git`, build output (`dist`, `build`, `out`, `.next` and similar), `vendor`,
  virtualenvs, lockfiles, binary files, files over 1.5 MB, and symlinks. It stops after 20,000 files and
  says so.

## Options and exit codes

```bash
npx caelo <path>            # scan a folder and print the report
npx caelo <path> --json     # the same result as JSON
npx caelo --version
npx caelo --help
```

Exit code `0` means a completed scan with no critical finding, `1` means at least one critical finding,
`2` means incomplete coverage or an internal error, and `64` is bad usage. Output is plain text with no color codes, so it reads the same in a
terminal, a pipe or a CI log.

`--json` prints `schemaVersion` (1), `status`, `coverage`, `caelo` (version), `target`, `examined`, `skipped`, `truncated`, `score`, `grade`,
`counts`, `findings` and `notes`. Each finding has `file`, `line`, `ruleId`, `title`, `severity`, a
redacted `value`, `why`, `fix` and `confidence` (`confirmed` or `needs_review`), plus `occurrences`
when one browser-exposed variable name is used in several files.

## Install it with a package manager

Caelo runs fine with a one-off `npx caelo .`, but you can also install it for good:

```bash
# Homebrew (macOS / Linux)
brew install arthi-arumugam-git/tap/caelo

# Nix (locked release source and dependencies)
nix run github:arthi-arumugam-git/caelo -- .

# Scoop (Windows)
scoop bucket add caelo https://github.com/arthi-arumugam-git/scoop-caelo
scoop install caelo

# mise (no plugin needed)
mise use -g npm:caelo

# asdf
asdf plugin add caelo https://github.com/arthi-arumugam-git/asdf-caelo
asdf install caelo latest

# npm, global
npm install -g caelo
```

Requires Node.js 18 or newer. The Nix flake supplies its own pinned runtime and locks the reviewed 0.1.3 source and npm dependency closure. Linux x86_64 CLI and MCP checks passed.

## Use it inside your editor (MCP)

Caelo is also an MCP server, so you can scan your repo without leaving Cursor, Claude Code, Windsurf
or any MCP client. The server exposes one tool, `roast_project`, which takes the folder path and
returns the same report as the CLI.

**Cursor** (one click):

[![Add to Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](cursor://anysphere.cursor-deeplink/mcp/install?name=caelo&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsImNhZWxvIiwiLS1tY3AiXX0=)

**Claude Code** (one line):

```bash
claude mcp add --transport stdio --scope user caelo -- npx -y caelo --mcp
```

**Claude Code plugin** (bundles the scanner, a `/caelo:scan` command, and the skill in one install):

```bash
claude plugin marketplace add arthi-arumugam-git/caelo
claude plugin install caelo@caelo
```

Then run `/caelo:scan` in any project, or just ask for a security check.

**Claude Desktop** (no terminal): download [`desktop-extension/caelo.mcpb`](desktop-extension/caelo.mcpb) and open it from Claude Desktop, Settings, Extensions. See [`desktop-extension/`](desktop-extension/).

**Any MCP client** (add to your MCP config):

```json
{
  "mcpServers": {
    "caelo": {
      "command": "npx",
      "args": ["-y", "caelo", "--mcp"]
    }
  }
}
```

Then ask: *"roast this project for security issues"*.

On Windows, if your MCP client can't find `npx`, set `"command": "cmd"` and `"args": ["/c", "npx", "-y", "caelo", "--mcp"]`.

**Continue.dev** uses YAML. Add to your `config.yaml`:

```yaml
mcpServers:
  - name: caelo
    command: npx
    args: ["-y", "caelo", "--mcp"]
```

## Use it as a Claude Code skill

Prefer plain English over config? There's a Claude Code skill in [`claude-code-skill/caelo`](claude-code-skill/caelo). Copy that folder into `~/.claude/skills/` and ask Claude Code to *"run a Caelo security scan"*; it runs the scan and explains the findings.

## Run it in CI

Fail a pull request when Caelo finds something critical:

```yaml
# .github/workflows/security.yml
- uses: arthi-arumugam-git/caelo-action@v1
```

## Use it as a pre-commit hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/arthi-arumugam-git/caelo
    rev: v0.1.3
    hooks:
      - id: caelo
```

The v0.1.3 hook runs `npx -y caelo@0.1.3 .`, so its executable version agrees with the reviewed hook revision.

## Show it off

Scanned and happy with the result? Add the badge to your README:

```md
[![Scanned with Caelo](https://img.shields.io/badge/scanned%20with-Caelo-c8e630?labelColor=111111)](https://caelo.sh)
```

[![Scanned with Caelo](https://img.shields.io/badge/scanned%20with-Caelo-c8e630?labelColor=111111)](https://caelo.sh)

The badge says a scan was run. It is not a certificate.

## How it is built

- `lib/scan.js` walks the folder and reads files. `lib/rules.js` holds every rule as a regular
  expression or a small state machine. `lib/git.js` parses `.git/index`. `lib/report.js` formats the
  result. Nothing in `lib/` opens a network connection.
- The one dependency, `@modelcontextprotocol/sdk`, is loaded only for `--mcp`.
- Tests: `npm test`. Every rule has a "should flag" case and a "should not flag" case, and one test
  checks that Caelo scanning its own repository finds nothing.

Found a false positive or a miss? Please open an issue with the smallest file that reproduces it.

## Who makes it, and the paid part

Caelo is made by Irth Labs and stays free under the MIT license. Irth Labs also sells human help,
which is how this tool is funded:

- **App Health Check ($490).** A person reviews every finding, runs the checks that need your consent
  (such as testing whether your live Supabase tables really enforce row-level security), and gives you a
  fixed quote for the fixes.
- **Full Cleanup ($24,500).** For a company that needs its AI-built app reviewed and fixed, and its business data cleaned up for AI.

When a scan has critical or high findings, the CLI prints one closing line that mentions the Health
Check. That line never appears in `--json` output or in the MCP tool's output. Details: <https://caelo.sh>.

## License

MIT. See [LICENSE](LICENSE).


Git awareness is limited to repository discovery within the selected scan folder. A root .git file can select linked-worktree metadata outside that folder. Only Git metadata and ignore files are read for this purpose. Caelo never executes Git. Selecting a subfolder does not read a parent repository's index.

Incomplete scans preserve findings and return explicit coverage-gap counts. Their score and grade are unavailable, and the CLI returns 2 unless a critical finding requires exit 1.
