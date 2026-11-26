# Caelo

[![npm version](https://img.shields.io/npm/v/caelo)](https://www.npmjs.com/package/caelo)
[![license](https://img.shields.io/npm/l/caelo)](LICENSE)
[![node](https://img.shields.io/node/v/caelo)](https://nodejs.org)

**See straight to the bottom of your code.**

Caelo is a free security **roast** for apps built with AI coding tools (Lovable, Bolt, Cursor, v0, Replit).
It flags the leaks that bite AI-built apps most often, with a plain-English fix for each:

- exposed API keys and secrets in source (Stripe, OpenAI, Anthropic, AWS, GitHub, SendGrid, Google, Slack, private keys)
- a Supabase **service-role** key in your code (the anon key is fine; this one bypasses row-level security)
- secrets shipped to the browser behind a public prefix (`NEXT_PUBLIC_…SERVICE_ROLE`, `VITE_…SECRET`)
- open Firebase rules (`allow read, write: if true`)
- permissive or missing Supabase row-level-security policies
- committed `.env` files and a `.gitignore` that misses them

**It runs entirely on your machine.** It reads your files as data, never executes your code, and
**redacts every secret value** it finds (you see `sk_l…cdEF (43 chars)`, never the key). Nothing is
uploaded anywhere.

## Quick start

```bash
npx caelo .
```

Point it at any project folder. Exit code is `1` if anything critical is found, else `0`.

## Use it inside your editor (MCP)

Caelo is also an MCP server, so you can roast your repo without leaving Cursor, Claude
Code, Windsurf or any MCP client.

**Cursor** (one click):

[![Add to Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](cursor://anysphere.cursor-deeplink/mcp/install?name=caelo&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsImNhZWxvIiwiLS1tY3AiXX0=)

**Claude Code** (one line):

```bash
claude mcp add --transport stdio --scope user caelo -- npx -y caelo --mcp
```

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

Then ask: *"roast this project for security issues"*. The `roast_project` tool takes the repo path.

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

## Run it with Docker

Prefer a container? Caelo ships as a Docker image on the GitHub Container Registry.
Mount the folder you want to scan at `/scan`:

```bash
docker run --rm -v "$PWD:/scan" ghcr.io/arthi-arumugam-git/caelo /scan
```

The container reads only the folder you mount and uploads nothing, just like the CLI.
Exit code is `1` if anything critical is found, else `0`.

Run the MCP server from the container instead:

```bash
docker run --rm -i -v "$PWD:/scan" ghcr.io/arthi-arumugam-git/caelo --mcp
```

## Run it in CI

Fail a pull request when a secret or an open database slips in:

```yaml
# .github/workflows/security.yml
- uses: arthi-arumugam-git/caelo-action@v1
```

## Use it as a pre-commit hook

Catch leaks before they are ever committed. Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/arthi-arumugam-git/caelo
    rev: v0.1.1
    hooks:
      - id: caelo
```

## Show it off

Scanned clean? Add the badge to your README:

```md
[![Scanned with Caelo](https://img.shields.io/badge/scanned%20with-Caelo-c8e630?labelColor=111111)](https://caelo.sh)
```

[![Scanned with Caelo](https://img.shields.io/badge/scanned%20with-Caelo-c8e630?labelColor=111111)](https://caelo.sh)

## What the free roast is, and isn't

This is the free gateway. It catches the common, high-impact leaks. What it does **not** do is the
deeper, judgement-heavy work: reviewing every finding to cut false alarms, the checks that need your
consent (like actually probing whether your Supabase tables enforce row-level security), and a fixed
quote to fix what's found. That's the **Caelo Health Check** ($490, credited toward the fix):
<https://caelo.sh>.

## License

MIT. Caelo is a product of Irth Labs. See [LICENSE](LICENSE).
