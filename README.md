# Caelo

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

**Claude Code / Cursor**: add to your MCP config:

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

## What the free roast is, and isn't

This is the free gateway. It catches the common, high-impact leaks. What it does **not** do is the
deeper, judgement-heavy work: reviewing every finding to cut false alarms, the checks that need your
consent (like actually probing whether your Supabase tables enforce row-level security), and a fixed
quote to fix what's found. That's the **Caelo Health Check** ($490, credited toward the fix):
<https://caelo.sh>.

## License

MIT. Caelo is a product of Irth Labs. See [LICENSE](LICENSE).
