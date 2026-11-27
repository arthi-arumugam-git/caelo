# Caelo as a Claude Desktop Extension

[`caelo.mcpb`](caelo.mcpb) is a one-click [Claude Desktop Extension](https://www.anthropic.com/engineering/desktop-extensions) that runs Caelo as a local MCP server inside Claude Desktop. No terminal, no config.

## Install

1. Download [`caelo.mcpb`](caelo.mcpb).
2. Open Claude Desktop → **Settings → Extensions**.
3. Drag `caelo.mcpb` in (or double-click the file) and click **Install**.

Then ask Claude: *"roast this project for security issues"* and point it at a folder. Caelo's `roast_project` tool scans locally, reads files only, uploads nothing, and redacts every secret it reports.

## What's inside

The bundle wraps the npm package [`caelo`](https://www.npmjs.com/package/caelo) and its dependencies, so it runs with the Node runtime Claude Desktop provides. The server command is `node node_modules/caelo/bin/caelo.js --mcp`.

## Rebuild it

```bash
# from a clean directory
npm init -y
npm install caelo@latest --omit=dev
# copy manifest.json and icon.png alongside node_modules, then:
npx @anthropic-ai/mcpb validate manifest.json
npx @anthropic-ai/mcpb pack . caelo.mcpb
```

Bump `version` in `manifest.json` to match the caelo release, then repack.

For an unreleased candidate, run `npm pack --pack-destination <scratch-directory>` from the CLI
repository, then install that local tarball in the clean bundle directory with
`npm install --ignore-scripts --omit=dev <path-to-caelo-tarball>`. Use that package instead of
`caelo@latest`, which still contains the previously published release. Copy the final manifest and
icon, validate, and pack as above. After the last source change, repack and compare every bundled
`node_modules/caelo/` file with the tarball before committing `caelo.mcpb`.

- Homepage: https://caelo.sh
- Source (MIT): https://github.com/arthi-arumugam-git/caelo
- Made by Irth Labs: https://www.irthlabs.com
