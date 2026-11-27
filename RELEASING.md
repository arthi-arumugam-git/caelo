# Releasing Caelo

Only the founder publishes. Everything up to `npm publish` can be prepared and checked by anyone.

## Before

1. One version everywhere. CI fails if these disagree:
   `package.json`, `server.json` (two places), `plugins/caelo/.claude-plugin/plugin.json`,
   `desktop-extension/manifest.json`. Run `npm install --package-lock-only` so the lockfile follows.
2. `CHANGELOG.md` has an entry for the version, written for users.
3. `npm test` passes. `node bin/caelo.js .` reports no findings. `npm pack --dry-run` lists only `bin/`,
   `lib/`, `README.md`, `LICENSE`, `package.json`.
4. The desktop extension is repacked with this version (`D:\startup\caelo\README.md` has the steps) and
   `desktop-extension/caelo.mcpb` is committed.

## Release (founder)

```
npm publish                      # asks for the 2FA code
git push origin master
git tag -a vX.Y.Z -m "caelo X.Y.Z" && git push origin vX.Y.Z    # the tag builds and pushes the Docker image
mcp-publisher login github --token "$(gh auth token)"
mcp-publisher publish
```

## After

1. `npm view caelo version` shows the new version, and `npx caelo@latest --version` prints it.
2. GitHub > Actions: the `ci` and `Publish Docker image` runs are green.
3. In the site repository set the version in `scripts/caelo-release.json`, rebuild and deploy
   (`node D:\startup\ops\deploy\deploy.mjs caelo --yes`).
4. A security release: say so in the GitHub release notes and point at `CHANGELOG.md`.

## Security fixes

Keep the fix commits local until you are ready to publish, then push and publish together, so the
fix and its description do not sit in public before users can upgrade.
