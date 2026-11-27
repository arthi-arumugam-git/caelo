# Security policy

Caelo is a security tool that runs on your machine and reads your source code, so a flaw in Caelo
matters. Please report one privately.

## Reporting a vulnerability

Email **arthi@irthlabs.com**, or use GitHub's "Report a vulnerability" button on this repository
(Security > Advisories). Please do not open a public issue for a security problem. We acknowledge
within 48 hours and aim to ship a fix or share a plan within 30 days. Good-faith research is welcome.

Supported version: the latest release on npm.

## What Caelo promises, and how to check it

| Promise | How it is kept |
|---|---|
| Reads files only; never runs your code | No `child_process`, `eval` or dynamic `import` of scanned content anywhere in `bin/` or `lib/` |
| Sends nothing anywhere | No network module is imported. The only dependency is the MCP SDK, used over stdio |
| Never prints a secret | Every matched value is masked at the point of detection (`redact` in `lib/rules.js`), so the text report, `--json` and the MCP tool result only ever receive the masked form; tests assert the raw value is absent |
| Never runs git | The git index is parsed as a file (`lib/git.js`) |
| Small, auditable package | The npm tarball holds only `bin/`, `lib/`, `README.md`, `LICENSE`, `package.json`; CI fails if anything else is packed |

## In scope

Anything that breaks a promise above: a scanned repository that makes Caelo read outside the target
folder, execute something, hang (for example a regular expression that backtracks badly), print an
unmasked secret, or pass repository-controlled text to an AI agent in a way that could steer it.

False positives and false negatives are bugs, not vulnerabilities: please open a normal issue.
