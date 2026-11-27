#!/usr/bin/env node
// Caelo: see straight to the bottom of your code. CLI + MCP entry.
//   npx caelo <path>          scan a folder and print the report
//   npx caelo <path> --json   same result as JSON
//   npx caelo --mcp           run as an MCP server over stdio (for Cursor / Claude Code / etc.)
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { scanDir } from "../lib/scan.js";
import { formatReport, toJson } from "../lib/report.js";
import { VERSION } from "../lib/version.js";

const USAGE = `usage:
  caelo <path>           scan a folder and print the report
  caelo <path> --json    print the result as JSON (findings only, nothing else)
  caelo --mcp            run as an MCP server over stdio
  caelo --version        print the version
  caelo --help           print this help

exit codes: 0 no critical findings, 1 at least one critical finding, 2 internal error, 64 bad usage`;

const FLAGS = new Set(["--mcp", "--json", "--help", "-h", "--version", "-v"]);

async function main() {
  const argv = process.argv.slice(2);
  const flags = argv.filter((a) => a.startsWith("-"));
  const paths = argv.filter((a) => !a.startsWith("-"));

  const unknown = flags.find((f) => !FLAGS.has(f));
  if (unknown) {
    console.error(`unknown option: ${unknown}\n\n${USAGE}`);
    process.exitCode = 64;
    return;
  }
  if (flags.includes("--help") || flags.includes("-h")) {
    console.log(USAGE);
    return;
  }
  if (flags.includes("--version") || flags.includes("-v")) {
    console.log(VERSION);
    return;
  }
  if (flags.includes("--mcp")) {
    const { startMcp } = await import("../lib/mcp.js");
    await startMcp();
    return; // stays alive on stdio
  }
  if (paths.length !== 1) {
    console.error(`${paths.length ? "expected exactly one path" : "missing path"}\n\n${USAGE}`);
    process.exitCode = 64;
    return;
  }
  const target = paths[0];
  const root = path.resolve(target);
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    console.error(`not a directory: ${target}`);
    process.exitCode = 64;
    return;
  }
  const result = scanDir(root);
  console.log(flags.includes("--json") ? JSON.stringify(toJson(result), null, 2) : formatReport(result, { footer: true }));
  process.exitCode = result.findings.some((f) => f.severity === "critical") ? 1 : 0;
}

main().catch((err) => {
  // The message can name a file path but never file contents.
  console.error(`caelo: internal error: ${err && err.message ? err.message : err}`);
  process.exitCode = 2;
});
