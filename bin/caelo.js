#!/usr/bin/env node
// Caelo: see straight to the bottom of your code. CLI + MCP entry.
//   npx caelo <path>     roast a folder and print the report
//   npx caelo --mcp      run as an MCP server over stdio (for Cursor / Claude Code / etc.)
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { scanDir, score } from "../lib/scan.js";
import { formatReport } from "../lib/report.js";

async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("--mcp")) {
    const { startMcp } = await import("../lib/mcp.js");
    await startMcp();
    return; // stays alive on stdio
  }
  const target = argv.find((a) => !a.startsWith("-"));
  if (!target || argv.includes("-h") || argv.includes("--help")) {
    console.log("usage:\n  caelo <path>     roast a folder\n  caelo --mcp      run as an MCP server (stdio)");
    process.exit(target ? 0 : 64);
  }
  const root = path.resolve(target);
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    console.error(`not a directory: ${target}`);
    process.exit(64);
  }
  const result = scanDir(root);
  console.log(formatReport(result));
  const critical = result.findings.some((f) => f.severity === "critical");
  process.exitCode = critical ? 1 : 0;
}

main().catch(() => {
  console.error("caelo crashed (internal error)");
  process.exitCode = 2;
});
