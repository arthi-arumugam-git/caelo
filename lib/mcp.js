// MCP server mode: exposes roast_project over stdio for Cursor / Claude Code / Windsurf / any MCP client.
// Uses the low-level Server API with plain JSON Schema (no zod coupling).
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { scanDir } from "./scan.js";
import { formatReport } from "./report.js";

const TOOL = {
  name: "roast_project",
  description:
    "Caelo: roast a local project folder for the security leaks common in AI-built apps (Lovable, Bolt, " +
    "Cursor, v0, Replit): exposed API keys and secrets, secrets shipped to the browser, Supabase " +
    "service-role keys and permissive policies, open Firebase rules, and committed .env files. Reads " +
    "files as data (never runs your code), redacts secret values, returns a grade plus findings with " +
    "fix guidance. Free. Point it at the repository root.",
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string", description: "Absolute path to the project folder to roast (the repo root)." },
    },
    required: ["path"],
  },
};

function roast(target) {
  if (typeof target !== "string" || !target) {
    return { content: [{ type: "text", text: "roast_project needs a 'path' string (the project folder)." }], isError: true };
  }
  const root = path.resolve(target);
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    return { content: [{ type: "text", text: `Not a directory: ${target}` }], isError: true };
  }
  try {
    return { content: [{ type: "text", text: formatReport(scanDir(root)) }] };
  } catch {
    return { content: [{ type: "text", text: "Roast failed (internal error)." }], isError: true };
  }
}

export async function startMcp() {
  const server = new Server({ name: "caelo", version: "0.1.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [TOOL] }));
  server.setRequestHandler(CallToolRequestSchema, async (req) =>
    req.params.name === TOOL.name
      ? roast(req.params.arguments?.path)
      : { content: [{ type: "text", text: `Unknown tool: ${req.params.name}` }], isError: true },
  );
  await server.connect(new StdioServerTransport());
}
