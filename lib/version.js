// Single source of truth for the version: package.json.
import { createRequire } from "node:module";

export const VERSION = createRequire(import.meta.url)("../package.json").version;
