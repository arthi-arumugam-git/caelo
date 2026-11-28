import { readFileSync, appendFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function imageTags({ event, ref, sha, prerelease, version }) {
  const image = "ghcr.io/arthi-arumugam-git/caelo";
  if (!/^[a-f0-9]{40}$/.test(sha)) throw new Error("Expected a full source revision");
  if (event === "workflow_dispatch") return [`${image}:manual-${sha.slice(0, 12)}`];
  if (!/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(version) || ref !== `v${version}`) {
    throw new Error("Release tag and package version must agree");
  }
  const tags = [`${image}:${version}`];
  if (event === "release" && !prerelease && !version.includes("-")) {
    tags.push(`${image}:${version.split(".").slice(0, 2).join(".")}`, `${image}:latest`);
  }
  return tags;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const version = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
  const tags = imageTags({
    event: process.env.EVENT_NAME, ref: process.env.EVENT_REF,
    sha: process.env.EVENT_SHA, prerelease: process.env.EVENT_PRERELEASE === "true", version,
  });
  if (!process.env.GITHUB_OUTPUT) throw new Error("Expected GitHub Actions output path");
  appendFileSync(process.env.GITHUB_OUTPUT, `tags<<CAELO_TAGS\n${tags.join("\n")}\nCAELO_TAGS\n`);
}
