import test from "node:test";
import assert from "node:assert/strict";
import { imageTags } from "../.github/image-tags.mjs";

test("only a stable published release promotes latest", () => {
  const base = { sha: "a".repeat(40), version: "0.1.3", ref: "v0.1.3", prerelease: false };
  assert.ok(imageTags({ ...base, event: "release" }).some((tag) => tag.endsWith(":latest")));
  for (const event of ["workflow_dispatch", "push"]) {
    assert.ok(imageTags({ ...base, event }).every((tag) => !tag.endsWith(":latest")));
  }
  assert.ok(imageTags({ ...base, event: "release", prerelease: true }).every((tag) => !tag.endsWith(":latest")));
  assert.throws(() => imageTags({ ...base, event: "release", ref: "v0.1.2" }));
});
