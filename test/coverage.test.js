import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanDir } from "../lib/scan.js";
import { formatReport, toJson } from "../lib/report.js";
import { redact } from "../lib/rules.js";

test("each work budget preserves explicit partial coverage and withholds a grade", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "caelo-coverage-"));
  try {
    mkdirSync(path.join(root, "nested"));
    writeFileSync(path.join(root, "sample.sql"), "select 1;");
    writeFileSync(path.join(root, "nested", "example.txt"), "Ordinary text.");
    for (const [limit, reason] of Object.entries({
      files: "file_limit", entries: "entry_limit", directories: "directory_limit",
      milliseconds: "time_limit", projectBytes: "project_bytes_limit",
    })) {
      const result = scanDir(root, { limits: { [limit]: 0 } });
      assert.equal(result.status, "partial", limit);
      assert.ok(result.coverage.gaps[reason], limit);
      assert.equal(toJson(result).score, null, limit);
      assert.doesNotMatch(formatReport(result, { footer: true }), /Solid grade/);
    }
    const complete = scanDir(root);
    assert.equal(complete.status, "completed");
    assert.match(formatReport(complete, { footer: true }), /Solid grade/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("read failures and oversize text retain separate safe coverage reasons", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "caelo-size-"));
  try {
    writeFileSync(path.join(root, "large.txt"), "a".repeat(1_500_001));
    const result = scanDir(root);
    assert.equal(result.coverage.gaps.file_size, 1);
    assert.equal(scanDir(path.join(root, "missing")).coverage.gaps.directory_read, 1);
    assert.equal(toJson(result).status, "partial");
    assert.match(formatReport(result), /coverage gap: file_size \(1\)/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("redaction returns length without any value-derived prefix or suffix", () => {
  assert.equal(redact("sample-private-value"), "[redacted] (20 chars)");
});
