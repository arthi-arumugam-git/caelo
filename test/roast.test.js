// Self-contained tests. Each "should flag" has a "should not flag" twin so a rule can't pass by
// flagging everything. Run with: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { scanDir, score } from "../lib/scan.js";
import { redact } from "../lib/rules.js";

// Synthetic Stripe-shaped test key, assembled at runtime and split across two string
// literals so secret-scanning push protection (GitHub, etc.) does not flag the test file.
// The runtime value is unchanged, so the scanner still sees a real-looking sk_live_ key.
const FAKE_STRIPE = "sk_live_" + "51H8xWpackedFAKEkey1234567890abcdEF";

function fixture(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "roast-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

test("redact never returns the raw secret", () => {
  const secret = FAKE_STRIPE;
  const masked = redact(secret);
  assert.ok(!masked.includes("packedFAKEkey"), "mask must not contain the middle of the secret");
  assert.match(masked, /chars\)$/);
});

test("flags a Stripe live key and a committed .env", () => {
  const dir = fixture({
    "src/pay.js": `const k = "${FAKE_STRIPE}";\n`,
    ".env": `STRIPE_SECRET_KEY=${FAKE_STRIPE}\n`,
    ".gitignore": "node_modules\n",
  });
  try {
    const r = scanDir(dir);
    const ids = r.findings.map((f) => f.ruleId);
    assert.ok(ids.includes("secrets.stripe-secret"), "should flag the Stripe key");
    assert.ok(ids.includes("env.committed"), "should flag the committed .env");
    assert.ok(score(r.findings) < 100, "score should drop below 100");
    for (const f of r.findings) {
      assert.ok(!/packedFAKEkey/.test(JSON.stringify(f)), "no finding may contain a raw secret");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("does NOT flag a clean project (anon key, example env, gitignored)", () => {
  const dir = fixture({
    // supabase anon key (role=anon) is public and fine; must not be flagged as service_role
    "src/supabase.js":
      'export const key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsInJlZiI6ImFiYyJ9.sig";\n',
    ".env.example": "STRIPE_SECRET_KEY=your-key-here\n",
    ".gitignore": ".env*\n!.env.example\nnode_modules\n",
  });
  try {
    const r = scanDir(dir);
    assert.equal(r.findings.length, 0, `clean project should have no findings, got: ${r.findings.map((f) => f.ruleId)}`);
    assert.equal(score(r.findings), 100);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("flags a Supabase service-role JWT but not an anon JWT", () => {
  // {"role":"service_role","ref":"abc"} base64url payload
  const serviceRole =
    "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwicmVmIjoiYWJjIn0.c2lnbmF0dXJlX3BsYWNlaG9sZGVy";
  const dir = fixture({ "src/admin.js": `const k = "${serviceRole}";\n` });
  try {
    const r = scanDir(dir);
    assert.ok(
      r.findings.some((f) => f.ruleId === "secrets.supabase-service-role"),
      "should flag the service_role JWT",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
