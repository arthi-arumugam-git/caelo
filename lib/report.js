// Formats a scan result as plain text, with the honest upgrade CTA.
import { score, grade } from "./scan.js";

const SEVERITIES = ["critical", "high", "medium", "low"];
const SITE = "https://caelo.sh";

export function upgradeCta(findings) {
  const crit = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  if (crit > 0 || high > 0) {
    return [
      "This free roast shows you what and where. The Caelo Health Check ($490) adds a human who",
      "reviews every finding, runs the checks that need your consent (like probing whether your Supabase",
      "tables actually enforce row-level security), and gives you a fixed quote to fix them. The $490 is",
      `credited toward the fix. Start one at ${SITE}.`,
    ].join("\n");
  }
  return [
    "No critical or high findings in what was scanned. This free roast covers the common leaks; a human",
    `review (the checks that need your consent, plus a fixed quote if anything turns up) is the Caelo Health Check at ${SITE}.`,
  ].join("\n");
}

export function formatReport(result) {
  const { target, examined, skipped, truncated, findings } = result;
  const s = score(findings);
  const out = [];
  out.push(`Caelo roast: ${target}`);
  out.push(`${examined} files examined, ${skipped} skipped${truncated ? " (file limit hit)" : ""}`);
  const counts = SEVERITIES.map((sev) => `${findings.filter((f) => f.severity === sev).length} ${sev}`).join(", ");
  out.push(`findings: ${counts}`);
  out.push(`grade: ${grade(s)} (${s}/100)`);

  for (const sev of SEVERITIES) {
    const list = findings.filter((f) => f.severity === sev);
    if (!list.length) continue;
    out.push("", `${sev.toUpperCase()} (${list.length})`);
    for (const f of list) {
      const tag = f.confidence === "needs_review" ? " [needs review]" : "";
      out.push(`- ${f.title}${tag}`);
      out.push(`    ${f.file}${f.line ? `:${f.line}` : ""}  (${f.ruleId})`);
      if (f.value) out.push(`    value: ${f.value}`);
      out.push(`    why: ${f.why}`);
      out.push(`    fix: ${f.fix}`);
    }
  }
  if (!findings.length) out.push("", "No findings in what was scanned. Nice.");

  if (grade(s) === "A") {
    out.push("", `Grade A. Show it: add the "Scanned with Caelo" badge to your README (${SITE}).`);
  }
  out.push("", "- - -", upgradeCta(findings));
  return out.join("\n");
}
