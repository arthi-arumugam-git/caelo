// Formats a scan result as plain text or JSON. Output is plain ASCII apart from the redaction
// ellipsis, with no color codes, so it reads the same in a terminal, a pipe, or a CI log.
import { score, grade } from "./scan.js";
import { VERSION } from "./version.js";

const SEVERITIES = ["critical", "high", "medium", "low"];
const SITE = "https://caelo.sh";
const BADGE_HELP = "https://github.com/arthi-arumugam-git/caelo#show-it-off";

function summarize(result) {
  const { findings, examined } = result;
  const counts = Object.fromEntries(SEVERITIES.map((sev) => [sev, findings.filter((f) => f.severity === sev).length]));
  // With nothing read there is nothing to grade; a "100/100" would be a claim Caelo cannot back.
  const s = examined > 0 ? score(findings) : null;
  return { counts, score: s, grade: s === null ? null : grade(s) };
}

/** Machine-readable result. Contains findings and counts only: no advice to buy anything. */
export function toJson(result) {
  const { counts, score: s, grade: g } = summarize(result);
  return {
    caelo: VERSION,
    target: result.target,
    examined: result.examined,
    skipped: result.skipped,
    truncated: result.truncated,
    score: s,
    grade: g,
    counts,
    findings: result.findings,
    notes: result.notes || [],
  };
}

/**
 * Human-readable report. `footer: true` (the interactive CLI only) may add ONE closing line: the
 * badge hint on a clean scan, or a pointer to the paid review when there are serious findings.
 * The MCP tool and --json never get it.
 */
export function formatReport(result, { footer = false } = {}) {
  const { target, examined, skipped, truncated, findings } = result;
  const { counts, score: s, grade: g } = summarize(result);
  const out = [];
  out.push(`Caelo roast: ${target}`);
  out.push(`${examined} file${examined === 1 ? "" : "s"} examined, ${skipped} skipped${truncated ? " (file limit hit, results are partial)" : ""}`);
  out.push(`findings: ${SEVERITIES.map((sev) => `${counts[sev]} ${sev}`).join(", ")}`);
  out.push(g === null ? "grade: n/a (no readable text files found)" : `grade: ${g} (${s}/100)`);

  for (const sev of SEVERITIES) {
    const list = findings.filter((f) => f.severity === sev);
    if (!list.length) continue;
    out.push("", `${sev.toUpperCase()} (${list.length})`);
    for (const f of list) {
      const tag = f.confidence === "needs_review" ? " [needs review]" : "";
      const more = f.occurrences > 1 ? `  (+${f.occurrences - 1} more file${f.occurrences > 2 ? "s" : ""})` : "";
      out.push(`- ${f.title}${tag}`);
      out.push(`    ${f.file}${f.line ? `:${f.line}` : ""}  (${f.ruleId})${more}`);
      if (f.value) out.push(`    value: ${f.value}`);
      out.push(`    why: ${f.why}`);
      out.push(`    fix: ${f.fix}`);
    }
  }
  if (!findings.length && examined > 0) out.push("", "No findings in what was scanned.");

  for (const n of result.notes || []) out.push("", `note: ${n}`);

  out.push("", "Caelo matches known leak patterns in files. It does not run your app, so a clean scan is not proof the app is secure.");

  if (footer && (counts.critical > 0 || counts.high > 0)) {
    out.push(`Want a human to check these findings? App Health Check, $490: ${SITE}`);
  } else if (footer && g === "Solid") {
    out.push(`Solid grade. To add the "Scanned with Caelo" badge to your README, see ${BADGE_HELP}`);
  }
  return out.join("\n");
}
