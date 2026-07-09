"use strict";

// Pure helpers for the "Post finding comments" step of claude-pr-checks.yml.
// Extracted from the inline github-script block so this dedup/redaction/
// marker logic — which carries the workflow's "re-runs never duplicate a
// comment" and "never leak a secret" guarantees — can be unit-tested.
// GitHub/Anthropic I/O stays in the workflow; everything here is pure.

const crypto = require("crypto");

const MAX_BODY = 65000; // GitHub comment limit is 65536 chars
const FINDING_MARKER = "claude-finding"; // <!-- claude-finding:<id> -->

// Comment bodies posted via the API are NOT covered by GitHub secret
// masking, so scrub key-shaped strings defensively: Anthropic keys plus
// GitHub tokens/PATs (finding text comes from an injection-prone agent).
const redact = (s) =>
  String(s)
    .replace(/sk-ant-[A-Za-z0-9_-]{8,}/g, "sk-ant-[REDACTED]")
    .replace(/gh[pousr]_[A-Za-z0-9]{20,}/g, "gh_[REDACTED]")
    .replace(/github_pat_[A-Za-z0-9_]{20,}/g, "github_pat_[REDACTED]");

// Truncate without cutting inside a surrogate pair (a lone high surrogate
// is rejected by the GitHub API).
const clamp = (s, max = MAX_BODY) =>
  s.length > max
    ? s.slice(0, max).replace(/[\uD800-\uDBFF]$/, "") + "\n\n*(truncated)*"
    : s;

// Fingerprint excludes the line number so line drift across pushes does not
// turn one finding into a "new" one.
const fingerprint = (key, file, summary) =>
  crypto
    .createHash("sha1")
    .update(`${key}\n${file}\n${String(summary).trim().replace(/\s+/g, " ").toLowerCase()}`)
    .digest("hex")
    .slice(0, 16);

// Unanchored entries render as **[Title] summary**; drop the "[Title] "
// prefix so the stored text is the bare summary.
const stripTitle = (s) => String(s).trim().replace(/^\[[^\]]+\]\s+/, "");

// Agent-authored text (summary/details) is untrusted. Strip any HTML
// comment so it can't smuggle a `<!-- claude-finding:... -->` marker into a
// posted body that a later run would harvest into the dedup state.
const sanitizeAgentText = (s) => String(s).replace(/<!--[\s\S]*?-->/g, "");

const markerRe = () => new RegExp(`<!--\\s*${FINDING_MARKER}:([0-9a-f]+)\\s*-->`, "g");
const findingRe = () =>
  new RegExp(`<!--\\s*${FINDING_MARKER}:([0-9a-f]+)\\s*-->[\\s\\S]*?\\*\\*(.+?)\\*\\*`, "g");

// From a list of comment bodies (already filtered to our own comments),
// collect every posted fingerprint (`seen`) and a fingerprint->summary map
// (`existingById`) for the semantic-dedup pass.
function collectSeen(bodies) {
  const seen = new Set();
  const existingById = new Map();
  const mre = markerRe();
  const fre = findingRe();
  for (const body of bodies) {
    if (!body) continue;
    for (const m of body.matchAll(mre)) seen.add(m[1]);
    for (const m of body.matchAll(fre)) {
      if (!existingById.has(m[1])) existingById.set(m[1], stripTitle(m[2]));
    }
  }
  return { seen, existingById };
}

// Parse each control's report file into normalized findings. Returns
// { findings, missing } where `missing` is the display titles of controls
// whose report was absent, unparsable, or malformed (so a broken report is
// never silently treated as a clean pass).
function collectFindings(reportsDir, fs, path, controls) {
  const findings = [];
  const missing = [];
  for (const { key, title } of controls) {
    const file = path.join(reportsDir, `report-${key}.json`);
    if (!fs.existsSync(file)) {
      missing.push(title);
      continue;
    }
    let result;
    try {
      result = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
      missing.push(title);
      continue;
    }
    if (result === null || typeof result !== "object") {
      missing.push(title);
      continue;
    }
    if (!result.has_findings) continue;
    if (!Array.isArray(result.findings) || result.findings.length === 0) {
      missing.push(title);
      continue;
    }
    for (const f of result.findings) {
      if (!f || typeof f !== "object" || !f.summary || !f.file) continue;
      const summary = sanitizeAgentText(f.summary);
      findings.push({
        key,
        title,
        summary,
        severity: typeof f.severity === "string" ? f.severity : "",
        file: String(f.file),
        line: Number.isInteger(f.line) ? f.line : null,
        details: sanitizeAgentText(typeof f.details === "string" ? f.details : ""),
        id: fingerprint(key, String(f.file), summary),
      });
    }
  }
  return { findings, missing };
}

// Render the body of one resolvable inline review comment.
function renderInlineBody(f) {
  const sev = f.severity ? ` _(${f.severity})_` : "";
  return clamp(
    redact(
      `<!-- ${FINDING_MARKER}:${f.id} -->\n` +
        `### 🔴 ${f.title}\n\n` +
        `**${f.summary}**${sev}\n\n` +
        `${f.details}\n\n` +
        `<sub>Control: \`.github/claude-prompts/${f.key}.md\` · resolve this conversation once addressed.</sub>`,
    ),
  );
}

// Merge unanchored findings into the previous aggregate issue-comment body,
// appending entry by entry only while under MAX_BODY so the size clamp never
// cuts a marker mid-body (which would erase a fingerprint and re-post it).
function buildUnanchoredBody(unanchoredMarker, prevBody, unanchored) {
  const header = `${unanchoredMarker}\n# Claude PR review — findings not anchorable to the diff`;
  let body = prevBody || header;
  let omitted = 0;
  for (const f of unanchored) {
    const sev = f.severity ? ` _(${f.severity})_` : "";
    const loc = `${f.file}${f.line ? ":" + f.line : ""}`;
    const entry = redact(
      `\n\n<!-- ${FINDING_MARKER}:${f.id} -->\n` +
        `- [ ] **[${f.title}] ${f.summary}**${sev} — \`${loc}\`\n\n  ` +
        `${f.details.replace(/\n/g, "\n  ")}`,
    );
    if (body.length + entry.length > MAX_BODY - 120) {
      omitted++;
      continue;
    }
    body += entry;
  }
  if (omitted > 0) {
    body += `\n\n> *(${omitted} further finding(s) omitted — comment size limit.)*`;
  }
  return clamp(body);
}

module.exports = {
  MAX_BODY,
  FINDING_MARKER,
  redact,
  clamp,
  fingerprint,
  stripTitle,
  sanitizeAgentText,
  markerRe,
  findingRe,
  collectSeen,
  collectFindings,
  renderInlineBody,
  buildUnanchoredBody,
};
