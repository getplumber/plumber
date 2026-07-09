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

// Fingerprint includes the line so two distinct defects that share a
// one-sentence summary in the same file (e.g. the same lint at lines 40 and
// 80) stay distinct instead of collapsing to one. Line drift across pushes
// changes the exact fingerprint, but the semantic-dedup pass catches the
// reworded/drifted repeat, so we don't re-post it.
const fingerprint = (key, file, line, summary) =>
  crypto
    .createHash("sha1")
    .update(`${key}\n${file}\n${line == null ? "" : line}\n${String(summary).trim().replace(/\s+/g, " ").toLowerCase()}`)
    .digest("hex")
    .slice(0, 16);

// Unanchored entries render as **[Title] summary**; drop the "[Title] "
// prefix so the stored text is the bare summary.
const stripTitle = (s) => String(s).trim().replace(/^\[[^\]]+\]\s+/, "");

// Agent-authored text is untrusted. Strip HTML comments so it can't smuggle
// a `<!-- claude-finding:... -->` marker into a posted body that a later run
// would harvest into the dedup state. Loop until stable so nested/overlapping
// comments can't reassemble a marker after a single pass.
const sanitizeAgentText = (s) => {
  let out = String(s);
  let prev;
  do {
    prev = out;
    out = out.replace(/<!--[\s\S]*?-->/g, "");
  } while (out !== prev);
  return out;
};

const markerRe = () => new RegExp(`<!--\\s*${FINDING_MARKER}:([0-9a-f]+)\\s*-->`, "g");
// Greedy (.+) — bounded to the summary line since `.` excludes newlines — so
// a summary that itself contains `**bold**` is recovered whole instead of
// being truncated at the first inner `**`.
const findingRe = () =>
  new RegExp(`<!--\\s*${FINDING_MARKER}:([0-9a-f]+)\\s*-->[\\s\\S]*?\\*\\*(.+)\\*\\*`, "g");

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
    const arr = Array.isArray(result.findings) ? result.findings : [];
    const valid = arr.filter((f) => f && typeof f === "object" && f.summary && f.file);
    if (!result.has_findings) {
      // A clean pass only if it truly reported nothing. Findings present
      // while has_findings is false is a contradictory/malformed report —
      // surface it as incomplete rather than silently dropping the entries.
      if (valid.length > 0) missing.push(title);
      continue;
    }
    // has_findings is true: it must deliver at least one usable finding,
    // otherwise the model claimed issues it never actually reported.
    if (valid.length === 0) {
      missing.push(title);
      continue;
    }
    for (const f of valid) {
      // Sanitize every agent-authored field that gets rendered into a
      // comment body — summary, details, severity, and file — so none can
      // smuggle a marker into the dedup state.
      const summary = sanitizeAgentText(f.summary);
      const file = sanitizeAgentText(f.file);
      const line = Number.isInteger(f.line) ? f.line : null;
      findings.push({
        key,
        title,
        summary,
        severity: sanitizeAgentText(typeof f.severity === "string" ? f.severity : ""),
        file,
        line,
        details: sanitizeAgentText(typeof f.details === "string" ? f.details : ""),
        id: fingerprint(key, file, line, summary),
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
    // The marker + summary line carries the fingerprint; keep it even when
    // the details don't fit, so the finding is still recorded (and deduped)
    // instead of churning as "new" on every run.
    const head = `\n\n<!-- ${FINDING_MARKER}:${f.id} -->\n- [ ] **[${f.title}] ${f.summary}**${sev} — \`${loc}\``;
    const full = redact(head + `\n\n  ${f.details.replace(/\n/g, "\n  ")}`);
    const compact = redact(head);
    if (body.length + full.length <= MAX_BODY - 120) body += full;
    else if (body.length + compact.length <= MAX_BODY - 120) body += compact;
    else omitted++;
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
