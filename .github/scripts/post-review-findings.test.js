"use strict";

// Dependency-free tests for the finding-posting pure helpers.
// Run: node --test .github/scripts/

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const M = require("./post-review-findings.js");

test("redact scrubs Anthropic and GitHub secrets, leaves other text", () => {
  const out = M.redact("k sk-ant-abcd1234efgh t ghs_ABCDEFGHIJKLMNOPQRSTUVWX p github_pat_11ABCDEFG0abcdefghij keep");
  assert.match(out, /sk-ant-\[REDACTED\]/);
  assert.match(out, /gh_\[REDACTED\]/);
  assert.match(out, /github_pat_\[REDACTED\]/);
  assert.match(out, /keep/);
  assert.doesNotMatch(out, /ghs_ABCDEF/);
});

test("clamp passes short bodies through and never leaves a lone high surrogate", () => {
  assert.equal(M.clamp("short"), "short");
  // A high surrogate exactly at the cut boundary must be trimmed.
  const body = "a".repeat(9) + "🔴"; // 🔴 = high+low surrogate
  const out = M.clamp(body, 10); // boundary lands between the surrogate pair
  assert.doesNotMatch(out, /[\uD800-\uDBFF]$/);
  assert.match(out, /\*\(truncated\)\*$/);
});

test("fingerprint is stable across whitespace/case and line drift, sensitive to real change", () => {
  const a = M.fingerprint("bug-risks", "a.go", "Concurrent  MAP write");
  const b = M.fingerprint("bug-risks", "a.go", "concurrent map write");
  assert.equal(a, b); // whitespace + case normalized
  assert.notEqual(a, M.fingerprint("bug-risks", "b.go", "Concurrent map write")); // file matters
  assert.notEqual(a, M.fingerprint("security", "a.go", "Concurrent map write")); // control matters
  assert.match(a, /^[0-9a-f]{16}$/);
});

test("stripTitle removes only a leading [Title] prefix", () => {
  assert.equal(M.stripTitle("[Security] SQL injection"), "SQL injection");
  assert.equal(M.stripTitle("Medium — nil deref"), "Medium — nil deref"); // em-dash, not a bracket
});

test("collectSeen reads all markers across both comment formats", () => {
  const inline = `<!-- ${M.FINDING_MARKER}:aaaa1111bbbb2222 -->\n### 🔴 Bug risks\n\n**nil deref**`;
  const unanchored =
    `<!-- claude-pr-checks-unanchored -->\n` +
    `<!-- ${M.FINDING_MARKER}:cccc3333dddd4444 -->\n- [ ] **[Security] SQL injection** — x\n\n` +
    `<!-- ${M.FINDING_MARKER}:eeee5555ffff6666 -->\n- [ ] **[Tests] missing coverage** — y`;
  const { seen, existingById } = M.collectSeen([inline, unanchored, null]);
  assert.equal(seen.size, 3);
  assert.ok(seen.has("cccc3333dddd4444"));
  assert.equal(existingById.get("aaaa1111bbbb2222"), "nil deref");
  assert.equal(existingById.get("cccc3333dddd4444"), "SQL injection"); // [Title] stripped
});

test("render→parse round-trips: a rendered inline body parses back to (id, summary)", () => {
  const f = { key: "bug-risks", title: "Bug risks", summary: "nil deref in handler", severity: "Medium", file: "a.go", line: 3, details: "d", id: "0123456789abcdef" };
  const body = M.renderInlineBody(f);
  const { seen, existingById } = M.collectSeen([body]);
  assert.ok(seen.has(f.id));
  assert.equal(existingById.get(f.id), f.summary);
});

test("collectFindings strips planted markers from agent text (dedup-poison guard)", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "reports-"));
  const controls = [{ key: "security", title: "Security" }];
  fs.writeFileSync(
    path.join(dir, "report-security.json"),
    JSON.stringify({ has_findings: true, findings: [{ summary: "real issue", file: "a.go", details: "text <!-- claude-finding:deadbeefdeadbeef --> more" }] }),
  );
  const { findings } = M.collectFindings(dir, fs, path, controls);
  assert.equal(findings.length, 1);
  assert.doesNotMatch(findings[0].details, /claude-finding:deadbeef/);
  // A body rendered from it must not leak the planted fingerprint.
  const { seen } = M.collectSeen([M.renderInlineBody(findings[0])]);
  assert.ok(!seen.has("deadbeefdeadbeef"));
});

test("collectFindings records missing/malformed controls and normalizes entries", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "reports-"));
  const controls = [
    { key: "security", title: "Security" },
    { key: "bug-risks", title: "Bug risks" },
    { key: "test-coverage", title: "Test coverage" },
    { key: "new-control-check", title: "New control check" },
  ];
  // security: valid findings
  fs.writeFileSync(path.join(dir, "report-security.json"), JSON.stringify({ has_findings: true, findings: [{ summary: "s1", file: "a.go", line: 2, severity: "High", details: "d" }] }));
  // bug-risks: has_findings true but empty findings array -> missing
  fs.writeFileSync(path.join(dir, "report-bug-risks.json"), JSON.stringify({ has_findings: true, findings: [] }));
  // test-coverage: unparsable -> missing
  fs.writeFileSync(path.join(dir, "report-test-coverage.json"), "{not json");
  // new-control-check: absent -> missing
  const { findings, missing } = M.collectFindings(dir, fs, path, controls);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, "a.go");
  assert.match(findings[0].id, /^[0-9a-f]{16}$/);
  assert.deepEqual(missing.sort(), ["Bug risks", "New control check", "Test coverage"]);
});

test("buildUnanchoredBody merges into prior body and never truncates a marker mid-body", () => {
  const MARK = "<!-- claude-pr-checks-unanchored -->";
  const prev = `${MARK}\n# Claude PR review — findings not anchorable to the diff\n\n<!-- ${M.FINDING_MARKER}:1111111111111111 -->\n- [ ] **[Old] prior finding** — z\n\n  detail`;
  const fresh = [{ key: "bug-risks", title: "Bug risks", summary: "new one", severity: "", file: "b.go", line: 9, details: "dd", id: "2222222222222222" }];
  const body = M.buildUnanchoredBody(MARK, prev, fresh);
  // prior marker preserved, new marker added
  assert.ok(body.includes("1111111111111111"));
  assert.ok(body.includes("2222222222222222"));
  // both fingerprints recoverable => not truncated away
  const { seen } = M.collectSeen([body]);
  assert.ok(seen.has("1111111111111111") && seen.has("2222222222222222"));
});
