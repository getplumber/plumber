---
name: Feature request
about: Suggest a new feature or improvement for Plumber
title: "[FEAT]"
labels: 'enhancement'
assignees: ''

---

## **Is your feature request related to a problem? Please describe.**

<!-- 
Describe the problem this feature would solve. Be specific about the attack vector,
compliance gap, or UX issue. Include links to relevant documentation, CVEs, or
real-world examples when possible.

Example: "When CI_DEBUG_TRACE is enabled, all environment variables including
masked secrets are printed in job logs. This is a well-documented attack vector..."
-->

## **Describe the solution you'd like**

<!--
Describe the feature you'd like to see. For new controls, include:
- The control name (e.g., pipelineMustNotDoX)
- What it detects
- Example YAML snippets showing what would be flagged

For other features, describe the expected behavior and user-facing interface
(CLI flags, config options, output format, etc.)
-->

### Configuration in `.plumber.yaml`

```yaml
controls:
  controlName:
    enabled: true
    # Add relevant configuration options here
```

## **Implementation Hints**

<!--
Optional. Keep it at the level of WHAT the rule should detect and WHICH
data it needs. Don't prescribe specific Go files — see CONTRIBUTING.md
("Adding a New Control") for the full file-by-file implementer checklist
that walks every layer (collector + IR, Rego rule, config plumbing,
catalog, bench gate, terminal output, JSON output, PBOM/CycloneDX,
compliance, --skip-controls, plumber config validate, tests, docs).

That checklist is copy-pasteable into Claude Code / Cursor / Copilot
so the implementer (or their LLM) can tick boxes step by step.

Detection logic for every new control lives in a Rego rule under
`policies/*.rego`. The `control/controlGitlab*.go` Go-pattern layer is
frozen — DO NOT propose new controls there.

Consider covering (briefly):
1. Data source: which IR field would the rule read? If the data isn't
   on the IR yet, does it need collector enrichment (GitLab/GitHub API
   call, external binary like gitleaks, …)?
2. Logic: a one-liner of what the rule flags.
3. Severity + ISSUE code suggestion (or "next available").
4. Default state: opt-in or default-on? Any external dependency the
   user would need to install first (e.g., gitleaks for secret detection)?
-->

## **Why It's Valuable**

<!--
Explain the impact. Why should this be prioritized? Who benefits?
Link to OWASP CI/CD risks, real incidents, or competitor features
when relevant.
-->

> **Note:** If you submit a PR for this feature, please keep "Allow edits from maintainers" enabled so we can collaborate more easily.
