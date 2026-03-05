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
Optional but appreciated. These are suggestions — contributors are free to 
take a different approach.

Consider covering:
1. Data source: Which collector/data structure provides the input?
2. New files: What new files would be created?
3. Logic: High-level algorithm or detection approach
4. Compliance scoring: How is the 0%-100% score calculated?
-->

## **Files Touched**

<!--
List the files that would likely need changes. This helps contributors
scope the work and reviewers know what to expect.
-->

- `control/controlGitlab<Name>.go` (new control)
- `control/types.go` (add result field to `AnalysisResult`)
- `control/task.go` (wire the new control in `RunAnalysis()`)
- `configuration/plumberconfig.go` (add config struct and getter)
- `.plumber.yaml` (add default config section)
- `cmd/analyze.go` (add output formatting)

## **Why It's Valuable**

<!--
Explain the impact. Why should this be prioritized? Who benefits?
Link to OWASP CI/CD risks, real incidents, or competitor features
when relevant.
-->

> **Note:** If you submit a PR for this feature, please keep "Allow edits from maintainers" enabled so we can collaborate more easily.
