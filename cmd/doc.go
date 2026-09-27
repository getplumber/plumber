// Package cmd is the Plumber command line: the cobra commands (analyze,
// config, explain, catalog, version), the provider dispatch between the
// GitLab and GitHub analysis paths, terminal rendering, and every output
// writer (results JSON, SARIF, GitLab SAST, OCSF, CSV, PBOM) plus the
// platform push. It orchestrates; the analysis itself lives in control.
package cmd
