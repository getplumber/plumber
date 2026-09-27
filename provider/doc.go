// Package provider is the seam between the command line and the two
// analysis paths: one Provider implementation per git host (GitLab, GitHub)
// answers how to run the analysis, compute compliance, write the PBOM and
// perform the post-analysis actions, so the cmd package never branches on
// the provider name itself.
package provider
