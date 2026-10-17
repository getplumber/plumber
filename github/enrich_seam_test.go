package github

import "github.com/getplumber/plumber/internal/ir"

// enrichActionsWithClient is enrichActions with a fetcher of its own over
// the raw host: the seam the enrichment tests drive through a stubbed
// transport.
func enrichActionsWithClient(pipeline *ir.NormalizedPipeline, client *GitHubMetadataClient, scanMutableExec bool, progressFn ProgressFunc) {
	enrichActions(pipeline, client, newDefinitionFetcher(httpRawFetcher, client), scanMutableExec, progressFn)
}
