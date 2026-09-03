package pbom

import "testing"

// The PBOM names the analyzed commit and ref on its project block (#443).
func TestPBOMProjectCarriesCommit(t *testing.T) {
	sha := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
	pb := NewGenerator("acme/target", 42, "https://gitlab.com", "release/2.0").
		WithCommit(sha, "release/2.0").
		Generate(nil, nil)
	if pb.Project.CommitSHA != sha {
		t.Errorf("Project.CommitSHA = %q, want the resolved commit", pb.Project.CommitSHA)
	}
	if pb.Project.Ref != "release/2.0" {
		t.Errorf("Project.Ref = %q, want the resolved ref", pb.Project.Ref)
	}
}

// No commit set leaves the fields empty (omitempty drops them), never a
// placeholder.
func TestPBOMProjectOmitsAbsentCommit(t *testing.T) {
	pb := NewGenerator("acme/target", 42, "https://gitlab.com", "main").Generate(nil, nil)
	if pb.Project.CommitSHA != "" || pb.Project.Ref != "" {
		t.Errorf("commit/ref should be empty when unset, got %q/%q", pb.Project.CommitSHA, pb.Project.Ref)
	}
}

// The GitHub PBOM path carries the same commit/ref provenance on its project
// block (#443), symmetric with the GitLab generator.
func TestGitHubPBOMProjectCarriesCommit(t *testing.T) {
	sha := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
	pb := NewGitHubGenerator("acme/target", "https://github.com", "main").
		WithCommit(sha, "release/2.0").
		GenerateFromGitHubIR(nil)
	if pb.Project.CommitSHA != sha {
		t.Errorf("Project.CommitSHA = %q, want the resolved commit on the GitHub path", pb.Project.CommitSHA)
	}
	if pb.Project.Ref != "release/2.0" {
		t.Errorf("Project.Ref = %q, want the resolved ref on the GitHub path", pb.Project.Ref)
	}

	// Unset leaves them empty on the GitHub path too.
	bare := NewGitHubGenerator("acme/target", "https://github.com", "main").GenerateFromGitHubIR(nil)
	if bare.Project.CommitSHA != "" || bare.Project.Ref != "" {
		t.Errorf("commit/ref should be empty when unset on GitHub, got %q/%q", bare.Project.CommitSHA, bare.Project.Ref)
	}
}
