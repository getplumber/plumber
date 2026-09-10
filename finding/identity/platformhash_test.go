package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// TestPlatformHash_MatchesThePlatformDigest pins #447: PlatformHash is sha256 hex over
// json.Marshal(fields.Pairs()), the platform's own issueident.Hash by construction, so a
// dismissed issue served by identity_hash matches the CLI's finding without a second recipe.
func TestPlatformHash_MatchesThePlatformDigest(t *testing.T) {
	f := Finding{Code: "ISSUE-103", File: ".gitlab-ci.yml", Job: "build", Message: "m", Data: map[string]any{"image": "nginx:latest"}}
	fields, ok := Of(f)
	if !ok {
		t.Fatal("fixture must have a code")
	}
	pairs, _ := json.Marshal(fields.Pairs())
	sum := sha256.Sum256(pairs)
	want := hex.EncodeToString(sum[:])
	got, version, ok := PlatformHash(f)
	if !ok || got != want || version != RecipeVersion {
		t.Fatalf("PlatformHash = (%q, %d, %v), want (%q, %d, true)", got, version, ok, want, RecipeVersion)
	}
	if _, _, ok := PlatformHash(Finding{}); ok {
		t.Error("a codeless finding has no identity and no platform hash")
	}

	// wire-stable: the platform stores this digest; changing Pairs() or the marshal is a recipe
	// bump.
	const golden = "b8d0fa47166be499d224422c5481db6aa9dca50849f8747e151d6bbda410c6dc"
	if got != golden {
		t.Fatalf("PlatformHash golden mismatch: got %q, want %q (Pairs() or the marshal changed)", got, golden)
	}
}
