package pbom

import "testing"

// CycloneDX carries the analyzed commit and ref as properties on the project
// component (#443).
func TestCycloneDXCarriesCommitProperties(t *testing.T) {
	sha := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
	pb := NewGenerator("acme/target", 42, "https://gitlab.com", "release/2.0").
		WithCommit(sha, "release/2.0").
		Generate(nil, nil)
	cdx := pb.ToCycloneDX("v0.0.0-test")

	props := map[string]string{}
	for _, p := range cdx.Metadata.Component.Properties {
		props[p.Name] = p.Value
	}
	if props["plumber:git:commit"] != sha {
		t.Errorf("plumber:git:commit = %q, want the resolved sha", props["plumber:git:commit"])
	}
	if props["plumber:git:ref"] != "release/2.0" {
		t.Errorf("plumber:git:ref = %q, want the resolved ref", props["plumber:git:ref"])
	}
}

// No commit means no git properties are fabricated.
func TestCycloneDXOmitsCommitPropertiesWhenAbsent(t *testing.T) {
	pb := NewGenerator("acme/target", 42, "https://gitlab.com", "main").Generate(nil, nil)
	cdx := pb.ToCycloneDX("v0.0.0-test")
	for _, p := range cdx.Metadata.Component.Properties {
		if p.Name == "plumber:git:commit" || p.Name == "plumber:git:ref" {
			t.Errorf("git property %q present with no commit", p.Name)
		}
	}
}
