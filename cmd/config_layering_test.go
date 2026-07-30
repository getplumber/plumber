package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

func TestLoadConfigOrOffer_ResolvesOverlayFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".plumber.yaml")
	overlay := `extends: plumber:default
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      minimumStars: 12345
`
	if err := os.WriteFile(path, []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	pc, _, _, err := loadConfigOrOffer(path, true)
	if err != nil {
		t.Fatalf("loadConfigOrOffer: %v", err)
	}
	c := pc.GitHub.Controls.GithubActionMustComeFromAuthorizedSources
	if c == nil || c.MinimumStars != 12345 {
		t.Fatalf("override lost: %+v", c)
	}
	if c.Enabled == nil || !*c.Enabled {
		t.Fatal("enabled should be inherited from base")
	}
	_ = configuration.ExtendsPlumberDefault // ensure import used
}
