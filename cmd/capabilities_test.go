package cmd

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/getplumber/plumber/capability"
)

// Spec 4.2: `plumber capabilities defaults` prints the CLI's built-in list in the
// declaration schema, verbatim, so a user can copy it into .plumber.yaml (or the org
// setting) and edit it: the output decodes strictly and equals the list the CLI runs.
func TestCapabilitiesDefaults_PrintsTheBuiltinListVerbatim(t *testing.T) {
	var buf bytes.Buffer
	if err := writeCapabilityDefaults(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), capability.BuiltinYAML()) {
		t.Fatalf("output is not builtin.yaml verbatim:\n%s", buf.Bytes())
	}
	decls, err := capability.DecodeYAML(buf.Bytes())
	if err != nil {
		t.Fatalf("the printed list does not decode strictly: %v", err)
	}
	if !reflect.DeepEqual(decls, capability.Builtin()) {
		t.Fatalf("decoded = %+v, want Builtin() %+v", decls, capability.Builtin())
	}
}

// The command is wired under the root as `capabilities defaults`.
func TestCapabilitiesDefaults_IsWired(t *testing.T) {
	c, _, err := rootCmd.Find([]string{"capabilities", "defaults"})
	if err != nil || c != capabilitiesDefaultsCmd {
		t.Fatalf("capabilities defaults resolves to %v (%v), want capabilitiesDefaultsCmd", c, err)
	}
}
