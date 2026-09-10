package opa

import (
	"bytes"
	"encoding/json"
	"testing"
)

// The platform hashes a finding's serialized JSON object as part of its own identity
// computation, so MarshalJSON must never let the CLI-local Dismissed marker (#447) leak into
// that object: a finding marshaled with Dismissed true or false must produce byte-identical
// output, with no "dismissed" key either way.
func TestFindingMarshalJSON_NeverEmitsDismissed(t *testing.T) {
	base := Finding{
		Code: "ISSUE-103", File: ".gitlab-ci.yml", Job: "build", Message: "m",
		Data: map[string]any{"imageRepo": "nginx"},
	}
	notDismissed := base
	notDismissed.Dismissed = false
	dismissed := base
	dismissed.Dismissed = true

	gotNot, err := json.Marshal(notDismissed)
	if err != nil {
		t.Fatalf("marshal (Dismissed=false): %v", err)
	}
	gotDismissed, err := json.Marshal(dismissed)
	if err != nil {
		t.Fatalf("marshal (Dismissed=true): %v", err)
	}

	if !bytes.Equal(gotNot, gotDismissed) {
		t.Fatalf("Dismissed changed the marshaled bytes: false=%s true=%s", gotNot, gotDismissed)
	}

	var decoded map[string]any
	if err := json.Unmarshal(gotDismissed, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := decoded["dismissed"]; present {
		t.Fatalf("MarshalJSON must never emit a \"dismissed\" key, got %s", gotDismissed)
	}
}
