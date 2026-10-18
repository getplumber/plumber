package gitlab

import (
	"strings"
	"testing"
)

// A chain of variables that each reference another several times must not
// expand without bound: the result stays within a sane size instead of
// growing geometrically with the number of passes.
func TestReplaceVariableBounded(t *testing.T) {
	m := map[string]string{}
	fan := 40
	ref := ""
	for i := 0; i < fan; i++ {
		ref += "$V1 "
	}
	m["V0"] = ref
	for i := 1; i <= 6; i++ {
		s := ""
		for j := 0; j < fan; j++ {
			s += "$V" + itoa(i+1) + " "
		}
		m["V"+itoa(i)] = s
	}
	m["V7"] = "PADPADPADPAD"
	out := ReplaceVariable("$V0", m, nil, nil, nil, nil, nil)
	if len(out) > 1<<20 {
		t.Fatalf("expansion grew to %d bytes, want it bounded under 1 MiB", len(out))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	d := ""
	for i > 0 {
		d = string(rune('0'+i%10)) + d
		i /= 10
	}
	return d
}

// A single expansion pass must not blow up either: a near-cap string of
// references to a large-valued variable is bounded within the one pass, not
// multiplied into gigabytes before the loop re-checks.
func TestReplaceVariableBoundedSinglePass(t *testing.T) {
	bigVal := strings.Repeat("x", 1<<20) // ~1 MiB value
	// 20000 * len("$W ") = 60000 bytes, below the 64 KiB cap, so the pre-pass
	// check passes and one expansion pass actually runs: the per-pass budget
	// must then leave the references as placeholders instead of expanding
	// them to ~20 GiB.
	refs := strings.Repeat("$W ", 20000)
	if len(refs) >= maxExpandedVariableBytes {
		t.Fatalf("test setup: refs %d must be below the cap %d", len(refs), maxExpandedVariableBytes)
	}
	out := ReplaceVariable(refs, map[string]string{"W": bigVal}, nil, nil, nil, nil, nil)
	if len(out) > 2*maxExpandedVariableBytes {
		t.Fatalf("single pass expanded to %d bytes, want it bounded near the cap", len(out))
	}
}
