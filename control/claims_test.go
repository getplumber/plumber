package control

import "testing"

func TestWorstStateOrdersUnknownAboveAssumedAboveProven(t *testing.T) {
	cases := []struct {
		in   []ClaimState
		want ClaimState
	}{
		{[]ClaimState{ClaimProven, ClaimProven}, ClaimProven},
		{[]ClaimState{ClaimProven, ClaimAssumed}, ClaimAssumed},
		{[]ClaimState{ClaimAssumed, ClaimUnknown, ClaimProven}, ClaimUnknown},
		{nil, ClaimProven},
	}
	for _, c := range cases {
		if got := WorstState(c.in...); got != c.want {
			t.Errorf("WorstState(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFactStateFoldsIntoClaimState(t *testing.T) {
	if FactUnknown != "unknown" {
		t.Fatalf("the entry state for an unread fact is %q, want unknown", FactUnknown)
	}
	if got := FactState("proven").Claim(); got != ClaimProven {
		t.Errorf("proven -> %q", got)
	}
	if got := FactUnknown.Claim(); got != ClaimUnknown {
		t.Errorf("unknown -> %q", got)
	}
}
