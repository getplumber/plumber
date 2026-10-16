package control

// ClaimState is how settled a claim about an attack path is: proven when
// the facts behind it are all settled, assumed when it rests on a default
// taken for lack of a declared signal, unknown when a fact it needs could
// not be decided at all. Only a claim that folds to ClaimProven moves the
// tier; the other two are the gap between what Plumber can show and what
// it is only willing to say.
type ClaimState string

const (
	ClaimProven  ClaimState = "proven"
	ClaimAssumed ClaimState = "assumed"
	ClaimUnknown ClaimState = "unknown"
)

// Claim is one proven-or-not statement an attack path rests on: what kind
// of claim it is, the subject it is about, how settled it is, and, when it
// is not proven outright, the source of the assumption or the gap (a
// default token, an unresolved fact, and the like).
type Claim struct {
	Kind    string     `json:"kind"`
	Subject string     `json:"subject"`
	State   ClaimState `json:"state"`
	Source  string     `json:"source"`
}

// claimRank orders ClaimState from best to worst: a proven claim first,
// an assumed one next, an unknown one last. WorstState folds a list of
// states to the single worst one by this order.
var claimRank = map[ClaimState]int{
	ClaimProven:  0,
	ClaimAssumed: 1,
	ClaimUnknown: 2,
}

// WorstState folds states to the worst one among them: unknown outranks
// assumed, which outranks proven. No states at all folds to ClaimProven,
// the identity of the fold: a path with nothing to claim has nothing
// unsettled either.
func WorstState(states ...ClaimState) ClaimState {
	worst := ClaimProven
	for _, s := range states {
		if claimRank[s] > claimRank[worst] {
			worst = s
		}
	}
	return worst
}

// Claim folds a FactState to the ClaimState it stands for: proven stays
// proven, unknown stays unknown. A FactState the facts layer never emits
// as settled or unknown (absent) has no claim to fold to and returns
// ClaimUnknown, the safe side of the fold.
func (s FactState) Claim() ClaimState {
	switch s {
	case "proven":
		return ClaimProven
	case FactUnknown:
		return ClaimUnknown
	default:
		return ClaimUnknown
	}
}
