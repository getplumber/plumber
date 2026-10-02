package control

import (
	"context"
	"encoding/json"
	"fmt"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies/situation"
)

// FactState is the confidence a situation fact was derived with: "proven"
// when the pipeline data settles it, "unresolvable" when it cannot be
// decided statically, "absent" when the fact does not hold.
type FactState string

// EntryKind names the way an attacker-controlled input can make a job run,
// or make it run on input it does not control the trust of. Mirrors
// policies/situation/situation.rego's entry() kinds.
type EntryKind string

const (
	EntryForkPR              EntryKind = "fork_pr"
	EntryPRTarget            EntryKind = "pr_target"
	EntryUntrustedExpression EntryKind = "untrusted_expression"
	EntryMutableDependency   EntryKind = "mutable_dependency"
	EntryUnprotectedPush     EntryKind = "unprotected_push"
)

// EntryFact is one way the job can be made to run (or run on input it does
// not control the trust of), with the evidence that proved it.
type EntryFact struct {
	Kind     EntryKind `json:"kind"`
	State    FactState `json:"state"`
	Evidence string    `json:"evidence"`
	Subject  string    `json:"subject"`
	File     string    `json:"file,omitempty"`
	Line     int       `json:"line,omitempty"`
}

// ImpactFact is something the job can change, and how sure the facts
// layer is that it does.
type ImpactFact struct {
	Kind     string    `json:"kind"` // publishes | deploys | writes_repo | signs_or_releases
	State    FactState `json:"state"`
	Evidence string    `json:"evidence"`
}

// Privilege is what the job holds: the secrets it can read, the token
// write scopes it has, and whether it persists credentials to disk.
type Privilege struct {
	Secrets              []string  `json:"secrets"`
	SecretsState         FactState `json:"secretsState"`
	SecretsInherit       bool      `json:"secretsInherit"`
	ProtectedSecrets     []string  `json:"protectedSecrets"`
	TokenWrite           []string  `json:"tokenWrite"`
	TokenWriteSource     string    `json:"tokenWriteSource"` // declared | default | none
	PersistedCredentials FactState `json:"persistedCredentials"`
	Environment          struct {
		Name      string `json:"name"`
		Protected string `json:"protected"` // "true" | "false" | "unknown"
	} `json:"environment"`
}

// JobSituation is the full fact set of one job (or of every job sharing
// its name, merged).
type JobSituation struct {
	Entries   []EntryFact  `json:"entries"`
	Privilege Privilege    `json:"privilege"`
	Impact    []ImpactFact `json:"impact"`
	Feeds     []string     `json:"feeds"`
}

// Situation is the whole facts layer for one pipeline: the repository's
// exposure plus every job's facts, keyed by job name.
type Situation struct {
	Exposure string                  `json:"exposure"` // ir.Visibility*
	Jobs     map[string]JobSituation `json:"jobs"`
}

// DecodeSituation parses data.situation.result. Missing jobs decode to an
// empty map so callers never nil-check.
func DecodeSituation(raw json.RawMessage) (*Situation, error) {
	var s Situation
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("decode situation: %w", err)
	}
	if s.Jobs == nil {
		s.Jobs = map[string]JobSituation{}
	}
	if s.Exposure == "" {
		s.Exposure = ir.VisibilityUnknown
	}
	return &s, nil
}

// situationSource is a seam so tests can inject a module.
var situationSource = func() (string, error) {
	src, err := situation.SituationFS.ReadFile(situation.SituationModule)
	return string(src), err
}

// EvaluateSituation runs the situation module on the pipeline. It returns an
// empty, unknown-exposure situation together with the error when the module
// cannot run: the score then degrades to "no path found" and the caller
// records the warning (I3: never a fake verdict, but never a crash either).
func EvaluateSituation(ctx context.Context, pipeline *ir.NormalizedPipeline, config map[string]any) (*Situation, error) {
	empty := &Situation{Exposure: ir.VisibilityUnknown, Jobs: map[string]JobSituation{}}
	src, err := situationSource()
	if err != nil {
		return empty, fmt.Errorf("situation module: %w", err)
	}
	raw, err := opaengine.New().EvaluateSituation(ctx, src, pipeline, config)
	if err != nil {
		return empty, err
	}
	s, err := DecodeSituation(raw)
	if err != nil {
		return empty, err
	}
	return s, nil
}
