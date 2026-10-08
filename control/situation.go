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
// read from the issue-code registry (EntryKindForCode); fork_pr and
// unprotected_push are also the kinds of the two structural trigger facts.
type EntryKind string

const (
	EntryForkPR              EntryKind = "fork_pr"
	EntryPRTarget            EntryKind = "pr_target"
	EntryUntrustedExpression EntryKind = "untrusted_expression"
	EntryMutableDependency   EntryKind = "mutable_dependency"
	EntryUnprotectedPush     EntryKind = "unprotected_push"
	// EntryPoisonedCache is a cache a run that is not trusted can write,
	// restored by the job (a release or publish job restoring a cache whose
	// key is not scoped to the released ref).
	EntryPoisonedCache EntryKind = "poisoned_cache"
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
	// Source is "token" when the impact is what the job token's write scope
	// lets any code in the job do, empty when a step of the job does it.
	Source string `json:"source,omitempty"`
	// Via names the job of a reusable workflow whose step does it, when the
	// job holding the impact is the one calling that workflow; empty for
	// the job's own steps and token.
	Via string `json:"via,omitempty"`
}

// CallerFact is one call of a job of a reusable workflow of the
// repository (JobSituation.Callers): the calling job and what the call
// gives the called job, its token (TokenWriteSource "default" when nothing
// up the chain declares permissions, the assumed repository default), the
// secrets it passes by their caller-side names, whether it passes every
// secret (secrets: inherit), the events it runs on.
type CallerFact struct {
	Job              string   `json:"job"`
	TokenWrite       []string `json:"tokenWrite"`
	TokenWriteSource string   `json:"tokenWriteSource"`
	Secrets          []string `json:"secrets"`
	AllSecrets       bool     `json:"allSecrets"`
	Triggers         []string `json:"triggers"`
}

// Privilege is what the job holds: the secrets it can read, the token
// write scopes it has, and whether it persists credentials to disk.
type Privilege struct {
	Secrets        []string  `json:"secrets"`
	SecretsState   FactState `json:"secretsState"`
	SecretsInherit bool      `json:"secretsInherit"`
	// AllSecrets is true when the job holds every secret of the repository,
	// proven by the way it reads them (secrets: inherit, or the whole
	// secrets context), whatever their names.
	AllSecrets           bool      `json:"allSecrets"`
	ProtectedSecrets     []string  `json:"protectedSecrets"`
	TokenWrite           []string  `json:"tokenWrite"`
	TokenWriteSource     string    `json:"tokenWriteSource"` // declared | default | none
	PersistedCredentials FactState `json:"persistedCredentials"`
	// Environment is the job's deployment environment, a protection the job
	// runs behind and never an impact by itself. Reviewers is whether it
	// requires an approval before the job runs: "unknown" while the provider's
	// environment settings are not collected.
	Environment struct {
		Name      string `json:"name"`
		Protected string `json:"protected"` // "true" | "false" | "unknown"
		Reviewers string `json:"reviewers"` // "unknown"
	} `json:"environment"`
}

// JobSituation is the full fact set of one job (or of every job sharing
// its name, merged).
type JobSituation struct {
	// ForkPR is the job's fork pull request trigger fact (at most one per
	// job, a union when same-named jobs merge): GitHub "on: pull_request"
	// without a same-repository guard, GitLab "rules: merge_request_event".
	// No control reports it; the platform reach rules read it.
	ForkPR []EntryFact `json:"forkPR"`
	// PrivilegedTriggers is the job's events that run in the base
	// repository's context with its secrets and write token
	// (pull_request_target, workflow_run, issue_comment and the like),
	// sorted. A fork run of a job carrying one keeps its privilege; the
	// platform reach rules read it.
	PrivilegedTriggers []string `json:"privilegedTriggers"`
	// RefTriggers is the job's events that run it on a branch or a tag of
	// the repository itself (push, schedule, release, workflow_dispatch),
	// sorted: such a run saves its cache in that ref's scope, never only in
	// a pull request's.
	RefTriggers []string `json:"refTriggers"`
	// Push is the job's push to the default branch fact, present while the
	// branch is not known to be protected; its state is unresolvable when
	// the trigger filter or the protection cannot be decided. A
	// branch-protection finding on that branch starts its path here.
	Push      []EntryFact  `json:"push"`
	Privilege Privilege    `json:"privilege"`
	Impact    []ImpactFact `json:"impact"`
	Feeds     []string     `json:"feeds"`
	// FeedsVia is, per job of Feeds, the kinds of edge that link the two,
	// sorted: FeedArtifact, FeedCache, FeedOutput.
	FeedsVia map[string][]string `json:"feedsVia"`
	// Caches is every cache the job restores, saves or both, with the step
	// declaring it, sorted: the step a poisoned cache finding is about names
	// its entry by the cache it restores (cacheEntrySubject).
	Caches []CacheFact `json:"caches"`
	// CacheScopes is the refs GitHub files what the job's runs save to the
	// cache under, sorted: "default" (the default branch: a push to it, a
	// schedule, a dispatch, workflow_run, pull_request_target and the other
	// events that run there), "tag", "pull_request", "merge_group",
	// "branch" (a push to other branches only), or "any" when the job
	// carries no trigger (GitLab). Only a "default" (or "any") save reaches
	// a run of another ref: a cache writer for a default-branch or tag
	// release is a job whose scopes hold one of them.
	CacheScopes []string `json:"cacheScopes"`
	// Callers is, on a job of a reusable workflow of the repository, every
	// call that runs it, sorted. The job's own Privilege already reads
	// through them (its token the union of theirs when it declares none,
	// its secrets those a call passes); a path entering the job names, per
	// caller, what that call gives.
	Callers []CallerFact `json:"callers"`
	// OwnImage is true when the job runs in a container and every image it
	// resolves to (through its matrix, or the image each caller of a
	// reusable workflow passes) is under the repository owner's namespace of
	// the GitHub container registry (ghcr.io/<owner>/...): an image of the
	// repository's organization, not an outside one.
	OwnImage bool `json:"ownImage"`
	// Dead is true when every job carrying the name has a constant false
	// if: (ir.Job.Dead): it never runs, so no path enters it, and it is no
	// feed edge either way.
	Dead bool `json:"dead"`
}

// CacheFact is one cache of a job (ir.CacheRef): its key, or its key
// prefix when Prefix is set (a restore-keys fallback, or a caching action
// keying on a fixed prefix followed by a run-time hash), whether the step
// restores, saves or both, and the step declaring it.
type CacheFact struct {
	// Key is what a save and a restore must share to reach each other (a
	// caching action's discriminators included: a dependency path, a
	// buildx scope, a rust-cache job id); Family is the name to print, the
	// key without them.
	Key    string `json:"key"`
	Family string `json:"family"`
	Mode   string `json:"mode"` // "restore", "save" or "both"
	Prefix bool   `json:"prefix"`
	Uses   string `json:"uses"`
	Line   int    `json:"line"`
}

// The kinds of edge by which a job feeds another (JobSituation.FeedsVia):
// an artifact it uploads and the other downloads, a cache it saves and the
// other restores, the job outputs the other reads through needs (on GitLab,
// a needs dependency alone, which also downloads the needed job's artifacts).
const (
	FeedArtifact = "artifact"
	FeedCache    = "cache"
	FeedOutput   = "output"
)

// IncludeFact is one pipeline include: the subject a job-less include
// finding names ("source@ref"), where the include is declared, and the
// jobs it shapes.
type IncludeFact struct {
	Subject string   `json:"subject"`
	File    string   `json:"file,omitempty"`
	Line    int      `json:"line,omitempty"`
	Jobs    []string `json:"jobs"`
}

// Situation is the whole facts layer for one pipeline: the repository's
// exposure plus every job's facts, keyed by job name.
type Situation struct {
	Exposure string                  `json:"exposure"` // ir.Visibility*
	Jobs     map[string]JobSituation `json:"jobs"`
	// DefaultBranch is the pipeline's default branch (input.pipeline.defaultBranch
	// on the Rego side), empty when the provider never gave it. A gate whose
	// own branch matches this one amplifies every path, not only paths
	// through jobs it shares (spec section 2, rule 7).
	DefaultBranch string `json:"defaultBranch"`
	// Provider is the pipeline's provider, "github" or "gitlab".
	Provider string `json:"provider"`
	// Includes is every pipeline include with a source.
	Includes []IncludeFact `json:"includes"`
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
