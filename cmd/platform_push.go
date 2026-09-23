package cmd

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sirupsen/logrus"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	defaultconfig "github.com/getplumber/plumber/defaultConfig"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/pbom"
	providerPkg "github.com/getplumber/plumber/provider"
	"github.com/getplumber/plumber/utils"
)

// platformSentinelURL is the GitLab CI component's default for its `platform`
// input. GitLab requires the `id_tokens:` block's `aud` to be non-empty, so
// the input (which doubles as both the audience and PLUMBER_ANALYZE_PLATFORM)
// cannot default to "". ".invalid" is reserved by RFC 2606 and can never
// resolve to a real host, so it is a safe value to mint a token against and
// wire through as the env var on every run without turning the push on for
// everyone. effectivePlatformPush treats this exact value as "not configured".
const platformSentinelURL = "https://platform.invalid"

// effectivePlatformPush resolves whether to push to the platform and the base
// URL to push to. Unlike the badge, there is no separate opt-in: supplying the
// URL is the opt-in, because a platform URL has no other meaning. Resolved only
// from operator-controlled sources (the flag / PLUMBER_ANALYZE_PLATFORM), never
// from the analyzed repository's config file. platformSentinelURL is the one
// value that does NOT opt in — see its doc comment.
func effectivePlatformPush() (push bool, endpoint string) {
	endpoint = strings.TrimRight(strings.TrimSpace(platformURL), "/")
	if endpoint == platformSentinelURL {
		return false, ""
	}
	return endpoint != "", endpoint
}

// The types below mirror the platform's ingestion.Push contract
// (platform/backend/ingestion/contract.go in the monorepo) field-for-field:
// same shape, same json tags, same optionality, snake_case throughout. That
// file is the source of truth. A prior version of this file diverged from
// it — results[].policy was sent as a {name,source,ref} object where the
// contract declares a plain string — and every push was rejected by the real
// parser (json.Unmarshal into a string field fails on an object) as a
// result. See docs/platform-push-testing.md for how a push's raw wire bytes
// are captured and checked against that contract shape, not just decoded
// back into this package's own types.
type platformPush struct {
	SchemaVersion int                    `json:"schema_version"`
	Provider      string                 `json:"provider,omitempty"`
	Instance      string                 `json:"instance,omitempty"`
	Project       platformProject        `json:"project"`
	Ref           platformRef            `json:"ref"`
	Pipeline      platformPipeline       `json:"pipeline"`
	CLI           platformCLI            `json:"cli"`
	Collection    platformCollectionMeta `json:"collection"`
	// Evaluation is the nothing-evaluated marker, present ONLY on a linked
	// run that evaluated nothing at all (row 63). Absent means this push
	// evaluated something, exactly as every push before the field existed.
	Evaluation *platformEvaluation `json:"evaluation,omitempty"`
	// Results carries one entry per policy. Local policy resolution always
	// yields exactly one; a multi-policy platform grows this array without
	// changing the shape of anything else.
	Results []platformPolicyResult `json:"results"`
	// BOM is the pipeline's bill of materials: what this pipeline depends on
	// (includes, container images, per-job services and runner tags). Optional
	// on the wire, so an older platform ignores it and an older CLI simply
	// does not send it.
	//
	// The CLI is the only parser of CI configuration (invariant I1), which is
	// why the section exists at all: the platform builds its dependencies
	// graph from what is pushed here rather than reading the configuration
	// itself.
	//
	// An image reference the run never resolved is left out: a reference that
	// still held a $VARIABLE was parsed out of a placeholder, and a
	// placeholder is not a dependency anyone can act on. The platform keys
	// its resource nodes on the string and computes no verdict of its own
	// (I1/I2), so pushing one would mint a fleet-wide node named after a
	// variable with real consumers hanging off it. The same goes for a job
	// service whose reference is unresolved or empty. The PBOM artifact still
	// lists them: it is an inventory of what the pipeline declares.
	//
	// GitLab pushes only, and only from a run that collected completely. The
	// platform replaces a project's dependency edges with the pushed bill as
	// ONE set, so a bill built on a degraded collection would delete the
	// edges the run merely failed to read. Such a run sends no section at
	// all, and the platform leaves the project's dependencies as they were,
	// exactly as a push from an older CLI does. Past any of the section's
	// bounds the same rule applies, and the bound is named on stderr.
	BOM *platformBOM `json:"bom,omitempty"`
}

// The bill-of-materials section, shaped by the dependencies-graph design spec
// (2026-09-23-dependencies-graph-design section 5). snake_case throughout,
// like the rest of the contract; the three-state booleans stay pointers so a
// control nobody evaluated leaves its key out rather than publishing a
// verdict.
type platformBOM struct {
	// Version is the section's own schema version, independent of the push's
	// schema_version: the section is optional and forward-tolerant, so adding
	// it did not move the envelope's version.
	Version int `json:"version"`
	// The three inventories are ALWAYS emitted, empty as `[]`, never absent.
	// Everywhere else on this wire absence is a refusal to claim, but inside
	// the section it has to mean zero: the platform replaces a project's
	// dependency edges with the pushed bill as one set, so a missing
	// `includes` key would have to be read as "delete every include edge"
	// while a missing `bom` key two fields away means "claim nothing".
	// Emitting all three removes the ambiguity for a few bytes.
	Includes []platformBOMInclude `json:"includes"`
	Images   []platformBOMImage   `json:"images"`
	Jobs     []platformBOMJob     `json:"jobs"`
}

type platformBOMInclude struct {
	// Type and Location carry no omitempty, matching pbom.Include: spec 4.1
	// keys every include node on its type, and an include that somehow
	// arrives without one must arrive blank rather than vanish, so the
	// platform can refuse it instead of never seeing it.
	Type           string                     `json:"type"`
	Location       string                     `json:"location"`
	Project        string                     `json:"project,omitempty"`
	Version        string                     `json:"version,omitempty"`
	LatestVersion  string                     `json:"latest_version,omitempty"`
	UpToDate       *bool                      `json:"up_to_date,omitempty"`
	ComponentName  string                     `json:"component_name,omitempty"`
	FromCatalog    bool                       `json:"from_catalog,omitempty"`
	Nested         bool                       `json:"nested,omitempty"`
	Overridden     bool                       `json:"overridden,omitempty"`
	OverriddenJobs []platformBOMOverriddenJob `json:"overridden_jobs,omitempty"`
	Archived       *bool                      `json:"archived,omitempty"`
	HasCVE         *bool                      `json:"has_cve,omitempty"`
	Advisories     []string                   `json:"advisories,omitempty"`
}

type platformBOMOverriddenJob struct {
	Job  string   `json:"job"`
	Keys []string `json:"keys,omitempty"`
}

type platformBOMImage struct {
	Image        string   `json:"image"`
	Registry     string   `json:"registry,omitempty"`
	Name         string   `json:"name,omitempty"`
	Tag          string   `json:"tag,omitempty"`
	Digest       string   `json:"digest,omitempty"`
	Jobs         []string `json:"jobs,omitempty"`
	Authorized   *bool    `json:"authorized,omitempty"`
	ForbiddenTag *bool    `json:"forbidden_tag,omitempty"`
}

type platformBOMJob struct {
	Name       string                `json:"name"`
	Services   []platformBOMImageRef `json:"services,omitempty"`
	RunnerTags []string              `json:"runner_tags,omitempty"`
}

type platformBOMImageRef struct {
	Image    string `json:"image"`
	Registry string `json:"registry,omitempty"`
	Name     string `json:"name,omitempty"`
	Tag      string `json:"tag,omitempty"`
	Digest   string `json:"digest,omitempty"`
}

// platformProject is the informational project identity carried in the
// body — NOT the authoritative one. The platform derives the authoritative
// identity from the verified CI OIDC claims server-side (ADR-0003); this is
// a convenience for display/search only.
type platformProject struct {
	Path string `json:"path,omitempty"`
	ID   string `json:"id,omitempty"`
}

// platformRef is the analyzed git ref, read straight from the CI environment
// (see platformRefFor). Tag is not populated by this build — the CLI has no
// tag-pipeline source wired to this call site yet.
type platformRef struct {
	Branch string `json:"branch,omitempty"`
	Tag    string `json:"tag,omitempty"`
	SHA    string `json:"sha,omitempty"`
}

// platformPipeline identifies the CI run that produced this push, read
// straight from the CI environment (see platformPipelineFor). StartedAt is
// not populated by this build (no CLI-side source for it yet).
type platformPipeline struct {
	ID        string `json:"id,omitempty"`
	JobID     string `json:"job_id,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
}

// platformCLI carries the CLI version that produced the push. ComponentVersion
// is not populated by this build — the GitLab component version is not
// currently threaded through to the binary at this call site.
type platformCLI struct {
	Version          string `json:"version,omitempty"`
	ComponentVersion string `json:"component_version,omitempty"`
}

// platformCollectionMeta is the honest degradation signal: whether data
// collection was degraded this run. SnapshotCollectedAt is not populated —
// the CLI has no snapshot concept yet. MissingFields is deliberately left
// omitted too: result.DegradedReasons is human prose ("branch protection
// could not be fetched (network or timeout)"), not the field-name list this
// key expects, and forcing prose through it would misrepresent the contract
// rather than honor it.
type platformCollectionMeta struct {
	Degraded            bool     `json:"degraded,omitempty"`
	SnapshotCollectedAt string   `json:"snapshot_collected_at,omitempty"`
	MissingFields       []string `json:"missing_fields,omitempty"`
}

// platformEvaluation is the nothing-evaluated marker (platform decision row
// 63). A linked run that resolved NO policy, or whose every resolved policy
// tree failed to apply, has nothing to report: it used to either not push at
// all (the run was lost and the platform kept showing the previous one as
// current) or push an empty results array the platform refused outright.
// Both were dishonest about the same fact - an analysis ran, and it evaluated
// nothing - so the run is pushed with this marker instead and the platform
// records it as not evaluable: no score, no verdict, and a gate that answers
// evaluated:false with the reason echoed.
//
// It only ever rides an EMPTY results array. The platform rejects a marked
// push that carries results (422), and rightly: the marker must only make
// the record say LESS.
type platformEvaluation struct {
	NothingEvaluated bool   `json:"nothing_evaluated"`
	Reason           string `json:"reason,omitempty"`
}

// The two reasons the contract's closed set defines.
const (
	platformReasonNoPolicy              = "no_policy"
	platformReasonPoliciesNotApplicable = "policies_not_applicable"
)

// platformPolicyResult is one policy's verdict: what it ran (EffectiveConfig),
// its explicit per-control findings, and the resulting score. Policy is a
// plain string — the platform's contract has no name/source/ref object here
// (a prior version of this file sent one; see the package doc above).
type platformPolicyResult struct {
	Policy string `json:"policy"`
	// PolicyID is the platform's uuid for Policy, taken from the resolved
	// policy set (buildPolicyResults). A string, not a uuid type, and
	// deliberately left "" rather than a placeholder when there is none:
	// with omitempty that means the key is genuinely absent from the wire,
	// never present with a zero value.
	//
	// A uuid-typed field would make this impossible to express. Go's
	// omitempty never omits a fixed-size array, so a zero uuid.UUID
	// marshals as the literal all-zero uuid string — which the platform's
	// contract explicitly forbids sending, because it is the id its derived
	// fallback policy carries and names no real policies row.
	PolicyID        string            `json:"policy_id,omitempty"`
	EffectiveConfig json.RawMessage   `json:"effective_config,omitempty"`
	Findings        []platformFinding `json:"findings"`
	// Score is a pointer so a run that evaluated nothing real (row 45: an
	// empty control set, or every declared control config_required) can
	// omit it from the wire entirely. platformScoreFrom itself still takes
	// and tolerates a nil *control.PlumberScoreResult by returning the
	// zero value (existing callers that always have a real score keep
	// working unchanged); it is the caller's job to leave this field nil
	// rather than call it when there is genuinely no score to send. The
	// platform's contract accepts an absent policy score.
	Score *platformScore `json:"score,omitempty"`
}

// platformFinding is one EXPLICIT per-control result entry — see
// platformFindingsFor for how the list is built. A failed control
// contributes one of these per underlying finding (Data populated); a
// passed or not-evaluable control contributes exactly one with no Data.
// Version/Requirement are not populated by this build (no CLI-side source
// for either yet).
type platformFinding struct {
	Control     string          `json:"control"`
	Version     string          `json:"version,omitempty"`
	Requirement string          `json:"requirement,omitempty"`
	Status      string          `json:"status"`
	Data        json.RawMessage `json:"data,omitempty"`

	// Dismissed carries the finding's own control.Finding.Dismissed bit
	// (#447): a finding the platform already served back as dismissed via
	// /context, matched by control.MarkDismissed before the push is built.
	// Omitted (never sent as false) on every finding that is not: the
	// platform reads its presence as the claim, not its value.
	Dismissed bool `json:"dismissed,omitempty"`

	// Name and Category are the control's display metadata (#440), the
	// docs-catalog wording next to the stable technical id in Control.
	// Additive: the platform ignores unknown fields, and consumers that
	// keyed on Control keep working unchanged.
	Name     string `json:"name,omitempty"`
	Category string `json:"category,omitempty"`
}

// decoratedPlatformFinding builds a push finding entry with the control's
// display metadata attached (#440), so every construction site stays in
// step with the exported catalog.
func decoratedPlatformFinding(controlName, status string, data json.RawMessage) platformFinding {
	f := platformFinding{Control: controlName, Status: status, Data: data}
	if meta, ok := configuration.ControlMetaFor(controlName); ok {
		f.Name = meta.DisplayName
		f.Category = meta.Category
	}
	return f
}

// Finding-status vocabulary the platform's contract defines.
// platformStatusNotEvaluable is never omitted for a degraded/could-not-
// evaluate control — see platformFindingsFor.
const (
	platformStatusPass         = "pass"
	platformStatusFail         = "fail"
	platformStatusNotEvaluable = "not_evaluable"
)

// platformScore is the entry's Plumber Score. Points is RawPointsUnclamped
// (signed, no floor); FinalPoints is the malus-capped final figure the
// banner shows (platform contract 2026-09-10, additive). See
// platformScoreFrom.
type platformScore struct {
	Letter      string `json:"letter,omitempty"`
	Points      int    `json:"points"`
	FinalPoints *int   `json:"final_points,omitempty"`
}

// UnmarshalJSON decodes a score the PLATFORM sent (the push response's
// global_score). Outgoing, this type is what the CLI writes and the fields
// are exact; incoming, the numbers are the platform's own and its contract
// types points as a NUMBER, so 60.5 is a legal value and letter may be null.
// Decoded into the int and string this struct declares, either one produced
// an UnmarshalTypeError, and the caller threw the whole response away with
// it, gate included: a blocking verdict became a fail-open over a field the
// gate never reads (the review finding).
//
// So the tolerance is exactly this: any JSON number for the points (rounded
// with math.Round, the same rounding platformScoreFrom applies on the way
// out, so a figure that makes the round trip is unchanged), and a null or
// absent letter. It is NOT "accept anything": a points value that is not a
// number, or a letter that is not a string, fails the decode, and the caller
// drops the score entirely rather than publishing a zero the platform never
// sent. The gate beside it is decoded separately and strictly, so nothing
// here can ever soften a verdict.
func (s *platformScore) UnmarshalJSON(data []byte) error {
	var raw struct {
		Letter      any `json:"letter"`
		Points      any `json:"points"`
		FinalPoints any `json:"final_points"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	switch letter := raw.Letter.(type) {
	case nil:
	case string:
		s.Letter = letter
	default:
		return fmt.Errorf("letter: want a string, got %T", raw.Letter)
	}
	points, err := roundJSONScorePoints(raw.Points)
	if err != nil {
		return fmt.Errorf("points: %w", err)
	}
	s.Points = points
	if raw.FinalPoints != nil {
		final, err := roundJSONScorePoints(raw.FinalPoints)
		if err != nil {
			return fmt.Errorf("final_points: %w", err)
		}
		s.FinalPoints = &final
	}
	return nil
}

// roundJSONScorePoints reads a points figure out of a decoded JSON value in
// whichever numeric shape it arrived in and rounds it to the nearest integer.
// An absent or null figure is zero, which is what the field's zero value
// already meant; anything else is not a points figure at all and is an error,
// because reporting it as zero would publish a score the platform never sent.
func roundJSONScorePoints(v any) (int, error) {
	switch n := v.(type) {
	case nil:
		return 0, nil
	case float64:
		return int(math.Round(n)), nil
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, err
		}
		return int(math.Round(f)), nil
	}
	return 0, fmt.Errorf("want a number, got %T", v)
}

// platformScoreFrom converts the already-computed Plumber Score to the wire
// shape. Points is RawPointsUnclamped — the SIGNED deficit with no floor at
// zero (the contract stores it unclamped; the gate/badge's floored-at-zero
// RawPoints is display-only) — rounded to the nearest int, matching what the
// contract's Score.Points type actually is. FinalPoints carries the
// malus-capped final figure (floored at 0, capped at 30 while any Critical
// exists) so the platform can cross-check its own recompute against the
// CLI's exact formula. Tolerates a nil score (a best-effort push should
// never panic a run over a nil pointer) by returning the zero value, with
// FinalPoints left nil; every caller that can genuinely have no score to
// send (row 45: nothing was evaluated) checks for nil itself and leaves the
// wire field absent instead of calling this with one.
func platformScoreFrom(score *control.PlumberScoreResult) platformScore {
	if score == nil {
		return platformScore{}
	}
	final := int(math.Round(score.FinalPoints))
	return platformScore{Letter: score.Score, Points: int(math.Round(score.RawPointsUnclamped)), FinalPoints: &final}
}

// policyNameFor derives a stable, human-meaningful policy name from the config
// path: ".plumber.yaml" is the unnamed default, and any leading qualifier
// ("team.plumber.yml", ".plumber.strict.yaml") names the policy.
func policyNameFor(configPath string) string {
	base := filepath.Base(strings.TrimSpace(configPath))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "default"
	}
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
	base = strings.TrimPrefix(base, ".")
	switch {
	case base == "" || base == "plumber":
		return "default"
	case strings.HasPrefix(base, "plumber."):
		return strings.TrimPrefix(base, "plumber.")
	case strings.HasSuffix(base, ".plumber"):
		return strings.TrimSuffix(base, ".plumber")
	default:
		return base
	}
}

// platformPolicyNameFor is policyNameFor with one normalization on top:
// builtinDefaultConfigSource ("built-in default") is the label
// conf.ConfigFilePath carries for a zero-config run that read the config
// embedded in the binary, not a real file — passing it to policyNameFor
// unchanged would leak that internal sentinel string as the policy name
// ("built-in default") instead of the clean "default" every other
// zero-config path produces. Treated the same as an empty/unresolved path,
// mirroring the special case the pre-contract-rework policy descriptor used
// to apply (platformPolicyFor, since removed).
func platformPolicyNameFor(configPath string) string {
	if strings.TrimSpace(configPath) == builtinDefaultConfigSource {
		return policyNameFor("")
	}
	return policyNameFor(configPath)
}

// platformBOMSchemaVersion is the bill-of-materials section's own schema
// version. It moves only when the section's shape changes, independently of
// the push envelope's schema_version.
const platformBOMSchemaVersion = 1

// The bill of materials' bounds, from the design spec's sizing section
// (2026-09-23-dependencies-graph-design section 4.4). They are the platform's
// own limits, restated here so the CLI never builds a bill the platform will
// refuse with a 400 and lose the whole push over.
//
// One for one, these mirror the platform's rejection reasons: bom_includes,
// bom_images, bom_jobs, bom_image_jobs, bom_services_per_job,
// bom_runner_tags_per_job, bom_advisories, bom_string_runes, bom_url_runes,
// bom_string_bytes, bom_url_bytes, bom_edges and bom_bytes. A bound the CLI
// does not mirror is a push the platform answers with a 422, and that answer
// costs the run its results, its findings and its score, not just its bill.
const (
	bomMaxIncludes = 500
	bomMaxImages   = 500
	bomMaxJobs     = 500
	// bomMaxJobsPerImage is the platform's own ceiling on the jobs one image
	// may name (bom_image_jobs). The design spec's sizing section does not
	// list it: an image shared by a thousand jobs sits inside every bound
	// the spec does name, and the platform refuses that push whole, so the
	// run would lose its results over a bill nobody bounded.
	bomMaxJobsPerImage     = 500
	bomMaxServicesPerJob   = 64
	bomMaxRunnerTagsPerJob = 32
	bomMaxAdvisories       = 50
	bomMaxStringRunes      = 512
	// A remote include is addressed by a URL, which is legitimately longer
	// than any other string in the bill.
	bomMaxRemoteURLRunes = 1024
	// bomMaxStringBytes and bomMaxURLBytes are the platform's BYTE companions
	// to the two rune bounds above (bom_string_bytes, bom_url_bytes). The
	// rune bounds are counted in runes because a path written in a non-Latin
	// script is not hostile; the byte bounds exist beside them because the
	// platform's projected key is a COMPOSITE of two of these strings bound
	// into a unique btree index, which Postgres refuses above 2704 bytes on
	// an 8 kB page. Under the rune bounds alone, 512 CJK runes are 1536 bytes
	// and two of them compose a 3073-byte key: every stated bound respected,
	// and the push lost inside the platform's ingest transaction.
	bomMaxStringBytes = 1024
	bomMaxURLBytes    = 2048
	// bomMaxEdges is the platform's product bound (bom_edges): one edge per
	// include, one per (image, job) pair, one per service and one per runner
	// tag of a job. Every count bound above can be respected and the product
	// still be enormous (twenty images of five hundred jobs is ten thousand
	// edges), and the platform refuses the whole push rather than write more
	// rows than one ingest transaction is willing to spend.
	bomMaxEdges = 10000
	// The document the platform stores is capped at 256 KiB. Unlike the
	// bounds above this one cannot be checked by counting: it is a property
	// of the encoded bytes, so it is checked on the marshalled section.
	bomMaxDocumentBytes = 256 * 1024
)

// platformBOMFrom projects the generated bill of materials onto the push's
// wire shape. The second return value names the bound that refused it, empty
// when the bill is fine; nil with an empty bound means there was nothing to
// describe.
//
// Nothing is ever truncated. A bill cut down to fit would misreport the
// estate, and the platform replaces a project's dependency edges with the
// pushed set in one go, so a short bill silently deletes real dependencies.
// Past a bound the section is dropped whole and the caller says which bound
// did it; the push still goes with its results intact, and the platform
// reports no bill for that run rather than a wrong one.
//
// A pure function of the document: it collects nothing and reads no state.
func platformBOMFrom(doc *pbom.PBOM) (*platformBOM, string) {
	if doc == nil {
		return nil, ""
	}

	out := &platformBOM{
		Version:  platformBOMSchemaVersion,
		Includes: []platformBOMInclude{},
		Images:   []platformBOMImage{},
		Jobs:     []platformBOMJob{},
	}
	for _, inc := range doc.Includes {
		entry := platformBOMInclude{
			Type:          inc.Type,
			Location:      inc.Location,
			Project:       inc.Project,
			Version:       inc.Version,
			LatestVersion: inc.LatestVersion,
			UpToDate:      inc.UpToDate,
			ComponentName: inc.ComponentName,
			FromCatalog:   inc.FromCatalog,
			Nested:        inc.Nested,
			Overridden:    inc.Overridden,
			Archived:      inc.Archived,
			HasCVE:        inc.HasCVE,
			Advisories:    inc.Advisories,
		}
		for _, job := range inc.OverriddenJobs {
			entry.OverriddenJobs = append(entry.OverriddenJobs, platformBOMOverriddenJob{
				Job:  job.JobName,
				Keys: job.OverriddenKeys,
			})
		}
		out.Includes = append(out.Includes, entry)
	}
	for _, img := range doc.ContainerImages {
		ref, ok := bomNormalizeRef(img.Image, img.Unresolved)
		if !ok {
			continue
		}
		out.Images = append(out.Images, platformBOMImage{
			Image:        ref.Image,
			Registry:     ref.Registry,
			Name:         ref.Name,
			Tag:          ref.Tag,
			Digest:       ref.Digest,
			Jobs:         img.Jobs,
			Authorized:   img.Authorized,
			ForbiddenTag: img.ForbiddenTag,
		})
	}
	for _, job := range doc.Jobs {
		entry := platformBOMJob{Name: job.Name, RunnerTags: job.RunnerTags}
		for _, svc := range job.Services {
			ref, ok := bomNormalizeRef(svc.Image, svc.Unresolved)
			if !ok {
				continue
			}
			entry.Services = append(entry.Services, platformBOMImageRef(ref))
		}
		// Dropping the placeholders can empty the job out. A job that asks a
		// runner for nothing this run can name is not listed at all, the same
		// guard processJobResources applies and for the same reason: the
		// platform replaces a project's edges with the pushed bill as one set
		// and keys its nodes on what it receives, so a bare name with no
		// service and no runner tag under it mints a job node that depends on
		// nothing. A variable-templated service image with no tags: is a
		// common enough shape to reach this every day.
		if len(entry.Services) == 0 && len(entry.RunnerTags) == 0 {
			continue
		}
		out.Jobs = append(out.Jobs, entry)
	}

	// Every bound is measured HERE, on the finished section, never on the
	// document it was built from. The loops above drop unresolved references
	// and the jobs those empty out, so a document over a bound routinely
	// emits a section inside it: 501 jobs of which one is a placeholder-only
	// job is a 500-job section, which the platform accepts. Measuring the
	// document instead refused that bill, and refusing is not a harmless
	// extra caution, because the push still goes: the platform then keeps the
	// project's stale dependency edges instead of the bill this run collected.
	//
	// The same reason applies to the strings. The normalisation can make one
	// longer than the collector's (the Docker Hub namespace adds eight
	// runes), and the platform counts what it receives.
	//
	// The cost is that a refused bill is built before it is refused. That is
	// the right trade here: the input is this run's own collection of its own
	// pipeline, not an untrusted body, and the byte cap below has to marshal
	// the finished section anyway.
	if bound := platformBOMBound(out); bound != "" {
		return nil, bound
	}

	// The spec's ninth bound: the platform stores the document capped at
	// 256 KiB. A bill can sit inside every count and length bound above and
	// still be megabytes (500 jobs of 64 services each is inside all of
	// them), and the platform refuses an oversized push WHOLE, which costs
	// the run its results, its findings and its score. Checking it here
	// costs the run only the bill. The marshal is the one the caller is
	// about to do anyway.
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, "document not serialisable"
	}
	if len(raw) > bomMaxDocumentBytes {
		return nil, "document > 256 KiB"
	}
	return out, ""
}

// bomRef is one image reference as the bill of materials reports it. The
// field set and the json tags are platformBOMImageRef's, so the two convert
// directly.
type bomRef struct {
	Image    string `json:"image"`
	Registry string `json:"registry,omitempty"`
	Name     string `json:"name,omitempty"`
	Tag      string `json:"tag,omitempty"`
	Digest   string `json:"digest,omitempty"`
}

// bomDockerHubRegistry is the canonical Docker Hub host, the same value the
// image collector defaults an unqualified reference to.
const bomDockerHubRegistry = "docker.io"

// bomNormalizeRef is the ONE normalisation every reference on the wire goes
// through, images and job services alike. It returns false when the
// reference may not be reported at all.
//
// It exists because the two collector paths split a reference differently and
// neither split is what the graph needs. The image collector splits the
// remainder on a colon and never learns about digests; the
// merged-configuration services reader splits the WHOLE reference on its last
// colon and has no notion of a registry at all. So `node@sha256:abc` arrives
// as the name `node@sha256` with the tag `abc`, `app:1.2@sha256:def` as the
// name `app` with the tag `1.2@sha256`, and the service
// `registry.example.com:5000/postgres` as the name `registry.example.com`
// with the tag `5000/postgres`.
//
// The platform keys its resource nodes on `<registry>/<name>` and stores what
// is pushed verbatim (I1/I2 leave it no room to re-derive anything), so every
// one of those becomes a wrong node. Deriving all four parts here, from the
// reference itself, is what makes the same upstream one node however it is
// written: `postgres` as a job image and `postgres` as a service both key
// `docker.io/library/postgres`. The reference STRING is never rewritten, so
// what the CLI collected is still on the wire as it collected it.
//
// The rules, all three from the image collector's own parser: the part before
// the first slash is a registry host when it holds a dot or a colon (so a
// host keeps its port); a colon separates the tag only after the last slash;
// an unqualified reference is a Docker Hub one, and Docker Hub's official
// images live under `library/`.
func bomNormalizeRef(image string, unresolved bool) (bomRef, bool) {
	ref := strings.TrimSpace(image)
	// A reference that still holds a $VARIABLE describes a placeholder, not
	// an image. The collector's own flag is the authority; the second test
	// catches the services path, which resolves no variables and so marks
	// nothing.
	if ref == "" || unresolved || strings.Contains(ref, "$") {
		return bomRef{}, false
	}

	out := bomRef{Image: image}
	head := ref
	if at := strings.Index(head, "@"); at >= 0 {
		out.Digest = head[at+1:]
		head = head[:at]
	}

	remainder := head
	out.Registry = bomDockerHubRegistry
	if slash := strings.Index(head, "/"); slash > 0 {
		if host := head[:slash]; strings.Contains(host, ".") || strings.Contains(host, ":") {
			out.Registry = host
			remainder = head[slash+1:]
		}
	}
	out.Registry = utils.CanonicalizeDockerHubRegistry(out.Registry)

	out.Name = remainder
	if colon := strings.LastIndex(remainder, ":"); colon > strings.LastIndex(remainder, "/") {
		out.Tag = remainder[colon+1:]
		out.Name = remainder[:colon]
	}
	if out.Name == "" {
		return bomRef{}, false
	}
	if out.Registry == bomDockerHubRegistry && !strings.Contains(out.Name, "/") {
		out.Name = "library/" + out.Name
	}
	return out, true
}

// platformBOMBound returns the bound the SECTION exceeds, empty when it fits.
// The single place every count, length and product bound lives, and it is
// handed the emitted shape rather than the document behind it, so what is
// measured is exactly what the platform will receive and count. See the call
// site for why that ordering is the whole point.
//
// The byte cap is the one bound not here: it is a property of the encoded
// bytes rather than of the section's fields, so it is checked on the marshal.
func platformBOMBound(out *platformBOM) string {
	if len(out.Includes) > bomMaxIncludes {
		return fmt.Sprintf("includes > %d", bomMaxIncludes)
	}
	if len(out.Images) > bomMaxImages {
		return fmt.Sprintf("images > %d", bomMaxImages)
	}
	if len(out.Jobs) > bomMaxJobs {
		return fmt.Sprintf("jobs > %d", bomMaxJobs)
	}
	// The product bound, checked here because it is arithmetic over the
	// section's own lengths and therefore costs nothing: a bill that would
	// write more edges than the platform writes in one transaction is refused
	// before a single one of its strings is walked.
	if n := bomProjectedEdges(out); n > bomMaxEdges {
		return fmt.Sprintf("edges > %d", bomMaxEdges)
	}
	for _, inc := range out.Includes {
		if len(inc.Advisories) > bomMaxAdvisories {
			return fmt.Sprintf("advisories per include > %d", bomMaxAdvisories)
		}
		if inc.Type == "remote" {
			if utf8.RuneCountInString(inc.Location) > bomMaxRemoteURLRunes {
				return fmt.Sprintf("remote include URL > %d runes", bomMaxRemoteURLRunes)
			}
			if len(inc.Location) > bomMaxURLBytes {
				return fmt.Sprintf("url > %d bytes", bomMaxURLBytes)
			}
		} else if bound := bomStringBound(inc.Location); bound != "" {
			return bound
		}
		strs := []string{inc.Type, inc.Project, inc.Version, inc.LatestVersion, inc.ComponentName}
		strs = append(strs, inc.Advisories...)
		for _, job := range inc.OverriddenJobs {
			strs = append(strs, job.Job)
			strs = append(strs, job.Keys...)
		}
		if bound := bomStringBound(strs...); bound != "" {
			return bound
		}
	}
	for _, img := range out.Images {
		if len(img.Jobs) > bomMaxJobsPerImage {
			return fmt.Sprintf("jobs per image > %d", bomMaxJobsPerImage)
		}
		strs := append([]string{img.Image, img.Registry, img.Name, img.Tag, img.Digest}, img.Jobs...)
		if bound := bomStringBound(strs...); bound != "" {
			return bound
		}
	}
	for _, job := range out.Jobs {
		if len(job.Services) > bomMaxServicesPerJob {
			return fmt.Sprintf("services per job > %d", bomMaxServicesPerJob)
		}
		if len(job.RunnerTags) > bomMaxRunnerTagsPerJob {
			return fmt.Sprintf("runner tags per job > %d", bomMaxRunnerTagsPerJob)
		}
		strs := append([]string{job.Name}, job.RunnerTags...)
		for _, svc := range job.Services {
			strs = append(strs, svc.Image, svc.Registry, svc.Name, svc.Tag, svc.Digest)
		}
		if bound := bomStringBound(strs...); bound != "" {
			return bound
		}
	}
	return ""
}

// bomStringBound names the string bound when any of the values exceeds it.
// Both halves the platform applies, in the order it applies them: the rune
// count first, so a string over both reports the bound the spec names rather
// than the one the platform's index imposes, then the byte length.
func bomStringBound(values ...string) string {
	for _, v := range values {
		if utf8.RuneCountInString(v) > bomMaxStringRunes {
			return fmt.Sprintf("string > %d runes", bomMaxStringRunes)
		}
		if len(v) > bomMaxStringBytes {
			return fmt.Sprintf("string > %d bytes", bomMaxStringBytes)
		}
	}
	return ""
}

// bomProjectedEdges counts the edges the platform's projection would write for
// this section, by arithmetic over its array lengths and nothing else. The
// platform's own count (ingestion.projectedEdges) one for one: one edge per
// include, one per (image, job) pair, one per service and one per runner tag
// of a job. It is an upper bound on both sides, because the projection drops
// the edges it cannot key, and both sides erring the same way is the point.
func bomProjectedEdges(out *platformBOM) int {
	n := len(out.Includes)
	for _, img := range out.Images {
		n += len(img.Jobs)
	}
	for _, job := range out.Jobs {
		n += len(job.Services) + len(job.RunnerTags)
	}
	return n
}

// platformBOMDocument builds the bill of materials the push carries, from the
// collections this run already made. Nothing is collected twice: the images,
// the includes and the pipeline model are the ones the analysis produced, and
// the generator is the same one the --pbom artifact is written from, so the
// two documents can never disagree about what the pipeline uses.
//
// Nil in three cases, each of which would otherwise have the platform replace
// a project's dependency edges with a wrong set:
//   - the GitHub path, whose resources the platform does not model (and whose
//     collections this GitLab generator cannot read anyway),
//   - a run that collected neither includes nor images, which knows nothing
//     about the pipeline's dependencies rather than knowing it has none,
//   - a run whose collection degraded, whose bill would be partial: the
//     platform replaces the project's edges with the pushed set in one go, so
//     a partial bill deletes the dependencies the run merely failed to read.
func platformBOMDocument(p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult, runs []policyRun) *pbom.PBOM {
	if p == nil || p.Name() != "gitlab" || result == nil {
		return nil
	}
	if result.DataCollectionDegraded {
		return nil
	}
	if result.PipelineOriginData == nil && result.PipelineImageData == nil {
		return nil
	}

	// In platform mode the findings the image flags are read from are the
	// policy runs' union, never the local configuration's, exactly as the
	// PBOM artifacts read them.
	source := result
	if len(runs) > 0 {
		source = platformUnionResult(result, runs)
	}
	summary := platformPBOMSummary(runs, nil)
	if summary != nil {
		summary.ForbiddenTagEvaluated, summary.AuthorizedSourceEvaluated = platformImageControlsEvaluated(p, runs)
	}

	var gitlabURL, branch string
	noControls := false
	if conf != nil {
		gitlabURL, branch, noControls = conf.GitlabURL, conf.Branch, conf.NoControls
	}
	gen := pbom.NewGenerator(result.ProjectPath, result.ProjectID, gitlabURL, branch).
		WithComplianceData(pbom.ImageComplianceFor(source, noControls, summary)).
		WithIncludeOverrideData(pbom.BuildIncludeOverrideData(source)).
		WithJobResources(platformPipelineJobs(result))
	if noControls {
		gen = gen.WithoutComplianceVerdicts()
	}
	return gen.Generate(result.PipelineImageData, result.PipelineOriginData)
}

// platformPipelineJobs returns the analyzed pipeline's jobs, which the bill of
// materials reads for each job's service images and runner tags. Nil when the
// run produced no normalized pipeline (a missing or invalid CI configuration).
func platformPipelineJobs(result *control.AnalysisResult) []ir.Job {
	if result.Pipeline == nil {
		return nil
	}
	return result.Pipeline.Jobs
}

// buildPlatformPush builds the body POSTed to the platform, matching
// ingestion.Push field-for-field (see the type doc comments above).
//
// configPath is the resolved config path the caller computed
// (conf.ConfigFilePath, falling back to the --config flag); it names the
// single policy of a STANDALONE push.
//
// runs are the evaluated platform policy runs (evaluatePlatformPolicies).
// When there are any, the results array carries one entry per policy they
// cover and nothing else - see buildPolicyResults, which owns that decision.
// With none, either the platform answered and assigned nothing (the run is
// pushed with the nothing-evaluated marker, row 63) or there is no platform
// answer at all, and the push keeps the single locally-named entry the CLI
// has always sent.
func buildPlatformPush(p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult, score *control.PlumberScoreResult, configPath string, runs []policyRun) ([]byte, error) {
	forgeHost, projectPath, _ := resolveScoreTarget(p, conf)

	// The branches are exclusive on purpose: a push built from the policy
	// runs never touches the local configuration, a linked run that evaluated
	// nothing sends no policy result at all rather than the local
	// configuration's verdict (row 63), and a standalone push never builds a
	// per-policy entry.
	//
	// The middle branch is keyed on RunContext.Engaged, the state that says
	// the /context fetch SUCCEEDED, not merely that a platform URL was set.
	// A platform the run could not reach assigned nothing because it said
	// nothing: that run is not a nothing-evaluated one, it is the existing
	// degradation to local collection, and it keeps pushing its local entry
	// exactly as it does today.
	linked, _ := effectivePlatformPush()
	rc := platformRunOf(conf)
	answered := linked && rc.Engaged()
	var results []platformPolicyResult
	switch {
	case len(runs) > 0:
		results = buildPolicyResults(runs, p, conf)
	case answered:
		results = []platformPolicyResult{}
	default:
		results = []platformPolicyResult{standalonePolicyResult(p, conf, result, score, configPath)}
	}
	// Marker exactly when there is nothing to report, which is what makes an
	// empty results array a legitimate run instead of a malformed envelope.
	// Derived from the results themselves so the two can never contradict
	// each other on the wire.
	var evaluation *platformEvaluation
	if answered && len(results) == 0 {
		evaluation = &platformEvaluation{
			NothingEvaluated: true,
			Reason:           nothingEvaluatedReason(rc),
		}
	}

	// The bill of materials is built from what this run already collected,
	// never from a second pass. A bound that refuses it is named out loud:
	// the push still goes, and the operator can see why the platform reports
	// no dependencies for this run.
	bom, bound := platformBOMFrom(platformBOMDocument(p, conf, result, runs))
	if bound != "" {
		logrus.WithField("bound", bound).Warn("platform push: bill of materials omitted")
	}

	push := platformPush{
		SchemaVersion: 1,
		Provider:      p.Name(),
		Instance:      forgeHost,
		Project:       platformProject{Path: projectPath, ID: platformProjectID(p, conf)},
		Ref:           platformRefFor(p),
		Pipeline:      platformPipelineFor(p),
		CLI:           platformCLI{Version: strings.TrimPrefix(Version, "v")},
		Collection:    platformCollectionFor(conf, result),
		Evaluation:    evaluation,
		Results:       results,
		BOM:           bom,
	}

	body, err := json.Marshal(push)
	if err != nil {
		return nil, fmt.Errorf("marshal platform push: %w", err)
	}
	return body, nil
}

// platformCollectionFor builds the honest-degradation block: whether this
// run's collection degraded, which snapshot read it consumed, and which
// snapshot lanes carried no data.
//
// snapshot_collected_at and missing_fields are populated only in platform
// mode, where a snapshot exists to describe. A standalone run has no
// snapshot, so both stay absent rather than being filled with a fabricated
// "nothing was missing".
func platformCollectionFor(conf *configuration.Configuration, result *control.AnalysisResult) platformCollectionMeta {
	meta := platformCollectionMeta{Degraded: result != nil && result.DataCollectionDegraded}
	if conf == nil || !conf.PlatformRun.Active() {
		return meta
	}
	meta.SnapshotCollectedAt = conf.PlatformRun.SnapshotCollectedAt()
	meta.MissingFields = conf.PlatformRun.MissingSnapshotFields()
	return meta
}

// platformProjectID returns the project's stable numeric GitLab id when it is
// cheaply available — conf.ProjectID, or the CI_PROJECT_ID env var GitLab CI
// always exports — without an extra API round trip. GitHub has no equivalent
// cheap numeric id at this call site, so this only ever returns non-empty for
// a GitLab-shaped provider.
func platformProjectID(p providerPkg.Provider, conf *configuration.Configuration) string {
	if p.Name() == "github" {
		return ""
	}
	if conf != nil && conf.ProjectID != 0 {
		return strconv.Itoa(conf.ProjectID)
	}
	return strings.TrimSpace(os.Getenv("CI_PROJECT_ID"))
}

// platformRefFor reads the analyzed ref straight from the CI environment: the
// running branch (ciRunBranch, already provider-aware) and the head commit
// SHA via the provider's own CIEnvMapping (CI_COMMIT_SHA / GITHUB_SHA — the
// same mapping resolveScoreTarget and the source-link builder use). Both are
// "" outside CI; the omitempty tags on platformRef drop them rather than
// sending a fabricated value.
func platformRefFor(p providerPkg.Provider) platformRef {
	return platformRef{
		Branch: ciRunBranch(p),
		SHA:    strings.TrimSpace(os.Getenv(p.CIEnvVars().CommitSHA)),
	}
}

// platformPipelineFor reads the CI run's own identifiers straight from the
// environment — GitLab's CI_PIPELINE_ID/CI_JOB_ID, GitHub's
// GITHUB_RUN_ID/GITHUB_JOB. Never fabricated for a local run: both env vars
// are simply unset there, and the omitempty tags drop them.
func platformPipelineFor(p providerPkg.Provider) platformPipeline {
	if p.Name() == "github" {
		return platformPipeline{
			ID:    strings.TrimSpace(os.Getenv("GITHUB_RUN_ID")),
			JobID: strings.TrimSpace(os.Getenv("GITHUB_JOB")),
		}
	}
	return platformPipeline{
		ID:    strings.TrimSpace(os.Getenv("CI_PIPELINE_ID")),
		JobID: strings.TrimSpace(os.Getenv("CI_JOB_ID")),
	}
}

// platformEffectiveConfigRaw renders the FLAT per-provider controls map the
// push contract specifies for effective_config (the J12-F5 ruling,
// 2026-08-31): top-level keys are control names, values their configs, in
// the config file's own camelCase spelling. That is exactly what the
// platform's issueident.ParamsFor unmarshals - it imports this module's
// configuration.ControlsConfig, and Go's case-insensitive JSON field match
// makes the camelCase keys land on the right fields. The previous nested
// report shape decoded there to a zero value, storing empty params on every
// issue.
//
// The map is parsed from the same raw text the report's plumberConfig block
// uses (pc.Raw, falling back to the embedded default), so the two surfaces
// cannot disagree about which policy ran; full provenance beyond the
// controls map stays available in the raw push artifact (ADR-0017). An
// absent or empty provider section returns nil and omitempty drops the
// field rather than sending "{}".
func platformEffectiveConfigRaw(pc *configuration.PlumberConfig, provider string) json.RawMessage {
	rawCfg := ""
	if pc != nil && pc.Raw != "" {
		rawCfg = pc.Raw
	}
	if rawCfg == "" {
		rawCfg = string(defaultconfig.Get())
	}
	policy := parsePolicyObject(rawCfg)
	section, _ := policy[provider].(map[string]any)
	controls, _ := section["controls"].(map[string]any)
	if len(controls) == 0 {
		return nil
	}
	raw, err := json.Marshal(controls)
	if err != nil {
		return nil
	}
	// The platform's value guard walks effective_config too, so the same
	// sanitization applies: a config that ever carries a variable value
	// beside its name must declare that value's provenance or not send it.
	sanitized, _ := sanitizeProvenance(raw)
	return sanitized
}

// platformFindingsFor builds the explicit-results findings list: one entry
// per applicable control this run evaluated, reusing control.StatusFor — the
// SAME four-state verdict (passed/failed/skipped/error) the --output JSON,
// CSV and OCSF renderers already compute per control — rather than deriving
// a second, possibly-diverging notion of "did this control pass" here.
//
//   - failed:  one entry PER underlying finding, status=fail, Data carrying
//     that finding serialized exactly as opaengine.Finding.MarshalJSON
//     already produces it.
//   - passed:  one entry, status=pass, no Data.
//   - error:   one entry, status=not_evaluable, no Data — NEVER omitted,
//     because an empty findings list for a control that could not really be
//     evaluated must not read as a silent pass.
//   - skipped: OMITTED entirely. A control disabled in .plumber.yaml (or
//     excluded via --controls/--skip-controls) is still visible in
//     effective_config; "not evaluated by choice" is a different fact from
//     "could not be evaluated" (not_evaluable), and folding them together
//     would hide operator intent from the platform.
//
// includeOnly/skip are conf.ControlsFilter/SkipControlsFilter, applied via
// control.MarkSkippedByFilter exactly as the terminal/JSON renderers do, so a
// --skip-controls run's platform push agrees with what it printed.
func platformFindingsFor(p providerPkg.Provider, result *control.AnalysisResult, pc *configuration.PlumberConfig, includeOnly, skip []string) []platformFinding {
	out := []platformFinding{}
	if pc == nil {
		return out
	}
	entries := p.Controls(pc)
	control.MarkSkippedByFilter(entries, includeOnly, skip)

	var findings []opaengine.Finding
	if result != nil {
		findings = result.Findings
	}
	findingsByControl := control.FindingsByControl(findings)

	for _, e := range entries {
		fs := findingsByControl[e.ControlName]
		switch control.StatusFor(e, result, len(fs)) {
		case control.StatusSkipped:
			continue
		case control.StatusFailed:
			for _, f := range fs {
				pf := decoratedPlatformFinding(platformFindingControlName(f), platformStatusFail, platformFindingDataRaw(f))
				pf.Dismissed = f.Dismissed
				out = append(out, pf)
			}
		case control.StatusError:
			out = append(out, decoratedPlatformFinding(e.ControlName, platformStatusNotEvaluable, notEvaluableReasonData(result, e.ControlName)))
		default: // control.StatusPassed
			out = append(out, decoratedPlatformFinding(e.ControlName, platformStatusPass, nil))
		}
	}
	return out
}

// notEvaluableReasonData carries WHY a control could not be evaluated, as a
// machine-readable reason on the finding, so the platform can distinguish
// "the CI configuration could not be resolved" from "this control's data
// lane is not switched over yet" without parsing prose.
//
// Absent when the run recorded no specific reason — the older, run-wide
// degradation signals (a missing or invalid CI config, a failed collection)
// name no single control, and inventing a reason for them would be worse
// than saying nothing.
func notEvaluableReasonData(result *control.AnalysisResult, controlName string) json.RawMessage {
	if result == nil {
		return nil
	}
	reason, ok := result.NotEvaluable[controlName]
	if !ok || reason == "" {
		return nil
	}
	raw, err := json.Marshal(map[string]string{"reason": reason})
	if err != nil {
		return nil
	}
	return raw
}

// platformFindingControlName names a failed finding's control via
// control.ControlKeyFor, the same registry lookup FindingsByControl itself
// buckets by (control.LookupCode), falling back to the raw code string when
// the code has no registry entry, never to the enclosing control's name,
// which would misattribute an unclassified finding as belonging to it.
//
// This calls the EXACT SAME helper control.MarkDismissed uses to bucket a
// served dismissed entry by control (#447): a second, independently
// maintained copy of "look up the code, else use it raw" here could drift
// from that one, and a finding whose code the registry cannot classify is
// exactly the case where the two sides most need to agree: it is pushed
// under its raw code, and the platform can only ever serve a dismissal for
// it back under that same raw code.
func platformFindingControlName(f opaengine.Finding) string {
	return control.ControlKeyFor(f.Code)
}

// platformFindingDataRaw serializes f exactly as opaengine.Finding.MarshalJSON
// already produces it (code/severity/message/job/file/line/url/fingerprint +
// Data keys, existing casing) — the flat shape the platform's finding
// vocabulary is built to consume, not re-shaped or re-cased here. Marshal
// only fails for a JSON-incompatible value inside f.Data (a channel, a
// function), which Rego cannot produce; nil (omitted) is the safe fallback
// if it ever did.
//
// The serialized data then passes through sanitizeProvenance, which is what
// keeps a finding carrying a variable value from costing the operator their
// whole push: the platform rejects an ENTIRE push (422) over one value
// whose provenance is not declared, so a rule that emits a value without
// declaring where it came from has its value withheld and described here
// rather than taken to the wire.
func platformFindingDataRaw(f opaengine.Finding) json.RawMessage {
	raw, err := json.Marshal(f)
	if err != nil {
		return nil
	}
	sanitized, _ := sanitizeProvenance(raw)
	return sanitized
}

// PlatformTokenError reports that the run could not obtain the CI OIDC
// id-token the platform push requires. It is the ONLY platform-push condition
// that fails a run: the grant is missing from the pipeline's own configuration,
// the user can fix it, and a silently skipped push would hide that from them.
// Everything remote — unreachable, 4xx, 5xx, oversized — is a warning.
type PlatformTokenError struct{ Reason string }

func (e *PlatformTokenError) Error() string {
	return "platform push: " + e.Reason
}

// platformTokenFailure reports a token failure on stderr AND returns it.
//
// Printing here rather than relying on the returned error is what makes the
// message reliable. finalizeRun evaluates this error last, deliberately, so a
// broken id-token grant can never mask a security finding the scan just made.
// The consequence is that on a run which also fails its gate the error is
// discarded, and without this line the user would be told nothing at all: no
// push, no warning, no clue why. That is the failure mode the whole feature
// exists to prevent, so the diagnosis is emitted at the point of failure and
// the error still propagates to decide the exit code when nothing outranks it.
func platformTokenFailure(reason string) error {
	fmt.Fprintf(os.Stderr, "⚠️  platform push: %s\n", reason)
	return &PlatformTokenError{Reason: reason}
}

// maybePushPlatform pushes the analysis result to the configured platform. It
// returns a *platformVerdict for every reached push (fail-open branches carry
// Unavailable and a nil error; a blocking gate carries the decoded verdict
// together with a *PlatformGateError) and (nil, error) ONLY for a token
// failure; see PlatformTokenError. conf supplies the resolved config
// path/PlumberConfig/ProjectID/control filters buildPlatformPush needs
// (falling back to the --config flag when conf is nil or has no resolved
// path, e.g. in tests that call this directly); result and score are
// threaded straight through so the platform, the terminal banner and the
// JSON report can never disagree about a run's findings or score. runs are
// the evaluated platform policy runs the push reports one entry per policy
// for; none means a run with no resolved policy set, which pushes the single
// locally-named entry. Project identity for the platform record is a separate
// matter and still comes from the verified OIDC claims server-side, never
// from operator-supplied config.
func maybePushPlatform(p providerPkg.Provider, conf *configuration.Configuration, result *control.AnalysisResult, score *control.PlumberScoreResult, runs []policyRun) (*platformVerdict, error) {
	push, endpoint := effectivePlatformPush()
	if !push {
		return nil, nil
	}

	// Every failure to obtain the token fails the run, INCLUDING a transport
	// error such as a timeout, DNS failure or refused connection while talking
	// to the CI's own token service. That is deliberate and is not an oversight
	// to be "fixed" into a warning later: minting happens inside the pipeline,
	// against the CI provider's own infrastructure, so a failure there is an
	// ordinary pipeline failure like any other step being unable to reach its
	// dependencies. The never-block rule protects the pipeline from ONE thing
	// only: the platform receiving the data being down. That is a third party
	// the pipeline should not be coupled to; the CI's token endpoint is not.
	token, err := scoreOIDCToken(p, endpoint)
	if err != nil {
		return nil, platformTokenFailure(fmt.Sprintf("could not mint the CI OIDC id-token for %s: %v", endpoint, err))
	}
	if token == "" {
		switch {
		case p.Name() == "github":
			return nil, platformTokenFailure("the workflow must grant `permissions: id-token: write` to push to the platform")
		default:
			return nil, platformTokenFailure("no CI OIDC id-token available for the platform push; the pipeline must declare the component's `id_tokens:` block (" + gitlabPlatformTokenEnv + ")")
		}
	}

	configPath := strings.TrimSpace(configFile)
	if conf != nil {
		if resolved := strings.TrimSpace(conf.ConfigFilePath); resolved != "" {
			configPath = resolved
		}
	}
	body, err := buildPlatformPush(p, conf, result, score, configPath, runs)
	if err != nil {
		scoreWarn(fmt.Sprintf("platform push skipped: %v", err))
		return nil, nil
	}

	// Every remote condition lands here, including 413 for an oversized body:
	// the server is the authority on its own limit, so the CLI enforces none.
	// The push is skipped whole rather than truncated, because the platform
	// renders the record as the complete picture. On failure this is also
	// the gate deadline: the same 15s transport timeout (scorePushHTTPTimeout)
	// bounds both the push and the gate verdict it carries, so no separate
	// gate timeout knob exists.
	respBody, statusCode, err := postScoreReportForBody(endpoint+"/api/v1/pushes", token, body)
	if err != nil {
		line := platformGateFailOpenLine(statusCode)
		scoreWarn(fmt.Sprintf("%s: %v", line, err))
		return &platformVerdict{Unavailable: line}, nil
	}
	fmt.Fprintf(os.Stderr, "✓ Results pushed to the platform: %s\n", endpoint)
	return evaluatePlatformGate(respBody)
}
