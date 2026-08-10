// Package identity holds Plumber's finding-identity recipe: the one selection
// of fields that says which findings are the same finding instance across runs.
//
// Two consumers need that answer and must never answer it differently. The CLI
// hashes the selection into the short `fingerprint` every export format carries
// (JSON, CSV, SARIF, GitLab SAST, OCSF). A platform grouping findings into
// long-lived issues needs the same selection, but as data it can store and
// query rather than an opaque hash. So the selection lives here, once, and both
// read it: Of returns the identity field set, Fingerprint hashes exactly what
// Of returned. They cannot drift.
//
// What the recipe selects, and why:
//
//   - code, file, job: the canonical coordinates of a finding.
//   - one subject key: what the rule actually flagged (an action ref, a
//     component path, a variable). Taken from the rule's structured payload in
//     the priority order of SubjectKeys, first match only. Preferring this over
//     the prose message is what makes identity survive a message rewording.
//   - step, when the workflow resolved one: the last discriminator between two
//     steps of one job that reference the same action.
//
// What it deliberately leaves out: line and url (they move whenever unrelated
// code above the finding is edited), advisories (grows as CVEs are published),
// latestVersion (moves on any upstream release), metadata (refetched every
// run), and reasons/status (they track current settings, not identity). Any of
// those in the identity would make an unchanged finding look new.
//
// See docs/FINGERPRINT.md for the full contract, and RecipeVersion for what a
// change to the selection costs.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// RecipeVersion is the version of the identity recipe. It tracks identity
// OUTCOMES, not just the code in this package, so bump it whenever findings
// come out keyed differently than they did before:
//
//   - the algorithm here changes: a new subject key, a reordering of
//     SubjectKeys, a field entering or leaving the identity; or
//   - a control starts or stops emitting a subject key, which moves its
//     findings between prose identity and structured identity just as much.
//
// The second case is the easy one to miss: nothing in this package changes, so
// its tests stay green. The per-control pins in policies/rules_test.go are what
// fire there.
//
// Treat a bump as a breaking change, made deliberately. A re-keyed finding is
// read downstream as the old issue disappearing and a new one appearing in its
// place, and a consumer holding only the hash (SARIF, OCSF, CSV) has no other
// signal that it happened. Stored next to a grouped finding, this constant is
// that signal.
//
// History:
//
//	1  The recipe as first shipped: canonical coordinates, the SubjectKeys
//	   priority list, the resolved step.
//	2  Eleven finding blocks changed what they identify on:
//	     - ISSUE-401 gained hardcodedJob. It kept job too: that field holds
//	       a real job name here, so it was correctly left in the identity.
//	     - ISSUE-402 GitLab / ISSUE-403 / ISSUE-404 gained includePath,
//	       ISSUE-405 / ISSUE-406 gained templatePath, ISSUE-408 / ISSUE-409
//	       gained componentPath, and ISSUE-417 gained requiredAction. Each
//	       of these also lost job: the field used to smuggle that same
//	       subject through a mislabelled job value, which the new key
//	       replaces.
//	     - ISSUE-501 / ISSUE-505 kept their existing branchName and lost
//	       job, for the same reason: job held the branch name, not a job.
//	   Ten of the eleven blocks lost job; only ISSUE-401 kept it. The
//	   algorithm is unchanged; their fingerprints are not.
const RecipeVersion = 2

// fingerprintLength is how many hex characters of the digest the short
// fingerprint keeps. 16 hex chars (64 bits) is short enough to read in a CSV
// cell and wide enough that collisions are not a practical concern at the
// number of findings one repository produces.
const fingerprintLength = 16

// messageKey is the subject key reported when a rule emits none of the
// structured keys and identity falls back to its prose message. It is not a
// member of SubjectKeys: a rule cannot select it, only fall back to it.
const messageKey = "message"

// subjectKeys lists the structured payload keys that say what a finding is
// ABOUT, in priority order. The first one a finding carries wins and every
// other is ignored, even when present.
//
// The order is deliberate: the most specific value wins. If `tag` outranked
// `link`, every image tagged `latest` in a project would share the subject
// `tag=latest`, whereas the full reference keeps `grafana/vale:latest` and
// `nginx:latest` apart.
var subjectKeys = []string{
	"uses", "branchName", "includePath", "templatePath", "componentPath",
	"requiredAction", "image", "serviceImage", "link", "tag", "variableName",
	"hardcodedJob", "scriptLine", "detail",
}

// SubjectKeys returns the subject-key priority list. The caller gets a copy, so
// sorting or trimming the result cannot re-key the findings this process
// computes afterwards.
func SubjectKeys() []string { return slices.Clone(subjectKeys) }

// Finding is the view of a finding the recipe reads. The CLI fills it from its
// own finding type; anything reading Plumber's serialized output builds it with
// FromMap. There is no Line or URL field on purpose: they are not inputs, and a
// type that carried them would suggest otherwise.
type Finding struct {
	Code    string
	File    string
	Job     string
	Message string
	// Data is the rule's structured payload: the subject keys above, the
	// resolved `step`, and anything else the rule emitted.
	Data map[string]any
}

// FromMap builds a Finding from a serialized finding: the flat JSON object
// Plumber writes, where the canonical fields and the structured payload sit
// side by side at the top level. Everything that is not a canonical field stays
// in Data, so a subject key added by a later rule is readable without a change
// here, and so is the volatile payload, which the recipe simply never selects.
//
// FromMap expects a whole serialized finding, not an exported issue entry from
// a *Result block in Plumber's JSON report: an issue entry has no file and no
// message, so running FromMap over one silently produces a different identity
// for any finding that has a file or that falls back to the prose subject.
func FromMap(m map[string]any) Finding {
	f := Finding{Data: map[string]any{}}
	for k, v := range m {
		switch k {
		case "code":
			f.Code, _ = v.(string)
		case "file":
			f.File, _ = v.(string)
		case "job":
			f.Job, _ = v.(string)
		case "message":
			f.Message, _ = v.(string)
		default:
			f.Data[k] = v
		}
	}
	return f
}

// Field is one key/value pair of a finding's identity.
type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Fields is the identity field set of one finding: everything the recipe
// selected, as data. Pairs renders it in the order it contributes to identity.
type Fields struct {
	Code string `json:"code"`
	File string `json:"file"`
	Job  string `json:"job"`
	// Subject is the one key/value pair that says what the finding is about.
	// Its Key is the winning member of SubjectKeys, or "message" when the rule
	// emitted none of them.
	Subject Field `json:"subject"`
	// SubjectFromMessage reports that Subject holds the prose fallback rather
	// than a structured key. Such a finding's identity is tied to the wording of
	// its rule, so rewording that rule re-keys it.
	SubjectFromMessage bool `json:"subjectFromMessage"`
	// Step is the resolved step name, empty when the finding has none.
	Step string `json:"step,omitempty"`
	// Version is the RecipeVersion that produced this field set, so a consumer
	// storing it can tell later which selection it was built from.
	Version int `json:"version"`
}

// Pairs returns the selected key/value pairs in the order they contribute to
// identity. The step pair is present only when the finding resolved one, so a
// finding without a step is not confused with one whose step is empty.
func (f Fields) Pairs() []Field {
	pairs := []Field{
		{Key: "code", Value: f.Code},
		{Key: "file", Value: f.File},
		{Key: "job", Value: f.Job},
		f.Subject,
	}
	if f.Step != "" {
		pairs = append(pairs, Field{Key: "step", Value: f.Step})
	}
	return pairs
}

// Of returns the identity field set of a finding. ok is false for a codeless
// finding: there is nothing stable to report it against, so it has no identity
// and gets no fingerprint.
//
// A coded finding always has an identity, even a narrow one. With no subject
// key and no message the subject is an empty "message" pair and the finding is
// identified by code, file and job alone, so every such finding of that control
// in one job shares a fingerprint. That is deterministic, not an error.
func Of(f Finding) (Fields, bool) {
	if f.Code == "" {
		return Fields{}, false
	}
	fields := Fields{
		Code:    f.Code,
		File:    f.File,
		Job:     f.Job,
		Step:    stringValue(f.Data, "step"),
		Version: RecipeVersion,
	}
	for _, k := range subjectKeys {
		if v := stringValue(f.Data, k); v != "" {
			fields.Subject = Field{Key: k, Value: v}
			return fields, true
		}
	}
	fields.Subject = Field{Key: messageKey, Value: f.Message}
	fields.SubjectFromMessage = true
	return fields, true
}

// Fingerprint returns the short, line-independent identifier of a finding: the
// hash of the very field set Of selects. Empty for a codeless finding.
func Fingerprint(f Finding) string {
	fields, ok := Of(f)
	if !ok {
		return ""
	}
	sum := sha256.Sum256([]byte(fields.canonical()))
	return hex.EncodeToString(sum[:])[:fingerprintLength]
}

// canonical renders the field set as the newline-joined string that is hashed.
// The structured subject contributes "key=value" so two different keys holding
// the same value cannot collide; the message fallback contributes the message
// alone, which is what the published fingerprints were computed from.
func (f Fields) canonical() string {
	subject := f.Subject.Value
	if !f.SubjectFromMessage {
		subject = f.Subject.Key + "=" + f.Subject.Value
	}
	segments := []string{f.Code, f.File, f.Job, subject}
	if f.Step != "" {
		segments = append(segments, f.Step)
	}
	return strings.Join(segments, "\n")
}

// stringValue reads a non-empty string from a payload bag, tolerating both a
// missing key and a value the rule emitted as something other than a string.
//
// A non-string is skipped, not coerced, and a subject key that is skipped drops
// the finding to prose identity. That is reachable from real payload: a JSON
// round trip turns a numeric `tag: 7` into a float64. Both sides of the recipe
// read it the same way, so the CLI and a consumer still agree, and
// Fields.SubjectFromMessage makes the degradation visible rather than silent.
// Coercing instead would be a better answer, but it would re-key every finding
// it applies to, so it is a RecipeVersion decision rather than a free fix.
func stringValue(data map[string]any, key string) string {
	v, _ := data[key].(string)
	return v
}
