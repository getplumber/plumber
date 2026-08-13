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
// Every registered code has a declaration (declarations.go): an ordered list
// of field names that identify one finding instance of that code. Of reads
// the finding's code, looks up its declaration, and renders exactly those
// fields, in declared order, as the identity. Reserved names file and job
// read the canonical finding fields; message, also reserved, reads the prose
// and flags the finding SubjectFromMessage; every other declared name reads
// the rule's structured Data payload (an action ref, a component path, a
// variable, a resolved step). There is no dynamic priority search: what a
// code declares is what it hashes on, so two rules can declare the same
// field name without one shadowing the other the way a global list would.
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
//	3  (2026-08-10): Finding.File is normalized to a repository-relative path
//	   before hashing. It was the collector's absolute path, so the same finding
//	   carried a different identity depending on whether it was scanned locally or
//	   on a runner. Re-keys every finding whose file was recorded absolutely.
//	4  (2026-08-12, #411): identity comes from per-code declarations
//	   (declarations.go) instead of the global subject priority list. The
//	   canonical form is uniformly `key=value` per declared field, so every
//	   fingerprint value changes at this bump even where the selected fields
//	   did not. No declared code keys on its prose: the 29 GitHub controls
//	   that measured onto message now key on a structured subject (uses /
//	   variableName / condition / ecosystem) or on canonical coordinates alone
//	   ({file, job}, {file}, or the {} singleton). message survives only as
//	   the backstop for an undeclared code. See docs/FINGERPRINT.md.
const RecipeVersion = 4

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

// SubjectKeys returns the v3 subject-key priority list.
//
// Deprecated: recipe v4 selects identity from per-code declarations
// (Declared) and never consults this list. Kept one release for external
// consumers still reading v3-stamped records; remove after that.
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

// Fields is the identity field set of one finding: the code plus the pairs
// its declaration selected, in declared order.
type Fields struct {
	Code string `json:"code"`
	// Selected holds the declared pairs, in declared (= hash) order.
	Selected []Field `json:"selected"`
	// SubjectFromMessage reports that the declaration includes the prose
	// message, so rewording the rule re-keys this finding.
	SubjectFromMessage bool `json:"subjectFromMessage"`
	// Version is the RecipeVersion that produced this field set.
	Version int `json:"version"`
}

// Pairs returns the full ordered identity: the code pair first, then the
// declared pairs. This is what the JSON identity block publishes.
func (f Fields) Pairs() []Field {
	return append([]Field{{Key: "code", Value: f.Code}}, f.Selected...)
}

// Of returns the identity field set of a finding. ok is false only for a
// codeless finding. A code missing from the declarations table (unreachable
// while the parity test is green) gets the deterministic backstop: identity
// is code + message, flagged SubjectFromMessage.
func Of(f Finding) (Fields, bool) {
	if f.Code == "" {
		return Fields{}, false
	}
	decl, ok := declarations[f.Code]
	if !ok {
		return Fields{
			Code:               f.Code,
			Selected:           []Field{{Key: messageKey, Value: f.Message}},
			SubjectFromMessage: true,
			Version:            RecipeVersion,
		}, true
	}
	out := Fields{Code: f.Code, Version: RecipeVersion, Selected: make([]Field, 0, len(decl))}
	for _, key := range decl {
		var v string
		switch key {
		case "file":
			v = f.File
		case "job":
			v = f.Job
		case messageKey:
			v = f.Message
			out.SubjectFromMessage = true
		default:
			v = stringValue(f.Data, key)
		}
		out.Selected = append(out.Selected, Field{Key: key, Value: v})
	}
	return out, true
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

// canonical renders the hashed form: the code, then every declared pair as
// key=value, newline-joined. Empty values render as `key=` so absence is
// deterministic and cannot shift later segments.
func (f Fields) canonical() string {
	segments := make([]string, 0, len(f.Selected)+1)
	segments = append(segments, f.Code)
	for _, p := range f.Selected {
		segments = append(segments, p.Key+"="+p.Value)
	}
	return strings.Join(segments, "\n")
}

// stringValue reads a non-empty string from a payload bag, tolerating both a
// missing key and a value the rule emitted as something other than a string.
//
// A non-string is skipped, not coerced: the declared field renders as an
// empty pair (key=), the same as when the rule never set the key at all. That
// is reachable from real payload: a JSON round trip turns a numeric `tag: 7`
// into a float64. Both sides of the recipe read it the same way, so the CLI
// and a consumer still agree. Coercing instead would be a better answer, but
// it would re-key every finding it applies to, so it is a RecipeVersion
// decision rather than a free fix.
func stringValue(data map[string]any, key string) string {
	v, _ := data[key].(string)
	return v
}
