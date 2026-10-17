package control

import (
	"strings"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// The ceilings of an entry a maintainer has to approve before it runs
// (ir.GateMaintainerApproved: a label, a human author, a merge, an
// environment that requires an approval): High, since an attacker has to
// get a maintainer to let the run go first; Medium when the job checks
// out the head commit that was approved, since what runs is then what
// the maintainer looked at, with no window to push other code after the
// approval. The path carries "maintainer_cap" or "pinned_head_cap" when
// the ceiling actually lowered it.
const (
	maintainerCeiling = TierHigh
	pinnedHeadCeiling = TierMedium
)

// gatedNote is the note on a finding whose job no outsider can make run
// (noOutsiderGate): it stays an individual finding, at Low. eventsNote
// replaces it when the privileged run never executes the job at all
// (ir.GateNoOutsider: its condition names other events).
const (
	gatedNote  = "gated to the repository's own branches"
	eventsNote = "gated to the repository's own events"
)

// gateNoteFor is the note markGatedFindings sets for a finding behind g.
func gateNoteFor(g ir.Gate) string {
	if g.Class == ir.GateNoOutsider {
		return eventsNote
	}
	return gatedNote
}

// entryJobGate is the gate that decides who reaches an entry of kind into
// js: the job's own (JobSituation.Gate) for a privileged checkout, and for
// an untrusted expression reached through a privileged trigger alone or
// in a job of a reusable workflow its calls gave a gate; an outsider's
// when no gate was decided for it (a privileged trigger the classifier
// does not read). An untrusted expression a fork pull request
// also reaches is an outsider's whatever the privileged trigger's gate
// says. ok is false for every other entry: who reaches a dependency, a
// push or a cache is not a trigger's gate.
func entryJobGate(kind EntryKind, js JobSituation) (g ir.Gate, ok bool) {
	switch kind {
	case EntryPRTarget:
	case EntryUntrustedExpression:
		if len(js.ForkPR) > 0 {
			return ir.Gate{Class: ir.GateOutsider}, true
		}
		// A job of a reusable workflow has no privileged trigger of its
		// own, its run is its caller's: the gate its calls give it
		// (ir.ClassifyGates) decides.
		if len(js.PrivilegedTriggers) == 0 && js.Gate == nil {
			return ir.Gate{}, false
		}
	default:
		return ir.Gate{}, false
	}
	if js.Gate == nil {
		return ir.Gate{Class: ir.GateOutsider}, true
	}
	return *js.Gate, true
}

// noOutsiderGate reports whether g lets no outsider in at all: the job
// only runs for code already in the repository (ir.GateSameRepo), never
// on the privileged run (ir.GateNoOutsider: its condition names other
// events), or
// only for pull requests a bot opens: a gate on the pull request's author
// ("author <login>", github.event.pull_request.user.login) naming a
// "[bot]" login, which nobody can take, and whose pull requests come from
// the repository's own branches (the Dependabot shape). A bot as the
// actor ("actor <login>": github.actor, github.triggering_actor) is no
// such proof: an outsider can make Dependabot the actor of a synchronize
// event on their own fork pull request, so it stays a maintainer's gate.
func noOutsiderGate(g ir.Gate) bool {
	switch g.Class {
	case ir.GateSameRepo, ir.GateNoOutsider:
		return true
	case ir.GateMaintainerApproved:
		login, ok := strings.CutPrefix(g.Reason, "author ")
		return ok && strings.HasSuffix(login, "[bot]")
	}
	return false
}

// gateEntry reads the entry job's gate onto an entry an outsider would
// reach through a trigger (entryJobGate): its actor, the gate's reason and
// whether the approved head commit is what runs (entryPinned). skip is
// set when no outsider gets in at all (noOutsiderGate): the entry anchors
// nothing. unknown is the references the gate could not resolve, on an
// unknown gate.
func gateEntry(kind EntryKind, fact *EntryFact, js JobSituation, f opaengine.Finding) (skip bool, unknown []string) {
	g, ok := entryJobGate(kind, js)
	if !ok {
		return false, nil
	}
	if noOutsiderGate(g) {
		return true, nil
	}
	fact.Actor, fact.Gate, fact.PinnedSha = string(g.Class), g.Reason, entryPinned(kind, *fact, g, f)
	if g.Class == ir.GateUnknown {
		unknown = g.Unknown
	}
	return false, unknown
}

// entryPinned reports whether what the entry runs is the head commit the
// maintainer approved. Only a checkout can be (an untrusted expression is
// injected whatever commit is checked out). Both must hold: the job is
// pinned (ir.Gate.PinnedSha: every head checkout in it is a commit SHA),
// and the anchoring finding's own ref, when it names the pull request or
// run head (its "ref" data, else its subject), is a SHA. Findings of
// several checkouts of one job share one identity and one path, so the
// finding's ref alone never proves the job runs only the approved commit.
func entryPinned(kind EntryKind, fact EntryFact, g ir.Gate, f opaengine.Finding) bool {
	if kind != EntryPRTarget {
		return false
	}
	if !g.PinnedSha {
		return false
	}
	ref, _ := f.Data["ref"].(string)
	if !ir.IsPRHeadRef(ref) {
		ref = fact.Subject
	}
	if ir.IsPRHeadRef(ref) {
		return ir.IsPRHeadShaRef(ref)
	}
	return true
}

// applyUnknownGate lowers a path whose entry gate could not be decided
// (ir.GateUnknown) one tier and marks it unverified: the outsider's entry
// stands, but its proof does not. A path already lowered as unverified
// is not lowered twice.
func applyUnknownGate(p *AttackPath, unknown []string) {
	if p.Entry.Actor != string(ir.GateUnknown) {
		return
	}
	p.unknownRefs = unknown
	if p.State == PathUnverified {
		return
	}
	p.Tier = tierShift(p.Tier, -1)
	p.State = PathUnverified
}

// gateCeiling lowers ceiling to what a maintainer-approved entry holds
// (maintainerCeiling, pinnedHeadCeiling) when that is lower, with the
// modifier saying so; any other entry keeps ceiling and modifiers.
func gateCeiling(entry EntryFact, ceiling PathTier, modifiers []string) (PathTier, []string) {
	if entry.Actor != string(ir.GateMaintainerApproved) {
		return ceiling, modifiers
	}
	c, m := maintainerCeiling, "maintainer_cap"
	if entry.PinnedSha {
		c, m = pinnedHeadCeiling, "pinned_head_cap"
	}
	if TierRank(c) < TierRank(ceiling) {
		return c, []string{m}
	}
	return ceiling, modifiers
}

// markGatedFindings downgrades every entry finding whose job no outsider
// can make run (noOutsiderGate on its entry job's gate): it anchors no
// path (anchorsFor), so it is priced as an individual finding, at Low
// (Data "occurrenceSeverity", which IndividualSeverity reads), with the
// note saying why (Data "gateNote"). A head checkout the policy found
// behind a same-repository guard of its own (Data "forkGuard") takes the
// same route when the classifier decided no gate for its job
// (JobSituation.Gate nil); a classified gate decides alone, so a
// maintainer's label gate keeps the finding at its own severity, without
// the note, anchoring its path. The identity of a finding
// never reads either key.
func markGatedFindings(findings []opaengine.Finding, sit *Situation) {
	if sit == nil {
		return
	}
	for i, f := range findings {
		kind, isEntry := EntryKindForCode(ErrorCode(f.Code))
		js, inSit := sit.Jobs[f.Job]
		if !isEntry || f.Job == "" || !inSit {
			continue
		}
		g, ok := entryJobGate(kind, js)
		// The policy's own fork guard decides only where the classifier
		// decided no gate for the job; a classified gate decides alone.
		forkGuarded := truthy(f.Data["forkGuard"]) && js.Gate == nil
		if !forkGuarded && (!ok || !noOutsiderGate(g)) {
			continue
		}
		if findings[i].Data == nil {
			findings[i].Data = map[string]any{}
		}
		findings[i].Data["occurrenceSeverity"] = string(SeverityLow)
		note := gatedNote
		if ok && noOutsiderGate(g) {
			note = gateNoteFor(g)
		}
		findings[i].Data["gateNote"] = note
	}
}

// gateWords is how the Entry line's nature (nature, after it) and the So
// line (actor) name a maintainer's gate, read off its reason
// (ir.ClassifyGate). labelled is what a maintainer labels on the job's
// trigger (labelledThing): "pull request", "issue" or "discussion".
func gateWords(reason, labelled string) (nature, actor string) {
	if label, ok := strings.CutPrefix(reason, "label "); ok {
		return ", gated by the label " + code(label), "as anyone whose " + labelled + " a maintainer labels " + code(label)
	}
	if login, ok := strings.CutPrefix(reason, "author "); ok {
		return ", author " + code(login) + " only", "as " + code(login) + ", and only " + code(login)
	}
	if login, ok := strings.CutPrefix(reason, "actor "); ok {
		// Whoever makes the login the actor gets in (an outsider can make
		// a bot the actor of an event on their own pull request), not
		// that login alone.
		return ", actor " + code(login) + " only", "as anyone who can make " + code(login) + " the actor"
	}
	if env, ok := strings.CutPrefix(reason, "environment "); ok {
		env = strings.TrimSuffix(env, " requires reviewers")
		return ", approved in environment " + code(env), "as anyone whose deployment a maintainer approves in " + code(env)
	}
	if types, ok := strings.CutPrefix(reason, "types "); ok {
		return ", on " + strings.Join(strings.Fields(types), " or ") + " only", "as anyone a maintainer lets in"
	}
	switch reason {
	case "label":
		return ", gated by a label", "as anyone whose " + labelled + " a maintainer labels"
	case "author", "actor":
		return ", gated by its " + reason, "as the " + reason + " its condition names"
	case "merged":
		return ", after merge only", "as anyone whose pull request a maintainer merges"
	}
	return ", gated by its condition", "as anyone a maintainer lets in"
}

// labelledThing is what a maintainer labels to let p's entry job run, read
// off its privileged triggers: a pull request on a pull request or
// workflow_run trigger, else a discussion on a discussion trigger, else an
// issue (an issue comment). A path without its situation reads a pull
// request.
func labelledThing(p AttackPath) string {
	if p.situation == nil || len(p.Jobs) == 0 {
		return "pull request"
	}
	triggers := p.situation.Jobs[p.Jobs[0]].PrivilegedTriggers
	has := func(prefix string) bool {
		for _, t := range triggers {
			if strings.HasPrefix(t, prefix) {
				return true
			}
		}
		return false
	}
	switch {
	case len(triggers) == 0 || has("pull_request") || has("workflow_run"):
		return "pull request"
	case has("discussion"):
		return "discussion"
	case has("issue"):
		return "issue"
	}
	return "pull request"
}

// maintainerApproved reports whether p's entry runs only once a maintainer
// let it.
func maintainerApproved(p AttackPath) bool {
	return p.Entry.Actor == string(ir.GateMaintainerApproved)
}

// gateNatureSuffix is what the Entry line's nature adds for a maintainer's
// gate, "" for any other entry.
func gateNatureSuffix(p AttackPath) string {
	if !maintainerApproved(p) {
		return ""
	}
	nature, _ := gateWords(p.Entry.Gate, labelledThing(p))
	return nature
}

// gatedActor is who gets in, for the So line, through a maintainer's
// gate; false for any other entry, which keeps its actor rule's words.
func gatedActor(p AttackPath) (string, bool) {
	if !maintainerApproved(p) {
		return "", false
	}
	_, actor := gateWords(p.Entry.Gate, labelledThing(p))
	return actor, true
}

// gatedFix is the fix of a path whose entry a maintainer's gate holds:
// the entry's fix, keeping the gate (removing it would let everyone in).
func gatedFix(p AttackPath, fix string) string {
	if !maintainerApproved(p) {
		return fix
	}
	return fix + ", and keep the gate"
}

// gateUnverifiedLine is the Entry line's unverified note of a path whose
// gate could not be decided, "" for any other.
func gateUnverifiedLine(p AttackPath) string {
	if p.Entry.Actor != string(ir.GateUnknown) {
		return ""
	}
	return "Plumber could not check who can make this job run"
}
