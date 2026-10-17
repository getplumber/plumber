package control

import (
	"slices"
	"sort"
	"strings"
)

// cacheWriter is what entering a job granted cache write takes: the
// strongest ceiling among the branches entering the job
// (AttackPath.ceiling) and the modifiers that ceiling sets when it holds
// a cache path, the scopes the entered run saves its cache under
// (cacheWriterScope), and the key templates of the caches the job
// declares saving (not merely restoring): data a sentence names the
// restored cache by when a declared save matches what a restorer reads,
// never a requirement for the edge to exist (cacheWriterReaches).
type cacheWriter struct {
	ceiling   PathTier
	modifiers []string
	scopes    []string
	templates []keyTemplate
}

// entryExecutesCode reports whether an entry of this kind runs code on
// the runner it enters: every entry kind this program knows today does
// (a fork pull request, a privileged base-context trigger, a mutable
// dependency, an untrusted expression, an unprotected push all run
// code), which is what lets the job's run save a cache at all once
// GitHub grants that run write. Kept explicit, rather than assumed for
// every EntryKind, so a future entry kind that only lets an attacker
// influence a value read inside an `if:` comparison, say, without ever
// running code itself, does not silently become a cache writer too.
func entryExecutesCode(kind EntryKind) bool {
	switch kind {
	case EntryForkPR, EntryPRTarget, EntryMutableDependency, EntryUntrustedExpression, EntryUnprotectedPush:
		return true
	default:
		return false
	}
}

// cacheWriters is the jobs whose entered run saves a cache: the entry
// jobs, of every branch of the paths given (none a poisoned_cache path),
// whose entry runs code (entryExecutesCode), whose own privilege survived
// the platform's reach rules, that run, and whose entered run GitHub lets
// save in the default branch's scope (cacheWriterScope), the one other
// refs' runs restore from. GitHub decides the last part by
// trigger: a trusted trigger saves, an event on its own ref saves there,
// and a low-trust event on the default branch (pull_request_target,
// issue_comment, workflow_run...) only reads unless the job's cache-mode
// grants write; the situation's CacheScopes already follow those rules.
// A poisoned_cache path exists only when its entry job, the job granted
// cache write, is one of these (AssemblePaths). Whether the writer's run
// reaches a given restoring job is decided per restoring job by
// cacheWriterReaches. Each writer keeps the strongest ceiling of the
// branches entering it, the first in the paths' order on a tie; it reads
// the assembled paths, so the order of the findings does not matter.
func cacheWriters(paths []AttackPath, sit *Situation) map[string]cacheWriter {
	out := map[string]cacheWriter{}
	ordered := append([]AttackPath(nil), paths...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for _, p := range ordered {
		if !entryExecutesCode(p.EntryKind) {
			continue
		}
		for _, b := range p.Branches {
			if !slices.Contains(b.survivingJobs, b.Job) {
				continue // a fork pull request run saves only its merge ref's cache
			}
			js := sit.Jobs[b.Job]
			if js.Dead {
				continue
			}
			scopes := cacheWriterScope(p.EntryKind, p.Entry.Subject, js)
			if !savesShared(scopes) {
				// The entered run saves nothing (GitHub's read-only
				// default), or only in a pull request's, a tag's or
				// another branch's scope, which runs of that same ref
				// alone restore.
				continue
			}
			ceiling := b.ceiling
			if ceiling == "" {
				ceiling = TierCritical
			}
			cur, ok := out[b.Job]
			if !ok || TierRank(ceiling) > TierRank(cur.ceiling) {
				cur.ceiling, cur.modifiers = ceiling, b.ceilingModifiers
			}
			cur.scopes = unionScopes(cur.scopes, scopes)
			if !ok {
				for _, c := range savingCaches(js) {
					cur.templates = append(cur.templates, cacheKeyTemplate(c, js))
				}
			}
			out[b.Job] = cur
		}
	}
	return out
}

// cacheWriterScope is the scopes the entry's own run saves its cache
// under, among the job's save scopes (JobSituation.CacheScopes: the
// scopes GitHub lets the job's runs save under, by trigger and
// cache-mode). A fork pull request run (EntryForkPR) saves in the pull
// request's merge ref alone, whatever other trigger the job also
// carries, because the run proving the entry is specifically the
// pull_request one. A privileged base-context entry (EntryPRTarget:
// pull_request_target, workflow_run, issue_comment and the other
// triggers that run with the base repository's context) saves in the
// default branch's, and only when the job's save scopes hold it: on a
// job granted cache write (the poisoned_cache entry job) they do, on any
// other the low-trust event only reads. Every other entry (a mutable
// dependency, an unprotected push, an untrusted expression) takes the
// job's save scopes as they are, since nothing about the entry narrows
// which of the job's runs holds it, except an untrusted expression whose
// context only some events carry (expressionEvents): it holds only in
// those events' runs, so it saves only where they save
// (JobSituation.SaveScopesByEvent). A pull request title saves nothing
// for the default branch: its pull_request run saves in the merge ref's
// scope and its pull_request_target run only reads, whatever push run
// the job also has. A context the table does not know takes the job's
// save scopes. A job carrying no trigger saves under "any" (GitLab),
// which narrows nothing. Mirrors the
// rego entry_cache_scope (policies/situation/situation.rego) for the
// entries a finding builds (pr_target, mutable_dependency,
// untrusted_expression).
func cacheWriterScope(kind EntryKind, subject string, js JobSituation) []string {
	var run string
	switch kind {
	case EntryForkPR:
		run = "pull_request"
	case EntryPRTarget:
		if scopes, ok := eventSaveScopes(js.PrivilegedTriggers, js); ok {
			if savesShared(scopes) {
				return []string{"default"}
			}
			return nil
		}
		run = "default"
	case EntryUntrustedExpression:
		return expressionSaveScopes(subject, js)
	default:
		return js.CacheScopes
	}
	if slices.Contains(js.CacheScopes, run) || slices.Contains(js.CacheScopes, "any") {
		return []string{run}
	}
	return nil
}

// savesShared reports whether a run saving under scopes saves what runs
// of other refs restore: the default branch's scope, or any scope (a job
// carrying no trigger). A save in a pull request's, a tag's or another
// branch's scope reaches runs of that same ref only.
func savesShared(scopes []string) bool {
	return slices.Contains(scopes, "default") || slices.Contains(scopes, "any")
}

// savingCaches is the CacheFacts of js that actually save (Mode "save" or
// "both"): a restore-only entry (Mode "restore", recorded whenever the
// collector resolves package-manager-cache: false, cache: false, a
// save-if: false or a cache-read-only: true) declares no save of its
// own. It never decides whether js writes a cache (code in a run granted
// write can save any key); it only feeds the templates a sentence names
// a declared, matching save by.
func savingCaches(js JobSituation) []CacheFact {
	var out []CacheFact
	for _, c := range js.Caches {
		if c.Mode == "save" || c.Mode == "both" {
			out = append(out, c)
		}
	}
	return out
}

// restoringCaches is the CacheFacts of js that restore (Mode "restore" or
// "both").
func restoringCaches(js JobSituation) []CacheFact {
	var out []CacheFact
	for _, c := range js.Caches {
		if c.Mode == "restore" || c.Mode == "both" {
			out = append(out, c)
		}
	}
	return out
}

// unionScopes is the sorted union of two scope sets, deduplicated.
func unionScopes(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	return sortedKeys(set)
}

// cacheWriterReaches reports whether cw's entered run can write what
// restoreJS restores, and the state that answer holds at. cw saves in the
// default branch's scope (cacheWriters keeps no other writer), which
// every run restores from, and code running in a run GitHub lets save can
// save any key there, so the edge exists whenever restoreJS runs and
// restores a cache its cache-mode leaves on (RestoresCache). The key
// template never decides the edge; it only names the cache
// (reachThroughCache). Both facts are settled by the situation, so the
// state is "proven": no fact produces "unknown" today. The unknown state
// (and weakerCacheWriterState, writersUnknown, the claims reading it) is
// kept for a restorer fact a later lane or provider cannot settle, which
// keeps the edge, missing data never proving a negative.
func cacheWriterReaches(_ cacheWriter, restoreJS JobSituation) (reaches bool, state string) {
	return restoreJS.RestoresCache && !restoreJS.Dead, "proven"
}

// weakerCacheWriterState combines two states cacheWriterReaches gave the
// same edge across branches of one path: unknown wins, so the recorded
// state does not depend on the order a map happened to iterate the
// branches in. "" (no prior state) defers to the other side.
func weakerCacheWriterState(a, b string) string {
	if a == "unknown" || b == "unknown" {
		return "unknown"
	}
	if a == "" {
		return b
	}
	return a
}

// reachThroughCache narrows g, the branch of a poisoned_cache path whose
// entry job holds the grant, to the jobs w's entered run reaches through
// the cache (cacheWriterReaches over the restorers walkedJobs listed),
// recomputing the reach when it drops one, and records each edge's
// state, whether any is proven, and the cache they all restore when w's
// declared save names it. false when the run reaches no job.
func (g *pathGroup) reachThroughCache(w cacheWriter, sit *Situation) bool {
	writer := g.jobs[0]
	var reached []string
	states := map[string]string{}
	proven := false
	for _, r := range g.jobs[1:] {
		ok, state := cacheWriterReaches(w, sit.Jobs[r])
		if !ok {
			continue
		}
		reached = append(reached, r)
		states[r] = state
		proven = proven || state == "proven"
	}
	if len(reached) == 0 {
		return false
	}
	if len(reached) != len(g.jobs)-1 {
		g.jobs = append([]string{writer}, reached...)
		g.reach, g.unresolvable, g.cause, g.surviving = reachOver(sit, reached, g.anchor.kind, g.anchor.fact.Subject)
	}
	g.cacheStates = states
	g.writersUnknown = !proven
	g.cacheName = declaredCacheName(w, reached, sit)
	return true
}

// declaredCacheName is the name of the cache every job of reached
// restores, when w declares a save whose key template matches a restore
// of each (keyTemplate.Matches) and those restores all carry one name
// (cacheFactName); "" otherwise, and the sentence stays generic.
func declaredCacheName(w cacheWriter, reached []string, sit *Situation) string {
	name := ""
	for _, r := range reached {
		js := sit.Jobs[r]
		got := ""
		for _, rc := range restoringCaches(js) {
			rt := cacheKeyTemplate(rc, js)
			if slices.ContainsFunc(w.templates, func(wt keyTemplate) bool { return wt.Matches(rt) }) {
				got = cacheFactName(rc)
				break
			}
		}
		if got == "" || (name != "" && got != name) {
			return ""
		}
		name = got
	}
	return name
}

// cacheEdges is, over the branches of a poisoned_cache path, the state of
// the edge to every job it reaches through the cache (the weaker on a
// job two branches reach) and the cache they all restore when every
// branch names the same one.
func (pg *pathGroups) cacheEdges() (map[string]string, string) {
	states := map[string]string{}
	name, first := "", true
	for _, job := range sortedKeys(pg.branchSet()) {
		g := pg.branches[job]
		for r, st := range g.cacheStates {
			states[r] = weakerCacheWriterState(states[r], st)
		}
		if first {
			name, first = g.cacheName, false
		} else if g.cacheName != name {
			name = ""
		}
	}
	return states, name
}

// branchSet is the entry jobs of pg's branches.
func (pg *pathGroups) branchSet() map[string]bool {
	out := make(map[string]bool, len(pg.branches))
	for j := range pg.branches {
		out[j] = true
	}
	return out
}

// rustCacheName opens the name of a rust-cache key family.
const rustCacheName = "Rust build cache, key prefix "

// cacheFactName names a cache a job restores the way a reader finds it
// in the workflow: the literal key of actions/cache, else the cache the
// step's action keys itself (builtinCacheRefs in the GitHub collector),
// by its family (CacheFact.Family, the key without the discriminators
// the edges match on; the key when the facts give none): a rust-cache
// key family, a setup action's cache of a manager, the Gradle cache.
func cacheFactName(c CacheFact) string {
	family := c.Family
	if family == "" {
		family = c.Key
	}
	name, _, _ := strings.Cut(strings.ToLower(c.Uses), "@")
	short := name[strings.LastIndex(name, "/")+1:]
	switch name {
	case "actions/cache", "actions/cache/restore", "actions/cache/save", "":
		return c.Key
	case "swatinem/rust-cache":
		return rustCacheName + family
	case "actions/setup-node", "actions/setup-python", "actions/setup-java", "actions/setup-dotnet", "actions/setup-go":
		if manager, ok := strings.CutPrefix(family, short+"-"); ok {
			return manager + " cache of " + short
		}
		return "cache of " + short
	case "gradle/actions/setup-gradle", "gradle/gradle-build-action":
		return "Gradle cache of " + short
	}
	return "cache of " + name
}
