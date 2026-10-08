package control

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxSentenceLen bounds every path explanation (spec section 3: a platform
// push cap and a terminal width budget at once).
const maxSentenceLen = 500

// maxCodeRunes bounds one name rendered in backticks.
const maxCodeRunes = 200

// code renders a name as a code span. The name is read off the workflow,
// and on a merge-request pipeline the workflow is the author's own text, so
// it can never break out of its span: every backtick and control character
// (a newline, a carriage return) becomes a space, the runs collapse, and
// the result is cut at maxCodeRunes on a rune boundary, marked "...".
func code(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '`' || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > maxCodeRunes {
		s = string([]rune(s)[:maxCodeRunes-3]) + "..."
	}
	return "`" + s + "`"
}

// codeList renders each name as its own code span, comma-separated.
func codeList(items []string) string {
	spans := make([]string, len(items))
	for i, s := range items {
		spans[i] = code(s)
	}
	return strings.Join(spans, ", ")
}

// entryClause renders how an attacker reaches this path's entry job, from
// the entry fact's own evidence (spec section 3). Every slot here is a
// name already visible in the workflow text (a job, a ref, an expression),
// never a secret or a settings value.
func entryClause(p AttackPath) string {
	job := code(p.Jobs[0])
	switch p.EntryKind {
	case EntryForkPR:
		return "A fork pull request can start " + job
	case EntryPRTarget:
		return fmt.Sprintf("A pull request from anyone runs inside %s with the base repository's privileges, checking out %s", job, code(p.Entry.Subject))
	case EntryUntrustedExpression:
		who := expressionController(p.Entry.Subject)
		if p.insider {
			who = insiderWho(p.Entry.Subject)
		}
		return fmt.Sprintf("%s controls %s, which %s passes to a shell", who, code(p.Entry.Subject), job)
	case EntryMutableDependency:
		return fmt.Sprintf("A new version of %s runs inside %s without any change in this repository", code(p.Entry.Subject), job)
	case EntryUnprotectedPush:
		return fmt.Sprintf("Anyone with write access to %s runs %s", code(p.Entry.Subject), job)
	case EntryPoisonedCache:
		return fmt.Sprintf("A run that is not trusted can write %s that %s restores", cacheWords(p.Entry.Subject), job)
	}
	return "An attacker can reach " + job
}

// namedCache is a cache name cacheEntrySubject gives a caching action's
// own cache ("npm cache of setup-node", "cache of setup-go"), read as words.
var namedCache = regexp.MustCompile(`^(.+ )?cache of [^ ]+$`)

// cacheWords is how a sentence names the cache of a poisoned_cache entry:
// a rust-cache key family by its prefix, in code; a name Plumber gave a
// caching action's cache, as words; a literal key, in code.
func cacheWords(subject string) string {
	if prefix, ok := strings.CutPrefix(subject, rustCacheSubject); ok {
		return "the Rust build cache under the key prefix " + code(prefix)
	}
	if namedCacheSubject(subject) {
		return "the " + subject
	}
	return "the cache " + code(subject)
}

// namedCacheSubject reports whether a poisoned_cache entry's subject is a
// name cacheEntrySubject gave the cache rather than a literal key.
func namedCacheSubject(subject string) bool {
	return strings.HasPrefix(subject, rustCacheSubject) || namedCache.MatchString(subject)
}

// expressionControllers maps the event payload an untrusted expression
// reads to who writes it, so the entry clause names the right population:
// an issue body is written by whoever opens the issue, not by someone
// opening a pull request. First match wins; anything else (pull request,
// head ref and commit fields, GitLab commit variables) keeps the general
// wording.
var expressionControllers = []struct{ prefix, who string }{
	{"github.event.issue.", "Anyone who can open or edit an issue"},
	{"github.event.comment.", "Anyone who can comment on an issue or a pull request"},
	{"github.event.review.", "Anyone who can review a pull request"},
	{"github.event.review_comment.", "Anyone who can review a pull request"},
	{"github.event.discussion.", "Anyone who can open or edit a discussion"},
	{"github.event.pages", "Anyone who can edit the wiki"},
	{"CI_MERGE_REQUEST_", "Anyone who can open a merge request"},
}

func expressionController(subject string) string {
	for _, c := range expressionControllers {
		if strings.HasPrefix(subject, c.prefix) {
			return c.who
		}
	}
	return "Anyone who can open a pull request or push a commit"
}

// foldList renders at most three names and folds the rest into a count.
// The names are already public: they are read straight off the workflow or
// the project's settings (a secret or token name, never its value).
func foldList(items []string) string {
	if len(items) <= 3 {
		return codeList(items)
	}
	return fmt.Sprintf("%s and %d more", codeList(items[:3]), len(items)-3)
}

// impactClause names what the path's impact facts let the attacker do, one
// clause per kind present, in the fixed order the spec lists them.
func impactClause(impacts []ImpactFact) string {
	kinds := map[string]ImpactFact{}
	for _, i := range impacts {
		if _, ok := kinds[i.Kind]; !ok {
			kinds[i.Kind] = i
		}
	}
	for _, k := range tokenOnlyKinds(impacts) {
		delete(kinds, k) // read out with the token that gives it
	}
	var parts []string
	for _, k := range []string{"publishes", "deploys", "writes_repo", "signs_or_releases"} {
		i, ok := kinds[k]
		if !ok {
			continue
		}
		switch k {
		case "publishes":
			parts = append(parts, "publishes the package")
		case "deploys":
			if env := strings.TrimPrefix(i.Evidence, "environment: "); env != i.Evidence {
				parts = append(parts, "deploys to "+code(env))
			} else {
				parts = append(parts, "deploys")
			}
		case "writes_repo":
			parts = append(parts, "pushes to the repository")
		case "signs_or_releases":
			parts = append(parts, "signs or publishes releases")
		}
	}
	return strings.Join(parts, " and ")
}

// reachClause names what the attacker holds once inside the path: the
// secrets and the token write scopes, rendered in the order the assembler
// already sorted them (sortedKeys, never re-sorted here), then the impact
// the walked jobs can cause. A path whose cause is unresolvableSecrets
// never falls to the "holds no secret" default, even when r.Secrets is
// empty: an unresolvable SecretsState (GitLab, the settings-variable
// listing could not be fetched) means Plumber could not list what the job
// holds, not that it holds nothing, and saying "holds no secret" right
// next to the unresolvable modifier's own trailing sentence would read as
// a contradiction. A job that holds every secret of the repository (the
// whole secrets context, or secrets: inherit) says so, names or not. The
// surviving write token, if any, still joins in.
func reachClause(p AttackPath) string {
	r := p.Reach
	secretsUnresolvable := p.cause == unresolvableSecrets && len(r.Secrets) == 0 && !r.AllSecrets
	token := fmt.Sprintf("a token with %s write", codeList(r.TokenWrite))
	if allows := tokenOnlyKinds(r.Impacts); len(allows) > 0 {
		token = tokenAllows(allows, tokenAbilities)
	}
	held := foldList(r.Secrets)
	if r.AllSecrets {
		held = everySecret
	}
	var hold string
	switch {
	case (len(r.Secrets) > 0 || r.AllSecrets) && len(r.TokenWrite) > 0:
		hold = fmt.Sprintf("holding %s and %s", held, token)
	case len(r.Secrets) > 0 || r.AllSecrets:
		hold = "holding " + held
	case secretsUnresolvable && len(r.TokenWrite) > 0:
		hold = "holding secrets Plumber could not list and " + token
	case secretsUnresolvable:
		hold = "holding secrets Plumber could not list"
	case len(r.TokenWrite) > 0:
		hold = "holding " + token
	default:
		// A proven impact is a write: the job holds no secret but does
		// something, never "cannot write anything".
		if imp := impactClause(r.Impacts); imp != "" {
			return "where it holds no secret but " + imp
		}
		return "but it holds no secret and cannot write anything"
	}
	if imp := impactClause(r.Impacts); imp != "" {
		hold += ", and it " + imp
	}
	return hold
}

// consequence is the path's tier read out loud. At TierCritical every
// impact (publishes, deploys, writes_repo, signs_or_releases) is what
// ships or releases, so the wording is the release one. At TierHigh the
// wording follows what the reach actually holds (control/paths.go's
// baseTier can land here with a secret, a write token and no secret, or
// an impact and neither), never the tier alone: a secret in scope reads as
// read-and-reused; a write token without a secret reads as
// repository/package write when one of its scopes is contents or packages
// (the only scopes that actually touch those), and as the token's
// permissions being abused otherwise, never naming a repository or a
// package the token cannot touch; and an impact keeps the general
// "deploys or publishes" wording.
func consequence(t PathTier, r Reach) string {
	switch t {
	case TierCritical:
		return "a compromise here ships a malicious release to your users or into production"
	case TierHigh:
		switch {
		case len(r.Secrets) > 0, r.AllSecrets:
			return "the secrets can be read and reused elsewhere"
		case len(r.TokenWrite) > 0:
			if tokenWriteTouchesRepoOrPackages(r.TokenWrite) {
				return "the token can write to the repository or its packages"
			}
			return "the token's write permissions can be abused"
		case len(r.Impacts) > 0:
			return "what this job deploys or publishes can be altered"
		}
		return runnerAbused
	case TierMedium:
		return runnerAbused
	}
	return "no exploitable reach was found"
}

// runnerAbused is what code execution alone gives the attacker.
const runnerAbused = "the runner can be abused and anything it caches or uploads can be poisoned"

// pathConsequence is consequence for p's BaseTier and reach. A path whose
// only privilege is secrets Plumber could not list is priced from High,
// what those secrets would give, and reads as the secrets being read and
// reused, the reach its Reaches line names, never as something the job
// deploys or publishes.
func pathConsequence(p AttackPath) string {
	r := p.Reach
	if p.BaseTier == TierHigh && p.cause == unresolvableSecrets && len(r.Secrets) == 0 && !r.AllSecrets && len(r.TokenWrite) == 0 && len(r.Impacts) == 0 {
		return "the secrets can be read and reused elsewhere"
	}
	s := consequence(p.BaseTier, r)
	// A consequence that rests on an impact Plumber could not confirm says
	// what may happen.
	if len(r.Impacts) > 0 && !slices.ContainsFunc(r.Impacts, func(i ImpactFact) bool { return i.State != "unresolvable" }) {
		switch s {
		case "a compromise here ships a malicious release to your users or into production":
			return "a compromise here may ship a malicious release to your users or into production"
		case "what this job deploys or publishes can be altered":
			return "what this job may deploy or publish can be altered"
		}
	}
	return s
}

// tokenWriteTouchesRepoOrPackages reports whether one of the token's write
// scopes is contents or packages, the only scopes that let the attacker
// actually write to the repository or to a package registry; every other
// write scope (id-token, security-events, and the like) is a privilege the
// token holds without that reach.
func tokenWriteTouchesRepoOrPackages(scopes []string) bool {
	for _, s := range scopes {
		if s == "contents" || s == "packages" {
			return true
		}
	}
	return false
}

// modifierSentences renders each of the path's modifiers as its own
// trailing sentence, in Modifiers order (the order AssemblePaths built
// them in).
func modifierSentences(p AttackPath) []string {
	var out []string
	throughWriters := slices.Contains(p.Modifiers, "cache_writer_cap")
	for _, m := range p.Modifiers {
		switch {
		case throughWriters && (m == "push_entry_cap" || m == "dependency_cap" || m == "source_cap"):
			// said with cache_writer_cap: the cap is the writers'
		case m == "cache_writer_cap":
			out = append(out, "Writing the cache takes getting into one of the jobs that can write it first, so this path is capped at "+tierTitle(p.Tier)+".")
		case m == "private_exposure":
			out = append(out, "The repository is private, so this entry needs an account with access.")
		case m == "push_entry_cap" && p.EntryKind == EntryUntrustedExpression:
			out = append(out, "Setting this value needs write access, so this path is capped at High.")
		case m == "push_entry_cap":
			out = append(out, "Pushing to this branch needs write access, so this path is capped at High.")
		case m == "dependency_cap" && slices.Contains(p.Modifiers, "source_cap"):
			out = append(out, "The dependency must be compromised first, but its source is not authorized, so this path is capped at High.")
		case m == "dependency_cap":
			out = append(out, "The dependency must be compromised first, so this path is capped at "+tierTitle(p.Tier)+".")
		case m == "source_cap":
			// said with dependency_cap, which it always follows
		case m == "unresolvable":
			out = append(out, unresolvableSentence(p))
		case strings.HasPrefix(m, "gate:"):
			gateCode := strings.TrimPrefix(m, "gate:")
			title := gateCode
			if info := LookupCode(ErrorCode(gateCode)); info != nil {
				title = info.Title
			}
			leadIn := "A protection is missing on this job"
			if ErrorCode(gateCode) == CodeBranchUnprotected || ErrorCode(gateCode) == CodeBranchNonCompliant {
				leadIn = "Nothing stands between this and the default branch"
				if branch := p.gateBranches[gateCode]; branch != "" {
					title += " on " + code(branch)
				}
			}
			out = append(out, fmt.Sprintf("%s: %s.", leadIn, title))
		}
	}
	return out
}

// unresolvableEvidence names the fact on the path that is itself the
// unresolvable one, for the "unresolvable" modifier sentence: the entry
// fact's own evidence, or an unresolvable impact fact's evidence. Empty
// when neither is itself unresolvable, which means the real cause is the
// job's SecretsState or a bare default token (unresolvableSentence picks
// between those from the path's own cause).
func unresolvableEvidence(p AttackPath) string {
	if p.Entry.State == "unresolvable" {
		return p.Entry.Evidence
	}
	for _, i := range p.Reach.Impacts {
		if i.State == "unresolvable" {
			return i.Evidence
		}
	}
	return ""
}

// unresolvableSentence renders the "unresolvable" modifier's trailing
// sentence: an unresolvable entry or impact fact's own evidence, quoted as
// a name, as today; a plain sentence saying which secrets are in scope is
// unknown, for an unresolvable SecretsState (prose, never a code span); or, for a bare default token with
// nothing else on the path to go on, a plain-language sentence naming the
// real cause rather than quoting a secret that does not exist.
func unresolvableSentence(p AttackPath) string {
	if entryComputedAtRunTime(p) {
		return "The reference is computed at run time, so this path is unverified."
	}
	if ev := unresolvableEvidence(p); ev != "" {
		return fmt.Sprintf("Plumber could not verify %s, so this path is unverified.", code(ev))
	}
	if p.cause == unresolvableDefaultToken {
		return "Plumber could not verify that `GITHUB_TOKEN` is really writable (no `permissions` block), so this path is unverified."
	}
	return "Plumber could not verify which secrets are in scope, so this path is unverified."
}

// PathSentence renders one attack path as a single plain-language sentence
// built from its own evidence (spec section 3): entry clause, reach
// clause and consequence joined into one sentence, then one trailing
// sentence per modifier, the whole thing capped at maxSentenceLen on a
// word boundary. A path with no job (should not happen once AssemblePaths
// has run) renders as the empty string rather than panic on Jobs[0].
func PathSentence(p AttackPath) string {
	if len(p.Jobs) == 0 {
		return ""
	}
	// The consequence clause follows BaseTier, what the attacker actually
	// reaches, never the amplified or lowered Tier; a gate or an
	// unresolvable modifier gets its own trailing sentence instead (below),
	// so the consequence clause itself never claims a reach the path does
	// not have.
	s := entryClause(p) + ", " + reachClause(p) + ": " + pathConsequence(p) + "."
	for _, m := range modifierSentences(p) {
		s += " " + m
	}
	if assumedTokenOnProvenPath(p) || p.cause != unresolvableDefaultToken && assumesToken(p) {
		s += " Plumber could not verify that `GITHUB_TOKEN` is really writable (no `permissions` block)."
	}
	return truncateWords(s, maxSentenceLen)
}

// truncateWords cuts s to at most n bytes on a word boundary, marking the
// cut with an ellipsis. A string already within the bound comes back
// unchanged. The cut point never lands inside a multi-byte UTF-8 sequence:
// n-3 can fall mid-rune (a run of multi-byte characters, say), and slicing
// there would produce invalid UTF-8, so the boundary backs up to the start
// of whatever rune it landed inside first.
func truncateWords(s string, n int) string {
	if len(s) <= n {
		return s
	}
	limit := n - 3
	if limit < 0 {
		limit = 0
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	cut := strings.LastIndex(s[:limit], " ")
	if cut <= 0 {
		cut = limit
	}
	return s[:cut] + "..."
}

// plural renders n with the singular word when n == 1, the plural word
// otherwise.
func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// secretsUnlisted is the line saying the secrets a job holds could not be
// listed.
const secretsUnlisted = "Plumber could not list the secrets"

// defaultTokenUnchecked is the line saying a default token's write is
// assumed.
const defaultTokenUnchecked = "Plumber could not check that the token can write (no permissions block)"

// commitSHARef is a reference pinned to a full commit SHA ("o/a@<40 hex>").
var commitSHARef = regexp.MustCompile(`@([0-9a-f]{12})[0-9a-f]{28}\b`)

// ShortenCommitSHA shows a full commit SHA after an "@" as its first 12
// characters, enough to tell commits apart on a screen; the finding's own
// line and the JSON keep the full reference.
func ShortenCommitSHA(s string) string {
	return commitSHARef.ReplaceAllString(s, "@$1")
}

// entryComputedAtRunTime reports whether the path's entry is unresolvable
// because its reference is only known when the job runs.
func entryComputedAtRunTime(p AttackPath) bool {
	code, _ := entryAnchor(p)
	return p.EntryKind == EntryMutableDependency && p.Entry.State == "unresolvable" && computedAtRunTime(code, p.Entry.Subject)
}

// unverifiedLines is what an unverified path could not check, in one short
// line beside the entry or beside the reach: the entry or an impact fact
// that is itself unresolvable, or a default token whose write access is
// assumed. Secrets Plumber could not list need no line: Reaches says so.
func unverifiedLines(p AttackPath) (entry, reach string) {
	switch {
	case p.Entry.State == "unresolvable" && p.EntryKind == EntryPoisonedCache:
		return "Plumber could not check that the cache is on when the job publishes", ""
	case entryComputedAtRunTime(p):
		return "the reference is computed at run time, so Plumber cannot know what runs", ""
	case p.Entry.State == "unresolvable":
		return "Plumber could not check what it runs", ""
	case unresolvableEvidence(p) != "":
		return "", "Plumber could not check that this job " + unresolvedImpacts(p.Reach.Impacts)
	case p.cause == unresolvableDefaultToken:
		return "", defaultTokenUnchecked
	}
	return "", ""
}

// unresolvedWords is what a job does, by impact kind, in the line saying
// it could not be checked.
var unresolvedWords = map[string]string{
	"publishes": "publishes", "deploys": "deploys", "writes_repo": "pushes to the repository", "signs_or_releases": "releases",
}

// unresolvedImpacts names the kinds of the impacts Plumber could not
// confirm, in impactOrder, joined with "or": "publishes or deploys".
func unresolvedImpacts(impacts []ImpactFact) string {
	var unresolved []ImpactFact
	for _, i := range impacts {
		if i.State == "unresolvable" {
			unresolved = append(unresolved, i)
		}
	}
	kinds := impactKinds(unresolved)
	words := make([]string, len(kinds))
	for i, k := range kinds {
		words[i] = unresolvedWords[k]
	}
	if len(words) <= 1 {
		return strings.Join(words, "")
	}
	return strings.Join(words[:len(words)-1], ", ") + " or " + words[len(words)-1]
}

// entryFamily names what the entry is, from the code that anchors it.
func entryFamily(p AttackPath) string {
	if row, ok := entryRow(p); ok && row.family != familyAction {
		return row.family
	}
	return actionOrWorkflow(p)
}

// dependencyKind is what a dependency entry is, in the word the block's
// lines use: "action", "reusable workflow", "image", "include" or
// "script". A reference naming both a tag and a branch (ISSUE-402) is an
// action's on GitHub, read off the workflow file the entry sits in, an
// include's otherwise.
func dependencyKind(p AttackPath) string {
	row, _ := entryRow(p)
	switch row.dependency {
	case depImage:
		return "image"
	case depInclude:
		return "include"
	case depScript:
		return "script"
	case depActionOrInclude:
		if !strings.Contains(p.Entry.File, ".github/workflows/") {
			return "include"
		}
	}
	return actionOrWorkflow(p)
}

// entryNature is what the entry of p is, in a few words after its subject
// on the Entry line, from the row of the code that anchors it (the most
// serious one when several do, entryAnchor): the variant the path calls
// for (entryNatureWords), its slots filled in.
func entryNature(p AttackPath) string {
	kind := dependencyKind(p)
	if entryComputedAtRunTime(p) {
		return kind + " computed at run time"
	}
	row, ok := entryRow(p)
	if !ok {
		return entryFamily(p)
	}
	n, own := row.nature, ownOrganization(p)
	_, untrusted := entryAnchor(p)
	words := n.base
	switch {
	// An include is never untrusted: no source code is about one.
	case untrusted && kind != "include":
		words = n.untrusted
	case n.own != "" && own:
		words = n.own
	case n.unchecked != "" && imageSourceUnchecked(p):
		words = n.unchecked
	case n.insider != "" && p.insider:
		words = n.insider
	case n.workflowRun != "" && entryTrigger(p) == "workflow_run":
		words = n.workflowRun
	}
	// dependency is the dependency as the nature names it: of your
	// organization when its owner is the analysed repository's.
	dependency := "external " + kind
	if own {
		dependency = kind + " of your organization"
	}
	return strings.NewReplacer("{dependency}", dependency, "{kind}", kind).Replace(words)
}

// entryTrigger is the trigger an entry's checkout reads another run's code
// from, "workflow_run" or "". The finding carries no trigger field: its
// subject is the ref the job checks out, which names the workflow_run
// payload ("github.event.workflow_run.head_sha") when the code is another
// workflow's run, and a finding without a ref falls back to its message,
// which lists the triggers. This is the one place that reads the trigger
// off that text.
func entryTrigger(p AttackPath) string {
	if strings.Contains(p.Entry.Subject, "workflow_run") {
		return "workflow_run"
	}
	return ""
}

// entryLineSubject is what the Entry line names first, the thing the user
// can search for: the entry's subject, a commit SHA shown as 12
// characters.
func entryLineSubject(p AttackPath) string {
	if len(p.alternatives) > 1 {
		shown := make([]string, len(p.alternatives))
		for i, s := range p.alternatives {
			shown[i] = ShortenCommitSHA(s)
		}
		return "one of: " + strings.Join(shown, ", ")
	}
	return ShortenCommitSHA(p.Entry.Subject)
}

// soActor is who gets in, the first half of the So line, by the actor rule
// of the code anchoring p (its entry kind's for a code without a row): a
// dependency compromised or malicious, or the person who sets what the job
// runs, as whom the attacker acts. kind is the dependency as the line
// names it (dependencyKind, or a shorter word).
func soActor(p AttackPath, kind string) string {
	rule := kindActors[p.EntryKind]
	if row, ok := entryRow(p); ok {
		rule = row.actor
	}
	switch rule {
	case actorKnownVulnerability:
		return "through the known vulnerability of this " + kind
	case actorImpostorCommit:
		return "through the commit this " + kind + " is pinned to, which is not in its repository"
	case actorHiddenFetch:
		return "through the code fetch this " + kind + " hides"
	case actorDependency:
		return dependencyActor(p, kind)
	case actorInjection:
		if t, ok := insiderTriggerOf(p.Entry.Subject); ok && p.insider {
			return "as " + insiderTriggers[t].actor
		}
		for _, c := range expressionControllers {
			if strings.HasPrefix(p.Entry.Subject, c.prefix) {
				return "as " + strings.ToLower(c.who[:1]) + c.who[1:]
			}
		}
		return "as anyone who can open a pull request"
	case actorCheckout:
		return "as anyone who opens a pull request"
	case actorForkPR:
		return "as anyone who opens a pull request from a fork"
	case actorCache:
		return "as anyone who can write that cache"
	case actorPush:
		return "as anyone with write access to " + code(p.Entry.Subject)
	}
	return "as anyone who reaches this job"
}

// dependencyActor is how an attacker gets in through a dependency, by its
// trust and its mutability (dependencyTrust): a trusted one can only be
// compromised, an untrusted one can also be malicious, and only one whose
// code can change can be compromised. No path is anchored on a trusted,
// immutable dependency, nothing in it being able to turn.
func dependencyActor(p AttackPath, kind string) string {
	trusted, mutable := dependencyTrust(p)
	// An image no control checked the source of is of unknown trust: it
	// may be malicious.
	trusted = trusted && !imageSourceUnchecked(p)
	switch {
	case !trusted && mutable:
		return "if this " + kind + " is compromised or malicious"
	case !trusted:
		return "if this " + kind + " is malicious"
	}
	return "if this " + kind + " is compromised"
}

// imageSourceUnchecked reports whether p enters through an image whose
// source no control checked: on GitHub no image-source control runs, so
// an image there that is not the organization's own, and that no source
// finding is about, is of unknown trust. On GitLab the source is checked.
func imageSourceUnchecked(p AttackPath) bool {
	if p.EntryKind != EntryMutableDependency || dependencyKind(p) != "image" || !strings.Contains(p.Entry.File, githubWorkflowDir) {
		return false
	}
	if slices.ContainsFunc(p.AnchorCodes, func(c ErrorCode) bool { return sourceDependencyCodes[c] }) || sourceDependencyCodes[p.AnchorCode] {
		return false
	}
	return !ownOrganization(p)
}

// ownOrganization reports whether the dependency entry of p is an action,
// a reusable workflow or an image of the analysed repository's own owner
// that no source code calls untrusted. An image is when the facts prove
// every entry job runs in the owner's own images (JobSituation.OwnImage),
// or else when its reference names the owner after its registry host.
func ownOrganization(p AttackPath) bool {
	if p.EntryKind != EntryMutableDependency {
		return false
	}
	if sourceDependencyCodes[p.AnchorCode] || slices.ContainsFunc(p.AnchorCodes, func(c ErrorCode) bool { return sourceDependencyCodes[c] }) {
		return false
	}
	if dependencyKind(p) == "image" && ownImageEntry(p) {
		return true
	}
	if p.ownRepo == "" {
		return false
	}
	subject := p.Entry.Subject
	switch dependencyKind(p) {
	case "image":
		// An image names its owner after its registry host.
		host, rest, ok := strings.Cut(subject, "/")
		if !ok || !strings.ContainsAny(host, ".:") && host != "localhost" {
			return false
		}
		subject = rest
	case "action", "reusable workflow":
	default:
		return false
	}
	return sameOwner(subject, p.ownRepo)
}

// ownImageEntry reports whether every entry job of p runs in images of
// the repository owner's own namespace, as the facts prove it.
func ownImageEntry(p AttackPath) bool {
	jobs := p.EntryJobs()
	if p.situation == nil || len(jobs) == 0 {
		return false
	}
	for _, j := range jobs {
		if !p.situation.Jobs[j].OwnImage {
			return false
		}
	}
	return true
}

// tokenScopeVerbs is what the write scopes that touch the repository, its
// packages and its deployments let code in the job do.
var tokenScopeVerbs = map[string]string{"contents": "push", "packages": "publish", "deployments": "deploy"}

// tokenReach is what a job token with these write scopes and impacts
// lets code in the job do: the verbs of the scopes that push, publish or
// deploy, in that order (from the token's write scopes and its impact
// facts alike); the other write scopes, in plain words ("pull requests");
// and whether it can request an OIDC token.
func tokenReach(scopes []string, impacts []ImpactFact) (verbs, others []string, oidc bool) {
	has := map[string]bool{}
	for _, k := range tokenKinds(impacts) {
		has[tokenVerbs[k]] = true
	}
	for _, s := range scopes {
		switch v, ok := tokenScopeVerbs[s]; {
		case ok:
			has[v] = true
		case s == "id-token":
			oidc = true
		default:
			others = append(others, strings.ReplaceAll(s, "-", " "))
		}
	}
	for _, v := range []string{"push", "publish", "deploy"} {
		if has[v] {
			verbs = append(verbs, v)
		}
	}
	return verbs, others, oidc
}

// tokenPhrase reads a token out by what it lets code do: the verbs of the
// scopes that push, publish or deploy, then every other write scope; ""
// for a token with neither.
func tokenPhrase(verbs, others []string) string {
	switch {
	case len(verbs) > 0 && len(others) > 0:
		return "a token with " + joinAnd(verbs) + " access and write access to " + joinAnd(others)
	case len(verbs) > 0:
		return "a token with " + joinAnd(verbs) + " access"
	case len(others) > 0:
		return "a token with write access to " + joinAnd(others)
	}
	return ""
}

// stepImpacts is the impact kinds a step of a walked job causes on its
// own, not through the job token.
func stepImpacts(impacts []ImpactFact) map[string]bool {
	out := map[string]bool{}
	for _, i := range impacts {
		if i.Source != impactFromToken {
			out[i.Kind] = true
		}
	}
	return out
}

// stepReach is a step impact as the reach names it, and the token verb
// that already gives it.
var stepReach = []struct{ kind, words, verb string }{
	{"publishes", "a step that publishes", "publish"},
	{"deploys", "a step that deploys", "deploy"},
	{"writes_repo", "a step that pushes", "push"},
	{"signs_or_releases", "a step that releases", ""},
}

// partsOf is the reach split by the job each item comes from (Reach.parts),
// or the whole reach as one job's when it was built without them.
func partsOf(r Reach) []reachPart {
	if len(r.parts) > 0 {
		return r.parts
	}
	return []reachPart{{secrets: r.Secrets, allSecrets: r.AllSecrets, scopes: r.TokenWrite, assumed: r.tokenAssumed, impacts: r.Impacts}}
}

// reachSegment is what one job adds to what a branch reaches: the job,
// and its items read out (reachSegments).
type reachSegment struct {
	job   string
	items []string
}

// reachSegments reads a reach out job by job, each item once, under the
// first walked job holding it (the entry job's own first): the secrets,
// the token by what it lets code do, with the assumed marker when that
// job's token is the default one, the OIDC token, then a step's impact the
// token does not already give. unlisted is set when the secrets of the
// walked jobs could not be listed. A job adding nothing has no segment.
func reachSegments(r Reach, unlisted bool) []reachSegment {
	shownSecret, shownScope, shownVerb, shownStep := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	shownAll := false
	var out []reachSegment
	for i, part := range viaParts(partsOf(r)) {
		var items []string
		fresh := 0
		for _, s := range part.secrets {
			if !shownSecret[s] && !shownAll {
				fresh++
			}
		}
		switch {
		case part.allSecrets && !shownAll:
			items = append(items, everySecret)
		case fresh > 0:
			items = append(items, plural(fresh, "secret", "secrets"))
		case i == 0 && unlisted && len(r.Secrets) == 0 && !r.AllSecrets:
			items = append(items, "secrets Plumber could not list")
		}
		var scopes []string
		for _, s := range part.scopes {
			if !shownScope[s] {
				scopes = append(scopes, s)
			}
		}
		var tokenImpacts []ImpactFact
		for _, imp := range part.impacts {
			if imp.Source == impactFromToken && !shownVerb[tokenVerbs[imp.Kind]] {
				tokenImpacts = append(tokenImpacts, imp)
			}
		}
		verbs, others, oidc := tokenReach(scopes, tokenImpacts)
		verbs = slices.DeleteFunc(verbs, func(v string) bool { return shownVerb[v] })
		if token := tokenPhrase(verbs, others); token != "" {
			if part.assumed {
				token += " (assumed: no permissions block)"
			}
			items = append(items, token)
		}
		if oidc {
			items = append(items, "an OIDC token")
		}
		steps := stepImpacts(part.impacts)
		for _, st := range stepReach {
			if steps[st.kind] && !shownStep[st.kind] && !slices.Contains(verbs, st.verb) && (st.verb == "" || !shownVerb[st.verb]) {
				items = append(items, st.words)
			}
		}
		for _, s := range part.secrets {
			shownSecret[s] = true
		}
		shownAll = shownAll || part.allSecrets
		for _, s := range part.scopes {
			shownScope[s] = true
		}
		for _, v := range verbs {
			shownVerb[v] = true
		}
		for k := range steps {
			shownStep[k] = true
		}
		if len(items) > 0 {
			out = append(out, reachSegment{job: part.job, items: items})
		}
	}
	return out
}

// viaParts is parts with the impacts a called job performs for its caller
// (ImpactFact.Via) moved out of the caller's part into one of their own,
// right after it, named by the called job: the reach reads them as reached
// through that job.
func viaParts(parts []reachPart) []reachPart {
	out := make([]reachPart, 0, len(parts))
	for _, part := range parts {
		own := part
		own.impacts = nil
		var called []reachPart
		for _, imp := range part.impacts {
			if imp.Via == "" {
				own.impacts = append(own.impacts, imp)
				continue
			}
			i := slices.IndexFunc(called, func(c reachPart) bool { return c.job == imp.Via })
			if i < 0 {
				called = append(called, reachPart{job: imp.Via})
				i = len(called) - 1
			}
			called[i].impacts = append(called[i].impacts, imp)
		}
		out = append(out, own)
		out = append(out, called...)
	}
	return out
}

// reachFragment is what a branch reaches, the words after "reaches":
// what its entry job holds, read out as a list (reachSegments), then what
// it reaches through each job it feeds, named ("2 secrets and, through job
// `release`, a token with push access"); code execution alone says there
// is nothing more. name names each job a hop goes through ("job `release`", or with the
// workflow it is in); nil names the job alone.
func reachFragment(r Reach, cause unresolvableCause, name func(job string) string) string {
	if name == nil {
		name = func(job string) string { return "job " + code(jobID(job)) }
	}
	segments := reachSegments(r, cause == unresolvableSecrets)
	if len(segments) == 0 {
		return "code execution on the runner, no secret and no write token"
	}
	out := ""
	if len(r.parts) == 0 || segments[0].job == r.parts[0].job {
		out = joinAnd(segments[0].items)
		if len(segments) > 1 {
			out = strings.Join(segments[0].items, ", ")
		}
		segments = segments[1:]
	}
	for _, seg := range segments {
		hop := "through " + name(seg.job) + ", " + joinAnd(seg.items)
		if out == "" {
			out = hop
			continue
		}
		out += " and, " + hop
	}
	return out
}

// jobID is a job's own name, without the workflow a GitHub job name
// carries before its slash.
func jobID(job string) string {
	if _, id, ok := strings.Cut(job, "/"); ok {
		return id
	}
	return job
}

// soCapability is what the attacker can do once in, the second half of
// the So line after "an attacker": read the secrets, then what the token
// and the steps let code do. A capability resting only on a token whose
// write is assumed, or only on impacts none of which is confirmed, is what
// the attacker may do: "can read 3 secrets and may push in your
// repository". whose says whose the secrets are ("of the repository").
func soCapability(p AttackPath, whose bool) string {
	r := p.Reach
	owner := ""
	if whose {
		owner = " of the repository"
	}
	var reads string
	switch {
	case r.AllSecrets:
		reads = "read every secret" + owner
	case len(r.Secrets) > 0:
		reads = "read " + plural(len(r.Secrets), "secret", "secrets") + owner
	case p.cause == unresolvableSecrets:
		reads = "read the secrets Plumber could not list"
	}
	// sure is, per verb or plain scope, whether a job whose token is not
	// assumed gives it.
	sure := map[string]bool{}
	var scopes []string
	for _, part := range partsOf(r) {
		v, o, oidc := tokenReach(part.scopes, part.impacts)
		names := slices.Concat(v, o)
		if oidc {
			names = append(names, "id-token")
		}
		for _, n := range names {
			sure[n] = sure[n] || !part.assumed
		}
		scopes = append(scopes, part.scopes...)
	}
	verbs, others, oidc := tokenReach(scopes, r.Impacts)
	steps, confirmed := map[string]bool{}, map[string]bool{}
	for _, i := range r.Impacts {
		if i.Source != impactFromToken {
			steps[i.Kind] = true
			confirmed[i.Kind] = confirmed[i.Kind] || i.State != "unresolvable"
		}
	}
	var token, tokenMay, stepped, steppedMay []string
	add := func(certain bool, words string, to, toMay *[]string) {
		if certain {
			*to = append(*to, words)
			return
		}
		*toMay = append(*toMay, words)
	}
	if slices.Contains(verbs, "push") || steps["writes_repo"] {
		add(sure["push"] || confirmed["writes_repo"], "push in your repository", &token, &tokenMay)
	}
	release := steps["publishes"] || steps["signs_or_releases"]
	if slices.Contains(verbs, "publish") && !release {
		add(sure["publish"], "publish packages", &token, &tokenMay)
	}
	switch {
	case steps["deploys"]:
		add(confirmed["deploys"], "alter what the job deploys", &stepped, &steppedMay)
	case slices.Contains(verbs, "deploy"):
		add(sure["deploy"], "deploy", &token, &tokenMay)
	}
	if release {
		add(confirmed["publishes"] || confirmed["signs_or_releases"], "ship a malicious release", &stepped, &steppedMay)
	}
	// The So line holds in two lines: the other scopes and the OIDC token
	// say what the token does only when no verb does (the branch line
	// lists every scope).
	if len(verbs) == 0 && len(others) > 0 {
		add(slices.ContainsFunc(others, func(o string) bool { return sure[o] }), "write to "+joinAnd(others), &token, &tokenMay)
	}
	if len(verbs) == 0 && oidc {
		add(sure["id-token"], "request an OIDC token", &token, &tokenMay)
	}
	can := capabilityPhrase(reads, token, stepped)
	may := capabilityPhrase("", tokenMay, steppedMay)
	switch {
	case can != "" && may != "":
		return "can " + can + " and may " + strings.TrimPrefix(may, "execute code to ")
	case may != "":
		return "may " + may
	case can != "":
		return "can " + can
	}
	return "can execute code on the runner and poison what it caches or uploads"
}

// capabilityPhrase reads capabilities out: the secrets read first, then
// what the token and the steps let code do, the code the token's
// capabilities need running first ("execute code to push in your
// repository"); "" when there is none.
func capabilityPhrase(reads string, token, stepped []string) string {
	caps := slices.Concat(token, stepped)
	switch {
	case reads != "":
		return joinAnd(append([]string{reads}, caps...))
	case len(token) > 0:
		return "execute code to " + joinAnd(caps)
	}
	return joinAnd(caps)
}

// soLine is what the path means, read out as one sentence: who gets in,
// then what an attacker can do there ("may" when the impact it rests on
// is unconfirmed).
func soLine(p AttackPath) string {
	kind := dependencyKind(p)
	shortKind := kind
	if kind == "reusable workflow" {
		shortKind = "workflow"
	}
	sentence := func(kind string, whose bool) string {
		return soActor(p, kind) + ", an attacker " + soCapability(p, whose)
	}
	// The line holds in two lines of a 100-column screen: the secrets say
	// whose they are, and a reusable workflow what kind of workflow it is,
	// only when it does.
	for _, s := range []string{sentence(kind, true), sentence(kind, false)} {
		if len(wrapHard(s, soLineWidth)) <= 2 {
			return s
		}
	}
	return sentence(shortKind, false)
}

// soLineWidth is the room the So line's text has on a 100-column screen,
// after the badge column and the label.
const soLineWidth = 100 - graphIndent - graphLabel

// findingFixes is the fix of a branch finding read on its own, as a best
// fix: it names whichever branch it is about, not only the default one.
var findingFixes = map[ErrorCode]string{
	CodeBranchUnprotected:  "protect the branch",
	CodeBranchNonCompliant: "fix the branch protection settings",
	// The entry codes, read on their own, say what their entry fix says.
	CodeImageUnauthorizedSource:  untrustedImageFix,
	CodeImageForbiddenTag:        "pin the image by digest",
	CodeImageNotPinnedByDigest:   "pin the image by digest",
	CodeActionUnauthorizedSource: untrustedActionFix("action"),
	// Every other code that never anchors a path, as something to do.
	"ISSUE-201": "protect the variable",
	"ISSUE-202": "mask the variable",
	"ISSUE-203": "turn off the CI debug trace",
	"ISSUE-205": "stop overriding the controlled variable in the job",
	"ISSUE-208": "stop re-enabling the deprecated workflow commands",
	"ISSUE-210": "gate on a check the actor cannot spoof",
	"ISSUE-211": "fix the if: condition",
	"ISSUE-212": "fix the contains() call",
	"ISSUE-214": "pin the package version or install from a lockfile",
	"ISSUE-215": "pass the value through an environment variable",
	"ISSUE-302": "forward only the secrets the called workflow needs",
	"ISSUE-303": "read the secret by name, not through fromJSON",
	"ISSUE-305": "gate the job with a protected environment",
	"ISSUE-306": "let the app token be revoked when the job ends",
	"ISSUE-307": "set persist-credentials: false on the checkout",
	"ISSUE-308": "read the secret by its name, not by a computed index",
	"ISSUE-309": "pass only the secrets the step needs, by name",
	"ISSUE-310": "set persist-credentials: false before uploading the workspace",
	"ISSUE-401": "replace the hard-coded job with the shared template",
	"ISSUE-403": "update the template to its current version",
	"ISSUE-405": "include the required template",
	"ISSUE-406": "stop overriding the required template",
	"ISSUE-408": "include the required component",
	"ISSUE-409": "stop overriding the required component",
	"ISSUE-410": "restore the security job's settings",
	"ISSUE-412": "drop the Docker-in-Docker service, or isolate it",
	"ISSUE-413": "turn on TLS for the Docker-in-Docker daemon",
	"ISSUE-417": "add the required action or reusable workflow",
	"ISSUE-418": "add a concurrency block",
	"ISSUE-419": "replace the misfeature pattern",
	"ISSUE-420": "remove the hidden characters from the script",
	"ISSUE-421": "publish through OIDC trusted publishing",
	"ISSUE-422": "give the workflow a name",
	"ISSUE-502": "require more approvals on merge requests",
	"ISSUE-503": "fix the merge request approval settings",
	"ISSUE-504": "cover every protected branch with an approval rule",
	"ISSUE-506": "fix the merge request settings",
	"ISSUE-601": "link the security policy project",
	"ISSUE-702": "replace the archived action",
	"ISSUE-704": "move the registry password into a secret",
	"ISSUE-706": "pin the Dockerfile base image by digest",
	"ISSUE-708": "make the version comment match the SHA",
	"ISSUE-709": "move the pin to the latest release",
	"ISSUE-711": "replace the action with the runner's built-in tool",
	"ISSUE-712": "sign what the workflow publishes",
	"ISSUE-801": "declare a permissions block with only what the job needs",
	"ISSUE-803": "narrow the permissions to what the job needs",
	"ISSUE-901": "turn off insecure external code execution in Dependabot",
	"ISSUE-902": "add a cooldown to the Dependabot ecosystem",
	"ISSUE-903": "add a dependency update tool (Dependabot or Renovate)",
	"ISSUE-904": "run a static analysis scanner in CI",
	"ISSUE-905": "add a SECURITY.md policy file",
}

// FindingFixFor is the fix of a finding of code read on its own, from
// the table the best fix reads (findingFixes); false when the table does
// not name the code.
func FindingFixFor(code ErrorCode) (string, bool) {
	do, ok := findingFixes[code]
	return do, ok
}

// fullCommitSHARef is a reference pinned to a full commit SHA.
var fullCommitSHARef = regexp.MustCompile(`@[0-9a-f]{40}$`)

// entryFix is the fix of a path code reads, from its row.
func entryFix(code ErrorCode) string {
	if row, ok := entryCodes[code]; ok {
		return row.fix
	}
	return "see the issue reference"
}

// pathFixOf is the fix of p, read off the code the block reads it by
// (entryAnchor): pathFix, a reference its entryCodes entry fixes
// otherwise when it reads as an action's or a reusable workflow's
// (actionFix), and an entry an unauthorized source joins replaced by a
// trusted one (untrustedFix, else a trusted image or action, pinned).
func pathFixOf(p AttackPath) string {
	if entryComputedAtRunTime(p) {
		return "pin the reference to a literal in place of " + code(runTimeExpression(p.Entry.Subject))
	}
	kind := dependencyKind(p)
	code, untrusted := entryAnchor(p)
	row := entryCodes[code]
	switch {
	case untrusted && row.untrustedFix != "":
		return row.untrustedFix
	case untrusted && kind == "image":
		return untrustedImageFix
	case untrusted && (kind == "action" || kind == "reusable workflow"):
		return untrustedActionFix(kind)
	case row.actionFix != "" && (kind == "action" || kind == "reusable workflow"):
		return row.actionFix
	}
	return pathFix(code, p.Entry.Subject)
}

// runTimeExpressionPattern is an expression a reference is computed with.
var runTimeExpressionPattern = regexp.MustCompile(`\$\{\{.*?\}\}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`)

// runTimeExpression is the first expression a reference computed at run
// time is made of, the whole reference when none reads as one.
func runTimeExpression(subject string) string {
	if e := runTimeExpressionPattern.FindString(subject); e != "" {
		return e
	}
	return subject
}

// pinnedFix is the fix of code when subject is already pinned to a full
// commit SHA, so the fix never asks for that pin again; false when the
// code has none or subject is not pinned.
func pinnedFix(code ErrorCode, subject string) (string, bool) {
	row := entryCodes[code]
	return row.pinnedFix, row.pinnedFix != "" && fullCommitSHARef.MatchString(subject)
}

// pathFix is the fix of a path its anchoring code and subject read: the
// pinned form when the subject is already pinned, else the code's entry
// fix, else the code's fix as a finding.
func pathFix(code ErrorCode, subject string) string {
	if do, ok := pinnedFix(code, subject); ok {
		return do
	}
	if row, ok := entryCodes[code]; ok {
		return row.fix
	}
	return findingFix(code, subject)
}

// findingFix is the fix of a finding read on its own, as a best fix:
// always something to do, never the code's title.
func findingFix(code ErrorCode, subject string) string {
	if do, ok := pinnedFix(code, subject); ok {
		return do
	}
	if do, ok := findingFixes[code]; ok {
		return do
	}
	return entryFix(code)
}

func runsIn(jobs []string) string {
	if len(jobs) == 1 {
		return "job " + jobs[0]
	}
	return "jobs " + strings.Join(jobs, ", ")
}

var impactOrder = []string{"publishes", "deploys", "writes_repo", "signs_or_releases"}

var impactNouns = map[string]string{
	"publishes": "publishing", "deploys": "deployment", "writes_repo": "repository writes",
	"signs_or_releases": "releases",
}

// impactKinds is the distinct impact kinds present, in impactOrder.
func impactKinds(impacts []ImpactFact) []string {
	present := map[string]bool{}
	for _, i := range impacts {
		present[i.Kind] = true
	}
	var out []string
	for _, k := range impactOrder {
		if present[k] {
			out = append(out, k)
		}
	}
	return out
}

// reachesShort is what the attacker holds and can change on the path, in
// a few words, for a table cell, a graph branch and a one-line summary:
// the secrets, the token by what it lets code in the job do ("token: push,
// publish") or "token: write" for any other write scope, then what the
// steps change, joined with semicolons.
func reachesShort(p AttackPath) string {
	r := p.Reach
	var parts []string
	switch {
	case r.AllSecrets:
		parts = append(parts, "every secret")
	case len(r.Secrets) > 0:
		parts = append(parts, plural(len(r.Secrets), "secret", "secrets"))
	case p.cause == unresolvableSecrets:
		parts = append(parts, "unlisted secrets")
	}
	given := tokenKinds(r.Impacts)
	switch {
	case len(given) > 0:
		verbs := make([]string, len(given))
		for i, k := range given {
			verbs[i] = tokenVerbs[k]
		}
		parts = append(parts, "token: "+strings.Join(verbs, ", "))
	case len(r.TokenWrite) == 1 && r.TokenWrite[0] == "id-token":
		parts = append(parts, "OIDC token")
	case len(r.TokenWrite) > 0 && r.tokenAssumed:
		parts = append(parts, "token: write (assumed)")
	case len(r.TokenWrite) > 0:
		parts = append(parts, "token: write")
	}
	for _, k := range impactKinds(r.Impacts) {
		if !slices.Contains(given, k) {
			parts = append(parts, impactNouns[k])
		}
	}
	if len(parts) == 0 {
		return "code execution without secrets"
	}
	return strings.Join(parts, "; ")
}

// everySecret is a reach holding every secret of the repository, proven by
// the way the job reads them whatever their names.
const everySecret = "every secret of the repository"

// tokenOrder is the order a token's impacts are read out in.
var tokenOrder = []string{"writes_repo", "publishes", "deploys"}

// tokenAbilities and tokenVerbs say what each impact a token gives lets
// the attacker do, in a sentence and in a table cell.
var tokenAbilities = map[string]string{
	"writes_repo": "write to the repository", "publishes": "publish packages", "deploys": "create deployments",
}

var tokenVerbs = map[string]string{"writes_repo": "push", "publishes": "publish", "deploys": "deploy"}

// tokenOnlyKinds is the impact kinds only the job token gives, no step of a
// walked job doing the same, in tokenOrder.
func tokenOnlyKinds(impacts []ImpactFact) []string {
	fromToken, fromStep := map[string]bool{}, map[string]bool{}
	for _, i := range impacts {
		if i.Source == impactFromToken {
			fromToken[i.Kind] = true
		} else {
			fromStep[i.Kind] = true
		}
	}
	var out []string
	for _, k := range tokenOrder {
		if fromToken[k] && !fromStep[k] {
			out = append(out, k)
		}
	}
	return out
}

// tokenKinds is the impact kinds the job token gives, whether a step of a
// walked job also does the same or not, in tokenOrder: the reach reads a
// token by what it can do, one way everywhere.
func tokenKinds(impacts []ImpactFact) []string {
	var out []string
	for _, k := range tokenOrder {
		if slices.ContainsFunc(impacts, func(i ImpactFact) bool { return i.Kind == k && i.Source == impactFromToken }) {
			out = append(out, k)
		}
	}
	return out
}

// tokenAllows reads a token out by what it lets the attacker do: "a token
// that can write to the repository and publish packages".
func tokenAllows(kinds []string, words map[string]string) string {
	phrases := make([]string, len(kinds))
	for i, k := range kinds {
		phrases[i] = words[k]
	}
	return "a token that can " + joinAnd(phrases)
}

// joinAnd joins items as a list read out loud: "a", "a and b", "a, b and c".
func joinAnd(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// tierTitle is a tier as a word in a sentence ("High").
func tierTitle(t PathTier) string {
	s := string(t)
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
