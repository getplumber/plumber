package control

import (
	"slices"
	"strings"
)

// claimsFor computes every claim p rests on, each with the state the
// facts behind it settle to (proven, assumed or unknown): one claim per
// fact the path's tier and reach depend on, never a restatement of a
// field already on p. Called once at assembly end (AssemblePaths), after
// every other field of p (including cacheWriterStates and downloadSource)
// is set, in a fixed order: the entry, then the reach's own secrets (walk
// order), then each walked edge, the token, the environment, the cache
// writer's edges, the download guard, and finally the reach's impacts.
func claimsFor(p *AttackPath, sit *Situation) []Claim {
	var claims []Claim
	claims = append(claims, entryClaim(p))
	claims = append(claims, secretClaims(p)...)
	claims = append(claims, edgeClaims(p)...)
	if c, ok := tokenClaim(p, sit); ok {
		claims = append(claims, c)
	}
	claims = append(claims, environmentClaims(p, sit)...)
	claims = append(claims, cacheClaims(p)...)
	if c, ok := downloadClaim(p); ok {
		claims = append(claims, c)
	}
	claims = append(claims, impactClaims(p)...)
	return claims
}

// entryClaim is the path's own entry: who can make it run. Proven for
// every gate class but the unknown one (outsider, maintainer_approved,
// same_repo, insider all settle it), unknown when the gate itself could
// not be decided (Entry.Actor "unknown"), its source then the references
// the gate evaluator could not resolve (p.unknownRefs).
func entryClaim(p *AttackPath) Claim {
	if p.Entry.Actor == "unknown" {
		return Claim{Kind: "entry", Subject: p.Entry.Subject, State: ClaimUnknown, Source: strings.Join(p.unknownRefs, ", ")}
	}
	return Claim{Kind: "entry", Subject: p.Entry.Subject, State: ClaimProven}
}

// secretClaims is one claim per secret name the reach holds (and, when a
// walked job holds every secret of the repository, one more for that),
// deduplicated, in reach (walk) order: proven when the holding job's own
// SecretsState settled it, unknown when it did not (reachPart.secretsUnknown,
// already read off Privilege.SecretsState by reachParts). A part whose
// SecretsState is unknown and contributed no claim of its own, whether it
// names no secret at all (and holds no AllSecrets either) or names only
// secrets an earlier part already claimed (deduplication leaves it with
// nothing new), still claims the gap (nothing else would): one claim
// naming "secrets Plumber could not list", job-qualified when the part
// is not the entry job, source "unlisted", so the path never reads as
// fully proven when a job's secrets could not be listed at all, even
// when every name it does give happens to already be claimed.
func secretClaims(p *AttackPath) []Claim {
	var claims []Claim
	seen := map[string]bool{}
	allSeen := false
	entryJob := ""
	if len(p.Jobs) > 0 {
		entryJob = p.Jobs[0]
	}
	for _, part := range p.Reach.parts {
		state := ClaimProven
		if part.secretsUnknown {
			state = ClaimUnknown
		}
		contributed := false
		for _, s := range part.secrets {
			if seen[s] {
				continue
			}
			seen[s] = true
			contributed = true
			claims = append(claims, Claim{Kind: "secret", Subject: s, State: state})
		}
		if part.allSecrets && !allSeen {
			allSeen = true
			contributed = true
			claims = append(claims, Claim{Kind: "secret", Subject: "every secret of the repository", State: state})
		}
		if part.secretsUnknown && !contributed {
			subject := "secrets Plumber could not list"
			if part.job != "" && part.job != entryJob {
				subject += " in job " + part.job
			}
			if !seen[subject] {
				seen[subject] = true
				claims = append(claims, Claim{Kind: "secret", Subject: subject, State: ClaimUnknown, Source: "unlisted"})
			}
		}
	}
	return claims
}

// edgeClaims is one claim per walked edge the path's branches record a
// kind for (PathBranch.FeedsVia), in branch then walk order: subject
// "from -> to (kind)", kind the FeedsVia kinds joined with "+". Proven
// for every kind but cache, whose state instead reads the cache edge's
// own recorded state (cacheWriterStates) when the fed job is one the
// poisoned_cache path reaches through the cache, proven otherwise:
// FeedsVia kinds are static facts the collector already settled, so there
// is no unknown
// edge kind to claim beyond that one recorded exception. A fed job with
// no FeedsVia entry at all (the kind itself unknown) claims nothing: there
// is no kind to name.
func edgeClaims(p *AttackPath) []Claim {
	var claims []Claim
	for _, b := range p.Branches {
		if len(b.Jobs) < 2 {
			continue
		}
		for _, to := range b.Jobs[1:] {
			kinds, ok := b.FeedsVia[to]
			if !ok {
				continue
			}
			claims = append(claims, edgeClaim(p, b.Job, to, kinds))
		}
	}
	return claims
}

func edgeClaim(p *AttackPath, from, to string, kinds []string) Claim {
	state := ClaimProven
	if slices.Contains(kinds, FeedCache) {
		if st, ok := p.cacheWriterStates[to]; ok && st == "unknown" {
			state = ClaimUnknown
		}
	}
	return Claim{Kind: "edge", Subject: from + " -> " + to + " (" + strings.Join(kinds, "+") + ")", State: state}
}

// tokenClaim is the path's write-token reach, when it has one: subject
// the scopes (joined), state the worst TokenWriteState across every job
// whose scopes survived into the reach. The source is the source of the
// job that contributed that worst state, the first such job in walk
// order; when the worst state is itself the gap (unknown), every job
// tied at that worst state contributes its own distinct source too,
// joined by a comma, in walk order, since the point of naming the source
// at all is to say why the write could not be settled, and more than one
// job can disagree on why (a declared default read as "unknown", another
// as "none"). A settled (proven) tie names only the first job's source:
// once the write is proven, which of several jobs proved it first is
// enough. A job carrying the default token whose scope was never read
// (TokenWriteSource "unknown", TokenWriteState unknown) contributes
// assumed, source "unknown": its write is taken for lack of a signal,
// and like an unknown claim it adds no tier. false when the reach holds
// no write scope at all: nothing to claim.
func tokenClaim(p *AttackPath, sit *Situation) (Claim, bool) {
	if len(p.Reach.TokenWrite) == 0 {
		return Claim{}, false
	}
	type contribution struct {
		state  ClaimState
		source string
	}
	var contributions []contribution
	for _, part := range p.Reach.parts {
		if len(part.scopes) == 0 {
			continue
		}
		js, ok := sit.Jobs[part.job]
		if !ok {
			continue
		}
		state := js.Privilege.TokenWriteState.Claim()
		if state == ClaimUnknown && js.Privilege.TokenWriteSource == "unknown" {
			// The default token whose scope was never read: its write is
			// taken for lack of a signal, an assumption rather than a fact
			// that failed to read.
			state = ClaimAssumed
		}
		contributions = append(contributions, contribution{state: state, source: js.Privilege.TokenWriteSource})
	}
	states := make([]ClaimState, len(contributions))
	for i, c := range contributions {
		states[i] = c.state
	}
	worst := worstState(states...)
	var sources []string
	seenSource := map[string]bool{}
	for _, c := range contributions {
		if c.state != worst || seenSource[c.source] {
			continue
		}
		seenSource[c.source] = true
		sources = append(sources, c.source)
		if worst != ClaimUnknown {
			break // a settled tie needs only its first job's source
		}
	}
	source := strings.Join(sources, ",")
	if source == "" {
		source = "unknown"
	}
	return Claim{Kind: "token", Subject: strings.Join(p.Reach.TokenWrite, ", "), State: worst, Source: source}, true
}

// environmentClaims is one claim per deployment environment a walked job
// runs behind (environmentOf), deduplicated by name, in walk order: proven
// when its reviewer rule was read authoritatively, unknown when it was
// not (environmentOf's own "unknown" reviewers value, read either off
// Privilege.Environment.Reviewers or off an impact's deploy evidence when
// the job carries no Environment fact of its own).
func environmentClaims(p *AttackPath, sit *Situation) []Claim {
	var claims []Claim
	seen := map[string]bool{}
	for _, j := range p.Jobs {
		js, ok := sit.Jobs[j]
		if !ok {
			continue
		}
		name, reviewers, has := environmentOf(js)
		if !has || seen[name] {
			continue
		}
		seen[name] = true
		state := ClaimProven
		if reviewers == "unknown" {
			state = ClaimUnknown
		}
		claims = append(claims, Claim{Kind: "environment", Subject: name, State: state})
	}
	return claims
}

// cacheClaims is, on a poisoned_cache path, one claim per job the path
// reaches through the cache (Jobs[1:], walk order): subject the edge from
// the job granted cache write ("writer -> restorer"), state the edge's
// own recorded state (p.cacheWriterStates).
func cacheClaims(p *AttackPath) []Claim {
	if p.EntryKind != EntryPoisonedCache || len(p.Jobs) < 2 {
		return nil
	}
	var claims []Claim
	for _, r := range p.Jobs[1:] {
		st, ok := p.cacheWriterStates[r]
		if !ok {
			continue
		}
		state := ClaimProven
		if st == "unknown" {
			state = ClaimUnknown
		}
		claims = append(claims, Claim{Kind: "cache", Subject: p.Jobs[0] + " -> " + r, State: state})
	}
	return claims
}

// downloadClaim is the path's run-time download anchor, when it has one
// (p.downloadSource, set at assembly from the anchor's own finding data):
// subject the entry subject, always proven (the character of the
// download, guarded, verified or unguarded, is itself a settled fact),
// source one of those three words. false when the anchor carries no such
// fact (downloadSource empty): nothing to claim.
func downloadClaim(p *AttackPath) (Claim, bool) {
	if p.downloadSource == "" {
		return Claim{}, false
	}
	return Claim{Kind: "download", Subject: p.Entry.Subject, State: ClaimProven, Source: p.downloadSource}, true
}

// impactClaims is one claim per impact fact of the reach (Reach.Impacts,
// already the walked jobs' impacts unioned), subject its kind, state the
// impact's own (FactState.Claim): an impact the facts could not confirm
// (a publish decided by an expression, say) claims unknown, never proven.
func impactClaims(p *AttackPath) []Claim {
	var claims []Claim
	for _, imp := range p.Reach.Impacts {
		claims = append(claims, Claim{Kind: "impact", Subject: imp.Kind, State: imp.State.Claim()})
	}
	return claims
}
