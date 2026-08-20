package identity

import "sort"

// declarations maps every registered ISSUE code to the ordered field names
// that identify one finding instance of that code across runs. This table IS
// recipe v4: Of reads it, Fingerprint hashes exactly what Of selected, and
// the platform reads the same table through this package.
//
// Reserved names file, job and message read the canonical finding fields;
// every other name reads the Data bag. Declared order is hash order, so
// reordering an entry re-keys that code as surely as changing its fields.
// The parity test keeps this table and control/codes.go identical; the
// policies harness proves every entry is emitted for real.
//
// Generated 2026-08-12 from the measured v3 selection
// (docs/superpowers/plans/2026-08-12-identity-measured.json), then corrected;
// the corrections are documented in docs/FINGERPRINT.md under recipe v4.
//
// Entries tagged "(benched, not yet live...)" are controls benched on every
// provider they apply to. Their identity is chosen from what the rule emits
// today, but a benched control's emission can still shift before it ships, so
// the declaration is provisional: revisit it when the control unbenches (a
// change then is a deliberate re-key, bump RecipeVersion).
//
// Corrections applied on top of the mechanical measurement transliteration:
//
//   - The 29 GitHub controls that measured v3SubjectKey "message" no longer
//     key on prose. Each now keys on a structured subject the rule emits
//     (uses / variableName / condition / ecosystem), or on canonical
//     coordinates alone where the finding is inherently one per job
//     ({file, job}), one per workflow file ({file}), or one per repository
//     ({}, the code alone). No declared code falls back to message now; the
//     recipe keeps message only as the backstop for a code with no
//     declaration at all (unreachable while the parity test is green).
//   - ISSUE-402 (ref confusion) has two deny blocks under one code: a GitHub
//     `uses:` surface and a GitLab `include:` surface (which deliberately
//     omits job). Declares the union {uses, includePath} in subjectKeys
//     priority order so either surface's finding identifies correctly; the
//     other surface's keys contribute deterministic empty pairs.
//   - ISSUE-714 / ISSUE-715 (action mutable remote exec, "exec" / "obfuscated"
//     tiers) each have a producer-side signal (the scanned repo IS the
//     action) that sets job="" and uses="", which is why the measurement
//     recorded a v3 conflict against "message". message is deliberately
//     NOT added to their declaration: policies/action_mutable_remote_exec.rego
//     builds the producer-side signal from input.pipeline.selfActionMutableExec,
//     a single value, not a collection, so at most one such finding exists
//     per scan per tier -- there is no same-run collision for message to
//     prevent, and adding it would tie that finding's identity to prose
//     wording for no discriminating benefit. The producer-side finding
//     therefore hashes as code+empty pairs, deterministically, same as
//     ISSUE-716 (the third tier of the same signal split, which the
//     measurement happened not to conflict on but which shares the identical
//     mechanism).
//   - 16 codes whose subject is a GitHub Action `uses:` reference (307, 402,
//     421, 701, 702, 703, 705, 707, 708, 709, 711, 713, 714, 715, 716, 804)
//     declare a trailing "step", even though the measurement recorded
//     sawStep=false for all 66 codes without exception. That is a coverage
//     gap in the measurement, not a production fact: the measurement only
//     observed policies/rules_test.go's hand-built fixtures, none of which
//     populate ir.Action.Name, so enrichFindingsWithJobLocation (engine.go)
//     never had a named step to resolve during that run. The mechanism is
//     real and load-bearing -- internal/engine/opa/step_resolution_test.go
//     exercises it directly for ISSUE-713/ISSUE-701/ISSUE-801, and every one
//     of the 16 codes' Rego rules sets "line" from the specific job.uses[]
//     action entry (object.get(action, "line", 0)), which is the exact
//     precondition enrichFindingsWithJobLocation matches on. Dropping "step"
//     from these declarations would silently re-collapse the grafana/grafana
//     same-action-referenced-twice-in-one-job collision that RecipeVersion 1
//     introduced the step discriminator to fix. No other declared key gets
//     this correction: enrichFindingsWithJobLocation only resolves a step
//     when Job is non-empty, and the two non-"uses" codes whose rules also
//     set an explicit "line" (ISSUE-403 from an include's originLine,
//     ISSUE-706 from a Dockerfile FROM line) both measured sawJob=false, so
//     the resolver's own `if f.Job == "" { continue }` guard makes step
//     resolution unreachable for them regardless.
var declarations = map[string][]string{
	// Untrusted image source: keyed on the image repository (registry/name, no tag) so a tag bump on the same untrusted image does not re-key.
	"ISSUE-101": {"file", "job", "imageRepo"},
	// Forbidden container image tag: keyed on the image reference (link).
	"ISSUE-102": {"file", "job", "link"},
	// Image not pinned by digest: keyed on the image repository (registry/name, no tag) so a tag bump on a still-digestless image does not re-key.
	"ISSUE-103": {"file", "job", "imageRepo"},
	// CI/CD settings variable not protected: keyed on the variable identity (settings-level, no file or job), mirroring the platform IdOnly (Name/Type/Environment).
	"ISSUE-201": {"variableName", "variableType", "environment"},
	// CI/CD settings variable not masked: keyed on the variable identity (settings-level, no file or job), same shape as ISSUE-201.
	"ISSUE-202": {"variableName", "variableType", "environment"},
	// CI debug trace enabled: keyed on the variable name.
	"ISSUE-203": {"file", "job", "variableName"},
	// Unsafe variable expansion: keyed on the variable name.
	"ISSUE-204": {"file", "job", "variableName"},
	// Job overrides a controlled variable: keyed on the variable name.
	"ISSUE-205": {"file", "job", "variableName"},
	// Template injection in a script: one finding per job (set-deduped), keyed on the job.
	"ISSUE-207": {"file", "job"},
	// Deprecated workflow commands re-enabled: one per job, keyed on the job (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-208": {"file", "job"},
	// Untrusted content written to $GITHUB_ENV/$GITHUB_PATH: keyed on the bound variable name.
	"ISSUE-209": {"file", "job", "variableName"},
	// Gates behaviour on a spoofable actor check: keyed on the condition (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-210": {"file", "job", "condition"},
	// Unsound `if:` condition: keyed on the condition (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-211": {"file", "job", "condition"},
	// `contains()` built-in misused: keyed on the condition (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-212": {"file", "job", "condition"},
	// Whole `github` context serialised: one per job, keyed on the job (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-213": {"file", "job"},
	// Package installed without a pinned version: one per job, keyed on the job (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-214": {"file", "job"},
	// Maintainer-adjacent template in a shell script: one per job, keyed on the job (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-215": {"file", "job"},
	// Reusable workflow called with `secrets: inherit`: keyed on the called workflow ref (uses).
	"ISSUE-302": {"file", "job", "uses"},
	// Secret via fromJSON bypasses log redaction: one per job, keyed on the job (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-303": {"file", "job"},
	// Deploy/release job with no `environment:` gate: one per job, keyed on the job (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-305": {"file", "job"},
	// App token issued without revocation: keyed on the token action ref (uses) (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-306": {"file", "job", "uses"},
	// Checkout persists credentials: keyed on the action ref (uses); step separates a reused action (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-307": {"file", "job", "uses", "step"},
	// Secret accessed via a dynamic index: one per job, keyed on the job (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-308": {"file", "job"},
	// Whole secrets context exported: one per job, keyed on the job.
	"ISSUE-309": {"file", "job"},
	// Hardcoded job: keyed on the hardcoded job name.
	"ISSUE-401": {"file", "job", "hardcodedJob"},
	// Ref collides with a tag and a branch: union of the GitHub `uses` and GitLab `includePath` surfaces (see note above).
	"ISSUE-402": {"file", "job", "uses", "includePath", "step"},
	// Outdated include/template: keyed on the include path.
	"ISSUE-403": {"file", "job", "includePath"},
	// Forbidden include version: keyed on the include path.
	"ISSUE-404": {"file", "job", "includePath"},
	// Missing required template: keyed on the template path.
	"ISSUE-405": {"file", "job", "templatePath"},
	// Forbidden override of a required template: keyed on the template path.
	"ISSUE-406": {"file", "job", "templatePath"},
	// Missing required component: keyed on the component path.
	"ISSUE-408": {"file", "job", "componentPath"},
	// Forbidden override of a required component: keyed on the component path.
	"ISSUE-409": {"file", "job", "componentPath"},
	// Security job weakened: keyed on the weakening token (detail = allow_failure / when_manual / rules_override), a stable token, NOT the prose reason.
	"ISSUE-410": {"file", "job", "detail"},
	// Unverified script execution: keyed on the script line.
	"ISSUE-411": {"file", "job", "scriptLine"},
	// Docker-in-Docker service: keyed on the service image.
	"ISSUE-412": {"file", "job", "serviceImage"},
	// Docker-in-Docker with an insecure daemon: one finding per job, keyed on the job (detail was prose; the finding is one-per-job so it needs no discriminator).
	"ISSUE-413": {"file", "job"},
	// Required action/workflow missing: keyed on the required action.
	"ISSUE-417": {"file", "job", "requiredAction"},
	// Workflow has no `concurrency:` block: one finding per workflow file, keyed on the file (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-418": {"file"},
	// Known misfeature pattern (checkout dir uploaded as artefact): one per job, keyed on the job (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-419": {"file", "job"},
	// Script obfuscation: one per job, keyed on the job (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-420": {"file", "job"},
	// Publish relies on a static token, not OIDC: keyed on the action ref (uses); step separates a reused action (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-421": {"file", "job", "uses", "step"},
	// Branch protection missing: keyed on the branch name.
	"ISSUE-501": {"file", "job", "branchName"},
	// MR approval rule below the configured minimum: keyed on the rule's stable GitLab ID. The renameable rule name is data only; keying on the ID keeps a rename from re-keying the finding, per the #370 volatile-field discipline (the platform IdOnly used the renameable name — corrected here).
	"ISSUE-502": {"approvalRuleId"},
	// MR approval settings not compliant: singleton finding (one per project); the platform IdOnly was empty, so the identity is the code alone. Deliberate consequence: changing WHICH settings deviate does not re-key the finding.
	"ISSUE-503": {},
	// No approval rule covers all protected branches: singleton finding (one per project); the platform IdOnly was empty, so the identity is the code alone.
	"ISSUE-504": {},
	// Branch protection not compliant: keyed on the branch name.
	"ISSUE-505": {"file", "job", "branchName"},
	// Workflow has no explicit name: one finding per workflow file, keyed on the file (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-601": {"file"},
	// Action not pinned by commit SHA: keyed on the action ref (uses); step separates a reused action.
	"ISSUE-701": {"file", "job", "uses", "step"},
	// Action in an archived repo: keyed on the action ref (uses); step separates a reused action.
	"ISSUE-702": {"file", "job", "uses", "step"},
	// Action version has a published advisory: keyed on the action ref (uses); step separates a reused action.
	"ISSUE-703": {"file", "job", "uses", "step"},
	// Container registry password hard-coded: one container per job, keyed on the job (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-704": {"file", "job"},
	// Publish workflow may consume a poisoned cache: keyed on the action ref (uses); step separates a reused action.
	"ISSUE-705": {"file", "job", "uses", "step"},
	// Dockerfile FROM not pinned by digest: keyed on the base image (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-706": {"file", "job", "image"},
	// Pinned SHA not in the action's repo: keyed on the action ref (uses); step separates a reused action.
	"ISSUE-707": {"file", "job", "uses", "step"},
	// Version comment does not match the SHA: keyed on the action ref (uses); step separates a reused action (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-708": {"file", "job", "uses", "step"},
	// Action pin is behind the latest release: keyed on the action ref (uses); step separates a reused action (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-709": {"file", "job", "uses", "step"},
	// Action duplicates a runner built-in: keyed on the action ref (uses); step separates a reused action (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-711": {"file", "job", "uses", "step"},
	// Release workflow produces unsigned artefacts: one per job, keyed on the job (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-712": {"file", "job"},
	// Action from an unauthorized source: keyed on the action ref (uses); step separates a reused action.
	"ISSUE-713": {"file", "job", "uses", "step"},
	// Action runs mutable remote code (open): action ref (uses)+step; `message` excluded (see note above).
	"ISSUE-714": {"file", "job", "uses", "step"},
	// Action obfuscates a remote code fetch/exec: action ref (uses)+step; `message` excluded (see note above).
	"ISSUE-715": {"file", "job", "uses", "step"},
	// Action source could not be verified: keyed on the action ref (uses); step separates a reused action.
	"ISSUE-716": {"file", "job", "uses", "step"},
	// Workflow has no `permissions:` block: one per job, keyed on the job.
	"ISSUE-801": {"file", "job"},
	// Dangerous workflow trigger: one per job, keyed on the job.
	"ISSUE-802": {"file", "job"},
	// Excessive workflow permissions: one per job, keyed on the job.
	"ISSUE-803": {"file", "job"},
	// pull_request_target checks out the PR head: keyed on the action ref (uses); step separates a reused action.
	"ISSUE-804": {"file", "job", "uses", "step"},
	// Dependabot re-enables insecure external exec: keyed on the ecosystem, per dependabot.yml (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-901": {"file", "ecosystem"},
	// Dependabot ecosystem has no cooldown: keyed on the ecosystem (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-902": {"file", "ecosystem"},
	// Workflows present but no dependency updater: one finding per repository, keyed on the code alone (singleton) (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-903": {},
	// No static-analysis scanner in CI: one finding per repository, keyed on the code alone (singleton) (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-904": {},
	// Repository has no SECURITY.md: one finding per repository, keyed on the code alone (singleton) (benched, not yet live: declaration provisional, revisit on unbench).
	"ISSUE-905": {},
}

// Declared returns the identity field names declared for code, and whether
// the code is declared at all. Callers get a copy: mutating the result must
// not re-key findings computed afterwards.
func Declared(code string) ([]string, bool) {
	d, ok := declarations[code]
	if !ok {
		return nil, false
	}
	out := make([]string, len(d))
	copy(out, d)
	return out, true
}

// DeclaredCodes returns every code the table declares, sorted, as a copy.
func DeclaredCodes() []string {
	out := make([]string, 0, len(declarations))
	for code := range declarations {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}
