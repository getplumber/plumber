# Testing the platform push

The `--platform` push (`cmd/platform_push.go`) has no local way to run the
platform's real parser, so `cmd/platform_push_test.go` verifies the wire
bytes it sends instead of trusting its own types. This is what that
capture-and-verify flow does and why it exists.

## Decoding into our own struct proves nothing

`buildPlatformPush` returns `[]byte`, and the obvious test is to
`json.Unmarshal` that back into `platformPush` and assert on the Go values.
That test would pass even if a field's `json` tag drifted from the contract:
a reverted tag, or a field whose Go type no longer matches what the platform
expects, still round-trips cleanly through its own (equally wrong) type. This
is not hypothetical: a prior version of this file sent `results[].policy`
as a `{name,source,ref}` object where the contract
(`platform/backend/ingestion/contract.go` in the monorepo) declares a plain
string, and every push was rejected: `json.Unmarshal` into a string field
fails outright on an object. Decoding into `platformPush` never would have
caught it, because both sides had drifted together.

## The fix: assert on the raw wire shape

`TestBuildPlatformPush_KeysAreSnakeCaseAndPolicyIsAString` unmarshals the
push body into `map[string]any` instead of `platformPush`, and checks the
JSON as the platform's parser would see it:

- `schema_version` is present as `1` (a float64 after `any`-decoding), and
  `schemaVersion` (the camelCase mistake) is absent.
- `results[0].policy` decodes to a Go `string`, not a nested object.
- `findings` and `effective_config` are present on every result entry.
- `project`, `ref`, `pipeline`, `cli`, `collection` are present at the top
  level (the contract has no `omitempty` on struct-typed top-level fields,
  so a `nil` there would drop the key entirely).

Because there is no Go type standing between the assertion and the bytes,
a tag or shape regression fails this test even when it would silently
decode clean into `platformPush`.

## Capturing the bytes that actually go over the wire

The rest of `platform_push_test.go` (`TestMaybePushPlatform_PostsThePush`
and its siblings) runs `maybePushPlatform` end to end against an
`httptest.Server` standing in for the platform, and reads the request body
the server received:

```go
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    gotBody, _ = io.ReadAll(r.Body)
    w.WriteHeader(http.StatusAccepted)
}))
```

This is what confirms the push is reachable and well-formed as a whole
request (path, `Authorization: Bearer <token>`, `Content-Type`), not just
that `buildPlatformPush`'s return value happens to look right in isolation.
Combined with the raw-map assertion above, the same captured bytes are
checked both for transport correctness and for wire-shape fidelity to the
contract.

## Keeping this in sync

`platform/backend/ingestion/contract.go` in the monorepo is the source of
truth for the shape. When it changes, update `platformPush` and its nested
types in `cmd/platform_push.go` to match, then extend
`TestBuildPlatformPush_KeysAreSnakeCaseAndPolicyIsAString` (or add a sibling
raw-map assertion) for the new or changed field: a change that only touches
the Go struct and its own round-trip test would repeat the exact failure
mode this file exists to catch.

## Variable values and the 422

The platform rejects a **whole push** with 422 when a finding carries a
variable name beside a value-shaped key without declaring where that value
came from. A single unlabelled value costs the operator every result in the
run, so this is worth a moment's care when writing a rule.

Two mechanisms cover it, and both are needed:

1. A rule that reads a value from a source it knows declares it at the point
   of emission - `"valueProvenance": "ci_file"` in `debug_trace.rego` and
   `job_variable_override.rego`, because those values come out of the CI
   configuration file, which lives in the repository.
2. `sanitizeProvenance` (`cmd/platform_provenance.go`) is the safety net. It
   walks the finding data and the effective config, and any value whose
   provenance is missing or unrecognized is **removed** and replaced with
   derived attributes - length, character class, whether it was truthy -
   which describe the value without disclosing it. Unknown provenance is
   treated as sensitive, which is the direction that cannot leak a secret.

A rule that emits a value from a genuinely secret source (a masked or hidden
CI/CD variable) must not emit it at all; declaring `settings_secret` is
rejected by the platform by design.

To check a change by hand against a live platform, POST a finding both ways
and compare - without provenance it is a 422 naming the offending path, with
`"valueProvenance": "ci_file"` it is a 201.

## The dismissed marker

A finding whose platform identity matches an entry in `/context`'s
`dismissed_issues` (#447) is marked by `control.MarkDismissed` right after
fingerprinting, and a failed control's pushed entries carry that as
`"dismissed":true` (`platformFinding.Dismissed`, omitted entirely when
false). The finding is still pushed, exactly like any other fail entry: the
marker is a claim about what the platform already knows, not a reason to
withhold data from it.

To see it in a captured request, follow the same flow as above (an
`httptest.Server` reading the push body), decode into `map[string]any`
rather than `platformPush`, walk `results[0].findings`, and check each
entry's `"dismissed"` key: present and `true` on a dismissed finding's
entry, absent on every other one.
`TestMaybePushPlatform_DismissedFindingWireShape` in
`cmd/platform_push_test.go` is the pinned example.

The wiring one level up - `markPlatformDismissedFindings` running between
`StampFingerprints` and `buildComplianceSummary`, which is what makes the mark
happen at all on a real run - lives in one place, `finalizeFindings`
(`cmd/analyze_shared.go`), called by both entry points: `runWithProvider` for
GitLab and `presentResultWithProvider` for the GitHub paths. It is pinned by
`TestSharedPipeline_ServedDismissalMarksThePushAndLeavesTheScore` in the same
file, which drives BOTH of them (the GitLab one with the provider's `Run`
stubbed to a canned result). The test builds the served entry the way the
platform does (`identity.PlatformHash` of the finding after stamping, at
`identity.RecipeVersion`) and reads both the marker on the wire and the score
that run computed, so dropping the call - or reintroducing a copy of the
sequence without it - fails there instead of shipping.

The `--output` JSON report is the one output with no marker on it, on purpose:
its finding objects are the same bytes the identity recipe hashes, so a field
added there would change the identity the platform and the CLI have to agree
on. The CSV export (a `dismissed` column) and the OCSF export (a
`dismissed: true` key) are free of that constraint and do carry it.

A dismissed finding is never dropped anywhere it would otherwise appear: the
terminal's Controls summary table counts it in a control's issue total and
per-severity tally (a per-control inventory of what ran, not the live
verdict), while that same finding is excluded from the Plumber Score and
called out separately, as "N issues, M dismissed", in the Failed Controls
detail section right below it.

## Testing platform mode end to end

Platform mode (`--platform`) reads `/context` and `/resolved-config` before
collection, so testing it needs a real backend. The backend has no dev mode
and no signature-skip: the only way in is to run it with a fake OIDC
issuer's URL in `PLUMBER_OIDC_ALLOWED_ISSUERS` and mint RS256 tokens whose
`project_path` claim matches the analyzed project.

A run then needs a `projects` row keyed on the full verified tuple
`(issuer, provider, forge_project_id)` - the token's `iss`, `"gitlab"` and
its `project_id` claim as a string - or the policy set falls back to the
derived default. Policies attach through `policy_projects`, and the settings
snapshot goes in `project_snapshots.data` using the shapes
`platform/backend/snapshot/collector.go` writes (`branch_protection` is
`{"protections": [...]}`, not a map of branch names).

Since platform mode evaluates only the resolved policies, a run with and
without `--platform` no longer evaluates the same control set, so diffing the
two is not a lane check any more. To check a collection lane, compare a
platform-mode run against the SAME policy evaluated locally by writing that
policy's control tree into a `.plumber.yaml` and running without `--platform`:
every difference must be a control moving to `not_evaluable`.

`internal/platform/live_test.go` exercises the client against a running
platform and skips unless `PLUMBER_E2E_PLATFORM`, `PLUMBER_E2E_TOKEN` and
`PLUMBER_E2E_PROJECT` are set.
