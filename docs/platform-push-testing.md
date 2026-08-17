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
