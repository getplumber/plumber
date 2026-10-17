package control

import "testing"

// TestActionsCacheTemplateSubstitutesTheKnownPlaceholders pins the
// actions/cache parsing rule: `${{ runner.os }}` becomes an os part,
// `${{ hashFiles(...) }}` a hash part, any other expression an any part,
// and the key splits on "-" around them.
func TestActionsCacheTemplateSubstitutesTheKnownPlaceholders(t *testing.T) {
	c := CacheFact{Key: "npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}", Uses: "actions/cache@v5"}
	got := cacheKeyTemplate(c, JobSituation{})
	want := keyTemplate{family: "npm", parts: []keyPart{literalPart("npm"), classPart(partOS), classPart(partHash)}}
	if got.family != want.family || !sameParts(got.parts, want.parts) {
		t.Errorf("template = %+v, want %+v", got, want)
	}
}

// TestActionsCacheTemplateMatchesItself: the same literal key, read twice
// (a save and a restore of the identical YAML text), always matches.
func TestActionsCacheTemplateMatchesItself(t *testing.T) {
	c := CacheFact{Key: "npm-${{ hashFiles('**/package-lock.json') }}", Uses: "actions/cache@v5"}
	a := cacheKeyTemplate(c, JobSituation{})
	b := cacheKeyTemplate(c, JobSituation{})
	if !a.Matches(b) {
		t.Errorf("a key matches itself: %+v", a)
	}
}

// TestActionsCacheTemplatesOfDifferentFamiliesNeverMatch: two literal
// prefixes that are not the same text are two different caches, whatever
// the rest of the key reads.
func TestActionsCacheTemplatesOfDifferentFamiliesNeverMatch(t *testing.T) {
	a := cacheKeyTemplate(CacheFact{Key: "npm-${{ hashFiles('**/package-lock.json') }}", Uses: "actions/cache@v5"}, JobSituation{})
	b := cacheKeyTemplate(CacheFact{Key: "lint-cache", Uses: "actions/cache@v5"}, JobSituation{})
	if a.Matches(b) {
		t.Errorf("different literal prefixes must not match: %+v / %+v", a, b)
	}
}

// TestRestoreKeysPrefixMatchesALongerSavedKey: a restore-keys fallback is
// a prefix, matching any saved key that starts with its literal parts,
// even one carrying more parts afterwards.
func TestRestoreKeysPrefixMatchesALongerSavedKey(t *testing.T) {
	saved := cacheKeyTemplate(CacheFact{Key: "npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}", Uses: "actions/cache@v5"}, JobSituation{})
	restoreKeys := cacheKeyTemplate(CacheFact{Key: "npm-", Uses: "actions/cache@v5", Prefix: true}, JobSituation{})
	if !saved.Matches(restoreKeys) {
		t.Errorf("a restore-keys prefix must match the longer saved key: %+v / %+v", saved, restoreKeys)
	}
}

// TestTwoExactKeysOfDifferentLengthDoNotMatch: neither side is a
// restore-keys prefix, so a literal remainder on the longer one (a
// different cache that merely shares a prefix) must not match.
func TestTwoExactKeysOfDifferentLengthDoNotMatch(t *testing.T) {
	a := cacheKeyTemplate(CacheFact{Key: "npm-cache", Uses: "actions/cache@v5"}, JobSituation{})
	b := cacheKeyTemplate(CacheFact{Key: "npm-cache-extra", Uses: "actions/cache@v5"}, JobSituation{})
	if a.Matches(b) {
		t.Errorf("exact keys of different length must not match: %+v / %+v", a, b)
	}
}

// TestRestoreKeysPrefixLongerThanTheSavedKeyDoesNotMatch pins the other
// direction of the restore-keys prefix rule: GitHub requires the saved
// key to start with the restore key, never the other way around, so a
// restore-keys prefix carrying MORE parts than the exact saved key
// cannot be a prefix of it and must not match; the shorter-prefix
// direction still matches exactly as TestRestoreKeysPrefixMatchesALongerSavedKey
// pins it.
func TestRestoreKeysPrefixLongerThanTheSavedKeyDoesNotMatch(t *testing.T) {
	saved := cacheKeyTemplate(CacheFact{Key: "deps-v1", Uses: "actions/cache@v5"}, JobSituation{})
	longerRestoreKeys := cacheKeyTemplate(CacheFact{Key: "deps-v1-extra", Uses: "actions/cache@v5", Prefix: true}, JobSituation{})
	if saved.Matches(longerRestoreKeys) {
		t.Errorf("a restore-keys prefix longer than the exact saved key must not match: %+v / %+v", saved, longerRestoreKeys)
	}

	longerSaved := cacheKeyTemplate(CacheFact{Key: "deps-v1-extra", Uses: "actions/cache@v5"}, JobSituation{})
	shorterRestoreKeys := cacheKeyTemplate(CacheFact{Key: "deps-v1", Uses: "actions/cache@v5", Prefix: true}, JobSituation{})
	if !longerSaved.Matches(shorterRestoreKeys) {
		t.Errorf("a restore-keys prefix shorter than the exact saved key must still match: %+v / %+v", longerSaved, shorterRestoreKeys)
	}

	a := cacheKeyTemplate(CacheFact{Key: "deps-v1", Uses: "actions/cache@v5"}, JobSituation{})
	b := cacheKeyTemplate(CacheFact{Key: "deps-v1-extra", Uses: "actions/cache@v5"}, JobSituation{})
	if a.Matches(b) {
		t.Errorf("two exact keys of different length must still not match: %+v / %+v", a, b)
	}
}

// TestRestoreKeysPrefixMatchesAnEqualLengthSavedKey pins the boundary
// that TestRestoreKeysPrefixMatchesALongerSavedKey leaves untested: a
// restore-keys prefix with the SAME part count as the saved key must
// still match on a string prefix at the last part, because GitHub
// restores whatever saved key starts with the restore-keys text,
// whatever the two sides' part counts happen to be. Two exact keys of
// equal length still require exact equality at that same position
// (never a prefix test), and a restore-keys prefix of equal length that
// is not itself a prefix of the saved text still does not match.
func TestRestoreKeysPrefixMatchesAnEqualLengthSavedKey(t *testing.T) {
	saved := cacheKeyTemplate(CacheFact{Key: "deps-Linux-npm", Uses: "actions/cache@v5"}, JobSituation{})
	restoreKeys := cacheKeyTemplate(CacheFact{Key: "deps-Linux-n", Uses: "actions/cache@v5", Prefix: true}, JobSituation{})
	if !saved.Matches(restoreKeys) {
		t.Errorf("an equal-length restore-keys prefix must match on the string prefix: %+v / %+v", saved, restoreKeys)
	}

	other := cacheKeyTemplate(CacheFact{Key: "deps-Linux-n", Uses: "actions/cache@v5"}, JobSituation{})
	if saved.Matches(other) {
		t.Errorf("two exact equal-length keys must require exact equality, not a prefix: %+v / %+v", saved, other)
	}

	notAPrefix := cacheKeyTemplate(CacheFact{Key: "deps-Linux-x", Uses: "actions/cache@v5", Prefix: true}, JobSituation{})
	if notAPrefix.Matches(saved) {
		t.Errorf("an equal-length restore-keys prefix that is not a string prefix must not match: %+v / %+v", notAPrefix, saved)
	}
}

// TestSetupNodeTemplateMatchesTheSameShapeTwice: the setup-node key shape
// (node-cache-<os>-<arch>-<manager>-<hash>), read with the same resolved
// os/arch/manager on both sides, matches.
func TestSetupNodeTemplateMatchesTheSameShapeTwice(t *testing.T) {
	c := CacheFact{Uses: "actions/setup-node@v5", Key: "setup-node-pnpm", Parts: map[string]string{"os": "Linux", "arch": "X64", "manager": "pnpm"}}
	a := cacheKeyTemplate(c, JobSituation{})
	b := cacheKeyTemplate(c, JobSituation{})
	if !a.Matches(b) {
		t.Errorf("the same setup-node shape must match itself: %+v", a)
	}
}

// TestSetupPythonVersionMismatchNeverMatches pins a resolved version
// mismatch: setup-python on 3.11 and on 3.12, same os, arch and manager,
// do not describe the same key.
func TestSetupPythonVersionMismatchNeverMatches(t *testing.T) {
	saver := cacheKeyTemplate(CacheFact{Uses: "actions/setup-python@v5", Key: "setup-python-pip",
		Parts: map[string]string{"os": "Linux", "arch": "X64", "version": "3.11", "manager": "pip"}}, JobSituation{})
	restorer := cacheKeyTemplate(CacheFact{Uses: "actions/setup-python@v5", Key: "setup-python-pip",
		Parts: map[string]string{"os": "Linux", "arch": "X64", "version": "3.12", "manager": "pip"}}, JobSituation{})
	if saver.Matches(restorer) {
		t.Errorf("3.11 must not match 3.12: %+v / %+v", saver, restorer)
	}
}

// TestSetupGoOSMismatchNeverMatches pins a resolved os mismatch:
// setup-go on Linux and on macOS do not describe the same key.
func TestSetupGoOSMismatchNeverMatches(t *testing.T) {
	saver := cacheKeyTemplate(CacheFact{Uses: "actions/setup-go@v5", Key: "setup-go",
		Parts: map[string]string{"os": "Linux", "arch": "X64", "version": "1.22"}}, JobSituation{})
	restorer := cacheKeyTemplate(CacheFact{Uses: "actions/setup-go@v5", Key: "setup-go",
		Parts: map[string]string{"os": "macOS", "arch": "X64", "version": "1.22"}}, JobSituation{})
	if saver.Matches(restorer) {
		t.Errorf("Linux must not match macOS: %+v / %+v", saver, restorer)
	}
}

// TestSetupActionsWithNoResolvedPartsStillMatch: when this program could
// not resolve a part (the common case: the collector carries no
// runs-on data), it stays an open placeholder that matches regardless,
// so a cache this program cannot fully read is never cleared by
// omission.
func TestSetupActionsWithNoResolvedPartsStillMatch(t *testing.T) {
	saver := cacheKeyTemplate(CacheFact{Uses: "actions/setup-node@v5", Key: "setup-node-npm"}, JobSituation{})
	restorer := cacheKeyTemplate(CacheFact{Uses: "actions/setup-node@v5", Key: "setup-node-npm"}, JobSituation{})
	if !saver.Matches(restorer) {
		t.Errorf("unresolved os/arch must stay open placeholders: %+v / %+v", saver, restorer)
	}
}

// TestSetupNodeManagerMismatchNeverMatches: a different package manager
// is a different cache even with everything else equal.
func TestSetupNodeManagerMismatchNeverMatches(t *testing.T) {
	saver := cacheKeyTemplate(CacheFact{Uses: "actions/setup-node@v5", Key: "setup-node-pnpm", Parts: map[string]string{"manager": "pnpm"}}, JobSituation{})
	restorer := cacheKeyTemplate(CacheFact{Uses: "actions/setup-node@v5", Key: "setup-node-npm", Parts: map[string]string{"manager": "npm"}}, JobSituation{})
	if saver.Matches(restorer) {
		t.Errorf("pnpm must not match npm: %+v / %+v", saver, restorer)
	}
}

// TestRustCacheTemplateComparesTheConfiguredPrefix: two rust-cache
// entries with the same configured prefix match; a different one does
// not, even though both are restore-keys-style prefixes themselves.
func TestRustCacheTemplateComparesTheConfiguredPrefix(t *testing.T) {
	same := cacheKeyTemplate(CacheFact{Uses: "Swatinem/rust-cache@v2", Key: "v0-rust", Prefix: true}, JobSituation{})
	other := cacheKeyTemplate(CacheFact{Uses: "Swatinem/rust-cache@v2", Key: "v0-rust", Prefix: true}, JobSituation{})
	if !same.Matches(other) {
		t.Errorf("the same rust-cache prefix must match: %+v", same)
	}
	different := cacheKeyTemplate(CacheFact{Uses: "Swatinem/rust-cache@v2", Key: "v1-custom", Prefix: true}, JobSituation{})
	if same.Matches(different) {
		t.Errorf("two different literal rust-cache prefixes must not match: %+v / %+v", same, different)
	}
}

// TestRustCacheExpressionPrefixIsOpen pins that a prefix-key or
// shared-key input the collector could not resolve (it still holds its
// `${{ ... }}` text, the collector filters neither input) is an open
// part, not an opaque literal that happens to contain expression syntax:
// it matches any other rust-cache prefix, literal or not.
func TestRustCacheExpressionPrefixIsOpen(t *testing.T) {
	open := cacheKeyTemplate(CacheFact{Uses: "Swatinem/rust-cache@v2", Key: "${{ matrix.job.os }}", Prefix: true}, JobSituation{})
	literal := cacheKeyTemplate(CacheFact{Uses: "Swatinem/rust-cache@v2", Key: "v0-rust", Prefix: true}, JobSituation{})
	if !open.Matches(literal) || !literal.Matches(open) {
		t.Errorf("an unresolved prefix-key expression must match any other prefix: %+v / %+v", open, literal)
	}
}

// TestBuildxTemplateComparesTheScopeAlone: two buildx gha caches of the
// same scope match whatever surrounds the key; different scopes do not.
func TestBuildxTemplateComparesTheScopeAlone(t *testing.T) {
	a := cacheKeyTemplate(CacheFact{Uses: "docker/build-push-action@v6", Key: "docker/build-push-action (scope=build)"}, JobSituation{})
	b := cacheKeyTemplate(CacheFact{Uses: "docker/build-push-action@v6", Key: "docker/build-push-action (scope=build)"}, JobSituation{})
	if !a.Matches(b) {
		t.Errorf("the same buildx scope must match: %+v", a)
	}
	c := cacheKeyTemplate(CacheFact{Uses: "docker/build-push-action@v6", Key: "docker/build-push-action (scope=test)"}, JobSituation{})
	if a.Matches(c) {
		t.Errorf("different buildx scopes must not match: %+v / %+v", a, c)
	}
}

// TestAnUnknownActionMatchesAnything: an action this file does not parse
// (a custom composite action, or one Plumber has no table entry for) is
// never cleared of suspicion by this file, only left unproven.
func TestAnUnknownActionMatchesAnything(t *testing.T) {
	a := cacheKeyTemplate(CacheFact{Uses: "some-org/custom-cache-action@v1", Key: "whatever"}, JobSituation{})
	if !a.unknown {
		t.Fatalf("an action with no known shape must be unknown: %+v", a)
	}
	b := cacheKeyTemplate(CacheFact{Key: "npm-${{ hashFiles('**/package-lock.json') }}", Uses: "actions/cache@v5"}, JobSituation{})
	if !a.Matches(b) || !b.Matches(a) {
		t.Errorf("an unknown template must match on either side: %+v / %+v", a, b)
	}
}

// TestAnOpenPartMatchesAnyLiteral pins the soundness fix: a part this
// program could not resolve (absent, an expression, a matrix
// placeholder) matches anything, including a literal of another
// semantic class entirely, not only a placeholder of its own class.
func TestAnOpenPartMatchesAnyLiteral(t *testing.T) {
	versionAbsent := cacheKeyTemplate(CacheFact{Uses: "actions/setup-python@v5", Key: "setup-python-pip",
		Parts: map[string]string{"os": "Linux", "arch": "X64", "manager": "pip"}}, JobSituation{})
	versionResolved := cacheKeyTemplate(CacheFact{Uses: "actions/setup-python@v5", Key: "setup-python-pip",
		Parts: map[string]string{"os": "Linux", "arch": "X64", "version": "3.11", "manager": "pip"}}, JobSituation{})
	if !versionAbsent.Matches(versionResolved) || !versionResolved.Matches(versionAbsent) {
		t.Errorf("an absent version must match a resolved one: %+v / %+v", versionAbsent, versionResolved)
	}

	osAbsent := cacheKeyTemplate(CacheFact{Uses: "actions/setup-go@v5", Key: "setup-go"}, JobSituation{})
	osResolved := cacheKeyTemplate(CacheFact{Uses: "actions/setup-go@v5", Key: "setup-go",
		Parts: map[string]string{"os": "Linux", "arch": "X64"}}, JobSituation{})
	if !osAbsent.Matches(osResolved) || !osResolved.Matches(osAbsent) {
		t.Errorf("an absent os must match a resolved one: %+v / %+v", osAbsent, osResolved)
	}

	literalOS := cacheKeyTemplate(CacheFact{Uses: "actions/cache@v5", Key: "npm-Linux-${{ hashFiles('**/package-lock.json') }}"}, JobSituation{})
	exprOS := cacheKeyTemplate(CacheFact{Uses: "actions/cache@v5", Key: "npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}"}, JobSituation{})
	if !literalOS.Matches(exprOS) || !exprOS.Matches(literalOS) {
		t.Errorf("a literal os token must match an unresolved `${{ runner.os }}`: %+v / %+v", literalOS, exprOS)
	}

	openFirst := cacheKeyTemplate(CacheFact{Uses: "actions/cache@v5", Key: "${{ inputs.p }}-${{ hashFiles('**/package-lock.json') }}"}, JobSituation{})
	resolvedFamily := cacheKeyTemplate(CacheFact{Uses: "actions/cache@v5", Key: "npm-${{ hashFiles('**/package-lock.json') }}"}, JobSituation{})
	if !openFirst.Matches(resolvedFamily) || !resolvedFamily.Matches(openFirst) {
		t.Errorf("an open first part must match a resolved family, the family check skipped: %+v / %+v", openFirst, resolvedFamily)
	}

	// Still a real mismatch when both sides are resolved and differ.
	v311 := cacheKeyTemplate(CacheFact{Uses: "actions/setup-python@v5", Key: "setup-python-pip",
		Parts: map[string]string{"version": "3.11"}}, JobSituation{})
	v312 := cacheKeyTemplate(CacheFact{Uses: "actions/setup-python@v5", Key: "setup-python-pip",
		Parts: map[string]string{"version": "3.12"}}, JobSituation{})
	if v311.Matches(v312) {
		t.Errorf("3.11 must still not match 3.12 when both are resolved: %+v / %+v", v311, v312)
	}
	linux := cacheKeyTemplate(CacheFact{Uses: "actions/setup-go@v5", Key: "setup-go", Parts: map[string]string{"os": "Linux"}}, JobSituation{})
	macos := cacheKeyTemplate(CacheFact{Uses: "actions/setup-go@v5", Key: "setup-go", Parts: map[string]string{"os": "macOS"}}, JobSituation{})
	if linux.Matches(macos) {
		t.Errorf("Linux must still not match macOS when both are resolved: %+v / %+v", linux, macos)
	}
}

// TestManagerExpressionIsOpen pins that a `cache: ${{ matrix.cache }}`
// style input gives no manager part at all (the same filter versions
// already get): an expression is never a resolved manager name.
func TestManagerExpressionIsOpen(t *testing.T) {
	expr := cacheKeyTemplate(CacheFact{Uses: "actions/setup-node@v5", Key: "setup-node-${{ matrix.cache }}",
		Parts: map[string]string{"os": "Linux", "arch": "X64", "manager": "${{ matrix.cache }}"}}, JobSituation{})
	npm := cacheKeyTemplate(CacheFact{Uses: "actions/setup-node@v5", Key: "setup-node-npm",
		Parts: map[string]string{"os": "Linux", "arch": "X64", "manager": "npm"}}, JobSituation{})
	if !expr.Matches(npm) || !npm.Matches(expr) {
		t.Errorf("an unresolved manager expression must match any manager: %+v / %+v", expr, npm)
	}
}

// TestRestoreKeysPrefixIsAStringPrefixNotATokenBoundary pins that a
// restore-keys value that does not end on a "-" boundary ("node-v") still
// matches a saved key whose same-position token runs on past it
// ("node-v20-<hash>"): the earlier, complete tokens still match exactly.
func TestRestoreKeysPrefixIsAStringPrefixNotATokenBoundary(t *testing.T) {
	saved := cacheKeyTemplate(CacheFact{Uses: "actions/cache@v5", Key: "node-v20-${{ hashFiles('**/package-lock.json') }}"}, JobSituation{})
	restoreKey := cacheKeyTemplate(CacheFact{Uses: "actions/cache@v5", Key: "node-v", Prefix: true}, JobSituation{})
	if !saved.Matches(restoreKey) {
		t.Errorf("node-v must match node-v20-<hash>: %+v / %+v", saved, restoreKey)
	}
	other := cacheKeyTemplate(CacheFact{Uses: "actions/cache@v5", Key: "node-w20-${{ hashFiles('**/package-lock.json') }}"}, JobSituation{})
	if other.Matches(restoreKey) {
		t.Errorf("node-v must not match node-w20-<hash>: %+v / %+v", other, restoreKey)
	}
}

// TestVersionNormalisesToMajorMinor pins the version comparison rule: a
// plain numeric dotted version compares at major.minor precision (1.22
// matches 1.22.3); anything not plainly numeric (a range, "latest",
// "stable", "lts/*") is left open rather than compared as text.
func TestVersionNormalisesToMajorMinor(t *testing.T) {
	cases := []struct {
		a, b  string
		match bool
	}{
		{"1.22", "1.22.3", true},
		{"1.22.0", "1.22.9", true},
		{"1.22", "1.23", false},
		{"3.11.x", "3.11", true},     // non-numeric stays open, matches anything
		{"3.x", "3.9", true},         // non-numeric stays open
		{"stable", "1.22", true},     // non-numeric stays open
		{"latest", "1.22", true},     // non-numeric stays open
		{"lts/*", "20", true},        // non-numeric stays open
		{"1.22\n1.23", "1.22", true}, // multi-line stays open
	}
	for _, c := range cases {
		a := cacheKeyTemplate(CacheFact{Uses: "actions/setup-go@v5", Key: "setup-go", Parts: map[string]string{"version": c.a}}, JobSituation{})
		b := cacheKeyTemplate(CacheFact{Uses: "actions/setup-go@v5", Key: "setup-go", Parts: map[string]string{"version": c.b}}, JobSituation{})
		if got := a.Matches(b); got != c.match {
			t.Errorf("%q vs %q: Matches = %v, want %v", c.a, c.b, got, c.match)
		}
	}
}

func sameParts(a, b []keyPart) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
