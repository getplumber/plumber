package control

import "testing"

func TestEveryCodeHasExactlyOneRole(t *testing.T) {
	for _, info := range AllCodes() {
		switch info.Role {
		case RoleEntry, RolePrivilege, RoleGate, RoleHygiene:
		default:
			t.Errorf("%s has no role (got %q)", info.Code, info.Role)
		}
		if info.Role == RoleEntry && info.EntryKind == "" {
			t.Errorf("%s is an entry without an entry kind", info.Code)
		}
		if info.Role != RoleEntry && info.EntryKind != "" {
			t.Errorf("%s carries an entry kind but is not an entry", info.Code)
		}
	}
}

func TestSpecAnchoredRoles(t *testing.T) {
	cases := map[ErrorCode]struct {
		role CodeRole
		kind EntryKind
	}{
		"ISSUE-102": {RoleEntry, EntryMutableDependency},
		"ISSUE-103": {RoleEntry, EntryMutableDependency},
		"ISSUE-207": {RoleEntry, EntryUntrustedExpression},
		"ISSUE-411": {RoleEntry, EntryMutableDependency},
		"ISSUE-703": {RoleEntry, EntryMutableDependency},
		"ISSUE-713": {RoleEntry, EntryMutableDependency},
		"ISSUE-714": {RoleEntry, EntryMutableDependency},
		"ISSUE-802": {RoleEntry, EntryPRTarget},
		"ISSUE-501": {RoleGate, ""},
		"ISSUE-505": {RoleGate, ""},
		"ISSUE-305": {RoleGate, ""},
		"ISSUE-307": {RolePrivilege, ""},
		"ISSUE-310": {RolePrivilege, ""},
		"ISSUE-803": {RolePrivilege, ""},
	}
	for code, want := range cases {
		if got := RoleForCode(code); got != want.role {
			t.Errorf("RoleForCode(%s) = %q, want %q", code, got, want.role)
		}
		kind, ok := EntryKindForCode(code)
		if want.kind == "" && ok {
			t.Errorf("EntryKindForCode(%s) = %q, want none", code, kind)
		}
		if want.kind != "" && (!ok || kind != want.kind) {
			t.Errorf("EntryKindForCode(%s) = %q,%v want %q", code, kind, ok, want.kind)
		}
	}
	if RoleForCode("ISSUE-999") != RoleHygiene {
		t.Error("an unknown code is hygiene: it can never anchor a path")
	}
}

// TestEntryKindsPinned pins the entry kind of every RoleEntry code (spec
// section 2). The count assertion is the catch: a new RoleEntry code added
// without a row here fails the count before it can go unpinned.
func TestEntryKindsPinned(t *testing.T) {
	want := map[ErrorCode]EntryKind{
		"ISSUE-101": EntryMutableDependency,
		"ISSUE-102": EntryMutableDependency,
		"ISSUE-103": EntryMutableDependency,
		"ISSUE-204": EntryUntrustedExpression,
		"ISSUE-207": EntryUntrustedExpression,
		"ISSUE-209": EntryUntrustedExpression,
		"ISSUE-213": EntryUntrustedExpression,
		"ISSUE-402": EntryMutableDependency,
		"ISSUE-404": EntryMutableDependency,
		"ISSUE-411": EntryMutableDependency,
		"ISSUE-701": EntryMutableDependency,
		"ISSUE-703": EntryMutableDependency,
		"ISSUE-707": EntryMutableDependency,
		"ISSUE-713": EntryMutableDependency,
		"ISSUE-714": EntryMutableDependency,
		"ISSUE-715": EntryMutableDependency,
		"ISSUE-716": EntryMutableDependency,
		"ISSUE-802": EntryPRTarget,
		"ISSUE-804": EntryPRTarget,
	}
	for code, wantKind := range want {
		kind, ok := EntryKindForCode(code)
		if !ok {
			t.Errorf("EntryKindForCode(%s) = not found, want %q", code, wantKind)
			continue
		}
		if kind != wantKind {
			t.Errorf("EntryKindForCode(%s) = %q, want %q", code, kind, wantKind)
		}
	}

	entryRoleCount := 0
	for _, info := range AllCodes() {
		if info.Role == RoleEntry {
			entryRoleCount++
		}
	}
	if entryRoleCount != len(want) {
		t.Errorf("AllCodes() has %d entry-role codes, want %d (a code was added or removed without updating this table)", entryRoleCount, len(want))
	}
}
