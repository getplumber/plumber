package control

// CodeRole is how a finding enters the score (spec section 2). Exactly one per
// code; the catalog golden pins the table.
type CodeRole string

const (
	RoleEntry     CodeRole = "entry"     // anchors an attack path
	RolePrivilege CodeRole = "privilege" // worsens what a reached job holds; hygiene when on no path
	RoleGate      CodeRole = "gate"      // removes a protection; amplifies a path, never the E cap alone
	RoleHygiene   CodeRole = "hygiene"   // on no path by construction
)

// An entry-role code anchors to a situation fact of one EntryKind; the type
// and its six values are declared with the facts in situation.go.

// RoleForCode returns the code's role; an unknown code is hygiene, so it can
// never anchor a path or amplify one.
func RoleForCode(code ErrorCode) CodeRole {
	if info := LookupCode(code); info != nil && info.Role != "" {
		return info.Role
	}
	return RoleHygiene
}

// EntryKindForCode returns the entry kind of an entry-role code.
func EntryKindForCode(code ErrorCode) (EntryKind, bool) {
	info := LookupCode(code)
	if info == nil || info.Role != RoleEntry || info.EntryKind == "" {
		return "", false
	}
	return info.EntryKind, true
}
