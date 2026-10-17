package capability

// Effective returns the effective capability list a run uses: the user list first, in its
// own order, then every built-in capability whose name the user list does not declare (spec
// 4.2). A user declaration that names a built-in replaces it whole: there is no merge of
// recognizers inside one name, so a user can narrow a built-in like secret_detection to
// their own tool alone. A nil or empty user list yields Builtin() unchanged.
func Effective(user []Declaration) []Declaration {
	if len(user) == 0 {
		return Builtin()
	}

	declared := make(map[string]bool, len(user))
	for _, d := range user {
		declared[d.Name] = true
	}

	out := append([]Declaration(nil), user...)
	for _, b := range Builtin() {
		if !declared[b.Name] {
			out = append(out, b)
		}
	}
	return out
}
