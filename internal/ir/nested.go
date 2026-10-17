package ir

import (
	"strconv"
	"strings"
)

// UnexpandedAction is a reference the nested resolution could not expand
// (monorepo spec 2026-10-16-nested-actions-resolution-design.md section 7):
// Uses as written, Via the chain above it, Reason one of the four below.
type UnexpandedAction struct {
	Uses   string   `json:"uses"`
	Via    []string `json:"via,omitempty"`
	Reason string   `json:"reason"`
	// Invalid marks a reference refused before any fetch because it is
	// outside GitHub's grammar (reason fetch). The capped fetch warning
	// names the reason from it, so it adds no warning line of its own.
	Invalid bool `json:"-"`
}

// The reasons a reference stays unexpanded (spec section 7).
const (
	// UnexpandedBudget: past MaxNestedContainers, the run is degraded (R3).
	UnexpandedBudget = "budget"
	// UnexpandedFetch: the definition could not be read, the run warns.
	UnexpandedFetch = "fetch"
	// UnexpandedExpression: `uses: ${{ ... }}`, never guessed (spec 3.3).
	UnexpandedExpression = "expression"
	// UnexpandedAPIDisabled: no API at all, the run warns and scores (R6).
	UnexpandedAPIDisabled = "api_disabled"
)

// SplitDefinedIn reads a DefinedIn locator back: "owner/repo@ref:path:line"
// (repo "owner/repo"), or "./path:line" for a composite of the scanned
// repository (repo ""). ok is false for anything else. A git ref never
// holds a colon, so the first colon after the @ ends the ref.
func SplitDefinedIn(s string) (repo, ref, file string, line int, ok bool) {
	i := strings.LastIndex(s, ":")
	if i <= 0 {
		return "", "", "", 0, false
	}
	n, err := strconv.Atoi(s[i+1:])
	if err != nil || n < 0 {
		return "", "", "", 0, false
	}
	head := s[:i]
	if rest, local := strings.CutPrefix(head, "./"); local {
		return "", "", rest, n, rest != ""
	}
	at := strings.Index(head, "@")
	if at <= 0 || !strings.Contains(head[:at], "/") {
		return "", "", "", 0, false
	}
	colon := strings.Index(head[at:], ":")
	if colon < 0 {
		return "", "", "", 0, false
	}
	file = head[at+colon+1:]
	if file == "" {
		return "", "", "", 0, false
	}
	return head[:at], head[at+1 : at+colon], file, n, true
}

// WorkflowDefinedIn is the locator of a line of a workflow called in
// another repository, from its qualified origin
// "owner/repo/.github/workflows/x.yml@ref" (spec 3.2). "" for any other
// origin, a workflow of the scanned repository included.
func WorkflowDefinedIn(origin string, line int) string {
	head, ref, ok := strings.Cut(origin, "@")
	if !ok || ref == "" {
		return ""
	}
	parts := strings.SplitN(head, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1] + "@" + ref + ":" + parts[2] + ":" + strconv.Itoa(line)
}

// ViaText renders a chain the way every output prints it (spec 6):
// outermost first, " > " separated.
func ViaText(via []string) string {
	return strings.Join(via, " > ")
}
