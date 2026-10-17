package control

import (
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

func findingWithData(data map[string]any) opaengine.Finding {
	return opaengine.Finding{Code: "ISSUE-714", Job: "build", Data: data}
}

// --- suppressed ---

func TestSuppressed_DownloadVerified(t *testing.T) {
	suppress, unknown := suppressed(findingWithData(map[string]any{"downloadVerified": true}))
	if !suppress || unknown {
		t.Fatalf("got (%v, %v), want (true, false)", suppress, unknown)
	}
}

func TestSuppressed_ArchivedTag(t *testing.T) {
	suppress, unknown := suppressed(findingWithData(map[string]any{"archivedTag": true}))
	if !suppress || unknown {
		t.Fatalf("got (%v, %v), want (true, false)", suppress, unknown)
	}
}

func TestSuppressed_GuardFiresOnKnownPreinstalledRunner(t *testing.T) {
	suppress, unknown := suppressed(findingWithData(map[string]any{
		"downloadGuard": "rustup",
		"runsOn":        []any{"ubuntu-latest"},
	}))
	if !suppress || unknown {
		t.Fatalf("got (%v, %v), want (true, false)", suppress, unknown)
	}
}

func TestSuppressed_GuardOnUnknownRunnerFamily(t *testing.T) {
	suppress, unknown := suppressed(findingWithData(map[string]any{
		"downloadGuard": "rustup",
		"runsOn":        []any{"self-hosted"},
	}))
	if suppress || !unknown {
		t.Fatalf("got (%v, %v), want (false, true)", suppress, unknown)
	}
}

func TestSuppressed_GuardOnKnownRunnerWhereToolIsNotPreinstalled(t *testing.T) {
	// macOS hosted images carry no docker: the guard is real, but it
	// never fires there, so the download always runs. Not suppressed,
	// and not unknown either: the runner family answered with
	// certainty.
	suppress, unknown := suppressed(findingWithData(map[string]any{
		"downloadGuard": "docker",
		"runsOn":        []any{"macos-14"},
	}))
	if suppress || unknown {
		t.Fatalf("got (%v, %v), want (false, false)", suppress, unknown)
	}
}

func TestSuppressed_MatrixRunsOnIsUnknown(t *testing.T) {
	suppress, unknown := suppressed(findingWithData(map[string]any{
		"downloadGuard":    "rustup",
		"runsOnExpression": true,
	}))
	if suppress || !unknown {
		t.Fatalf("got (%v, %v), want (false, true)", suppress, unknown)
	}
}

// TestSuppressed_GuardInAContainerJobIsUnknown pins that a job running
// its steps inside a container (container:, job.image) proves nothing
// about the hosted image's tools: the guard checks the container, so the
// anchor stays, its state unknown, even on a runner where the tool ships.
func TestSuppressed_GuardInAContainerJobIsUnknown(t *testing.T) {
	suppress, unknown := suppressed(findingWithData(map[string]any{
		"downloadGuard": "rustup",
		"runsOn":        []any{"ubuntu-latest"},
		"container":     true,
	}))
	if suppress || !unknown {
		t.Fatalf("got (%v, %v), want (false, true)", suppress, unknown)
	}
}

// TestSuppressed_GuardReadsTheImageTheLabelRuns pins the per-image
// table: terraform ships on ubuntu-22.04 only, so its guard fires there
// and never on ubuntu-24.04 or ubuntu-latest (24.04 today); a label the
// plain hosted-label parser does not read (a larger runner, an arm
// variant) answers unknown.
func TestSuppressed_GuardReadsTheImageTheLabelRuns(t *testing.T) {
	cases := []struct {
		label             string
		suppress, unknown bool
	}{
		{"ubuntu-22.04", true, false},
		{"ubuntu-24.04", false, false},
		{"ubuntu-latest", false, false},
		{"ubuntu-latest-4-cores", false, true},
		{"ubuntu-24.04-arm", false, true},
	}
	for _, tc := range cases {
		suppress, unknown := suppressed(findingWithData(map[string]any{
			"downloadGuard": "terraform",
			"runsOn":        []any{tc.label},
		}))
		if suppress != tc.suppress || unknown != tc.unknown {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", tc.label, suppress, unknown, tc.suppress, tc.unknown)
		}
	}
}

func TestSuppressed_NoSignalsAtAll(t *testing.T) {
	suppress, unknown := suppressed(findingWithData(nil))
	if suppress || unknown {
		t.Fatalf("got (%v, %v), want (false, false)", suppress, unknown)
	}
}

// --- actorFor ---

func TestActorFor_FirstPartyScript(t *testing.T) {
	a := pathAnchor{
		kind: EntryMutableDependency,
		fact: EntryFact{Subject: "https://clickhouse.com/"},
		data: map[string]any{"firstParty": true},
	}
	actor, class := actorFor(a, "clickhouse/x")
	if class != ir.GateInsider {
		t.Fatalf("class = %q, want %q", class, ir.GateInsider)
	}
	// Names the host alone, not "<owner>'s <host>": the owner's proper
	// casing is not available anywhere in the finding data, so the
	// possessive form would read as "clickhouse's clickhouse.com".
	if want := "as someone with write access to clickhouse.com"; actor != want {
		t.Errorf("actor = %q, want %q", actor, want)
	}
}

func TestActorFor_SiblingOrganizationRedirect(t *testing.T) {
	a := pathAnchor{
		kind: EntryMutableDependency,
		fact: EntryFact{Subject: "ask-bonk/ask-bonk@main"},
		data: map[string]any{"redirectedOwner": "Cloudflare-Studio"},
	}
	actor, class := actorFor(a, "cloudflare/project")
	if class != ir.GateInsider {
		t.Fatalf("class = %q, want %q", class, ir.GateInsider)
	}
	if !strings.Contains(actor, "Cloudflare-Studio") {
		t.Errorf("actor = %q, want it to name the redirected owner", actor)
	}
}

func TestActorFor_SameOwnerRedirectIsAlsoInsider(t *testing.T) {
	// A literal rename the workflow's `uses:` text has not caught up
	// with: the redirected owner IS the scanned repository's own.
	a := pathAnchor{
		kind: EntryMutableDependency,
		fact: EntryFact{Subject: "old-name/tool@main"},
		data: map[string]any{"redirectedOwner": "me"},
	}
	_, class := actorFor(a, "me/repo")
	if class != ir.GateInsider {
		t.Fatalf("class = %q, want %q", class, ir.GateInsider)
	}
}

func TestActorFor_UnrelatedRedirectIsNotInsider(t *testing.T) {
	a := pathAnchor{
		kind: EntryMutableDependency,
		fact: EntryFact{Subject: "some/tool@main"},
		data: map[string]any{"redirectedOwner": "totally-unrelated-org"},
	}
	_, class := actorFor(a, "me/repo")
	if class == ir.GateInsider {
		t.Fatal("an unrelated redirect must not read as an insider")
	}
}

func TestActorFor_NoOpinionOnAnythingElse(t *testing.T) {
	a := pathAnchor{kind: EntryMutableDependency, data: map[string]any{}}
	actor, class := actorFor(a, "me/repo")
	if actor != "" || class != "" {
		t.Fatalf("got (%q, %q), want (\"\", \"\")", actor, class)
	}
}

func TestActorFor_OnlyAppliesToMutableDependency(t *testing.T) {
	a := pathAnchor{
		kind: EntryUntrustedExpression,
		data: map[string]any{"firstParty": true},
	}
	actor, class := actorFor(a, "me/repo")
	if actor != "" || class != "" {
		t.Fatalf("got (%q, %q), want (\"\", \"\") for a non-mutable_dependency kind", actor, class)
	}
}

// --- fix round 2, item 4: urlHost drops userinfo and port too ---

func TestUrlHost_DropsUserinfoAndPort(t *testing.T) {
	cases := []struct {
		url, want string
	}{
		{"https://sh.rustup.rs", "sh.rustup.rs"},
		{"https://sh.rustup.rs:443/x", "sh.rustup.rs"},
		{"https://user:pass@sh.rustup.rs/x", "sh.rustup.rs"},
		{"https://user:pass@sh.rustup.rs:443/x", "sh.rustup.rs"},
		{"https://www.example.com/x", "example.com"},
		{"not a url", ""},
	}
	for _, tc := range cases {
		if got := urlHost(tc.url); got != tc.want {
			t.Errorf("urlHost(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}
