package gitlab

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/getplumber/plumber/configuration"
)

// membersServer serves GET /api/v4/projects/:id/members/all from pages, 100
// per page, with GitLab's X-Next-Page pagination header, and records how many
// pages were asked for.
func membersServer(t *testing.T, pages [][]string, status int) (*httptest.Server, *int) {
	t.Helper()
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/members/all") {
			http.NotFound(w, r)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"nope"}`))
			return
		}
		asked++
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		if page < len(pages) {
			w.Header().Set("X-Next-Page", strconv.Itoa(page+1))
		} else {
			w.Header().Set("X-Next-Page", "")
		}
		w.Header().Set("X-Page", strconv.Itoa(page))
		w.Header().Set("X-Total-Pages", strconv.Itoa(len(pages)))
		w.Header().Set("Content-Type", "application/json")
		if page > len(pages) {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte("[" + strings.Join(pages[page-1], ",") + "]"))
	}))
	t.Cleanup(srv.Close)
	return srv, &asked
}

func member(id int, username string, level int) string {
	return fmt.Sprintf(`{"id":%d,"username":%q,"name":"n","state":"active","access_level":%d}`, id, username, level)
}

func testConf() *configuration.Configuration {
	conf := configuration.NewDefaultConfiguration()
	conf.GitlabRetryMaxRetries = 0
	return conf
}

// Spec 4.3: Owners are level 50, Maintainers 40, Developers 30; Total counts
// every non-bot member at any level; only usernames matching the anchored
// access-token bot shape are skipped, both the modern
// project_<id>_bot_<random> / group_<id>_bot_<random> form and the legacy
// pre-14.0 forms that survive an upgrade (project_<id>_bot,
// project_<id>_bot1, project_<id>_bot2, ..., and the group_ equivalents). A
// human whose name merely contains _bot_, or a suffix like "bottle", or a
// prefix that does not match the shape, is still counted.
func TestFetchProjectMemberCountsTalliesRolesAndSkipsBots(t *testing.T) {
	srv, _ := membersServer(t, [][]string{{
		member(1, "alice", 50),
		member(2, "bob", 40),
		member(3, "carol", 40),
		member(4, "dave", 30),
		member(5, "erin", 20),
		member(6, "frank", 10),
		member(7, "project_42_bot_abc", 40),
		member(8, "group_7_bot_def", 50),
		member(9, "deploy_bot_ci", 50),
		member(10, "bot_project_1_bot_x", 30),
		member(11, "project_42_bot", 50),   // legacy pre-14.0 bot, excluded
		member(12, "project_42_bot1", 40),  // legacy pre-14.0 bot, excluded
		member(13, "group_7_bot2", 30),     // legacy pre-14.0 bot, excluded
		member(14, "project_1_bottle", 30), // human, "bottle" is not a bot suffix, counted
	}}, http.StatusOK)

	counts, known, status, err := FetchProjectMemberCounts(42, "tok", srv.URL, testConf())
	if err != nil || !known || status != http.StatusOK {
		t.Fatalf("known=%v status=%d err=%v", known, status, err)
	}
	// Owners: alice, deploy_bot_ci (project_42_bot excluded) = 2
	// Maintainers: bob, carol (project_42_bot1 excluded) = 2
	// Developers: dave, bot_project_1_bot_x, project_1_bottle (group_7_bot2 excluded) = 3
	// Total: the 8 non-bot members from before, plus project_1_bottle = 9
	want := MemberCounts{Owners: 2, Maintainers: 2, Developers: 3, Total: 9}
	if counts != want {
		t.Fatalf("counts = %+v, want %+v", counts, want)
	}
}

// Pagination follows X-Next-Page across pages and stops when it is empty.
func TestFetchProjectMemberCountsPaginates(t *testing.T) {
	var p1, p2 []string
	for i := 0; i < 100; i++ {
		p1 = append(p1, member(i, fmt.Sprintf("u%d", i), 30))
	}
	for i := 100; i < 105; i++ {
		p2 = append(p2, member(i, fmt.Sprintf("u%d", i), 50))
	}
	srv, asked := membersServer(t, [][]string{p1, p2}, http.StatusOK)

	counts, known, _, err := FetchProjectMemberCounts(42, "tok", srv.URL, testConf())
	if err != nil || !known {
		t.Fatalf("known=%v err=%v", known, err)
	}
	if *asked != 2 {
		t.Fatalf("asked %d pages, want 2", *asked)
	}
	if counts.Developers != 100 || counts.Owners != 5 || counts.Total != 105 {
		t.Fatalf("counts = %+v", counts)
	}
}

// Spec 4.3: past maxMemberPages the count is unknown rather than truncated.
func TestFetchProjectMemberCountsCapMakesTheCountUnknown(t *testing.T) {
	pages := make([][]string, maxMemberPages+1)
	for p := range pages {
		for i := 0; i < 100; i++ {
			pages[p] = append(pages[p], member(p*100+i, fmt.Sprintf("u%d", p*100+i), 30))
		}
	}
	srv, asked := membersServer(t, pages, http.StatusOK)

	_, known, _, err := FetchProjectMemberCounts(42, "tok", srv.URL, testConf())
	if err != nil {
		t.Fatalf("the cap is not an error: %v", err)
	}
	if known {
		t.Fatal("a listing longer than the cap must not be reported as known")
	}
	if *asked > maxMemberPages {
		t.Fatalf("asked %d pages, the cap is %d", *asked, maxMemberPages)
	}
}

// Exactly at the cap: 20 full pages then an empty X-Next-Page is a complete
// listing, known, with no 21st request.
func TestFetchProjectMemberCountsExactlyAtCapIsKnown(t *testing.T) {
	pages := make([][]string, maxMemberPages)
	for p := range pages {
		for i := 0; i < 100; i++ {
			pages[p] = append(pages[p], member(p*100+i, fmt.Sprintf("u%d", p*100+i), 40))
		}
	}
	srv, asked := membersServer(t, pages, http.StatusOK)

	counts, known, _, err := FetchProjectMemberCounts(42, "tok", srv.URL, testConf())
	if err != nil || !known {
		t.Fatalf("a listing of exactly the cap must be known: known=%v err=%v", known, err)
	}
	if *asked != maxMemberPages {
		t.Fatalf("asked %d pages, want exactly %d", *asked, maxMemberPages)
	}
	if counts.Maintainers != 2000 || counts.Total != 2000 || counts.Owners != 0 || counts.Developers != 0 {
		t.Fatalf("counts = %+v", counts)
	}
}

// A 403 or 404 is "cannot read", surfaced through the status for the caller
// to classify, never a count of zero.
func TestFetchProjectMemberCountsForbiddenIsNotKnown(t *testing.T) {
	srv, _ := membersServer(t, nil, http.StatusForbidden)
	_, known, status, err := FetchProjectMemberCounts(42, "tok", srv.URL, testConf())
	if err == nil || known || status != http.StatusForbidden {
		t.Fatalf("known=%v status=%d err=%v", known, status, err)
	}
}

// CollectProjectMembers is the collection the run calls: it folds a 403/404
// into Known=false with no error (a permission fact, not a failure) and
// leaves every other error to the caller (a network failure degrades the run).
func TestCollectProjectMembersClassifies(t *testing.T) {
	ok, _ := membersServer(t, [][]string{{member(1, "alice", 50)}}, http.StatusOK)
	conf := testConf()
	conf.GitlabURL = ok.URL
	data, err := CollectProjectMembers(&ProjectInfo{ID: 42, Path: "g/p"}, "tok", conf)
	if err != nil || data == nil || !data.Known || data.Counts.Owners != 1 {
		t.Fatalf("data=%+v err=%v", data, err)
	}

	denied, _ := membersServer(t, nil, http.StatusNotFound)
	conf.GitlabURL = denied.URL
	data, err = CollectProjectMembers(&ProjectInfo{ID: 42, Path: "g/p"}, "tok", conf)
	if err != nil {
		t.Fatalf("a 404 is a permission fact, not an error: %v", err)
	}
	if data == nil || data.Known {
		t.Fatalf("a 404 must leave the counts unknown: %+v", data)
	}

	broken, _ := membersServer(t, nil, http.StatusInternalServerError)
	conf.GitlabURL = broken.URL
	data, err = CollectProjectMembers(&ProjectInfo{ID: 42, Path: "g/p"}, "tok", conf)
	if err == nil {
		t.Fatal("a 500 must surface as an error")
	}
	if data == nil || data.Known {
		t.Fatalf("a failed read must not be known: %+v", data)
	}
}
