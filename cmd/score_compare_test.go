package cmd

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getplumber/plumber/control"
)

// codeLossesJSON builds the [{code, cappedLoss}] array the CLI writes under
// plumberScore.codeLosses.
func codeLossesJSON(codes map[string]float64) []map[string]any {
	if codes == nil {
		return nil
	}
	out := make([]map[string]any, 0, len(codes))
	for code, points := range codes {
		out = append(out, map[string]any{"code": code, "cappedLoss": points})
	}
	return out
}

// TestScoreCompareMatrix: the matrix counts v3-letter to v4-letter migrations,
// and a two-or-more-letter drop lands in Dropped.
func TestScoreCompareMatrix(t *testing.T) {
	dir := t.TempDir()
	write := func(name, profile, letter string, points float64, codes map[string]float64) {
		doc := map[string]any{"plumberScore": map[string]any{"profileId": profile, "score": letter, "finalPoints": points, "codeLosses": codeLossesJSON(codes)}, "projectPath": name}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+"."+strings.TrimPrefix(profile, "scoring-")+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a", "scoring-v3", "E", 0, map[string]float64{"ISSUE-501": 25})
	write("a", "scoring-v4", "C", 63, map[string]float64{"ISSUE-501": 25})
	write("b", "scoring-v3", "A", 100, nil)
	write("b", "scoring-v4", "C", 60, nil) // dropped two letters: must be listed

	rep, err := buildScoreCompareReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Matrix["E"]["C"] != 1 || rep.Matrix["A"]["C"] != 1 {
		t.Errorf("matrix = %+v", rep.Matrix)
	}
	if len(rep.Dropped) != 1 || rep.Dropped[0].Project != "b" {
		t.Errorf("dropped = %+v", rep.Dropped)
	}

	md := rep.Markdown()
	if !strings.Contains(md, "| E |") || !strings.Contains(md, "b") {
		t.Errorf("markdown:\n%s", md)
	}
}

// TestScoreCompareUnpaired checks that a project with only one of the two
// profiles is reported under Unpaired, never fatal, and never counted in
// the matrix or the dropped list (there is nothing to compare it against).
func TestScoreCompareUnpaired(t *testing.T) {
	dir := t.TempDir()
	write := func(name, profile, letter string) {
		doc := map[string]any{"plumberScore": map[string]any{"profileId": profile, "score": letter}, "projectPath": name}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+"."+strings.TrimPrefix(profile, "scoring-")+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// "paired" has both files; "orphan" only has a v4 file (its v3 Radar
	// run never produced a result, or the file never landed).
	write("paired", "scoring-v3", "B")
	write("paired", "scoring-v4", "B")
	write("orphan", "scoring-v4", "D")

	rep, err := buildScoreCompareReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Unpaired) != 1 || rep.Unpaired[0] != "orphan" {
		t.Fatalf("unpaired = %+v", rep.Unpaired)
	}
	if rep.Matrix["B"]["B"] != 1 {
		t.Errorf("matrix = %+v", rep.Matrix)
	}
	for letter, row := range rep.Matrix {
		for other, count := range row {
			if (letter == "D" || other == "D") && count != 0 {
				t.Errorf("orphan leaked into the matrix: %+v", rep.Matrix)
			}
		}
	}
	if len(rep.Dropped) != 0 {
		t.Errorf("dropped = %+v, want none (orphan has nothing to compare against)", rep.Dropped)
	}

	md := rep.Markdown()
	if !strings.Contains(md, "orphan") {
		t.Errorf("markdown does not mention the unpaired project:\n%s", md)
	}
}

// TestScoreCompareRankDirection pins ScoreLetterRank's direction (A best,
// E worst, per control/scoring.go) against what counts as "dropped": a
// project that IMPROVES by several letters must never be listed, and the
// rank gap used for "two or more letters down" must run v3 minus v4, not
// the other way around.
func TestScoreCompareRankDirection(t *testing.T) {
	if control.ScoreLetterRank("A") <= control.ScoreLetterRank("E") {
		t.Fatalf("ScoreLetterRank direction assumption broken: rank(A)=%d, rank(E)=%d", control.ScoreLetterRank("A"), control.ScoreLetterRank("E"))
	}

	dir := t.TempDir()
	write := func(name, profile, letter string) {
		doc := map[string]any{"plumberScore": map[string]any{"profileId": profile, "score": letter}, "projectPath": name}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+"."+strings.TrimPrefix(profile, "scoring-")+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// "improved" goes E -> A: a huge rank gap, but upward, so it must
	// never be reported as dropped.
	write("improved", "scoring-v3", "E")
	write("improved", "scoring-v4", "A")
	// "dropped" goes A -> D: two ranks down, must be reported.
	write("dropped", "scoring-v3", "A")
	write("dropped", "scoring-v4", "D")
	// "shifted" goes B -> C: one rank down, below the "two or more"
	// threshold, must not be reported.
	write("shifted", "scoring-v3", "B")
	write("shifted", "scoring-v4", "C")

	rep, err := buildScoreCompareReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Dropped) != 1 || rep.Dropped[0].Project != "dropped" {
		t.Fatalf("dropped = %+v, want only \"dropped\"", rep.Dropped)
	}
}

// TestScoreCompareRecoveredAttribution exercises the "points recovered"
// computation: a code's v4 contribution is its codeLosses entry (an other
// finding, priced per code) plus an even share of every
// pathLosses bucket whose pathIds resolve, through plumberScore.paths, to
// that code as the anchor. A bucket covering two differently-anchored
// paths splits its cappedLoss evenly between their two codes.
func TestScoreCompareRecoveredAttribution(t *testing.T) {
	dir := t.TempDir()
	writeRaw := func(name, suffix string, doc map[string]any) {
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+"."+suffix+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// v3: ISSUE-600 lost 40, ISSUE-700 lost 20, ISSUE-701 lost 20.
	writeRaw("x", "v3", map[string]any{
		"projectPath": "x",
		"plumberScore": map[string]any{
			"profileId":  "scoring-v3",
			"score":      "E",
			"codeLosses": codeLossesJSON(map[string]float64{"ISSUE-600": 40, "ISSUE-700": 20, "ISSUE-701": 20}),
		},
	})
	// v4: ISSUE-600 survives as an other finding, now priced at 10
	// (codeLosses). A single assembled path anchors on it too (p0,
	// cappedLoss 5, attributed in full since the bucket has one path).
	// ISSUE-700/ISSUE-701 anchor a shared pathLosses bucket (two paths,
	// cappedLoss 20 split evenly: 10 each).
	writeRaw("x", "v4", map[string]any{
		"projectPath": "x",
		"plumberScore": map[string]any{
			"profileId":  "scoring-v4",
			"score":      "C",
			"codeLosses": codeLossesJSON(map[string]float64{"ISSUE-600": 10}),
			"paths": []map[string]any{
				{"id": "p0", "anchorCode": "ISSUE-600"},
				{"id": "p1", "anchorCode": "ISSUE-700"},
				{"id": "p2", "anchorCode": "ISSUE-701"},
			},
			"pathLosses": []map[string]any{
				{"cappedLoss": 5, "pathIds": []string{"p0"}},
				{"cappedLoss": 20, "pathIds": []string{"p1", "p2"}},
			},
		},
	})

	rep, err := buildScoreCompareReport(dir)
	if err != nil {
		t.Fatal(err)
	}

	byCode := map[string]float64{}
	for _, c := range rep.Recovered {
		byCode[c.Code] = c.Recovered
	}

	// ISSUE-600: v3 loss 40, v4 contribution 10 (gate) + 5 (its own
	// anchored path, the only one in that bucket) = 15. Recovered = 25.
	if got, want := byCode["ISSUE-600"], 25.0; got != want {
		t.Errorf("ISSUE-600 recovered = %v, want %v (rep.Recovered = %+v)", got, want, rep.Recovered)
	}
	// ISSUE-700 and ISSUE-701 each anchor one path in a two-path bucket
	// capped at 20: each absorbs half. v3 loss 20, v4 contribution 10,
	// recovered 10 each.
	if got, want := byCode["ISSUE-700"], 10.0; got != want {
		t.Errorf("ISSUE-700 recovered = %v, want %v (rep.Recovered = %+v)", got, want, rep.Recovered)
	}
	if got, want := byCode["ISSUE-701"], 10.0; got != want {
		t.Errorf("ISSUE-701 recovered = %v, want %v (rep.Recovered = %+v)", got, want, rep.Recovered)
	}

	// Ordering: most recovered first (ISSUE-600 at 25 before the two at 10).
	if len(rep.Recovered) < 3 || rep.Recovered[0].Code != "ISSUE-600" {
		t.Fatalf("recovered order = %+v, want ISSUE-600 first", rep.Recovered)
	}
	// Tie-break: equal recovered points sort by code string ascending.
	if rep.Recovered[1].Code != "ISSUE-700" || rep.Recovered[2].Code != "ISSUE-701" {
		t.Errorf("recovered tie-break order = %+v, want ISSUE-700 before ISSUE-701", rep.Recovered)
	}
}

// TestAccumulateCodeRecoveryDropsAnUnresolvableAnchorShareWithoutNaN pins
// the len(codes)==0 guard: a pathLosses bucket whose path id resolves,
// through plumberScore.paths, to no code at all (a hand-built or older
// Radar path carrying neither anchorCode nor anchorCodes, which
// comparePath.codes() explicitly tolerates by returning nil) must have its
// share dropped rather than divided by zero. Every TestScoreCompare
// RecoveredAttribution* fixture resolves every path id, so this guard
// never ran before.
func TestAccumulateCodeRecoveryDropsAnUnresolvableAnchorShareWithoutNaN(t *testing.T) {
	acc := map[string]float64{}
	v3 := comparePlumberScore{CodeLosses: []compareCodeLoss{{Code: "ISSUE-900", CappedLoss: 30}}}
	v4 := comparePlumberScore{
		Paths: []control.AttackPath{{ID: "p0"}, {ID: "p1", AnchorCode: "ISSUE-900"}},
		PathLosses: []comparePathLoss{
			{CappedLoss: 15, PathIDs: []string{"p0"}}, // p0 has no anchor code at all: its share is dropped.
			{CappedLoss: 12, PathIDs: []string{"p1"}},
		},
	}
	accumulateCodeRecovery(acc, v3, v4)

	// v3 loss 30, v4 contribution 12 (only the resolvable p1 bucket counts;
	// p0's share is dropped, not divided by zero). Recovered = 18.
	if got, want := acc["ISSUE-900"], 18.0; got != want {
		t.Errorf("ISSUE-900 recovered = %v, want %v", got, want)
	}
	for code, v := range acc {
		if math.IsNaN(v) {
			t.Errorf("acc[%s] = NaN, want the unresolvable bucket's share dropped instead", code)
		}
	}
	if _, ok := acc[""]; ok {
		t.Errorf("acc must not carry an entry for the unresolvable path's (empty) code, got %+v", acc)
	}
}

// TestScoreCompareRecoveredAttributionSplitsMergedPathAcrossAnchorCodes
// pins the merged-path case control/paths.go's AnchorCodes exists for: a
// path two findings anchor together shares its pathLosses cappedLoss
// evenly across every one of its anchorCodes, not just the first
// (anchorCode) alone, so neither finding's own code is overcredited with
// the whole path's loss.
func TestScoreCompareRecoveredAttributionSplitsMergedPathAcrossAnchorCodes(t *testing.T) {
	dir := t.TempDir()
	writeRaw := func(name, suffix string, doc map[string]any) {
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+"."+suffix+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// v3: ISSUE-800 and ISSUE-801 each lost 20 points of their own.
	writeRaw("y", "v3", map[string]any{
		"projectPath": "y",
		"plumberScore": map[string]any{
			"profileId":  "scoring-v3",
			"score":      "E",
			"codeLosses": codeLossesJSON(map[string]float64{"ISSUE-800": 20, "ISSUE-801": 20}),
		},
	})
	// v4: both findings merged into one path (p0), anchored by both
	// codes. Its bucket's whole cappedLoss (20) must split evenly
	// between ISSUE-800 and ISSUE-801, 10 each, not go to ISSUE-800
	// (anchorCode, the first of anchorCodes) alone.
	writeRaw("y", "v4", map[string]any{
		"projectPath": "y",
		"plumberScore": map[string]any{
			"profileId": "scoring-v4",
			"score":     "C",
			"paths": []map[string]any{
				{"id": "p0", "anchorCode": "ISSUE-800", "anchorCodes": []string{"ISSUE-800", "ISSUE-801"}},
			},
			"pathLosses": []map[string]any{
				{"cappedLoss": 20, "pathIds": []string{"p0"}},
			},
		},
	})

	rep, err := buildScoreCompareReport(dir)
	if err != nil {
		t.Fatal(err)
	}

	byCode := map[string]float64{}
	for _, c := range rep.Recovered {
		byCode[c.Code] = c.Recovered
	}
	if got, want := byCode["ISSUE-800"], 10.0; got != want {
		t.Errorf("ISSUE-800 recovered = %v, want %v (rep.Recovered = %+v)", got, want, rep.Recovered)
	}
	if got, want := byCode["ISSUE-801"], 10.0; got != want {
		t.Errorf("ISSUE-801 recovered = %v, want %v (rep.Recovered = %+v)", got, want, rep.Recovered)
	}
}

// A project that dropped two letters or more says why: its worst attack
// path in the line the final screen prints, then the situation facts. A
// pipe in a job name never breaks the table.
func TestScoreCompareDroppedSaysTheWorstPathThenTheFacts(t *testing.T) {
	dir := t.TempDir()
	write := func(profile string, score map[string]any) {
		raw, err := json.Marshal(map[string]any{"projectPath": "p", "plumberScore": score})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "p."+profile+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := func(id, tier string, loss float64) map[string]any {
		return map[string]any{"id": id, "tier": tier, "baseTier": tier, "entryKind": "mutable_dependency", "anchorCode": "ISSUE-102",
			"entry": map[string]any{"subject": "docker.io/alpine:" + id}, "jobs": []string{"est|file"},
			"reach": map[string]any{"secrets": []string{"A", "B"}}, "loss": loss}
	}
	write("v3", map[string]any{"profileId": "scoring-v3", "score": "A", "finalPoints": 95})
	write("v4", map[string]any{"profileId": "scoring-v4", "score": "C", "finalPoints": 55,
		"paths":     []any{path("medium", "medium", 6), path("high", "high", 15)},
		"situation": "Repository: private. Default branch: master, protected. Pipeline: 1 job in 1 pipeline."})
	rep, err := buildScoreCompareReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := `| p | A | C | 2 | high path 1: docker.io/alpine:high (mutable image tag) in job est\|file, reaches 2 secrets, -15 pts. Repository: private. Default branch: master, protected. Pipeline: 1 job in 1 pipeline. |`
	if md := rep.Markdown(); !strings.Contains(md, want) {
		t.Errorf("markdown lacks\n%s\nin:\n%s", want, md)
	}
}
