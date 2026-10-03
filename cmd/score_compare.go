package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/getplumber/plumber/control"
	"github.com/spf13/cobra"
)

// scoreCompareLetters is the full letter range in display order, used both
// to pre-seed the matrix (so an empty cell still prints "0" rather than
// being absent) and to walk it deterministically in Markdown.
var scoreCompareLetters = []string{"A", "B", "C", "D", "E"}

// compareCodeLoss mirrors the subset of control.CodeLoss this report reads
// from plumberScore.codeLosses and plumberScore.gateLosses: which code, and
// how many points it cost after capping.
type compareCodeLoss struct {
	Code       string  `json:"code"`
	CappedLoss float64 `json:"cappedLoss"`
}

// comparePathLoss mirrors the subset of control.PathLoss this report reads
// from plumberScore.pathLosses: the combined cost of every assembled path
// sharing one tier and entry kind, and which path ids share it.
type comparePathLoss struct {
	CappedLoss float64  `json:"cappedLoss"`
	PathIDs    []string `json:"pathIds"`
}

// comparePath mirrors the subset of control.AttackPath this report reads
// from plumberScore.paths: enough to resolve a pathLosses bucket's path ids
// back to the code that anchored each one.
type comparePath struct {
	ID         string `json:"id"`
	AnchorCode string `json:"anchorCode"`
}

// comparePlumberScore mirrors the subset of control.PlumberScoreResult this
// report reads (control/scoring.go, control/scoring_v4.go).
type comparePlumberScore struct {
	ProfileID   string            `json:"profileId"`
	Score       string            `json:"score"`
	FinalPoints float64           `json:"finalPoints"`
	CodeLosses  []compareCodeLoss `json:"codeLosses"`
	PathLosses  []comparePathLoss `json:"pathLosses"`
	GateLosses  []compareCodeLoss `json:"gateLosses"`
	Paths       []comparePath     `json:"paths"`
	Situation   string            `json:"situation"`
}

// compareDoc is one Radar output file: plumber analyze --score-profile
// v3|v4 --output <file>.
type compareDoc struct {
	ProjectPath  string              `json:"projectPath"`
	PlumberScore comparePlumberScore `json:"plumberScore"`
}

// codeRecovery is one code's total points recovered (or lost, if negative)
// across every paired project, summed over the whole corpus.
type codeRecovery struct {
	Code      string
	Recovered float64
}

// droppedProject is a project whose score fell two or more letters from
// scoring-v3 to scoring-v4.
type droppedProject struct {
	Project   string
	V3Letter  string
	V4Letter  string
	Drop      int
	Situation string
}

// scoreCompareReport is the result of comparing every paired
// scoring-v3/scoring-v4 Radar output in a directory.
type scoreCompareReport struct {
	Matrix    map[string]map[string]int
	Recovered []codeRecovery
	Dropped   []droppedProject
	Unpaired  []string
}

// newScoreCompareMatrix pre-seeds every v3-letter by v4-letter cell at 0, so
// the report always prints the full 5x5 grid, not just the cells a corpus
// happened to populate.
func newScoreCompareMatrix() map[string]map[string]int {
	m := make(map[string]map[string]int, len(scoreCompareLetters))
	for _, row := range scoreCompareLetters {
		m[row] = make(map[string]int, len(scoreCompareLetters))
		for _, col := range scoreCompareLetters {
			m[row][col] = 0
		}
	}
	return m
}

// scoreComparePair holds, for one project, the scoring-v3 and scoring-v4
// documents found so far (either may still be nil while files are scanned).
type scoreComparePair struct {
	v3, v4 *compareDoc
}

// buildScoreCompareReport reads every "<project>.v3.json" / "<project>.v4.json"
// pair in dir (the naming plumber analyze --score-profile v3|v4 --output
// produces) and builds the migration report: the letter matrix, the top 20
// codes by points recovered, the projects that dropped two or more letters,
// and any file left without its pair.
func buildScoreCompareReport(dir string) (*scoreCompareReport, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	pairs := map[string]*scoreComparePair{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		var project, profile string
		switch {
		case strings.HasSuffix(name, ".v3.json"):
			project, profile = strings.TrimSuffix(name, ".v3.json"), "v3"
		case strings.HasSuffix(name, ".v4.json"):
			project, profile = strings.TrimSuffix(name, ".v4.json"), "v4"
		default:
			continue // not a Radar comparison file, ignore
		}

		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		var doc compareDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}

		p := pairs[project]
		if p == nil {
			p = &scoreComparePair{}
			pairs[project] = p
		}
		if profile == "v3" {
			p.v3 = &doc
		} else {
			p.v4 = &doc
		}
	}

	projects := make([]string, 0, len(pairs))
	for name := range pairs {
		projects = append(projects, name)
	}
	sort.Strings(projects)

	rep := &scoreCompareReport{Matrix: newScoreCompareMatrix()}
	recovered := map[string]float64{}

	for _, name := range projects {
		p := pairs[name]
		if p.v3 == nil || p.v4 == nil {
			rep.Unpaired = append(rep.Unpaired, name)
			continue
		}

		v3Letter := strings.ToUpper(p.v3.PlumberScore.Score)
		v4Letter := strings.ToUpper(p.v4.PlumberScore.Score)
		matrixRow(rep.Matrix, v3Letter)[v4Letter]++

		drop := control.ScoreLetterRank(v3Letter) - control.ScoreLetterRank(v4Letter)
		if drop >= 2 {
			rep.Dropped = append(rep.Dropped, droppedProject{
				Project:   name,
				V3Letter:  v3Letter,
				V4Letter:  v4Letter,
				Drop:      drop,
				Situation: p.v4.PlumberScore.Situation,
			})
		}

		accumulateCodeRecovery(recovered, p.v3.PlumberScore, p.v4.PlumberScore)
	}

	sort.Slice(rep.Dropped, func(i, j int) bool {
		if rep.Dropped[i].Drop != rep.Dropped[j].Drop {
			return rep.Dropped[i].Drop > rep.Dropped[j].Drop
		}
		return rep.Dropped[i].Project < rep.Dropped[j].Project
	})

	rep.Recovered = topCodeRecoveries(recovered, 20)

	return rep, nil
}

// matrixRow returns the matrix row for letter, creating it if the letter
// fell outside A..E (malformed input never panics the report).
func matrixRow(m map[string]map[string]int, letter string) map[string]int {
	row := m[letter]
	if row == nil {
		row = map[string]int{}
		m[letter] = row
	}
	return row
}

// accumulateCodeRecovery adds one project's per-code points recovered (v3
// loss minus v4 contribution) into acc, keyed by code, summed across the
// whole corpus as the caller walks every paired project.
//
// A code's v4 contribution is:
//   - its gateLosses entry (a gate-role finding still priced per code,
//     exactly as v3 prices every code) when gateLosses is present, falling
//     back to codeLosses otherwise (on scoring-v4 output the two are the
//     same content, codeLosses being exactly the gate losses restated);
//     plus
//   - an even share of every pathLosses bucket's cappedLoss, one share per
//     path id in that bucket, attributed through plumberScore.paths (each
//     path id's anchorCode) to the code that anchored it.
func accumulateCodeRecovery(acc map[string]float64, v3, v4 comparePlumberScore) {
	v3Loss := map[string]float64{}
	for _, cl := range v3.CodeLosses {
		v3Loss[cl.Code] += cl.CappedLoss
	}

	v4Loss := map[string]float64{}
	gateLosses := v4.GateLosses
	if len(gateLosses) == 0 {
		gateLosses = v4.CodeLosses
	}
	for _, gl := range gateLosses {
		v4Loss[gl.Code] += gl.CappedLoss
	}

	anchorCodeByPathID := map[string]string{}
	for _, p := range v4.Paths {
		anchorCodeByPathID[p.ID] = p.AnchorCode
	}
	for _, pl := range v4.PathLosses {
		if len(pl.PathIDs) == 0 {
			continue
		}
		share := pl.CappedLoss / float64(len(pl.PathIDs))
		for _, id := range pl.PathIDs {
			code := anchorCodeByPathID[id]
			if code == "" {
				continue // path id has no resolvable anchor code, skip its share
			}
			v4Loss[code] += share
		}
	}

	codes := map[string]struct{}{}
	for c := range v3Loss {
		codes[c] = struct{}{}
	}
	for c := range v4Loss {
		codes[c] = struct{}{}
	}
	for c := range codes {
		acc[c] += v3Loss[c] - v4Loss[c]
	}
}

// topCodeRecoveries sorts acc by points recovered descending, code string
// ascending on ties, and keeps the top n.
func topCodeRecoveries(acc map[string]float64, n int) []codeRecovery {
	out := make([]codeRecovery, 0, len(acc))
	for code, points := range acc {
		out = append(out, codeRecovery{Code: code, Recovered: points})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Recovered != out[j].Recovered {
			return out[i].Recovered > out[j].Recovered
		}
		return out[i].Code < out[j].Code
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Markdown renders the report in the headings docs/scoring-v4-migration.md
// documents.
func (r *scoreCompareReport) Markdown() string {
	var b strings.Builder

	b.WriteString("## Letter migration matrix\n\n")
	b.WriteString("v3 rows, v4 columns, repository counts.\n\n")
	b.WriteString("| v3 \\ v4 |")
	for _, col := range scoreCompareLetters {
		fmt.Fprintf(&b, " %s |", col)
	}
	b.WriteString("\n|---|")
	for range scoreCompareLetters {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, row := range scoreCompareLetters {
		fmt.Fprintf(&b, "| %s |", row)
		for _, col := range scoreCompareLetters {
			fmt.Fprintf(&b, " %d |", r.Matrix[row][col])
		}
		b.WriteString("\n")
	}

	b.WriteString("\n## Top 20 codes by points recovered\n\n")
	if len(r.Recovered) == 0 {
		b.WriteString("None.\n")
	} else {
		b.WriteString("| Code | Points recovered |\n|---|---|\n")
		for _, c := range r.Recovered {
			fmt.Fprintf(&b, "| %s | %.2f |\n", c.Code, c.Recovered)
		}
	}

	b.WriteString("\n## Dropped two or more letters\n\n")
	if len(r.Dropped) == 0 {
		b.WriteString("None.\n")
	} else {
		b.WriteString("| Project | v3 | v4 | Letters down | Situation |\n|---|---|---|---|---|\n")
		for _, d := range r.Dropped {
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %s |\n", d.Project, d.V3Letter, d.V4Letter, d.Drop, d.Situation)
		}
	}

	b.WriteString("\n## Unpaired\n\n")
	if len(r.Unpaired) == 0 {
		b.WriteString("None.\n")
	} else {
		for _, name := range r.Unpaired {
			fmt.Fprintf(&b, "- %s\n", name)
		}
	}

	return b.String()
}

var (
	scoreCompareInput  string
	scoreCompareOutput string
)

// scoreCompareCmd is hidden: it is a Radar operational tool, not a
// user-facing analyze workflow (same reasoning as the other internal
// commands this package hides).
var scoreCompareCmd = &cobra.Command{
	Use:    "score-compare",
	Short:  "Compare paired scoring-v3 and scoring-v4 Radar results",
	Hidden: true,
	Long: `Read every "<project>.v3.json" / "<project>.v4.json" pair that
plumber analyze --score-profile v3|v4 --output produced for the same
repository, and write the migration report: the letter matrix, the top 20
codes by points recovered, and the projects whose score dropped two or
more letters moving from scoring-v3 to scoring-v4.

This is the tool side of the Radar corpus run; running the CLI twice over
the corpus and feeding this command its output directory is operational
work, done separately.`,
	RunE: runScoreCompare,
}

func init() {
	scoreCompareCmd.Flags().StringVar(&scoreCompareInput, "input", "", "directory holding the <project>.v3.json / <project>.v4.json Radar output pairs (required)")
	scoreCompareCmd.Flags().StringVar(&scoreCompareOutput, "output", "", "file to write the markdown report to (default: stdout)")
	rootCmd.AddCommand(scoreCompareCmd)
}

func runScoreCompare(cmd *cobra.Command, args []string) error {
	if scoreCompareInput == "" {
		return fmt.Errorf("--input is required")
	}

	rep, err := buildScoreCompareReport(scoreCompareInput)
	if err != nil {
		return err
	}

	md := rep.Markdown()
	if scoreCompareOutput == "" {
		_, err := fmt.Fprint(cmd.OutOrStdout(), md)
		return err
	}
	if err := os.WriteFile(scoreCompareOutput, []byte(md), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", scoreCompareOutput, err)
	}
	return nil
}
