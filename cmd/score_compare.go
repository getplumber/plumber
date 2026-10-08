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
// from plumberScore.codeLosses: which code, and how many points it cost
// after capping.
type compareCodeLoss struct {
	Code       string  `json:"code"`
	CappedLoss float64 `json:"cappedLoss"`
}

// comparePathLoss mirrors the subset of control.PathLoss this report reads
// from plumberScore.pathLosses: the combined cost of every assembled path
// of one tier, and which path ids share it.
type comparePathLoss struct {
	CappedLoss float64  `json:"cappedLoss"`
	PathIDs    []string `json:"pathIds"`
}

// pathCodes is every code a path is anchored by: AnchorCodes, falling back
// to AnchorCode alone when the list is absent (an older Radar output, or a
// path control/paths.go built by hand rather than through AssemblePaths).
// It resolves a pathLosses bucket's path ids back to the code (or codes,
// for a merged path) that anchored each one.
func pathCodes(p control.AttackPath) []string {
	if len(p.AnchorCodes) > 0 {
		codes := make([]string, len(p.AnchorCodes))
		for i, c := range p.AnchorCodes {
			codes[i] = string(c)
		}
		return codes
	}
	if p.AnchorCode != "" {
		return []string{string(p.AnchorCode)}
	}
	return nil
}

// comparePlumberScore mirrors the subset of control.PlumberScoreResult this
// report reads (control/scoring.go, control/scoring_v4.go).
type comparePlumberScore struct {
	ProfileID   string               `json:"profileId"`
	Score       string               `json:"score"`
	FinalPoints float64              `json:"finalPoints"`
	CodeLosses  []compareCodeLoss    `json:"codeLosses"`
	PathLosses  []comparePathLoss    `json:"pathLosses"`
	Paths       []control.AttackPath `json:"paths"`
	Situation   string               `json:"situation"`
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
				Situation: droppedSituation(p.v4.PlumberScore),
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

// droppedSituation says why a project dropped: its worst attack path in
// the line the final screen prints, then the situation facts. A Radar
// output carries names read off the scanned repository, so the cell is
// one line and its pipes are escaped.
func droppedSituation(s comparePlumberScore) string {
	text := s.Situation
	if paths := control.PathsWorstFirst(s.Paths); len(paths) > 0 {
		p := paths[0]
		text = fmt.Sprintf("%s path 1: %s, -%s pts. %s", p.Tier, control.PathSummary(p), fmtPoints(p.Loss), text)
	}
	text = strings.Join(strings.Fields(sanitizeTerminal(text)), " ")
	return strings.ReplaceAll(text, "|", `\|`)
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
//   - its codeLosses entry (on scoring-v4 output, the other findings per
//     code, each code's share of the capped bucket); plus
//   - an even share of every pathLosses bucket's cappedLoss, one share per
//     path id in that bucket, attributed through plumberScore.paths to the
//     code that anchored it; a merged path (two or more findings sharing
//     one entry and one subject) splits its
//     own share again, evenly across every one of its anchorCodes, so a
//     finding that only co-anchors a path is not overcredited with the
//     whole thing, falling back to anchorCode alone when the list is
//     absent.
func accumulateCodeRecovery(acc map[string]float64, v3, v4 comparePlumberScore) {
	v3Loss := map[string]float64{}
	for _, cl := range v3.CodeLosses {
		v3Loss[cl.Code] += cl.CappedLoss
	}

	v4Loss := map[string]float64{}
	for _, cl := range v4.CodeLosses {
		v4Loss[cl.Code] += cl.CappedLoss
	}

	codesByPathID := map[string][]string{}
	for _, p := range v4.Paths {
		codesByPathID[p.ID] = pathCodes(p)
	}
	for _, pl := range v4.PathLosses {
		if len(pl.PathIDs) == 0 {
			continue
		}
		share := pl.CappedLoss / float64(len(pl.PathIDs))
		for _, id := range pl.PathIDs {
			codes := codesByPathID[id]
			if len(codes) == 0 {
				continue // path id has no resolvable anchor code, skip its share
			}
			perCode := share / float64(len(codes))
			for _, code := range codes {
				v4Loss[code] += perCode
			}
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
