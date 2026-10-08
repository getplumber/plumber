package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/finding/identity"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/runcache"
)

var (
	explainAttack   string
	explainRun      string
	explainProject  string
	explainProvider string
)

// userCacheDir is where the run cache lives (os.UserCacheDir, which
// honours XDG_CACHE_HOME on Linux); tests point it elsewhere.
var userCacheDir = os.UserCacheDir

// runCacheRoot is the run cache's root directory.
func runCacheRoot() (string, error) {
	dir, err := userCacheDir()
	if err != nil {
		return "", err
	}
	return runcache.Root(dir), nil
}

// cacheReport keeps the JSON report of this run in the run cache, under
// the provider and project, or the working directory when the run has no
// project path. Best-effort: a failure is a debug line, never an error or
// a warning of the run.
func cacheReport(provider, project string, payload []byte) {
	root, err := runCacheRoot()
	if err != nil {
		logrus.Debugf("run cache: no user cache directory: %v", err)
		return
	}
	cwd := ""
	if project == "" {
		if wd, err := os.Getwd(); err == nil {
			cwd, _ = filepath.Abs(wd)
		}
	}
	if err := runcache.Write(root, runcache.Key(provider, project, cwd), payload); err != nil {
		logrus.Debugf("run cache: report not kept: %v", err)
	}
}

// jsonPathBlock is a path block as the JSON report's pathBlocks carry it
// (control.PathBlock with its findings), keyed by the path's id, so a
// report read back prints the block the run printed.
type jsonPathBlock struct {
	ID              string                 `json:"id"`
	Tier            control.PathTier       `json:"tier"`
	Unverified      bool                   `json:"unverified,omitempty"`
	Loss            float64                `json:"loss"`
	Entry           string                 `json:"entry"`
	EntrySubject    string                 `json:"entrySubject,omitempty"`
	Branches        []jsonPathBlockBranch  `json:"branches"`
	EntryWriter     string                 `json:"entryWriter,omitempty"`
	EntryUnverified string                 `json:"entryUnverified,omitempty"`
	RunsIn          string                 `json:"runsIn,omitempty"`
	ReachesShort    string                 `json:"reachesShort,omitempty"`
	ReachUnverified string                 `json:"reachUnverified,omitempty"`
	So              string                 `json:"so,omitempty"`
	Cap             string                 `json:"cap,omitempty"`
	Environment     []string               `json:"environment,omitempty"`
	Fix             string                 `json:"fix,omitempty"`
	Findings        []jsonPathBlockFinding `json:"findings"`
}

type jsonPathBlockBranch struct {
	Job    string     `json:"job"`
	Fed    []string   `json:"fed,omitempty"`
	FedVia [][]string `json:"fedVia,omitempty"`
	Reach  string     `json:"reach"`
	Marker string     `json:"marker,omitempty"`
}

type jsonPathBlockFinding struct {
	Code     control.ErrorCode `json:"code"`
	Title    string            `json:"title"`
	Location string            `json:"location,omitempty"`
	Count    int               `json:"count,omitempty"`
	// Details is every finding the line stands for, in full, in file and
	// line order, so `explain -a` prints each one as the details section
	// does. Empty in a report written before it was carried.
	Details []jsonPathFindingDetail `json:"details,omitempty"`
}

// jsonPathFindingDetail is one finding of a path block line: its own
// message, its contextual severity, its forge URL when the run has one,
// its file:line, and the sub-lines some codes carry (ISSUE-505).
type jsonPathFindingDetail struct {
	Message     string   `json:"message"`
	Severity    string   `json:"severity,omitempty"`
	URL         string   `json:"url,omitempty"`
	Location    string   `json:"location,omitempty"`
	DetailLines []string `json:"detailLines,omitempty"`
}

func jsonPathBlockOf(id string, b control.PathBlock) jsonPathBlock {
	j := jsonPathBlock{
		ID: id, Tier: b.Tier, Unverified: b.Unverified, Loss: b.Loss, Entry: b.Entry, EntrySubject: b.EntrySubject,
		EntryWriter: b.EntryWriter, EntryUnverified: b.EntryUnverified, RunsIn: b.RunsIn, ReachesShort: b.ReachesShort,
		ReachUnverified: b.ReachUnverified, So: b.So, Cap: b.Cap, Environment: b.Environment, Fix: b.Fix,
		Branches: []jsonPathBlockBranch{}, Findings: []jsonPathBlockFinding{},
	}
	for _, br := range b.Branches {
		j.Branches = append(j.Branches, jsonPathBlockBranch(br))
	}
	for _, f := range b.Findings {
		j.Findings = append(j.Findings, jsonPathBlockFinding{Code: f.Code, Title: f.Title, Location: f.Location, Count: f.Count})
	}
	return j
}

func (j jsonPathBlock) block() control.PathBlock {
	b := control.PathBlock{
		Tier: j.Tier, Unverified: j.Unverified, Loss: j.Loss, Entry: j.Entry, EntrySubject: j.EntrySubject,
		EntryWriter: j.EntryWriter, EntryUnverified: j.EntryUnverified, RunsIn: j.RunsIn, ReachesShort: j.ReachesShort,
		ReachUnverified: j.ReachUnverified, So: j.So, Cap: j.Cap, Environment: j.Environment, Fix: j.Fix,
	}
	for _, br := range j.Branches {
		b.Branches = append(b.Branches, control.PathBlockBranch(br))
	}
	for _, f := range j.Findings {
		b.Findings = append(b.Findings, control.PathBlockFinding{Code: f.Code, Title: f.Title, Location: f.Location, Count: f.Count})
	}
	return b
}

// details is every finding of the block in full, one group per line of
// its Findings list, the way the details section prints a finding; nil
// when a line carries none (a report written before they were carried),
// and the block then lists its findings one line per code.
func (j jsonPathBlock) details(p control.AttackPath) []findingCodeGroup {
	var out []findingCodeGroup
	for _, f := range j.Findings {
		if len(f.Details) == 0 {
			return nil
		}
		// The block's Fix line fixes its entry; a finding that does not
		// anchor the path (a privilege, a gate) says its own fix.
		group := findingCodeGroup{Code: f.Code, Title: f.Title}
		if f.Code != p.AnchorCode && !slices.Contains(p.AnchorCodes, f.Code) {
			group.Fix = codeFix(f.Code)
		}
		for _, d := range f.Details {
			loc := d.URL
			if loc == "" {
				loc = d.Location
			}
			group.Findings = append(group.Findings, detailedFinding{
				Code: f.Code, Message: d.Message, DocURL: f.Code.DocURL(), Location: loc,
				File: fileOfLocation(d.Location), DetailLines: d.DetailLines, ContextualSeverity: d.Severity,
			})
		}
		out = append(out, group)
	}
	return out
}

// fileOfLocation is the file of a file:line location.
func fileOfLocation(loc string) string {
	if i := strings.LastIndex(loc, ":"); i >= 0 && strings.Trim(loc[i+1:], "0123456789") == "" {
		return loc[:i]
	}
	return loc
}

// jsonPathBlocks is every path's block, worst first, for the JSON report,
// each line of its Findings list carrying its findings in full.
// defaultBranch is the pipeline's, which a finding on no path is priced
// against.
func jsonPathBlocks(paths []control.AttackPath, findings []opaengine.Finding, defaultBranch string) []jsonPathBlock {
	byHash := map[string]opaengine.Finding{}
	for _, f := range findings {
		if f.Dismissed {
			continue
		}
		if h, _, ok := identity.PlatformHash(f.IdentityInput()); ok {
			if _, dup := byHash[h]; !dup {
				byHash[h] = f
			}
		}
	}
	out := []jsonPathBlock{}
	for _, p := range control.PathsWorstFirst(paths) {
		j := jsonPathBlockOf(p.ID, control.NewPathBlock(p, findings))
		addFindingDetails(&j, p, paths, byHash, defaultBranch)
		out = append(out, j)
	}
	return out
}

// addFindingDetails fills in each line of j's Findings list with the live
// findings of p it stands for (p's anchors, gates and privilege findings,
// by their identity hash, the hash the path keeps), in file and line
// order: the message, the contextual severity across paths, the forge
// URL and file:line.
func addFindingDetails(j *jsonPathBlock, p control.AttackPath, paths []control.AttackPath, byHash map[string]opaengine.Finding, defaultBranch string) {
	byCode := map[control.ErrorCode][]opaengine.Finding{}
	seen := map[string]bool{}
	for _, h := range slices.Concat(p.AllAnchorHashes(), p.GateHashes, p.FindingIDs) {
		f, ok := byHash[h]
		if !ok || seen[h] {
			continue
		}
		seen[h] = true
		byCode[control.ErrorCode(f.Code)] = append(byCode[control.ErrorCode(f.Code)], f)
	}
	for i := range j.Findings {
		fs := byCode[j.Findings[i].Code]
		sort.SliceStable(fs, func(a, b int) bool {
			return fs[a].File < fs[b].File || fs[a].File == fs[b].File && fs[a].Line < fs[b].Line
		})
		for _, f := range fs {
			loc := f.File
			if loc != "" && f.Line > 0 {
				loc += ":" + strconv.Itoa(f.Line)
			}
			j.Findings[i].Details = append(j.Findings[i].Details, jsonPathFindingDetail{
				Message: f.Message, Severity: string(control.ContextualSeverity(f, paths, defaultBranch)), URL: f.URL,
				Location: loc, DetailLines: detailLinesFromFinding(f),
			})
		}
	}
}

// attackSource is the report `explain -a` reads: a file written by
// --output (run), a project's cached run (project, under provider when
// set), or the last cached run.
type attackSource struct {
	run      string
	project  string
	provider string
}

// readAttackReport reads the report src names and says where it is.
func readAttackReport(src attackSource) ([]byte, string, error) {
	if src.run != "" {
		raw, err := os.ReadFile(src.run)
		return raw, src.run, err
	}
	root, err := runCacheRoot()
	if err != nil {
		return nil, "", fmt.Errorf("no user cache directory to read a run from (%v): pass --run with a report written by --output", err)
	}
	var file string
	if src.project != "" {
		file, err = runcache.Find(root, src.provider, src.project)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", fmt.Errorf("%v: run plumber analyze on it first", err)
		}
	} else {
		file, err = runcache.Last(root)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", fmt.Errorf("no cached run at %s: run plumber analyze first", filepath.Join(root, "last"))
		}
	}
	if err != nil {
		return nil, "", err
	}
	raw, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", fmt.Errorf("no cached run at %s: run plumber analyze first", file)
	}
	return raw, file, err
}

// runExplainAttack prints the attack path numbered sel ("all" for every
// one) of the report src names, numbered worst first as every report
// numbers them, each block with its findings and their documentation.
func runExplainAttack(out io.Writer, sel string, src attackSource, caps termCaps) error {
	if sel == "" {
		return errors.New("--run, --project and --provider choose the report of --attack (-a): add -a with a path number or all")
	}
	if src.run != "" && src.project != "" {
		return errors.New("--run and --project both name a report: pass one")
	}
	raw, where, err := readAttackReport(src)
	if err != nil {
		return err
	}
	var doc struct {
		PlumberScore *struct {
			Paths []control.AttackPath `json:"paths"`
		} `json:"plumberScore"`
		PathBlocks []jsonPathBlock `json:"pathBlocks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%s is not a Plumber JSON report: %w", where, err)
	}
	var paths []control.AttackPath
	if doc.PlumberScore != nil {
		paths = control.PathsWorstFirst(doc.PlumberScore.Paths)
	}
	if len(paths) == 0 {
		return fmt.Errorf("the run in %s has no attack path", where)
	}
	blocks := map[string]jsonPathBlock{}
	for _, j := range doc.PathBlocks {
		blocks[j.ID] = j
	}
	numbers := []int{}
	if strings.EqualFold(sel, "all") {
		for i := range paths {
			numbers = append(numbers, i+1)
		}
	} else {
		n, err := strconv.Atoi(sel)
		if err != nil || n < 1 || n > len(paths) {
			return fmt.Errorf("the run in %s has %s: -a takes a number from 1 to %d, or all, not %q", where, plural(len(paths), "attack path", "attack paths"), len(paths), sel)
		}
		numbers = append(numbers, n)
	}
	for _, n := range numbers {
		if _, ok := blocks[paths[n-1].ID]; !ok {
			return fmt.Errorf("the report in %s does not carry the details of its attack paths: run plumber analyze again", where)
		}
	}
	for i, n := range numbers {
		if i > 0 {
			fprintPathRule(out, caps)
		}
		j := blocks[paths[n-1].ID]
		opts := explainBlock
		opts.Details = j.details(paths[n-1])
		renderPathBlock(out, n, j.block(), caps, opts)
	}
	return nil
}
