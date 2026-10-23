package github

import (
	"maps"
	"strings"

	yamlv3 "gopkg.in/yaml.v3"

	"github.com/getplumber/plumber/internal/ir"
)

// jobLocations is where one job's constructs sit in its workflow file,
// read off the YAML node tree so a finding can point at the line it is
// about instead of the job header (#572).
type jobLocations struct {
	keys      map[string]int
	image     int
	variables map[string]int
	// scripts is the line of every "\n"-split line of each non-empty
	// run: string, steps in order: the same walk extractGitHubRunScripts
	// does, so the two pair index for index when they agree in length.
	scripts [][]int
}

// scanGitHubJobLocations returns the locations of every job of a
// workflow, by job id. A job that does not set permissions: takes the
// workflow-level key's line, as it takes the block itself, and its
// variables start from the workflow env: lines, job then step entries
// overriding them in the order mergedEnv merges the values.
func scanGitHubJobLocations(data []byte) map[string]jobLocations {
	out := map[string]jobLocations{}
	var doc yamlv3.Node
	if err := yamlv3.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return out
	}
	root := doc.Content[0]
	jobs := mappingValue(root, "jobs")
	if jobs == nil || jobs.Kind != yamlv3.MappingNode {
		return out
	}
	wfPerms := 0
	if k := mappingKey(root, "permissions"); k != nil {
		wfPerms = k.Line
	}
	wfEnv := envLines(mappingValue(root, "env"))
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		section := jobs.Content[i+1]
		if section.Kind != yamlv3.MappingNode {
			continue
		}
		loc := jobLocations{keys: map[string]int{}, variables: map[string]int{}}
		for k := 0; k+1 < len(section.Content); k += 2 {
			loc.keys[section.Content[k].Value] = section.Content[k].Line
		}
		if _, own := loc.keys["permissions"]; !own && wfPerms > 0 {
			loc.keys["permissions"] = wfPerms
		}
		loc.image = containerImageLine(mappingValue(section, "container"))
		maps.Copy(loc.variables, wfEnv)
		maps.Copy(loc.variables, envLines(mappingValue(section, "env")))
		if steps := mappingValue(section, "steps"); steps != nil && steps.Kind == yamlv3.SequenceNode {
			for _, step := range steps.Content {
				maps.Copy(loc.variables, envLines(mappingValue(step, "env")))
				if run := mappingValue(step, "run"); isNonEmptyString(run) {
					loc.scripts = append(loc.scripts, scalarLines(run))
				}
			}
		}
		out[jobs.Content[i].Value] = loc
	}
	return out
}

// applyJobLocations copies a job's locations onto it. ScriptLines is
// set only when the scan found exactly as many run: scripts as the
// decoder did: the two read the same steps with different YAML
// versions (`run: yes` is a boolean to one, a string to the other), and
// a list that does not pair index for index would name wrong lines.
func applyJobLocations(job *ir.Job, loc jobLocations) {
	if len(loc.keys) > 0 {
		job.KeyLines = loc.keys
	}
	if len(loc.variables) > 0 && len(job.Variables) > 0 {
		job.VariableLines = loc.variables
	}
	if len(loc.scripts) > 0 && len(loc.scripts) == len(job.Scripts) {
		job.ScriptLines = loc.scripts
	}
	if loc.image > 0 {
		if job.Image != nil {
			job.Image.Line = loc.image
		}
		for k := range job.MatrixImages {
			job.MatrixImages[k].Line = loc.image
		}
	}
}

// clearJobLocations drops every line applyJobLocations set: on a job of
// a workflow called from another repository they are lines of that
// file, and the finding must land on the calling job instead.
func clearJobLocations(job *ir.Job) {
	job.KeyLines, job.VariableLines, job.ScriptLines = nil, nil, nil
	if job.Image != nil {
		img := *job.Image
		img.Line = 0
		job.Image = &img
	}
	for k := range job.MatrixImages {
		job.MatrixImages[k].Line = 0
	}
}

// containerImageLine is the line of a container: reference, in its
// string form or as the image: of its mapping form.
func containerImageLine(n *yamlv3.Node) int {
	if n == nil {
		return 0
	}
	if n.Kind == yamlv3.ScalarNode {
		return n.Line
	}
	if img := mappingValue(n, "image"); img != nil && img.Kind == yamlv3.ScalarNode {
		return img.Line
	}
	return 0
}

// envLines is the key line of every entry of an env: mapping.
func envLines(n *yamlv3.Node) map[string]int {
	if n == nil || n.Kind != yamlv3.MappingNode {
		return nil
	}
	out := make(map[string]int, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		out[n.Content[i].Value] = n.Content[i].Line
	}
	return out
}

func isNonEmptyString(n *yamlv3.Node) bool {
	return n != nil && n.Kind == yamlv3.ScalarNode && n.Tag == "!!str" && n.Value != ""
}

// scalarLines maps each "\n"-split line of a scalar's value to its source
// line. A literal block keeps its lines as written, starting on the line
// after its indicator. Any other style folds or joins lines, or spells a
// newline as an escape, so its lines are reported at the line the value
// starts on: the line after the indicator for a folded block, the
// scalar's own line otherwise.
func scalarLines(n *yamlv3.Node) []int {
	count := strings.Count(n.Value, "\n") + 1
	out := make([]int, count)
	switch {
	case n.Style&yamlv3.LiteralStyle != 0:
		for i := range out {
			out[i] = n.Line + 1 + i
		}
	case n.Style&yamlv3.FoldedStyle != 0:
		for i := range out {
			out[i] = n.Line + 1
		}
	default:
		for i := range out {
			out[i] = n.Line
		}
	}
	return out
}
