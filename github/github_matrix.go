package github

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/getplumber/plumber/internal/ir"
)

// maxMatrixCombinations bounds the expansion of a reference built from
// matrix values: past it the reference is left unresolved rather than
// listing a combinatorial set of images.
const maxMatrixCombinations = 64

// maxMatrixJobs is the most combinations GitHub runs for one matrix; a
// matrix declaring more does not run, and is not read.
const maxMatrixJobs = 256

// matrixValueExpr matches one `${{ matrix.KEY }}` expression.
var matrixValueExpr = regexp.MustCompile(`\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}`)

// containerImageRef is the image reference a job's `container:` names, as
// written: the shortcut string or the long form's image field.
func containerImageRef(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case map[any]any:
		m, _ := ghCastStringMap(c)
		if img, ok := m["image"].(string); ok {
			return img
		}
	}
	return ""
}

// matrixImages resolves an image reference built from `${{ matrix.X }}`
// values to the image of each combination the job's matrix runs, sorted
// and de-duplicated. Nil when the reference holds no matrix value, holds
// any other expression, or names a key some combination gives no literal
// for, or the matrix itself is computed at run time.
func matrixImages(ref string, section map[string]any) []ir.Image {
	refs := expandMatrixRef(ref, matrixCombinations(section))
	if len(refs) == 0 {
		return nil
	}
	out := make([]ir.Image, 0, len(refs))
	for _, r := range refs {
		out = append(out, splitImageRef(r))
	}
	return out
}

// expandMatrixRef is ref once per matrix combination, every
// `${{ matrix.KEY }}` of it replaced by that combination's value for KEY
// (so a key used twice takes the same value twice), sorted and
// de-duplicated. Nil when nothing can be resolved: no matrix value in ref,
// another expression, a combination without a literal for a key ref uses,
// or more distinct references than maxMatrixCombinations.
func expandMatrixRef(ref string, combos []map[string]string) []string {
	if !matrixValueExpr.MatchString(ref) || len(combos) == 0 {
		return nil
	}
	// Any expression left once the matrix values are taken out is decided
	// at run time: the reference cannot be listed.
	if strings.Contains(matrixValueExpr.ReplaceAllString(ref, ""), "${{") {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, combo := range combos {
		missing := false
		r := matrixValueExpr.ReplaceAllStringFunc(ref, func(expr string) string {
			v, ok := combo[matrixValueExpr.FindStringSubmatch(expr)[1]]
			missing = missing || !ok
			return v
		})
		if missing {
			return nil
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	if len(out) > maxMatrixCombinations {
		return nil
	}
	sort.Strings(out)
	return out
}

// runtimeValue stands for a matrix value decided at run time (a list
// written as an expression): it equals no literal, and has none.
type runtimeValue struct{}

// matrixCombinations reads `strategy.matrix` into the combinations GitHub runs,
// each as its keys' scalar values: the cartesian product of the matrix's
// lists, less every combination an `exclude:` entry matches, then each
// `include:` entry merged into every original combination none of whose
// original values it would change (it may overwrite a value an earlier
// entry added), or run as a combination of its own when it matches none.
// A value that is not a plain scalar (a list, a map, an expression) is
// left out of its combination, so a reference using it stays unresolved.
// Nil when the matrix is not a literal map (`${{ fromJSON(...) }}`) or
// declares more than maxMatrixJobs combinations.
func matrixCombinations(section map[string]any) []map[string]string {
	strategy, ok := ghCastStringMap(section["strategy"])
	if !ok {
		return nil
	}
	matrix, ok := ghCastStringMap(strategy["matrix"])
	if !ok {
		return nil
	}
	var axes []string
	for key := range matrix {
		if key != "include" && key != "exclude" {
			axes = append(axes, key)
		}
	}
	sort.Strings(axes)
	var combos []map[string]any
	if len(axes) > 0 {
		combos = []map[string]any{{}}
	}
	for _, key := range axes {
		values, ok := matrix[key].([]any)
		if !ok {
			values = []any{runtimeValue{}}
		}
		if len(combos)*len(values) > maxMatrixJobs {
			return nil
		}
		next := make([]map[string]any, 0, len(combos)*len(values))
		for _, combo := range combos {
			for _, v := range values {
				r := make(map[string]any, len(combo)+1)
				for k, x := range combo {
					r[k] = x
				}
				r[key] = v
				next = append(next, r)
			}
		}
		combos = next
	}
	matches := func(combo, entry map[string]any, only map[string]bool) bool {
		for k, v := range entry {
			if (only == nil || only[k]) && !reflect.DeepEqual(combo[k], v) {
				return false
			}
		}
		return true
	}
	for _, entry := range matrixEntries(matrix["exclude"]) {
		kept := combos[:0]
		for _, combo := range combos {
			if !matches(combo, entry, nil) {
				kept = append(kept, combo)
			}
		}
		combos = kept
	}
	original := map[string]bool{}
	for _, key := range axes {
		original[key] = true
	}
	var added []map[string]any
	for _, entry := range matrixEntries(matrix["include"]) {
		merged := false
		for _, combo := range combos {
			if matches(combo, entry, original) {
				merged = true
				for k, v := range entry {
					combo[k] = v
				}
			}
		}
		if !merged {
			added = append(added, entry)
		}
	}
	combos = append(combos, added...)
	if len(combos) > maxMatrixJobs {
		return nil
	}
	out := make([]map[string]string, 0, len(combos))
	for _, combo := range combos {
		r := make(map[string]string, len(combo))
		for k, v := range combo {
			if s, ok := matrixScalar(v); ok {
				r[k] = s
			}
		}
		out = append(out, r)
	}
	return out
}

// matrixEntries is the maps an `include:` or `exclude:` list holds, each a
// copy; anything else in the list is skipped.
func matrixEntries(v any) []map[string]any {
	list, _ := v.([]any)
	var out []map[string]any
	for _, e := range list {
		if m, ok := ghCastStringMap(e); ok {
			out = append(out, m)
		}
	}
	return out
}

// matrixScalar renders a matrix value that is a plain scalar, as GitHub
// reads it: an unquoted 3.10 is the number 3.1.
func matrixScalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		if strings.Contains(x, "${{") {
			return "", false
		}
		return x, true
	case int, int64, uint64, float64, bool:
		return fmt.Sprint(x), true
	}
	return "", false
}
