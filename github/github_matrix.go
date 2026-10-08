package github

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/getplumber/plumber/internal/ir"
)

// maxMatrixCombinations bounds the expansion of a reference built from
// several matrix keys: past it the reference is left unresolved rather
// than listing a combinatorial set of images.
const maxMatrixCombinations = 64

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
// values to the images the job's matrix lists as literals, one per value
// (the cartesian product when several keys are used), sorted and
// de-duplicated. Nil when the reference holds no matrix value, holds any
// other expression, names a key the matrix gives no literal for, or the
// matrix itself is computed at run time.
func matrixImages(ref string, section map[string]any) []ir.Image {
	refs := expandMatrixRef(ref, matrixLiterals(section))
	if len(refs) == 0 {
		return nil
	}
	out := make([]ir.Image, 0, len(refs))
	for _, r := range refs {
		out = append(out, splitImageRef(r))
	}
	return out
}

// expandMatrixRef substitutes every `${{ matrix.KEY }}` of ref with each
// literal the matrix lists for KEY. Nil when nothing can be resolved.
func expandMatrixRef(ref string, literals map[string][]string) []string {
	if !matrixValueExpr.MatchString(ref) {
		return nil
	}
	// Any expression left once the matrix values are taken out is decided
	// at run time: the reference cannot be listed.
	if strings.Contains(matrixValueExpr.ReplaceAllString(ref, ""), "${{") {
		return nil
	}
	refs := []string{ref}
	for _, m := range matrixValueExpr.FindAllStringSubmatch(ref, -1) {
		values, ok := literals[m[1]]
		if !ok || len(values) == 0 {
			return nil
		}
		if len(refs)*len(values) > maxMatrixCombinations {
			return nil
		}
		var next []string
		for _, r := range refs {
			for _, v := range values {
				next = append(next, strings.Replace(r, m[0], v, 1))
			}
		}
		refs = next
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range refs {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// matrixLiterals reads `strategy.matrix` into, per key, the scalar values
// it lists: the key's own list plus the value every `include:` entry gives
// it. A key with any value that is not a plain scalar (a list, a map, an
// expression) is left out, so a reference using it stays unresolved. Nil
// when the matrix is not a literal map (`${{ fromJSON(...) }}`).
func matrixLiterals(section map[string]any) map[string][]string {
	strategy, ok := ghCastStringMap(section["strategy"])
	if !ok {
		return nil
	}
	matrix, ok := ghCastStringMap(strategy["matrix"])
	if !ok {
		return nil
	}
	values := map[string][]string{}
	unresolvable := map[string]bool{}
	add := func(key string, v any) {
		s, ok := matrixScalar(v)
		if !ok {
			unresolvable[key] = true
			return
		}
		values[key] = append(values[key], s)
	}
	for key, v := range matrix {
		switch key {
		case "include":
			entries, _ := v.([]any)
			for _, e := range entries {
				m, ok := ghCastStringMap(e)
				if !ok {
					continue
				}
				for k, vv := range m {
					add(k, vv)
				}
			}
		case "exclude":
			// Removing combinations never adds a value; the listed set is a
			// superset of what runs, which is what a finding per value needs.
		default:
			list, ok := v.([]any)
			if !ok {
				unresolvable[key] = true
				continue
			}
			for _, item := range list {
				add(key, item)
			}
		}
	}
	for key := range unresolvable {
		delete(values, key)
	}
	return values
}

// matrixScalar renders a matrix value that is a plain scalar.
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
