package github

import (
	"regexp"
	"slices"
	"strings"

	"github.com/getplumber/plumber/internal/ir"
	yamlv3 "gopkg.in/yaml.v3"
)

// cacheModeValues are the cache-mode values GitHub accepts.
var cacheModeValues = map[string]bool{"read": true, "write": true, "write-only": true, "none": true}

// cacheModeQuoted is a single-quoted string in a GitHub expression.
var cacheModeQuoted = regexp.MustCompile(`'((?:[^']|'')*)'`)

// cacheModeContext is a context read in a GitHub expression. GitHub rejects
// a workflow whose cache-mode reads one (probed on github.com: github,
// vars and inputs all make the file invalid), so such a value never runs.
var cacheModeContext = regexp.MustCompile(`\b(github|env|vars|job|jobs|steps|runner|secrets|strategy|matrix|needs|inputs)\s*[.\[]`)

// resolveCacheMode returns the access a cache-mode value grants. A literal
// is taken as is. An expression reads no context (or the file is invalid),
// so its result is one of the strings it quotes: it grants write when one
// of them does, and the access they all name when they agree on read or
// none. Anything else resolves to "" (nothing GitHub would run, or nothing
// a static read can tell).
func resolveCacheMode(value string) string {
	v := strings.TrimSpace(value)
	if !strings.HasPrefix(v, "${{") {
		if cacheModeValues[v] {
			return v
		}
		return ""
	}
	expr := strings.TrimSuffix(strings.TrimPrefix(v, "${{"), "}}")
	if cacheModeContext.MatchString(cacheModeQuoted.ReplaceAllString(expr, "''")) {
		return ""
	}
	quoted := cacheModeQuoted.FindAllStringSubmatch(expr, -1)
	if len(quoted) == 0 {
		return ""
	}
	var grants []string
	for _, q := range quoted {
		s := q[1]
		if !cacheModeValues[s] {
			return ""
		}
		grants = append(grants, s)
	}
	for _, s := range grants {
		if s == "write" || s == "write-only" {
			return s
		}
	}
	// No write left: read when one is quoted, none when that is all.
	if slices.Contains(grants, "read") {
		return "read"
	}
	return "none"
}

// cacheModeDecl builds the declaration for a raw cache-mode value, nil
// when the value is not a string.
func cacheModeDecl(raw any, line int, level string) *ir.CacheModeDecl {
	s, ok := raw.(string)
	if !ok {
		return nil
	}
	return &ir.CacheModeDecl{Value: s, Effective: resolveCacheMode(s), Line: line, Level: level}
}

// scanGitHubCacheModeLines returns the line of the workflow-level
// cache-mode and of each job's own one, from the YAML node tree.
func scanGitHubCacheModeLines(data []byte) (int, map[string]int) {
	jobLines := map[string]int{}
	var doc yamlv3.Node
	if err := yamlv3.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return 0, jobLines
	}
	root := doc.Content[0]
	wfLine := 0
	if k := mappingKey(root, "cache-mode"); k != nil {
		wfLine = k.Line
	}
	if jobs := mappingValue(root, "jobs"); jobs != nil && jobs.Kind == yamlv3.MappingNode {
		for i := 0; i+1 < len(jobs.Content); i += 2 {
			if k := mappingKey(jobs.Content[i+1], "cache-mode"); k != nil {
				jobLines[jobs.Content[i].Value] = k.Line
			}
		}
	}
	return wfLine, jobLines
}

// mappingKey returns the key node named key in a mapping node.
func mappingKey(m *yamlv3.Node, key string) *yamlv3.Node {
	if m == nil || m.Kind != yamlv3.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i]
		}
	}
	return nil
}

// mappingValue returns the value node of key in a mapping node.
func mappingValue(m *yamlv3.Node, key string) *yamlv3.Node {
	if m == nil || m.Kind != yamlv3.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
