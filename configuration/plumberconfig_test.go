package configuration

import (
	"testing"
)

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int
	}{
		{
			name:     "identical strings",
			a:        "hello",
			b:        "hello",
			expected: 0,
		},
		{
			name:     "single character difference",
			a:        "hello",
			b:        "hallo",
			expected: 1,
		},
		{
			name:     "empty first string",
			a:        "",
			b:        "hello",
			expected: 5,
		},
		{
			name:     "empty second string",
			a:        "hello",
			b:        "",
			expected: 5,
		},
		{
			name:     "both empty",
			a:        "",
			b:        "",
			expected: 0,
		},
		{
			name:     "insertion",
			a:        "abc",
			b:        "abcd",
			expected: 1,
		},
		{
			name:     "deletion",
			a:        "abcd",
			b:        "abc",
			expected: 1,
		},
		{
			name:     "substitution",
			a:        "kitten",
			b:        "sitting",
			expected: 3,
		},
		{
			name:     "common typo - containerImage",
			a:        "containerImageMustNotUseForbiddenTags",
			b:        "containerImageMustNotUseForbiddenTag",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := levenshteinDistance(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("levenshteinDistance(%q, %q) = %d, want %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestFindClosestMatch(t *testing.T) {
	validKeys := []string{
		"containerImageMustNotUseForbiddenTags",
		"containerImageMustComeFromAuthorizedSources",
		"branchMustBeProtected",
		"pipelineMustNotIncludeHardcodedJobs",
		"includesMustBeUpToDate",
		"includesMustNotUseForbiddenVersions",
		"pipelineMustIncludeComponent",
		"pipelineMustIncludeTemplate",
	}

	tests := []struct {
		name        string
		input       string
		expectMatch bool
		expectedKey string
	}{
		{
			name:        "exact match",
			input:       "containerImageMustNotUseForbiddenTags",
			expectMatch: true,
			expectedKey: "containerImageMustNotUseForbiddenTags",
		},
		{
			name:        "typo - missing 's' at end",
			input:       "containerImageMustNotUseForbiddenTag",
			expectMatch: true,
			expectedKey: "containerImageMustNotUseForbiddenTags",
		},
		{
			name:        "typo - wrong character",
			input:       "branchMustBeProtectod",
			expectMatch: true,
			expectedKey: "branchMustBeProtected",
		},
		{
			name:        "completely different string - no match",
			input:       "xyz123",
			expectMatch: false,
			expectedKey: "",
		},
		{
			name:        "similar but too different",
			input:       "containerMustNotUseTags",
			expectMatch: false,
			expectedKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findClosestMatch(tt.input, validKeys)
			if tt.expectMatch {
				if result != tt.expectedKey {
					t.Errorf("findClosestMatch(%q) = %q, want %q", tt.input, result, tt.expectedKey)
				}
			} else {
				if result != "" {
					t.Errorf("findClosestMatch(%q) = %q, want empty string", tt.input, result)
				}
			}
		})
	}
}

func TestValidateKnownKeys(t *testing.T) {
	tests := []struct {
		name           string
		yamlContent    string
		expectWarnings int
		wantContains   string
	}{
		{
			name: "valid config - no warnings",
			yamlContent: `
version: "1"
controls:
  containerImageMustNotUseForbiddenTags:
    enabled: true
  branchMustBeProtected:
    enabled: true
`,
			expectWarnings: 0,
		},
		{
			name: "unknown control key - typo missing 's'",
			yamlContent: `
version: "1"
controls:
  containerImageMustNotUseForbiddenTag:
    enabled: true
`,
			expectWarnings: 1,
			wantContains:   "containerImageMustNotUseForbiddenTags",
		},
		{
			name: "multiple unknown keys",
			yamlContent: `
version: "1"
controls:
  containerImageMustNotUseForbiddenTag:
    enabled: true
  branchMustBeProtectod:
    enabled: true
`,
			expectWarnings: 2,
		},
		{
			name: "completely unknown key",
			yamlContent: `
version: "1"
controls:
  someRandomControl:
    enabled: true
`,
			expectWarnings: 1,
		},
		{
			name: "unknown sub-key - tags typo",
			yamlContent: `
version: "1"
controls:
  containerImageMustNotUseForbiddenTags:
    enabled: true
    tag:
      - latest
`,
			expectWarnings: 1,
			wantContains:   "tags",
		},
		{
			name: "unknown sub-key - allowForcePush typo",
			yamlContent: `
version: "1"
controls:
  branchMustBeProtected:
    enabled: true
    allowForcePushes: false
`,
			expectWarnings: 1,
			wantContains:   "allowForcePush",
		},
		{
			name: "multiple sub-key typos in same control",
			yamlContent: `
version: "1"
controls:
  branchMustBeProtected:
    enabled: true
    namePattern:
      - main
    allowForcePushes: false
`,
			expectWarnings: 2,
		},
		{
			name: "typo at both control and sub-key level",
			yamlContent: `
version: "1"
controls:
  containerImageMustNotUseForbiddenTag:
    enabled: true
  branchMustBeProtected:
    enabled: true
    allowForcePushes: false
`,
			expectWarnings: 2,
		},
		{
			name: "valid sub-keys - no warnings",
			yamlContent: `
version: "1"
controls:
  branchMustBeProtected:
    enabled: true
    namePatterns:
      - main
    defaultMustBeProtected: true
    allowForcePush: false
    codeOwnerApprovalRequired: false
    minMergeAccessLevel: 30
    minPushAccessLevel: 40
`,
			expectWarnings: 0,
		},
		{
			name: "completely unknown sub-key",
			yamlContent: `
version: "1"
controls:
  includesMustBeUpToDate:
    enabled: true
    somethingTotallyRandom: true
`,
			expectWarnings: 1,
		},
		{
			name:           "invalid yaml - no warnings returned",
			yamlContent:    `{{{invalid yaml`,
			expectWarnings: 0,
		},
		{
			name: "empty controls section - no warnings",
			yamlContent: `
version: "1"
controls: {}
`,
			expectWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := ValidateKnownKeys([]byte(tt.yamlContent))
			if len(warnings) != tt.expectWarnings {
				t.Errorf("ValidateKnownKeys() returned %d warnings, want %d. Warnings: %v",
					len(warnings), tt.expectWarnings, warnings)
			}
			if tt.wantContains != "" && len(warnings) > 0 {
				found := false
				for _, w := range warnings {
					if contains([]string{w}, tt.wantContains) || len(w) > 0 && containsSubstring(w, tt.wantContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected warning to contain %q, but got: %v", tt.wantContains, warnings)
				}
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
