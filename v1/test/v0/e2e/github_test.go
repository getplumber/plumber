//go:build cli && e2e

package e2e

import "testing"

// TestGitHubIssue102 covers ISSUE-102, a container image on a forbidden tag (branch issue-102).
func TestGitHubIssue102(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "forbidden-tags-only",
			args:   []string{"analyze", githubTarget, "--branch", "issue-102", "--controls", "containerImageMustNotUseForbiddenTags", "--config", "forbidden-tags-only.plumber.yaml", "-o", "report.json"},
			inputs: []string{"forbidden-tags-only.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue103 covers ISSUE-103, a container image not pinned by digest (branch issue-103).
func TestGitHubIssue103(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-103", "--controls", "containerImageMustNotUseForbiddenTags", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue203 covers ISSUE-203, step debug logging turned on in the workflow (branch issue-203).
func TestGitHubIssue203(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-203", "--controls", "pipelineMustNotEnableDebugTrace", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue207 covers ISSUE-207, an issue title inlined into a shell script (branch issue-207).
func TestGitHubIssue207(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-207", "--controls", "workflowMustNotInjectUserInputInScripts", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue209 covers ISSUE-209, an issue title written to $GITHUB_ENV (branch issue-209).
func TestGitHubIssue209(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-209", "--controls", "workflowMustNotWriteUntrustedContentToGitHubEnv", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue302 covers ISSUE-302, a call to a local reusable workflow with `secrets: inherit` (branch issue-302).
func TestGitHubIssue302(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-302", "--controls", "reusableWorkflowsMustNotInheritSecrets", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue309 covers ISSUE-309, the whole secrets context exported to one step (branch issue-309).
func TestGitHubIssue309(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-309", "--controls", "workflowMustNotExportEntireSecretsContext", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue410 covers ISSUE-410, a security job that can fail without failing the run (branch issue-410).
func TestGitHubIssue410(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-410", "--controls", "securityJobsMustNotBeWeakened", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue411 covers ISSUE-411, a remote script piped into a shell (branch issue-411).
func TestGitHubIssue411(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-411", "--controls", "pipelineMustNotExecuteUnverifiedScripts", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue417 covers ISSUE-417, a required action no workflow references (branch issue-417).
func TestGitHubIssue417(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "required-action",
			args:   []string{"analyze", githubTarget, "--branch", "issue-417", "--controls", "workflowMustIncludeRequiredActions", "--config", "required-action.plumber.yaml", "-o", "report.json"},
			inputs: []string{"required-action.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue423 covers ISSUE-423, a workflow file that is not valid YAML (branch issue-423).
func TestGitHubIssue423(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-423", "--controls", "workflowsMustBeValid", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue501 covers ISSUE-501, a branch that must be protected and is not (branch issue-501).
func TestGitHubIssue501(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "protected-fixture-branch",
			args:   []string{"analyze", githubTarget, "--branch", "issue-501", "--controls", "branchMustBeProtected", "--config", "protected-fixture-branch.plumber.yaml", "-o", "report.json"},
			inputs: []string{"protected-fixture-branch.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue505 covers ISSUE-505, a protected branch without code owner approval (branch issue-505).
func TestGitHubIssue505(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "code-owner-approval",
			args:   []string{"analyze", githubTarget, "--branch", "issue-505", "--controls", "branchMustBeProtected", "--config", "code-owner-approval.plumber.yaml", "-o", "report.json"},
			inputs: []string{"code-owner-approval.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue714 covers ISSUE-714, the repository's own action runs code fetched from a mutable ref (branch issue-714).
func TestGitHubIssue714(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-714", "--controls", "actionsMustNotExecuteMutableRemoteCode", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue715 covers ISSUE-715, the repository's own action decodes a payload and runs it (branch issue-715).
func TestGitHubIssue715(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-715", "--controls", "actionsMustNotExecuteMutableRemoteCode", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue801 covers ISSUE-801, a workflow with no `permissions:` block (branch issue-801).
func TestGitHubIssue801(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-801", "--controls", "workflowsMustDeclarePermissions", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}

// TestGitHubIssue803 covers ISSUE-803, a workflow that grants `permissions: write-all` (branch issue-803).
func TestGitHubIssue803(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", githubTarget, "--branch", "issue-803", "--controls", "workflowMustNotGrantPermissionsWriteAll", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitHub, tt)
		})
	}
}
