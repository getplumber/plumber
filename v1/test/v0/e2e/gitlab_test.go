//go:build cli && e2e

package e2e

import "testing"

// TestGitLabIssue101 covers ISSUE-101, an image from a registry outside the authorized sources (branch issue-101).
func TestGitLabIssue101(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", gitlabTarget, "--branch", "issue-101", "--controls", "containerImageMustComeFromAuthorizedSources", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue102 covers ISSUE-102, an image on a forbidden tag (branch issue-102).
func TestGitLabIssue102(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "forbidden-tags-only",
			args:   []string{"analyze", gitlabTarget, "--branch", "issue-102", "--controls", "containerImageMustNotUseForbiddenTags", "--config", "forbidden-tags-only.plumber.yaml", "-o", "report.json"},
			inputs: []string{"forbidden-tags-only.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue103 covers ISSUE-103, an image not pinned by digest (branch issue-103).
func TestGitLabIssue103(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", gitlabTarget, "--branch", "issue-103", "--controls", "containerImageMustNotUseForbiddenTags", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue203 covers ISSUE-203, the CI debug trace turned on (branch issue-203).
func TestGitLabIssue203(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", gitlabTarget, "--branch", "issue-203", "--controls", "pipelineMustNotEnableDebugTrace", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue204 covers ISSUE-204, a commit message evaluated by the shell (branch issue-204).
func TestGitLabIssue204(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", gitlabTarget, "--branch", "issue-204", "--controls", "pipelineMustNotUseUnsafeVariableExpansion", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue205 covers ISSUE-205, the pipeline turns SAST off through its variables (branch issue-205).
func TestGitLabIssue205(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", gitlabTarget, "--branch", "issue-205", "--controls", "pipelineMustNotOverrideJobVariables", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue401 covers ISSUE-401, a job written in .gitlab-ci.yml, not included (branch issue-401).
func TestGitLabIssue401(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "hardcoded-jobs",
			args:   []string{"analyze", gitlabTarget, "--branch", "issue-401", "--controls", "pipelineMustNotIncludeHardcodedJobs", "--config", "hardcoded-jobs.plumber.yaml", "-o", "report.json"},
			inputs: []string{"hardcoded-jobs.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue405 covers ISSUE-405, a required template the pipeline doesn't include (branch issue-405).
func TestGitLabIssue405(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "required-template",
			args:   []string{"analyze", gitlabTarget, "--branch", "issue-405", "--controls", "pipelineMustIncludeTemplate", "--config", "required-template.plumber.yaml", "-o", "report.json"},
			inputs: []string{"required-template.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue408 covers ISSUE-408, a required component the pipeline doesn't include (branch issue-408).
func TestGitLabIssue408(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "required-component",
			args:   []string{"analyze", gitlabTarget, "--branch", "issue-408", "--controls", "pipelineMustIncludeComponent", "--config", "required-component.plumber.yaml", "-o", "report.json"},
			inputs: []string{"required-component.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue410 covers ISSUE-410, a security job that only runs when started by hand (branch issue-410).
func TestGitLabIssue410(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", gitlabTarget, "--branch", "issue-410", "--controls", "securityJobsMustNotBeWeakened", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue411 covers ISSUE-411, a remote script piped into a shell (branch issue-411).
func TestGitLabIssue411(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", gitlabTarget, "--branch", "issue-411", "--controls", "pipelineMustNotExecuteUnverifiedScripts", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue412 covers ISSUE-412, a Docker-in-Docker service (branch issue-412).
func TestGitLabIssue412(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", gitlabTarget, "--branch", "issue-412", "--controls", "pipelineMustNotUseDockerInDocker", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue413 covers ISSUE-413, a Docker-in-Docker service with TLS turned off, which also raises ISSUE-412 (branch issue-413).
func TestGitLabIssue413(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", gitlabTarget, "--branch", "issue-413", "--controls", "pipelineMustNotUseDockerInDocker", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue415 covers ISSUE-415, a GitLab Function from another group (branch issue-415).
func TestGitLabIssue415(t *testing.T) {
	tests := []e2eCase{
		{
			name: "default",
			args: []string{"analyze", gitlabTarget, "--branch", "issue-415", "--controls", "functionMustComeFromAuthorizedSources", "-o", "report.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue501 covers ISSUE-501, a branch that must be protected and is not (branch issue-501).
func TestGitLabIssue501(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "protected-fixture-branch",
			args:   []string{"analyze", gitlabTarget, "--branch", "issue-501", "--controls", "branchMustBeProtected", "--config", "protected-fixture-branch.plumber.yaml", "-o", "report.json"},
			inputs: []string{"protected-fixture-branch.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue503 covers ISSUE-503, MR approval settings that let committers approve (branch issue-503).
func TestGitLabIssue503(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "approval-settings",
			args:   []string{"analyze", gitlabTarget, "--branch", "issue-503", "--controls", "mergeRequestApprovalSettingsMustBeCompliant", "--config", "approval-settings.plumber.yaml", "-o", "report.json"},
			inputs: []string{"approval-settings.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue505 covers ISSUE-505, a protected branch without code owner approval (branch issue-505).
func TestGitLabIssue505(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "code-owner-approval",
			args:   []string{"analyze", gitlabTarget, "--branch", "issue-505", "--controls", "branchMustBeProtected", "--config", "code-owner-approval.plumber.yaml", "-o", "report.json"},
			inputs: []string{"code-owner-approval.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue506 covers ISSUE-506, merge commits where the config requires fast-forward (branch issue-506).
func TestGitLabIssue506(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "merge-settings",
			args:   []string{"analyze", gitlabTarget, "--branch", "issue-506", "--controls", "mergeRequestSettingsMustBeCompliant", "--config", "merge-settings.plumber.yaml", "-o", "report.json"},
			inputs: []string{"merge-settings.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}

// TestGitLabIssue601 covers ISSUE-601, no linked security policy project (branch issue-601).
func TestGitLabIssue601(t *testing.T) {
	tests := []e2eCase{
		{
			name:   "security-policy-source",
			args:   []string{"analyze", gitlabTarget, "--branch", "issue-601", "--controls", "projectMustHaveSecurityPolicySource", "--config", "security-policy-source.plumber.yaml", "-o", "report.json"},
			inputs: []string{"security-policy-source.plumber.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runE2E(t, providerGitLab, tt)
		})
	}
}
