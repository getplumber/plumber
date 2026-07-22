# unpinned-package-install — flag `run:` steps that invoke a
# package manager against a single package name without pinning
# a version (pip install pkg==1.2.3) and without a lockfile-based
# install (pip install -r requirements.txt, npm ci). The window
# between runs then resolves whatever the registry serves at
# execution time — the exact surface typosquat and maintainer-
# account compromise attacks exploit.
#
# Narrow by design: flags only `pip install pkg` / `npm install
# pkg` when the package name is the first and only argument.
# Commands with flags (`-r`, `--require-hashes`, `-e .`, `-c`) or
# lockfile-based commands (`npm ci`) stay silent. The intent is to
# catch the shape typosquats live on, not every flagged variation.
package unpinned_package_install

import rego.v1

bare_pip_install_pattern := `(?m)^\s*(?:python[0-9.]*\s+-m\s+)?pip(?:3)?\s+install\s+[A-Za-z_][A-Za-z0-9._-]*\s*$`

# Inline pin `pip install pkg==1.2.3` keeps the command silent.
pip_pinned_pattern := `\bpip(?:3)?\s+install\s+[A-Za-z_][A-Za-z0-9._-]*==`

bare_npm_install_pattern := `(?m)^\s*npm\s+install\s+(?:@[a-zA-Z0-9-]+/)?[a-zA-Z][a-zA-Z0-9._-]*\s*$`

npm_pinned_pattern := `\bnpm\s+install\s+(?:@[a-zA-Z0-9-]+/)?[a-zA-Z0-9._-]+@[0-9^~>=<]`

deny contains finding if {
	# GitHub-only control (workflowMustPinPackageInstalls). The rule reads
	# generic job.scripts, which GitLab pipelines populate too, so without
	# this guard a bare `pip install`/`npm install` in a GitLab `script:`
	# would fire it (getplumber/plumber#349). The catalog gate also drops
	# it, but guarding at the source is defense-in-depth.
	input.pipeline.provider == "github"
	some i, j
	job := input.pipeline.jobs[i]
	script := job.scripts[j]
	_unpinned_package_install(script)
	finding := {
		"code":     "ISSUE-214",
		"severity": "medium",
		"message":  sprintf("job %q installs a package without a pinned version or lockfile — add `==X.Y.Z` / `@X.Y.Z` or switch to `pip install -r requirements.txt` / `npm ci`", [job.name]),
		"job":      job.name,
	}
}

_unpinned_package_install(script) if {
	regex.match(bare_pip_install_pattern, script)
	not regex.match(pip_pinned_pattern, script)
}

_unpinned_package_install(script) if {
	regex.match(bare_npm_install_pattern, script)
	not regex.match(npm_pinned_pattern, script)
}
