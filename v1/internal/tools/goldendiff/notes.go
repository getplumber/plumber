package main

// notes returns why each golden of test/v1/local differs from test/v0/local
// or is new, keyed by "<Test>/<row>". A golden that changes or appears needs
// a note here, and a note whose golden no longer differs must go: render
// fails on both.
func notes() map[string]string {
	return map[string]string{
		"TestHelpFlag/help-flag":      "Same output as `plumber help`, with the same changes.",
		"TestHelpFlag/help-flag-help": "The global `-v, --verbose` flag is gone: `PLUMBER_LOG_LEVEL` replaces it.",
		"TestHelpFlag/help-flag-version": "New short text, the `--json` and `--short` flags, and no global " +
			"`-v, --verbose`.",
		"TestRoot/help": "New root description. Only the commands rewritten so far, `version` has its new " +
			"short text, and `-v, --verbose` is gone (`PLUMBER_LOG_LEVEL` replaces it). The root command runs " +
			"(it prints the help), so cobra adds `plumber [flags]`.",
		"TestRoot/unknown-command": "Exit 1 instead of 2: exit codes are a later step. The error is a colored " +
			"zerolog line instead of cobra's `Error:` line.",
		"TestRoot/unknown-flag": "v0 rejects `analyze --nope`; the rewrite has no `analyze` yet, so the row " +
			"runs `version --nope`. Same exit code and log line changes as `unknown-command`.",
		"TestRoot/version": "One line in golangci-lint's format instead of three. The v1 sandbox normalizes " +
			"the Go version to `<GO>`.",
		"TestRoot/version-flag-unsupported": "Still an unknown flag. v0 printed the whole usage on stderr; v1 " +
			"prints only the error line (`SilenceUsage`) and exits 1.",
		"TestRoot/version-json":  "The build info as JSON (`--json`).",
		"TestRoot/version-short": "The version alone (`--short`).",
	}
}
