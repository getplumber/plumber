package main

import (
	"runtime"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ldflags string
		module  string
		want    string
	}{
		{name: "ldflags wins", ldflags: "1.2.3", module: "v9.9.9", want: "1.2.3"},
		{name: "module version", ldflags: "dev", module: "v1.4.0", want: "1.4.0"},
		{name: "empty ldflags", ldflags: "", module: "v1.4.0", want: "1.4.0"},
		{name: "local build", ldflags: "dev", module: "(devel)", want: "dev"},
		{name: "no module version", ldflags: "dev", module: "", want: "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resolveVersion(tt.ldflags, tt.module); got != tt.want {
				t.Errorf("resolveVersion(%q, %q) = %q, want %q", tt.ldflags, tt.module, got, tt.want)
			}
		})
	}
}

func TestBuildInfo(t *testing.T) {
	t.Parallel()
	info := buildInfo()
	if info.Version == "" || info.GoVersion != runtime.Version() || info.Commit != buildCommit || info.Date != buildDate {
		t.Errorf("buildInfo() = %+v, want a version, Go %q, commit %q, date %q",
			info, runtime.Version(), buildCommit, buildDate)
	}
}
