package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// Env-var fallbacks for `plumber analyze` flags. The helpers apply the
// environment variable only when the flag was not set on the command line and
// the variable is non-empty, so CLI flags always win and unset/empty variables
// are ignored. ParseBool/ParseFloat errors surface as actionable errors.

func newFallbackCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("str", "", "")
	cmd.Flags().Bool("bln", false, "")
	cmd.Flags().Float64("flt", 0, "")
	return cmd
}

func TestEnvStringFallback(t *testing.T) {
	t.Run("applies env when flag not set", func(t *testing.T) {
		cmd := newFallbackCmd()
		t.Setenv("PLUMBER_TEST_STR", "from-env")
		dest := "default"
		if err := envStringFallback(cmd, "str", "PLUMBER_TEST_STR", &dest); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest != "from-env" {
			t.Fatalf("want %q, got %q", "from-env", dest)
		}
	})

	t.Run("flag takes precedence over env", func(t *testing.T) {
		cmd := newFallbackCmd()
		if err := cmd.Flags().Set("str", "from-flag"); err != nil {
			t.Fatalf("set flag: %v", err)
		}
		t.Setenv("PLUMBER_TEST_STR", "from-env")
		dest := "from-flag"
		if err := envStringFallback(cmd, "str", "PLUMBER_TEST_STR", &dest); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest != "from-flag" {
			t.Fatalf("flag should win, got %q", dest)
		}
	})

	t.Run("empty env leaves dest unchanged", func(t *testing.T) {
		cmd := newFallbackCmd()
		t.Setenv("PLUMBER_TEST_STR", "")
		dest := "default"
		if err := envStringFallback(cmd, "str", "PLUMBER_TEST_STR", &dest); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest != "default" {
			t.Fatalf("want %q, got %q", "default", dest)
		}
	})
}

func TestEnvBoolFallback(t *testing.T) {
	t.Run("applies env when flag not set", func(t *testing.T) {
		cmd := newFallbackCmd()
		t.Setenv("PLUMBER_TEST_BLN", "true")
		dest := false
		if err := envBoolFallback(cmd, "bln", "PLUMBER_TEST_BLN", &dest); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !dest {
			t.Fatal("want true, got false")
		}
	})

	t.Run("flag takes precedence over env", func(t *testing.T) {
		cmd := newFallbackCmd()
		if err := cmd.Flags().Set("bln", "true"); err != nil {
			t.Fatalf("set flag: %v", err)
		}
		t.Setenv("PLUMBER_TEST_BLN", "false")
		dest := true
		if err := envBoolFallback(cmd, "bln", "PLUMBER_TEST_BLN", &dest); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !dest {
			t.Fatal("flag should win (true), got false")
		}
	})

	t.Run("invalid value errors", func(t *testing.T) {
		cmd := newFallbackCmd()
		t.Setenv("PLUMBER_TEST_BLN", "notabool")
		dest := false
		if err := envBoolFallback(cmd, "bln", "PLUMBER_TEST_BLN", &dest); err == nil {
			t.Fatal("expected error for invalid bool, got nil")
		}
	})

	t.Run("empty env leaves dest unchanged", func(t *testing.T) {
		cmd := newFallbackCmd()
		t.Setenv("PLUMBER_TEST_BLN", "")
		dest := true
		if err := envBoolFallback(cmd, "bln", "PLUMBER_TEST_BLN", &dest); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !dest {
			t.Fatal("want unchanged true, got false")
		}
	})
}

func TestEnvFloat64Fallback(t *testing.T) {
	t.Run("applies env when flag not set", func(t *testing.T) {
		cmd := newFallbackCmd()
		t.Setenv("PLUMBER_TEST_FLT", "80")
		dest := 100.0
		if err := envFloat64Fallback(cmd, "flt", "PLUMBER_TEST_FLT", &dest); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest != 80 {
			t.Fatalf("want 80, got %v", dest)
		}
	})

	t.Run("flag takes precedence over env", func(t *testing.T) {
		cmd := newFallbackCmd()
		if err := cmd.Flags().Set("flt", "50"); err != nil {
			t.Fatalf("set flag: %v", err)
		}
		t.Setenv("PLUMBER_TEST_FLT", "80")
		dest := 50.0
		if err := envFloat64Fallback(cmd, "flt", "PLUMBER_TEST_FLT", &dest); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest != 50 {
			t.Fatalf("flag should win (50), got %v", dest)
		}
	})

	t.Run("invalid value errors", func(t *testing.T) {
		cmd := newFallbackCmd()
		t.Setenv("PLUMBER_TEST_FLT", "abc")
		dest := 100.0
		if err := envFloat64Fallback(cmd, "flt", "PLUMBER_TEST_FLT", &dest); err == nil {
			t.Fatal("expected error for invalid float, got nil")
		}
	})
}
