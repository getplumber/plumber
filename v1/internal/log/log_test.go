package log

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

// Lines as zerolog's ConsoleWriter colors them: the level in its color and
// the message in bold. Debug has no color.
const (
	colorDebug = "DBG debug\n"
	colorInfo  = "\x1b[32mINF\x1b[0m \x1b[1minfo\x1b[0m\n"
	colorWarn  = "\x1b[33mWRN\x1b[0m \x1b[1mwarn\x1b[0m\n"
	colorError = "\x1b[31mERR\x1b[0m \x1b[1merror\x1b[0m\n"
)

// setLevel sets the log_level key of the global viper for one test, as
// PLUMBER_LOG_LEVEL does once internal/cli has set viper up.
func setLevel(t *testing.T, value string) {
	t.Helper()
	viper.Set("log_level", value)
	t.Cleanup(viper.Reset)
}

func TestNew(t *testing.T) { //nolint:paralleltest // writes the global viper
	tests := []struct {
		name  string
		level string // value of log_level
		want  string
	}{
		{name: "unset", want: colorInfo + colorWarn + colorError},
		{name: "debug", level: "debug", want: colorDebug + colorInfo + colorWarn + colorError},
		{name: "error", level: "error", want: colorError},
	}
	for _, tt := range tests { //nolint:paralleltest // writes the global viper
		t.Run(tt.name, func(t *testing.T) {
			setLevel(t, tt.level)
			var out bytes.Buffer
			logger := New(&out)
			logger.Debug().Msg("debug")
			logger.Info().Msg("info")
			logger.Warn().Msg("warn")
			logger.Error().Msg("error")
			if got := out.String(); got != tt.want {
				t.Errorf("log = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLevel(t *testing.T) { //nolint:paralleltest // writes the global viper
	tests := []struct {
		value string // value of log_level
		want  zerolog.Level
	}{
		{value: "debug", want: zerolog.DebugLevel},
		{value: "info", want: zerolog.InfoLevel},
		{value: "warn", want: zerolog.WarnLevel},
		{value: "error", want: zerolog.ErrorLevel},
		{value: "", want: zerolog.InfoLevel},
		{value: "trace", want: zerolog.InfoLevel},
		{value: "nope", want: zerolog.InfoLevel},
	}
	for _, tt := range tests { //nolint:paralleltest // writes the global viper
		t.Run(tt.value, func(t *testing.T) {
			setLevel(t, tt.value)
			if got := level(); got != tt.want {
				t.Errorf("level() with log_level=%q = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}
