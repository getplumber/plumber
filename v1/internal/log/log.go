// Package log builds the zerolog logger of the CLI. A command that logs
// takes the logger in its constructor.
package log

import (
	"io"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

// New returns the logger of a run, writing to w at the level
// PLUMBER_LOG_LEVEL sets. A line is colored and has no timestamp, such as
// "ERR unknown command".
func New(w io.Writer) zerolog.Logger {
	out := zerolog.ConsoleWriter{
		Out:          w,
		NoColor:      false,
		PartsExclude: []string{zerolog.TimestampFieldName},
	}
	return zerolog.New(out).Level(level())
}

// level returns the level PLUMBER_LOG_LEVEL names: debug, info, warn or
// error. It is info when the variable is unset or holds any other value. It
// reads the global viper, which internal/cli sets up.
func level() zerolog.Level {
	switch viper.GetString("log_level") {
	case "debug":
		return zerolog.DebugLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}
