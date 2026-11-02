// The service log with fields and levels: read both by people and by log
// collectors.
package watch

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// LogConfig - how the service writes its own log.
type LogConfig struct {
	// text (the default) for reading by eye, json for collectors.
	Format string `json:"format"`
	// debug, info, warn, error.
	Level string `json:"level"`
}

// SetupLogging configures the service log: text for reading by eye, json for log
// collectors. Built on log/slog from the standard library.
func SetupLogging(cfg LogConfig, output io.Writer) *slog.Logger {
	if output == nil {
		output = os.Stderr
	}
	level := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(cfg.Level)) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.EqualFold(strings.TrimSpace(cfg.Format), "json") {
		handler = slog.NewJSONHandler(output, options)
	} else {
		handler = slog.NewTextHandler(output, options)
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}

// logEvent writes an observation event into the service log as fields rather
// than as a string: fields are what people search by later.
func logEvent(event Event) {
	level := slog.LevelInfo
	switch event.Severity {
	case SevWarn:
		level = slog.LevelWarn
	case SevAlert:
		level = slog.LevelError
	}
	slog.Log(context.Background(), level, "observation event",
		slog.String("source", event.Source),
		slog.String("kind", event.Kind),
		slog.String("severity", string(event.Severity)),
		slog.String("ip", event.IP),
		slog.String("subject", sampleOf(event.Subject, 200)),
		slog.Int("count", event.Count),
		slog.Uint64("seq", event.Seq),
	)
}
