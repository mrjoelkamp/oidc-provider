package op

import (
	"log/slog"
	"os"
)

type Logger struct {
	*slog.Logger
}

var logLevels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

func NewLogger(config *Config) *Logger {
	level, exists := logLevels[config.LogLevel]
	if !exists {
		level = slog.LevelInfo // default level
	}
	return &Logger{slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: false,
		Level:     level,
	}))}
}
