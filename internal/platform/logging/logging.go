package logging

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func New() (*slog.Logger, error) {
	level := new(slog.LevelVar)
	level.Set(slog.LevelInfo)

	if v := os.Getenv("LOG_LEVEL"); v != "" {
		parsed, err := parseLevel(v)
		if err != nil {
			return nil, err
		}
		level.Set(parsed)
	}

	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(h), nil
}

func parseLevel(v string) (slog.Level, error) {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid LOG_LEVEL: %q", v)
	}
}
