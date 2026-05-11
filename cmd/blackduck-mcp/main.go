package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := InitializeApp()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	slog.SetDefault(a.Logger)

	if err := a.Run(ctx); err != nil {
		a.Logger.Error("app exited with error", "error", err)
		os.Exit(1)
	}
}
