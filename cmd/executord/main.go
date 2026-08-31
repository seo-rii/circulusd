package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hancomac/circulusd/internal/daemonshell"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(executeExecutord(ctx, os.Args[1:], daemonshell.DefaultDependencies(os.Stderr)))
}

func executeExecutord(ctx context.Context, arguments []string, dependencies daemonshell.Dependencies) int {
	return daemonshell.Execute(ctx, arguments, daemonshell.ExecutordProfile(), dependencies)
}
