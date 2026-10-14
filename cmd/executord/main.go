package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hancomac/circulusd/internal/daemonshell"
)

func main() {
	os.Exit(runExecutord(os.Args[1:], daemonshell.DefaultDependencies(os.Stderr)))
}

func runExecutord(arguments []string, dependencies daemonshell.Dependencies) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The first signal starts a graceful shutdown. Restore the default
	// action right away so a second signal ends a shutdown that hangs.
	context.AfterFunc(ctx, stop)
	return executeExecutord(ctx, arguments, dependencies)
}

func executeExecutord(ctx context.Context, arguments []string, dependencies daemonshell.Dependencies) int {
	return daemonshell.Execute(ctx, arguments, daemonshell.ExecutordProfile(), dependencies)
}
