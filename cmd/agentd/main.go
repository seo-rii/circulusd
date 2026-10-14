package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hancomac/circulusd/internal/daemonshell"
)

func main() {
	os.Exit(runAgentd(os.Args[1:], daemonshell.DefaultDependencies(os.Stderr)))
}

func runAgentd(arguments []string, dependencies daemonshell.Dependencies) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The first signal starts a graceful shutdown. Restore the default
	// action right away so a second signal ends a shutdown that hangs.
	context.AfterFunc(ctx, stop)
	return executeAgentd(ctx, arguments, dependencies)
}

func executeAgentd(ctx context.Context, arguments []string, dependencies daemonshell.Dependencies) int {
	return daemonshell.Execute(ctx, arguments, daemonshell.AgentdProfile(), dependencies)
}
