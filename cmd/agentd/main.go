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
	os.Exit(executeAgentd(ctx, os.Args[1:], daemonshell.DefaultDependencies(os.Stderr)))
}

func executeAgentd(ctx context.Context, arguments []string, dependencies daemonshell.Dependencies) int {
	return daemonshell.Execute(ctx, arguments, daemonshell.AgentdProfile(), dependencies)
}
