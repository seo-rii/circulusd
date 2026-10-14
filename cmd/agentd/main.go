// agentd is a diagnostic-only shell for the agentd role. It serves only the
// private control socket (package daemonshell; default
// /run/pi-platform/agentd.sock) and reports agent.isolation and
// agent.workerd as unavailable (NOT_WIRED). It starts no workerd and admits
// no workload.
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
