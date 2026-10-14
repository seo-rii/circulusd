// executord is a diagnostic-only shell for the executord role. It serves only
// the private control socket (package daemonshell; default
// /run/pi-platform/executord.sock) and reports execution.docker,
// execution.environments, execution.firecracker and execution.nsjail as
// unavailable (NOT_WIRED). It constructs no execution provider.
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
