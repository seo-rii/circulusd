// sandbox-agent is circulusd-test's stand-in for circulusd's executord: it
// launches one sandboxd instance inside a jail (nsjail, docker, or util-linux
// unshare), performs the one-time-nonce handshake, and exposes a small local
// JSON API that the Node backend calls to run python inside the sandbox.
//
// The wire protocol is circulusd's own: the generated protobuf types and
// connect-go clients from api/generated/circulus/v1alpha are used unchanged.
// Only the request-digest / nonce-proof rules of internal/sandboxrpc (which
// Go's internal-package rule keeps private) are mirrored in protocol.go.
//
//	sandbox-agent serve --sandboxd <path> [--launcher auto|nsjail|docker|unshare] ...
//	sandbox-agent jail-init ...      (internal: runs inside the unshare user namespace)
//	sandbox-agent write-manifest ... (internal: runs inside a throwaway user namespace)
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sandbox-agent serve|jail-init|write-manifest [options]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "jail-init":
		os.Exit(runJailInit(os.Args[2:]))
	case "write-manifest":
		os.Exit(runWriteManifest(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "sandbox-agent: unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "agent: "+format+"\n", args...)
}
