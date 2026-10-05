//go:build !linux

package main

import (
	"fmt"
	"os"
)

func unsupported(command string) int {
	fmt.Fprintf(os.Stderr, "sandbox-agent %s only runs on Linux\n", command)
	return 2
}

func runServe([]string) int         { return unsupported("serve") }
func runJailInit([]string) int      { return unsupported("jail-init") }
func runWriteManifest([]string) int { return unsupported("write-manifest") }
