//go:build linux

// qualification-helper must be built and packaged into the signed dedicated
// rootfs. It must never be invoked directly on a development host.
package main

import (
	"fmt"
	"github.com/hancomac/circulusd/internal/conformance/nsjail/fixture"
	"os"
)

func main() {
	if err := fixture.Main(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "qualification helper:", err)
		os.Exit(1)
	}
}
