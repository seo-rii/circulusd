//go:build linux

package materialized

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenDirectoryAtRootDuplicatesWithCloseOnExec(t *testing.T) {
	t.Parallel()

	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	duplicate, err := openDirectoryAt(int(directory.Fd()), ".")
	if err != nil {
		t.Fatalf("openDirectoryAt(.) error = %v", err)
	}
	defer unix.Close(duplicate)
	flags, err := unix.FcntlInt(uintptr(duplicate), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD error = %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("openDirectoryAt(.) returned an inheritable descriptor")
	}
}
