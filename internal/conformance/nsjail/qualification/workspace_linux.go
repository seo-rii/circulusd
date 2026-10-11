//go:build linux

package qualification

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

func readQualificationWorkspace(path string, owner uint32) ([]byte, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "qualification-workspace-marker")
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != owner || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o777 != 0o600 || st.Nlink != 1 || st.Size != 32 {
		return nil, errors.New("unsafe qualification workspace marker")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("invalid workspace readback")
	}
	return raw, nil
}
