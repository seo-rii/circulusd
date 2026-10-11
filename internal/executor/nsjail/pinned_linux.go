//go:build linux

package nsjail

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// snapshotPinnedExecutable closes the hash/exec race, including in-place
// writes to the original inode. The returned file owns immutable ELF bytes.
func snapshotPinnedExecutable(fd int, expected string) (_ *os.File, err error) {
	const maximumExecutableBytes = 256 << 20
	duplicate, err := duplicateCloseOnExec(fd)
	if err != nil {
		return nil, err
	}
	source := os.NewFile(uintptr(duplicate), "nsjail-source")
	defer source.Close()
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	snapshotFD, err := unix.MemfdCreate("circulusd-nsjail", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if errors.Is(err, unix.EINVAL) {
		snapshotFD, err = unix.MemfdCreate("circulusd-nsjail", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: executable snapshot: %w", ErrUnsafeArtifact, err)
	}
	snapshot := os.NewFile(uintptr(snapshotFD), "nsjail-snapshot")
	defer func() {
		if err != nil {
			_ = snapshot.Close()
		}
	}()
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(snapshot, hash), io.LimitReader(source, maximumExecutableBytes+1))
	if err != nil || count == 0 || count > maximumExecutableBytes {
		return nil, fmt.Errorf("%w: executable snapshot exceeds bounds or cannot be read", ErrUnsafeArtifact)
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected {
		return nil, fmt.Errorf("%w: NsJail executable", ErrArtifactDigestMismatch)
	}
	parsed, err := elf.NewFile(snapshot)
	if err != nil {
		return nil, fmt.Errorf("%w: pinned executable must be ELF", ErrUnsafeArtifact)
	}
	if parsed.Type != elf.ET_EXEC && parsed.Type != elf.ET_DYN {
		return nil, fmt.Errorf("%w: pinned ELF is not executable", ErrUnsafeArtifact)
	}
	if err := snapshot.Chmod(0o500); err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(snapshot.Fd(), unix.F_ADD_SEALS,
		unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, err
	}
	readFD, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", snapshotFD), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	_ = snapshot.Close()
	return os.NewFile(uintptr(readFD), "nsjail-immutable-executable"), nil
}
