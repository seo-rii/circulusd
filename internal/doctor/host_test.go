package doctor

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/conformance"
)

func TestHostProbesQualifyOnlyTheDetectedHostCapabilities(t *testing.T) {
	t.Parallel()

	files := map[string]string{
		"/proc/sys/kernel/osrelease":        "6.12.4-reference\n",
		"/sys/fs/cgroup/cgroup.controllers": "cpu io memory pids\n",
		"/proc/self/mountinfo": strings.Join([]string{
			"29 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw",
			"30 23 8:1 / /var/lib/circulusd rw,relatime,prjquota - ext4 /dev/sda1 rw,prjquota",
		}, "\n"),
	}
	knownPaths := map[string]bool{
		"/proc/self/ns/user": true,
		"/proc/self/ns/mnt":  true,
		"/proc/self/ns/pid":  true,
		"/proc/self/ns/net":  true,
		"/proc/self/ns/ipc":  true,
		"/proc/self/ns/uts":  true,
	}
	probes, err := HostProbes(HostRequirements{
		DataDirectory:     "/var/lib/circulusd",
		MinimumFreeBytes:  10_000,
		MinimumFreeInodes: 100,
	}, HostSources{
		OperatingSystem: "linux",
		Architecture:    "amd64",
		ReadFile: func(path string, _ int64) ([]byte, error) {
			value, found := files[path]
			if !found {
				return nil, fs.ErrNotExist
			}
			return []byte(value), nil
		},
		Stat: func(path string) error {
			if !knownPaths[path] {
				return fs.ErrNotExist
			}
			return nil
		},
		StatFS: func(path string) (FileSystemStats, error) {
			if path != "/var/lib/circulusd" {
				return FileSystemStats{}, fs.ErrNotExist
			}
			return FileSystemStats{FreeBytes: 20_000, FreeInodes: 200}, nil
		},
		LookPath: func(name string) (string, error) {
			if name != "nft" {
				return "", fs.ErrNotExist
			}
			return "/usr/sbin/nft", nil
		},
		OpenReadWrite: func(path string) error {
			if path != "/dev/kvm" {
				return fs.ErrNotExist
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("HostProbes() error = %v", err)
	}
	if len(probes) != 8 {
		t.Fatalf("len(HostProbes()) = %d, want 8", len(probes))
	}
	for _, probe := range probes {
		result := probe.Run(t.Context())
		if result.Component != probe.Component || result.Status != conformance.Pass {
			t.Fatalf("probe %q result = %+v, want PASS", probe.Component, result)
		}
	}
}

func TestHostProbesFailOrReportUnavailableWithoutOverclaiming(t *testing.T) {
	t.Parallel()

	probes, err := HostProbes(HostRequirements{
		DataDirectory:     "/var/lib/circulusd",
		MinimumFreeBytes:  10_000,
		MinimumFreeInodes: 100,
	}, HostSources{
		OperatingSystem: "darwin",
		Architecture:    "386",
		ReadFile: func(path string, _ int64) ([]byte, error) {
			switch path {
			case "/proc/sys/kernel/osrelease":
				return []byte("5.14.0\n"), nil
			case "/sys/fs/cgroup/cgroup.controllers":
				return []byte("cpu\n"), nil
			case "/proc/self/mountinfo":
				return []byte("30 23 8:1 / /var/lib/circulusd rw - ext4 /dev/sda1 rw"), nil
			default:
				return nil, fs.ErrNotExist
			}
		},
		Stat: func(string) error { return fs.ErrNotExist },
		StatFS: func(string) (FileSystemStats, error) {
			return FileSystemStats{FreeBytes: 9_999, FreeInodes: 99}, nil
		},
		LookPath:      func(string) (string, error) { return "", fs.ErrNotExist },
		OpenReadWrite: func(string) error { return fs.ErrPermission },
	})
	if err != nil {
		t.Fatalf("HostProbes() error = %v", err)
	}
	want := map[string]conformance.Status{
		"host.architecture":      conformance.Fail,
		"host.kernel":            conformance.Fail,
		"host.cgroup-v2":         conformance.Fail,
		"host.namespace-handles": conformance.Fail,
		"host.disk":              conformance.Fail,
		"host.scratch-quota":     conformance.Unavailable,
		"host.nftables-tool":     conformance.Unavailable,
		"host.kvm-access":        conformance.Unavailable,
	}
	for _, probe := range probes {
		result := probe.Run(t.Context())
		if result.Status != want[result.Component] || result.Reason == "" {
			t.Fatalf("probe %q result = %+v, want %s with reason", probe.Component, result, want[result.Component])
		}
	}
}

func TestHostProbesRejectInvalidOrIncompleteSources(t *testing.T) {
	t.Parallel()

	valid := HostSources{
		OperatingSystem: "linux",
		Architecture:    "amd64",
		ReadFile:        func(string, int64) ([]byte, error) { return nil, errors.New("unused") },
		Stat:            func(string) error { return errors.New("unused") },
		StatFS:          func(string) (FileSystemStats, error) { return FileSystemStats{}, errors.New("unused") },
		LookPath:        func(string) (string, error) { return "", errors.New("unused") },
		OpenReadWrite:   func(string) error { return errors.New("unused") },
	}
	invalid := []struct {
		requirements HostRequirements
		sources      HostSources
	}{
		{requirements: HostRequirements{DataDirectory: "relative", MinimumFreeBytes: 1, MinimumFreeInodes: 1}, sources: valid},
		{requirements: HostRequirements{DataDirectory: "/", MinimumFreeBytes: 1, MinimumFreeInodes: 1}, sources: valid},
		{requirements: HostRequirements{DataDirectory: "/var/lib/circulusd", MinimumFreeInodes: 1}, sources: valid},
		{requirements: HostRequirements{DataDirectory: "/var/lib/circulusd", MinimumFreeBytes: 1, MinimumFreeInodes: 1}, sources: HostSources{}},
	}
	for index, candidate := range invalid {
		if _, err := HostProbes(candidate.requirements, candidate.sources); err == nil {
			t.Fatalf("HostProbes(invalid[%d]) error = nil", index)
		}
	}
}
