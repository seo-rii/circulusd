package doctor

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance"
	"golang.org/x/sys/unix"
)

const (
	maximumKernelReleaseBytes = 4 << 10
	maximumControllersBytes   = 64 << 10
	maximumMountInfoBytes     = 1 << 20
)

var kernelReleasePattern = regexp.MustCompile(`^([0-9]+)\.([0-9]+)(?:\.|-|$)`)

type HostRequirements struct {
	DataDirectory     string
	MinimumFreeBytes  uint64
	MinimumFreeInodes uint64
}

type FileSystemStats struct {
	FreeBytes  uint64
	FreeInodes uint64
}

type HostSources struct {
	OperatingSystem string
	Architecture    string
	ReadFile        func(path string, maximumBytes int64) ([]byte, error)
	Stat            func(path string) error
	StatFS          func(path string) (FileSystemStats, error)
	LookPath        func(name string) (string, error)
	OpenReadWrite   func(path string) error
}

func LocalHostSources() HostSources {
	return HostSources{
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
		ReadFile: func(path string, maximumBytes int64) ([]byte, error) {
			file, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer file.Close()
			contents, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
			if err != nil {
				return nil, err
			}
			if int64(len(contents)) > maximumBytes {
				return nil, fmt.Errorf("host metadata exceeds %d bytes", maximumBytes)
			}
			return contents, nil
		},
		Stat: func(path string) error {
			_, err := os.Stat(path)
			return err
		},
		StatFS: func(path string) (FileSystemStats, error) {
			var stats unix.Statfs_t
			if err := unix.Statfs(path, &stats); err != nil {
				return FileSystemStats{}, err
			}
			blockSize := uint64(stats.Bsize)
			freeBlocks := stats.Bavail
			freeBytes := uint64(math.MaxUint64)
			if blockSize == 0 || freeBlocks <= math.MaxUint64/blockSize {
				freeBytes = freeBlocks * blockSize
			}
			return FileSystemStats{
				FreeBytes:  freeBytes,
				FreeInodes: stats.Ffree,
			}, nil
		},
		LookPath: exec.LookPath,
		OpenReadWrite: func(path string) error {
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			return file.Close()
		},
	}
}

func HostProbes(requirements HostRequirements, sources HostSources) ([]Probe, error) {
	if !filepath.IsAbs(requirements.DataDirectory) ||
		filepath.Clean(requirements.DataDirectory) != requirements.DataDirectory ||
		requirements.DataDirectory == string(filepath.Separator) ||
		requirements.MinimumFreeBytes == 0 ||
		requirements.MinimumFreeInodes == 0 ||
		sources.OperatingSystem == "" ||
		sources.Architecture == "" ||
		sources.ReadFile == nil ||
		sources.Stat == nil ||
		sources.StatFS == nil ||
		sources.LookPath == nil ||
		sources.OpenReadWrite == nil {
		return nil, fmt.Errorf("doctor: host probe configuration is invalid")
	}

	probes := []Probe{
		{
			Component: "host.architecture",
			Run: func(ctx context.Context) conformance.Result {
				if result, canceled := canceledHostProbe(ctx, "host.architecture"); canceled {
					return result
				}
				if sources.OperatingSystem != "linux" {
					return conformance.Result{Component: "host.architecture", Status: conformance.Fail, Reason: "host operating system is not Linux"}
				}
				architecture := ""
				switch sources.Architecture {
				case "amd64":
					architecture = "x86_64"
				case "arm64":
					architecture = "aarch64"
				default:
					return conformance.Result{Component: "host.architecture", Status: conformance.Fail, Reason: "host architecture is unsupported"}
				}
				return conformance.Result{
					Component: "host.architecture",
					Status:    conformance.Pass,
					Evidence:  conformance.Evidence{Architecture: architecture},
				}
			},
		},
		{
			Component: "host.kernel",
			Run: func(ctx context.Context) conformance.Result {
				if result, canceled := canceledHostProbe(ctx, "host.kernel"); canceled {
					return result
				}
				if sources.OperatingSystem != "linux" {
					return conformance.Result{Component: "host.kernel", Status: conformance.Fail, Reason: "Linux kernel is required"}
				}
				encoded, err := sources.ReadFile(
					"/proc/sys/kernel/osrelease",
					maximumKernelReleaseBytes,
				)
				if err != nil {
					return conformance.Result{Component: "host.kernel", Status: conformance.Fail, Reason: "kernel release cannot be read"}
				}
				release := strings.TrimSpace(string(encoded))
				matches := kernelReleasePattern.FindStringSubmatch(release)
				if len(matches) != 3 {
					return conformance.Result{Component: "host.kernel", Status: conformance.Fail, Reason: "kernel release is not canonical"}
				}
				major, majorErr := strconv.ParseUint(matches[1], 10, 32)
				minor, minorErr := strconv.ParseUint(matches[2], 10, 32)
				if majorErr != nil || minorErr != nil || major < 5 || major == 5 && minor < 15 {
					return conformance.Result{
						Component: "host.kernel",
						Status:    conformance.Fail,
						Reason:    "kernel is older than the required Linux 5.15 baseline",
						Evidence:  conformance.Evidence{Kernel: release},
					}
				}
				return conformance.Result{
					Component: "host.kernel",
					Status:    conformance.Pass,
					Evidence:  conformance.Evidence{Kernel: release},
				}
			},
		},
		{
			Component: "host.cgroup-v2",
			Run: func(ctx context.Context) conformance.Result {
				if result, canceled := canceledHostProbe(ctx, "host.cgroup-v2"); canceled {
					return result
				}
				if sources.OperatingSystem != "linux" {
					return conformance.Result{Component: "host.cgroup-v2", Status: conformance.Fail, Reason: "cgroup v2 requires Linux"}
				}
				controllers, err := sources.ReadFile(
					"/sys/fs/cgroup/cgroup.controllers",
					maximumControllersBytes,
				)
				if err != nil {
					return conformance.Result{Component: "host.cgroup-v2", Status: conformance.Fail, Reason: "cgroup v2 controller list cannot be read"}
				}
				available := make(map[string]struct{})
				for _, controller := range strings.Fields(string(controllers)) {
					available[controller] = struct{}{}
				}
				for _, required := range []string{"cpu", "memory", "pids"} {
					if _, found := available[required]; !found {
						return conformance.Result{Component: "host.cgroup-v2", Status: conformance.Fail, Reason: "required cgroup v2 controllers are unavailable"}
					}
				}
				mountInfo, err := sources.ReadFile("/proc/self/mountinfo", maximumMountInfoBytes)
				if err != nil || !strings.Contains(string(mountInfo), " - cgroup2 ") {
					return conformance.Result{Component: "host.cgroup-v2", Status: conformance.Fail, Reason: "unified cgroup v2 hierarchy is not mounted"}
				}
				return conformance.Result{Component: "host.cgroup-v2", Status: conformance.Pass}
			},
		},
		{
			Component: "host.namespace-handles",
			Run: func(ctx context.Context) conformance.Result {
				if result, canceled := canceledHostProbe(ctx, "host.namespace-handles"); canceled {
					return result
				}
				if sources.OperatingSystem != "linux" {
					return conformance.Result{Component: "host.namespace-handles", Status: conformance.Fail, Reason: "Linux namespaces are required"}
				}
				for _, namespace := range []string{"user", "mnt", "pid", "net", "ipc", "uts"} {
					if err := sources.Stat("/proc/self/ns/" + namespace); err != nil {
						return conformance.Result{Component: "host.namespace-handles", Status: conformance.Fail, Reason: "required namespace handles are unavailable"}
					}
				}
				return conformance.Result{Component: "host.namespace-handles", Status: conformance.Pass}
			},
		},
		{
			Component: "host.disk",
			Run: func(ctx context.Context) conformance.Result {
				if result, canceled := canceledHostProbe(ctx, "host.disk"); canceled {
					return result
				}
				stats, err := sources.StatFS(requirements.DataDirectory)
				if err != nil {
					return conformance.Result{Component: "host.disk", Status: conformance.Fail, Reason: "data filesystem cannot be inspected"}
				}
				if stats.FreeBytes < requirements.MinimumFreeBytes ||
					stats.FreeInodes < requirements.MinimumFreeInodes {
					return conformance.Result{Component: "host.disk", Status: conformance.Fail, Reason: "data filesystem free space or inodes are below policy"}
				}
				return conformance.Result{Component: "host.disk", Status: conformance.Pass}
			},
		},
		{
			Component: "host.scratch-quota",
			Run: func(ctx context.Context) conformance.Result {
				if result, canceled := canceledHostProbe(ctx, "host.scratch-quota"); canceled {
					return result
				}
				if sources.OperatingSystem != "linux" {
					return conformance.Result{Component: "host.scratch-quota", Status: conformance.Unavailable, Reason: "project quota inspection requires Linux"}
				}
				mountInfo, err := sources.ReadFile("/proc/self/mountinfo", maximumMountInfoBytes)
				if err != nil {
					return conformance.Result{Component: "host.scratch-quota", Status: conformance.Unavailable, Reason: "filesystem mount options cannot be read"}
				}
				bestMountLength := -1
				bestFilesystem := ""
				bestOptions := ""
				decodeMountPath := strings.NewReplacer(
					`\040`, " ",
					`\011`, "\t",
					`\012`, "\n",
					`\134`, `\`,
				)
				for _, line := range strings.Split(string(mountInfo), "\n") {
					fields := strings.Fields(line)
					separator := -1
					for index, field := range fields {
						if field == "-" {
							separator = index
							break
						}
					}
					if separator < 6 || separator+3 >= len(fields) {
						continue
					}
					mountPoint := decodeMountPath.Replace(fields[4])
					containsDataDirectory := mountPoint == requirements.DataDirectory ||
						mountPoint == "/" ||
						strings.HasPrefix(requirements.DataDirectory, mountPoint+"/")
					if !containsDataDirectory || len(mountPoint) <= bestMountLength {
						continue
					}
					bestMountLength = len(mountPoint)
					bestFilesystem = fields[separator+1]
					bestOptions = fields[5] + "," + fields[separator+3]
				}
				if bestMountLength < 0 || bestFilesystem != "ext4" && bestFilesystem != "xfs" {
					return conformance.Result{Component: "host.scratch-quota", Status: conformance.Unavailable, Reason: "data filesystem does not expose supported project quota"}
				}
				quotaEnabled := false
				for _, option := range strings.Split(bestOptions, ",") {
					if option == "prjquota" || option == "pquota" {
						quotaEnabled = true
						break
					}
				}
				if !quotaEnabled {
					return conformance.Result{Component: "host.scratch-quota", Status: conformance.Unavailable, Reason: "project quota is not enabled on the data filesystem"}
				}
				return conformance.Result{Component: "host.scratch-quota", Status: conformance.Pass}
			},
		},
		{
			Component: "host.nftables-tool",
			Run: func(ctx context.Context) conformance.Result {
				if result, canceled := canceledHostProbe(ctx, "host.nftables-tool"); canceled {
					return result
				}
				if sources.OperatingSystem != "linux" {
					return conformance.Result{Component: "host.nftables-tool", Status: conformance.Unavailable, Reason: "nftables requires Linux"}
				}
				path, err := sources.LookPath("nft")
				if err != nil {
					return conformance.Result{Component: "host.nftables-tool", Status: conformance.Unavailable, Reason: "nft executable is unavailable"}
				}
				if !filepath.IsAbs(path) || filepath.Clean(path) != path {
					return conformance.Result{Component: "host.nftables-tool", Status: conformance.Fail, Reason: "nft executable path is invalid"}
				}
				return conformance.Result{Component: "host.nftables-tool", Status: conformance.Pass}
			},
		},
		{
			Component: "host.kvm-access",
			Run: func(ctx context.Context) conformance.Result {
				if result, canceled := canceledHostProbe(ctx, "host.kvm-access"); canceled {
					return result
				}
				if sources.OperatingSystem != "linux" {
					return conformance.Result{Component: "host.kvm-access", Status: conformance.Unavailable, Reason: "KVM requires Linux"}
				}
				if err := sources.OpenReadWrite("/dev/kvm"); err != nil {
					return conformance.Result{Component: "host.kvm-access", Status: conformance.Unavailable, Reason: "/dev/kvm is absent or inaccessible"}
				}
				return conformance.Result{Component: "host.kvm-access", Status: conformance.Pass}
			},
		},
	}
	return probes, nil
}

func canceledHostProbe(ctx context.Context, component string) (conformance.Result, bool) {
	if ctx == nil || ctx.Err() != nil {
		return conformance.Result{
			Component: component,
			Status:    conformance.Fail,
			Reason:    "probe canceled",
		}, true
	}
	return conformance.Result{}, false
}
