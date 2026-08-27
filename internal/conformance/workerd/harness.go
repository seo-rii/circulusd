// Package workerd runs release-pinned Phase 0A probes against stock workerd.
// A PASS means the digest-pinned process executed that exact probe. Checks that
// need a real Pi package, stable broker RPC, or agentd-managed cgroups remain
// explicit NOT_RUN results until an external fixture supplies those boundaries.
package workerd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hancomac/circulusd/internal/conformance"
)

const maximumBinaryBytes = 512 << 20

const verifiedFDVersionDiagnostic = "Unable to find and open the program executable, " +
	"so unable to determine if there is a compiled-in config file. " +
	"Proceeding on the assumption that there is not.\n"

var (
	canonicalDigestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	compatibilityDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	compatibilityFlagPattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

	//go:embed fixture/phase0.capnp.tmpl fixture/session-host.mjs fixture/pi-worker.mjs
	fixtureFiles embed.FS
)

type Config struct {
	// BinaryPath is optional. When empty, Run resolves "workerd" through PATH.
	// An explicitly configured path must be absolute and canonical.
	BinaryPath string

	ExpectedBinaryDigest string
	ExpectedVersion      string
	CompatibilityDate    string
	CompatibilityFlags   []string
	ProbeTimeout         time.Duration
}

type Harness struct {
	config            Config
	environmentDigest string
	probes            []probe
	lookPath          func(string) (string, error)
	runCommand        func(context.Context, string, []string, string) commandOutput
}

type probe struct {
	component    string
	entrypoint   string
	notRunReason string
	mock         bool
}

var requiredProbes = []probe{
	{component: "workerd.agent-adapter-smoke", entrypoint: "agentEngine", mock: true},
	{component: "workerd.agent-engine", notRunReason: "real pinned Pi package probe is not configured"},
	{component: "workerd.content-addressed-replacement", entrypoint: "contentAddressedReplacement"},
	{component: "workerd.dynamic-worker", entrypoint: "dynamicWorker"},
	{component: "workerd.extension-order", entrypoint: "extensionOrder"},
	{component: "workerd.isolate-separation", entrypoint: "isolateSeparation"},
	{component: "workerd.outbound-denial", entrypoint: "outboundDenial"},
	{component: "workerd.shard-recycle", notRunReason: "agentd-managed cgroup pressure and same-identity Worker reconstruction probe is not configured"},
	{component: "workerd.stable-broker-binding", notRunReason: "stable broker RPC probe is not configured"},
}

type commandOutput struct {
	stdout []byte
	stderr []byte
	err    error
}

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = buffer.buffer.Write(value)
	}
	return originalLength, nil
}

func New(config Config) (*Harness, error) {
	if config.BinaryPath != "" &&
		(!filepath.IsAbs(config.BinaryPath) || filepath.Clean(config.BinaryPath) != config.BinaryPath) {
		return nil, fmt.Errorf("workerd conformance: binary path must be canonical and absolute")
	}
	if !canonicalDigestPattern.MatchString(config.ExpectedBinaryDigest) {
		return nil, fmt.Errorf("workerd conformance: expected binary digest is invalid")
	}
	if config.ExpectedVersion == "" || len(config.ExpectedVersion) > 128 ||
		strings.TrimSpace(config.ExpectedVersion) != config.ExpectedVersion ||
		strings.ContainsAny(config.ExpectedVersion, "\r\n\x00") {
		return nil, fmt.Errorf("workerd conformance: expected version is invalid")
	}
	if !compatibilityDatePattern.MatchString(config.CompatibilityDate) {
		return nil, fmt.Errorf("workerd conformance: compatibility date is invalid")
	}
	if _, err := time.Parse("2006-01-02", config.CompatibilityDate); err != nil {
		return nil, fmt.Errorf("workerd conformance: compatibility date is invalid")
	}
	if len(config.CompatibilityFlags) > 64 {
		return nil, fmt.Errorf("workerd conformance: too many compatibility flags")
	}
	flags := append([]string(nil), config.CompatibilityFlags...)
	for index, flag := range flags {
		if !compatibilityFlagPattern.MatchString(flag) {
			return nil, fmt.Errorf("workerd conformance: compatibility flag %d is invalid", index)
		}
		if index > 0 && flags[index-1] >= flag {
			return nil, fmt.Errorf("workerd conformance: compatibility flags must be unique and sorted")
		}
	}
	if config.ProbeTimeout <= 0 || config.ProbeTimeout > 5*time.Minute {
		return nil, fmt.Errorf("workerd conformance: probe timeout is outside its bound")
	}
	config.CompatibilityFlags = flags
	probes := append([]probe(nil), requiredProbes...)

	hash := sha256.New()
	for _, value := range []string{
		config.CompatibilityDate,
		strings.Join(config.CompatibilityFlags, "\x00"),
		"fixture/phase0.capnp.tmpl",
		"fixture/session-host.mjs",
		"fixture/pi-worker.mjs",
	} {
		_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(value))))
		_, _ = hash.Write([]byte(value))
	}
	for _, candidate := range probes {
		for _, value := range []string{
			"probe",
			candidate.component,
			candidate.entrypoint,
			candidate.notRunReason,
			fmt.Sprintf("%t", candidate.mock),
		} {
			_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(value))))
			_, _ = hash.Write([]byte(value))
		}
	}
	for _, path := range []string{
		"fixture/phase0.capnp.tmpl",
		"fixture/session-host.mjs",
		"fixture/pi-worker.mjs",
	} {
		contents, err := fixtureFiles.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("workerd conformance: read embedded fixture: %w", err)
		}
		_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(contents))))
		_, _ = hash.Write(contents)
	}

	harness := &Harness{
		config:            config,
		environmentDigest: fmt.Sprintf("sha256:%x", hash.Sum(nil)),
		probes:            probes,
		lookPath:          exec.LookPath,
	}
	harness.runCommand = func(ctx context.Context, binary string, arguments []string, directory string) commandOutput {
		command := exec.CommandContext(ctx, binary, arguments...)
		command.Dir = directory
		command.Env = []string{
			"HOME=" + directory,
			"LANG=C",
			"LC_ALL=C",
			"PATH=/nonexistent",
			"TMPDIR=" + directory,
			"TZ=UTC",
		}
		stdout := &boundedBuffer{limit: 64 << 10}
		stderr := &boundedBuffer{limit: 64 << 10}
		command.Stdout = stdout
		command.Stderr = stderr
		err := command.Run()
		return commandOutput{stdout: stdout.buffer.Bytes(), stderr: stderr.buffer.Bytes(), err: err}
	}
	return harness, nil
}

func (harness *Harness) Run(ctx context.Context) conformance.Report {
	defaultStatus := conformance.Pass
	defaultReason := ""
	binaryDigest := ""
	version := ""
	binaryPath := harness.config.BinaryPath
	binaryDirectory := ""
	var binaryFile *os.File

	if ctx == nil || ctx.Err() != nil {
		defaultStatus = conformance.NotRun
		defaultReason = "conformance run was canceled"
	}
	if defaultStatus == conformance.Pass && binaryPath == "" {
		resolved, err := harness.lookPath("workerd")
		if err != nil {
			defaultStatus = conformance.Unavailable
			defaultReason = "workerd executable is unavailable"
		} else {
			binaryPath, err = filepath.Abs(resolved)
			if err != nil {
				defaultStatus = conformance.Unavailable
				defaultReason = "workerd executable is unavailable"
			}
		}
	}
	if defaultStatus == conformance.Pass {
		binaryDirectory = filepath.Dir(binaryPath)
		file, err := os.Open(binaryPath)
		if errors.Is(err, fs.ErrNotExist) {
			defaultStatus = conformance.Unavailable
			defaultReason = "workerd executable is unavailable"
		} else if err != nil {
			defaultStatus = conformance.Fail
			defaultReason = "configured workerd executable cannot be inspected"
		} else {
			binaryFile = file
			defer binaryFile.Close()
			info, statErr := binaryFile.Stat()
			if statErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
				info.Size() > maximumBinaryBytes || info.Mode().Perm()&0o111 == 0 ||
				info.Mode().Perm()&0o022 != 0 {
				defaultStatus = conformance.Fail
				defaultReason = "configured workerd executable is not a sealed executable"
			}
		}
	}
	if defaultStatus == conformance.Pass {
		hash := sha256.New()
		_, copyErr := io.Copy(hash, io.LimitReader(binaryFile, maximumBinaryBytes+1))
		if copyErr != nil {
			defaultStatus = conformance.Fail
			defaultReason = "configured workerd executable cannot be inspected"
		} else {
			binaryDigest = fmt.Sprintf("sha256:%x", hash.Sum(nil))
			if binaryDigest != harness.config.ExpectedBinaryDigest {
				defaultStatus = conformance.Fail
				defaultReason = "workerd binary digest does not match the release pin"
			}
		}
	}
	verifiedBinaryPath := binaryPath
	if defaultStatus == conformance.Pass {
		verifiedBinaryPath = fmt.Sprintf("/proc/self/fd/%d", binaryFile.Fd())
	}
	if defaultStatus == conformance.Pass {
		versionContext, cancel := context.WithTimeout(ctx, harness.config.ProbeTimeout)
		output := harness.runCommand(versionContext, verifiedBinaryPath, []string{"--version"}, binaryDirectory)
		versionContextError := versionContext.Err()
		cancel()
		if output.err != nil {
			defaultStatus = conformance.Fail
			if errors.Is(versionContextError, context.DeadlineExceeded) {
				defaultReason = "workerd version probe exceeded its time budget"
			} else if errors.Is(versionContextError, context.Canceled) {
				defaultStatus = conformance.NotRun
				defaultReason = "conformance run was canceled"
			} else {
				defaultReason = "workerd version probe could not be completed"
			}
		} else {
			actualVersion := strings.TrimRight(string(output.stdout), "\r\n")
			stderrAccepted := len(output.stderr) == 0 || string(output.stderr) == verifiedFDVersionDiagnostic
			if actualVersion != harness.config.ExpectedVersion || !stderrAccepted {
				defaultStatus = conformance.Fail
				defaultReason = "workerd version does not match the release pin"
			} else {
				version = actualVersion
			}
		}
	}

	probeResults := make(map[string]conformance.Result, len(harness.probes))
	if defaultStatus == conformance.Pass {
		for _, candidate := range harness.probes {
			if candidate.entrypoint == "" {
				probeResults[candidate.component] = conformance.Result{
					Component: candidate.component,
					Status:    conformance.NotRun,
					Reason:    candidate.notRunReason,
				}
			}
		}
		directory, err := os.MkdirTemp("", "circulusd-workerd-conformance-")
		if err != nil {
			defaultStatus = conformance.Fail
			defaultReason = "workerd fixture directory could not be created"
		} else {
			defer os.RemoveAll(directory)
			template, templateErr := fixtureFiles.ReadFile("fixture/phase0.capnp.tmpl")
			host, hostErr := fixtureFiles.ReadFile("fixture/session-host.mjs")
			worker, workerErr := fixtureFiles.ReadFile("fixture/pi-worker.mjs")
			flags := make([]string, len(harness.config.CompatibilityFlags))
			for index, flag := range harness.config.CompatibilityFlags {
				flags[index] = `"` + flag + `"`
			}
			configuration := strings.ReplaceAll(string(template), "@COMPATIBILITY_DATE@", harness.config.CompatibilityDate)
			configuration = strings.ReplaceAll(configuration, "@COMPATIBILITY_FLAGS@", strings.Join(flags, ", "))
			hostSource := strings.ReplaceAll(string(host), "@COMPATIBILITY_DATE@", harness.config.CompatibilityDate)
			hostSource = strings.ReplaceAll(hostSource, "@COMPATIBILITY_FLAGS@", strings.Join(flags, ", "))
			writeErrors := []error{templateErr, hostErr, workerErr}
			if templateErr == nil {
				writeErrors = append(writeErrors,
					os.WriteFile(filepath.Join(directory, "phase0.capnp"), []byte(configuration), 0o600),
					os.WriteFile(filepath.Join(directory, "session-host.mjs"), []byte(hostSource), 0o600),
					os.WriteFile(filepath.Join(directory, "pi-worker.mjs"), worker, 0o600),
				)
			}
			for _, writeErr := range writeErrors {
				if writeErr != nil {
					defaultStatus = conformance.Fail
					defaultReason = "workerd fixture could not be materialized"
					break
				}
			}
			if defaultStatus == conformance.Pass {
				for _, candidate := range harness.probes {
					if candidate.entrypoint == "" {
						continue
					}
					if ctx.Err() != nil {
						probeResults[candidate.component] = conformance.Result{
							Component: candidate.component,
							Status:    conformance.NotRun,
							Reason:    "conformance run was canceled",
						}
						continue
					}
					probeContext, cancel := context.WithTimeout(ctx, harness.config.ProbeTimeout)
					output := harness.runCommand(probeContext, verifiedBinaryPath, []string{
						"test",
						"--experimental",
						"--predictable",
						"--no-verbose",
						"-I" + directory,
						filepath.Join(directory, "phase0.capnp"),
						"phase0:" + candidate.entrypoint,
					}, directory)
					probeContextError := probeContext.Err()
					cancel()
						result := conformance.Result{
							Component: candidate.component,
							Status:    conformance.Pass,
							Evidence:  conformance.Evidence{Mock: candidate.mock},
						}
					if output.err != nil {
						result.Status = conformance.Fail
						if errors.Is(probeContextError, context.DeadlineExceeded) {
							result.Reason = "stock workerd probe exceeded its time budget"
						} else if errors.Is(probeContextError, context.Canceled) {
							result.Status = conformance.NotRun
							result.Reason = "conformance run was canceled"
						} else {
							result.Reason = "stock workerd probe returned a non-zero exit status"
						}
					} else if len(output.stdout) != 0 {
						result.Status = conformance.Fail
						result.Reason = "stock workerd probe emitted unexpected standard output"
					}
					probeResults[candidate.component] = result
				}
			}
		}
	}

	collector := conformance.NewCollector()
	probes := append([]probe(nil), harness.probes...)
	sort.Slice(probes, func(left, right int) bool { return probes[left].component < probes[right].component })
	for _, candidate := range probes {
		result, found := probeResults[candidate.component]
		if !found {
			result = conformance.Result{
				Component: candidate.component,
				Status:    defaultStatus,
				Reason:    defaultReason,
			}
		}
		if binaryDigest != "" {
			result.Evidence.BinaryDigest = binaryDigest
			result.Evidence.EnvironmentDigest = harness.environmentDigest
		}
		if version != "" {
			result.Evidence.Version = version
		}
		_ = collector.Add(result)
	}
	return collector.Report()
}
