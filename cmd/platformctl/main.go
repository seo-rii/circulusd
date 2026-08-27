package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hancomac/circulusd/internal/config"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/doctor"
	"github.com/hancomac/circulusd/internal/release"
)

const (
	defaultConfigurationPath = "/etc/pi-platform/config.yaml"
	defaultReleasePath       = "/usr/lib/pi-platform/release-manifest.json"
	defaultReleaseRootsPath  = "/etc/pi-platform/release-trust-roots.json"
	minimumDoctorFreeBytes   = 5 << 30
	minimumDoctorFreeInodes  = 100_000
)

type configurationSnapshot struct {
	dataDirectory string
	backends      []config.Backend
}

type commandDependencies struct {
	stdout            io.Writer
	stderr            io.Writer
	clock             func() time.Time
	loadConfiguration func(string, config.InstallProfile) (configurationSnapshot, string, error)
	loadRelease       func(string, string, bool) (doctor.Probe, string, error)
	hostSources       doctor.HostSources
	additionalProbes  []doctor.Probe
	runID             func() (string, error)
	hostID            func() (string, error)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(execute(ctx, os.Args[1:], defaultDependencies()))
}

func execute(ctx context.Context, arguments []string, dependencies commandDependencies) int {
	if len(arguments) == 0 || arguments[0] != "doctor" {
		if dependencies.stderr != nil {
			fmt.Fprintln(dependencies.stderr, "usage: platformctl doctor [options]")
		}
		return 2
	}
	flags := flag.NewFlagSet("platformctl doctor", flag.ContinueOnError)
	flags.SetOutput(dependencies.stderr)
	configurationPath := flags.String("config", defaultConfigurationPath, "absolute platform configuration path")
	releasePath := flags.String("release-manifest", defaultReleasePath, "absolute release manifest path")
	releaseRootsPath := flags.String("release-trust-roots", defaultReleaseRootsPath, "absolute offline release trust-root path")
	profileName := flags.String("profile", string(config.InstallProfileFull), "install profile")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	if !filepath.IsAbs(*configurationPath) ||
		filepath.Clean(*configurationPath) != *configurationPath ||
		*configurationPath == string(filepath.Separator) ||
		!filepath.IsAbs(*releasePath) ||
		filepath.Clean(*releasePath) != *releasePath ||
		*releasePath == string(filepath.Separator) ||
		!filepath.IsAbs(*releaseRootsPath) ||
		filepath.Clean(*releaseRootsPath) != *releaseRootsPath ||
		*releaseRootsPath == string(filepath.Separator) {
		if dependencies.stderr != nil {
			fmt.Fprintln(dependencies.stderr, "platformctl: configuration, release, and trust-root paths must be canonical absolute files")
		}
		return 2
	}
	profile := config.InstallProfile(*profileName)
	switch profile {
	case config.InstallProfileLightweight,
		config.InstallProfileDocker,
		config.InstallProfileFull,
		config.InstallProfileFirecracker,
		config.InstallProfileDevelopment:
	default:
		if dependencies.stderr != nil {
			fmt.Fprintf(dependencies.stderr, "platformctl: unsupported profile %q\n", *profileName)
		}
		return 2
	}
	if ctx == nil || dependencies.stdout == nil || dependencies.stderr == nil ||
		dependencies.clock == nil || dependencies.loadConfiguration == nil ||
		dependencies.loadRelease == nil || dependencies.runID == nil || dependencies.hostID == nil {
		return 1
	}

	configuration, configurationDigest, err := dependencies.loadConfiguration(
		*configurationPath,
		profile,
	)
	if err != nil {
		fmt.Fprintf(dependencies.stderr, "platformctl: load configuration: %v\n", err)
		return 1
	}
	conformanceProfile, err := doctor.ConformanceProfile(profile, configuration.backends)
	if err != nil {
		fmt.Fprintf(dependencies.stderr, "platformctl: select conformance profile: %v\n", err)
		return 1
	}
	releaseProbe, releaseDigest, err := dependencies.loadRelease(
		*releasePath,
		*releaseRootsPath,
		conformanceProfile.Production,
	)
	if err != nil {
		fmt.Fprintf(dependencies.stderr, "platformctl: load release manifest: %v\n", err)
		return 1
	}
	hostProbes, err := doctor.HostProbes(doctor.HostRequirements{
		DataDirectory:     configuration.dataDirectory,
		MinimumFreeBytes:  minimumDoctorFreeBytes,
		MinimumFreeInodes: minimumDoctorFreeInodes,
	}, dependencies.hostSources)
	if err != nil {
		fmt.Fprintf(dependencies.stderr, "platformctl: configure host probes: %v\n", err)
		return 1
	}
	runID, err := dependencies.runID()
	if err != nil {
		fmt.Fprintln(dependencies.stderr, "platformctl: create doctor run identity")
		return 1
	}
	hostID, err := dependencies.hostID()
	if err != nil {
		fmt.Fprintln(dependencies.stderr, "platformctl: read host identity")
		return 1
	}
	probes := make(
		[]doctor.Probe,
		0,
		len(hostProbes)+1+len(dependencies.additionalProbes),
	)
	probes = append(probes, hostProbes...)
	probes = append(probes, releaseProbe)
	probes = append(probes, dependencies.additionalProbes...)
	report, err := doctor.Run(ctx, doctor.Plan{
		RunID:         runID,
		Profile:       conformanceProfile,
		ConfigDigest:  configurationDigest,
		ReleaseDigest: releaseDigest,
		HostID:        hostID,
		Clock:         dependencies.clock,
		Probes:        probes,
	})
	if err != nil {
		fmt.Fprintf(dependencies.stderr, "platformctl: run doctor: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(dependencies.stdout)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(dependencies.stderr, "platformctl: write doctor report")
		return 1
	}
	if !report.ProfileQualified {
		return 1
	}
	return 0
}

func defaultDependencies() commandDependencies {
	return commandDependencies{
		stdout: os.Stdout,
		stderr: os.Stderr,
		clock:  time.Now,
		loadConfiguration: func(
			path string,
			profile config.InstallProfile,
		) (configurationSnapshot, string, error) {
			file, err := os.Open(path)
			if err != nil {
				return configurationSnapshot{}, "", err
			}
			hasher := sha256.New()
			configuration, parseErr := config.Parse(io.TeeReader(file, hasher))
			closeErr := file.Close()
			if parseErr != nil {
				return configurationSnapshot{}, "", parseErr
			}
			if closeErr != nil {
				return configurationSnapshot{}, "", closeErr
			}
			if err := configuration.ValidateForProfile(profile); err != nil {
				return configurationSnapshot{}, "", err
			}
			return configurationSnapshot{
				dataDirectory: configuration.Server.DataDirectory,
				backends:      append([]config.Backend(nil), configuration.Execution.AllowedBackends...),
			}, "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
		},
		loadRelease: func(path string, trustRootsPath string, production bool) (doctor.Probe, string, error) {
			manifest, err := release.Load(path)
			if err != nil {
				return doctor.Probe{}, "", err
			}
			if err := manifest.Validate(); err != nil {
				return doctor.Probe{}, "", err
			}
			digest, err := release.ManifestSigningDigest(manifest)
			if err != nil {
				return doctor.Probe{}, "", err
			}
			result := conformance.Result{
				Component: "release.signature",
				Status:    conformance.NotRun,
				Reason:    "offline release signature trust roots are not configured",
				Evidence: conformance.Evidence{
					BinaryDigest: digest,
					Version:      manifest.Release.Version,
				},
			}
			if manifest.Release.Status == "development" {
				if production {
					result.Status = conformance.Fail
					result.Reason = "development release manifest cannot qualify a production profile"
				} else {
					result.Status = conformance.Pass
					result.Reason = "unsigned development manifest is reference-only"
					result.Evidence.Mock = true
				}
			} else {
				trustStore, trustErr := release.LoadTrustStore(trustRootsPath)
				switch {
				case errors.Is(trustErr, fs.ErrNotExist):
				case trustErr != nil:
					result.Status = conformance.Fail
					result.Reason = "offline release signature trust roots are invalid or unreadable"
				case trustStore.VerifyPromotion(manifest) != nil:
					result.Status = conformance.Fail
					result.Reason = "release manifest or artifact signature verification failed"
				default:
					result.Status = conformance.Pass
					result.Reason = "release manifest and artifacts match a configured offline trust root"
				}
			}
			return doctor.Probe{
				Component: "release.signature",
				Run:       func(context.Context) conformance.Result { return result },
			}, digest, nil
		},
		hostSources: doctor.LocalHostSources(),
		runID: func() (string, error) {
			bytes := make([]byte, 16)
			if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
				return "", err
			}
			return "doctor-" + hex.EncodeToString(bytes), nil
		},
		hostID: func() (string, error) {
			file, err := os.Open("/etc/machine-id")
			if err != nil {
				return "", err
			}
			encoded, readErr := io.ReadAll(io.LimitReader(file, 1_025))
			closeErr := file.Close()
			if readErr != nil {
				return "", readErr
			}
			if closeErr != nil {
				return "", closeErr
			}
			machineID := strings.TrimSpace(string(encoded))
			if machineID == "" || len(encoded) > 1_024 {
				return "", fmt.Errorf("machine identity is invalid")
			}
			digest := sha256.Sum256([]byte(machineID))
			return "host-" + hex.EncodeToString(digest[:]), nil
		},
	}
}
