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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/config"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/controlrpc"
	"github.com/hancomac/circulusd/internal/doctor"
	"github.com/hancomac/circulusd/internal/doctoruds"
	"github.com/hancomac/circulusd/internal/release"
)

const (
	defaultConfigurationPath = "/etc/pi-platform/config.yaml"
	defaultReleasePath       = "/usr/lib/pi-platform/release-manifest.json"
	defaultReleaseRootsPath  = "/etc/pi-platform/release-trust-roots.json"
	defaultPlatformdSocket   = "/run/pi-platform/platformd.sock"
	defaultAgentdSocket      = "/run/pi-platform/agentd.sock"
	defaultExecutordSocket   = "/run/pi-platform/executord.sock"
	minimumDoctorFreeBytes   = 5 << 30
	minimumDoctorFreeInodes  = 100_000
	defaultControlTimeout    = 30 * time.Second
	maximumControlTimeout    = 5 * time.Minute
	maximumControlPathBytes  = 107
)

type configurationSnapshot struct {
	dataDirectory string
	backends      []config.Backend
}

type commandDependencies struct {
	stdout             io.Writer
	stderr             io.Writer
	clock              func() time.Time
	loadConfiguration  func(string, config.InstallProfile) (configurationSnapshot, string, error)
	loadRelease        func(string, string, bool) (doctor.Probe, string, error)
	hostSources        doctor.HostSources
	additionalProbes   []doctor.Probe
	runID              func() (string, error)
	hostID             func() (string, error)
	runnerBinaryDigest func() (string, error)
	targetInstanceID   func() (string, error)
	buildUDSProbe      func(doctoruds.Config) (doctor.Probe, error)
	getCapabilities    func(context.Context, string) (*v1.GetCapabilitiesResponse, error)
}

type capabilitiesOutput struct {
	APIVersion     string             `json:"apiVersion"`
	Protocol       protocolOutput     `json:"protocol"`
	ServerSequence string             `json:"serverSequence"`
	Capabilities   []capabilityOutput `json:"capabilities"`
}

type protocolOutput struct {
	Major            uint64 `json:"major"`
	Minor            uint64 `json:"minor"`
	DescriptorDigest string `json:"descriptorDigest"`
}

type capabilityOutput struct {
	Name              string                 `json:"name"`
	Availability      string                 `json:"availability"`
	UnavailableReason *capabilityErrorOutput `json:"unavailableReason,omitempty"`
	Attributes        map[string]string      `json:"attributes,omitempty"`
}

type capabilityErrorOutput struct {
	Code         string            `json:"code"`
	Reason       string            `json:"reason"`
	Message      string            `json:"message"`
	Retryable    bool              `json:"retryable"`
	RetryAfterMS string            `json:"retryAfterMs,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(execute(ctx, os.Args[1:], defaultDependencies()))
}

func execute(ctx context.Context, arguments []string, dependencies commandDependencies) int {
	if dependencies.stdout != nil {
		reflected := reflect.ValueOf(dependencies.stdout)
		switch reflected.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if reflected.IsNil() {
				dependencies.stdout = nil
			}
		}
	}
	if dependencies.stderr != nil {
		reflected := reflect.ValueOf(dependencies.stderr)
		switch reflected.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if reflected.IsNil() {
				dependencies.stderr = nil
			}
		}
	}
	if len(arguments) == 0 {
		if dependencies.stderr != nil {
			fmt.Fprintln(dependencies.stderr, "usage: platformctl <doctor|capabilities> [options]")
		}
		return 2
	}
	if arguments[0] == "capabilities" {
		flags := flag.NewFlagSet("platformctl capabilities", flag.ContinueOnError)
		flags.SetOutput(dependencies.stderr)
		socketPath := flags.String("socket", defaultPlatformdSocket, "canonical absolute platformd control socket path")
		timeout := flags.Duration("timeout", defaultControlTimeout, "control request timeout")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
			return 2
		}
		if !filepath.IsAbs(*socketPath) || filepath.Clean(*socketPath) != *socketPath ||
			*socketPath == string(filepath.Separator) || *timeout <= 0 || *timeout > maximumControlTimeout {
			if dependencies.stderr != nil {
				fmt.Fprintln(dependencies.stderr, "platformctl: socket must be canonical and absolute and timeout must be within (0, 5m]")
			}
			return 2
		}
		if ctx == nil || dependencies.stdout == nil || dependencies.stderr == nil || dependencies.getCapabilities == nil {
			return 1
		}
		requestContext, cancel := context.WithTimeout(ctx, *timeout)
		response, err := dependencies.getCapabilities(requestContext, *socketPath)
		cancel()
		if err != nil {
			fmt.Fprintf(dependencies.stderr, "platformctl: query capabilities failed (code=%s)\n", connect.CodeOf(err))
			return 1
		}
		if response == nil || response.GetMeta() == nil || response.GetMeta().GetServerSequence() == 0 ||
			response.GetProtocolVersion().GetMajor() != 1 || response.GetProtocolVersion().GetMinor() != 0 ||
			response.GetDescriptorDigest().GetAlgorithm() != v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 ||
			len(response.GetDescriptorDigest().GetValue()) != sha256.Size {
			fmt.Fprintln(dependencies.stderr, "platformctl: invalid capability response")
			return 1
		}
		document := capabilitiesOutput{
			APIVersion: "v1alpha",
			Protocol: protocolOutput{
				Major:            response.GetProtocolVersion().GetMajor(),
				Minor:            response.GetProtocolVersion().GetMinor(),
				DescriptorDigest: "sha256:" + hex.EncodeToString(response.GetDescriptorDigest().GetValue()),
			},
			ServerSequence: strconv.FormatUint(response.GetMeta().GetServerSequence(), 10),
			Capabilities:   make([]capabilityOutput, 0, len(response.GetCapabilities())),
		}
		seenNames := make(map[string]struct{}, len(response.GetCapabilities()))
		for _, capability := range response.GetCapabilities() {
			if capability == nil {
				fmt.Fprintln(dependencies.stderr, "platformctl: invalid capability response")
				return 1
			}
			validName := capability.GetName() != "" && len(capability.GetName()) <= 256
			for _, character := range capability.GetName() {
				if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
					character != '.' && character != '_' && character != ':' && character != '/' && character != '-' {
					validName = false
				}
			}
			if !validName {
				fmt.Fprintln(dependencies.stderr, "platformctl: invalid capability response")
				return 1
			}
			if _, duplicate := seenNames[capability.GetName()]; duplicate {
				fmt.Fprintln(dependencies.stderr, "platformctl: invalid capability response")
				return 1
			}
			seenNames[capability.GetName()] = struct{}{}
			item := capabilityOutput{Name: capability.GetName()}
			switch capability.GetAvailability() {
			case v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE:
				if capability.GetUnavailableReason() != nil {
					fmt.Fprintln(dependencies.stderr, "platformctl: invalid capability response")
					return 1
				}
				item.Availability = "available"
			case v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE,
				v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_DEGRADED,
				v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_FORBIDDEN:
				reason := capability.GetUnavailableReason()
				if reason == nil || reason.GetCode() <= v1.ErrorCode_ERROR_CODE_UNSPECIFIED ||
					reason.GetCode() > v1.ErrorCode_ERROR_CODE_NEEDS_CONFIRMATION ||
					reason.GetReason() == "" || reason.GetReason() != strings.TrimSpace(reason.GetReason()) ||
					reason.GetMessage() == "" || !utf8.ValidString(reason.GetReason()) || !utf8.ValidString(reason.GetMessage()) ||
					len(reason.GetReason()) > 256 || len(reason.GetMessage()) > 1_024 ||
					strings.IndexFunc(reason.GetReason(), unicode.IsControl) >= 0 || strings.IndexFunc(reason.GetMessage(), unicode.IsControl) >= 0 ||
					len(reason.GetMetadata()) > 32 {
					fmt.Fprintln(dependencies.stderr, "platformctl: invalid capability response")
					return 1
				}
				item.Availability = strings.ToLower(strings.TrimPrefix(capability.GetAvailability().String(), "CAPABILITY_AVAILABILITY_"))
				item.UnavailableReason = &capabilityErrorOutput{
					Code:      strings.ToLower(strings.TrimPrefix(reason.GetCode().String(), "ERROR_CODE_")),
					Reason:    reason.GetReason(),
					Message:   reason.GetMessage(),
					Retryable: reason.GetRetryable(),
				}
				if reason.GetRetryAfterMs() != 0 {
					item.UnavailableReason.RetryAfterMS = strconv.FormatUint(reason.GetRetryAfterMs(), 10)
				}
				if len(reason.GetMetadata()) != 0 {
					item.UnavailableReason.Metadata = make(map[string]string, len(reason.GetMetadata()))
					for key, value := range reason.GetMetadata() {
						if key == "" || !utf8.ValidString(key) || !utf8.ValidString(value) || len(key) > 256 || len(value) > 1_024 ||
							strings.IndexFunc(key, unicode.IsControl) >= 0 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
							fmt.Fprintln(dependencies.stderr, "platformctl: invalid capability response")
							return 1
						}
						item.UnavailableReason.Metadata[key] = value
					}
				}
			default:
				fmt.Fprintln(dependencies.stderr, "platformctl: invalid capability response")
				return 1
			}
			if len(capability.GetAttributes()) > 32 {
				fmt.Fprintln(dependencies.stderr, "platformctl: invalid capability response")
				return 1
			}
			if len(capability.GetAttributes()) != 0 {
				item.Attributes = make(map[string]string, len(capability.GetAttributes()))
				for key, value := range capability.GetAttributes() {
					if key == "" || !utf8.ValidString(key) || !utf8.ValidString(value) || len(key) > 256 || len(value) > 1_024 ||
						strings.IndexFunc(key, unicode.IsControl) >= 0 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
						fmt.Fprintln(dependencies.stderr, "platformctl: invalid capability response")
						return 1
					}
					item.Attributes[key] = value
				}
			}
			document.Capabilities = append(document.Capabilities, item)
		}
		sort.Slice(document.Capabilities, func(left, right int) bool {
			return document.Capabilities[left].Name < document.Capabilities[right].Name
		})
		encoder := json.NewEncoder(dependencies.stdout)
		encoder.SetEscapeHTML(true)
		if err := encoder.Encode(document); err != nil {
			fmt.Fprintln(dependencies.stderr, "platformctl: write capability report")
			return 1
		}
		return 0
	}
	if arguments[0] != "doctor" {
		if dependencies.stderr != nil {
			fmt.Fprintln(dependencies.stderr, "usage: platformctl <doctor|capabilities> [options]")
		}
		return 2
	}
	flags := flag.NewFlagSet("platformctl doctor", flag.ContinueOnError)
	flags.SetOutput(dependencies.stderr)
	configurationPath := flags.String("config", defaultConfigurationPath, "absolute platform configuration path")
	releasePath := flags.String("release-manifest", defaultReleasePath, "absolute release manifest path")
	releaseRootsPath := flags.String("release-trust-roots", defaultReleaseRootsPath, "absolute offline release trust-root path")
	profileName := flags.String("profile", string(config.InstallProfileFull), "install profile")
	platformdSocket := flags.String("platformd-socket", defaultPlatformdSocket, "canonical absolute platformd control socket path")
	agentdSocket := flags.String("agentd-socket", defaultAgentdSocket, "canonical absolute agentd control socket path")
	executordSocket := flags.String("executord-socket", defaultExecutordSocket, "canonical absolute executord control socket path")
	udsTimeout := flags.Duration("uds-timeout", defaultControlTimeout, "total daemon control protocol probe timeout")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	invalidControlSocket := false
	controlSockets := []string{*platformdSocket, *agentdSocket, *executordSocket}
	seenControlSockets := make(map[string]struct{}, len(controlSockets))
	for _, path := range controlSockets {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
			path == string(filepath.Separator) || len(path) > maximumControlPathBytes ||
			!utf8.ValidString(path) || strings.IndexFunc(path, unicode.IsControl) >= 0 {
			invalidControlSocket = true
		}
		if _, duplicate := seenControlSockets[path]; duplicate {
			invalidControlSocket = true
		}
		seenControlSockets[path] = struct{}{}
	}
	if !filepath.IsAbs(*configurationPath) ||
		filepath.Clean(*configurationPath) != *configurationPath ||
		*configurationPath == string(filepath.Separator) ||
		!filepath.IsAbs(*releasePath) ||
		filepath.Clean(*releasePath) != *releasePath ||
		*releasePath == string(filepath.Separator) ||
		!filepath.IsAbs(*releaseRootsPath) ||
		filepath.Clean(*releaseRootsPath) != *releaseRootsPath ||
		*releaseRootsPath == string(filepath.Separator) || invalidControlSocket ||
		*udsTimeout <= 0 || *udsTimeout > doctoruds.MaximumProbeTimeout {
		if dependencies.stderr != nil {
			fmt.Fprintln(dependencies.stderr, "platformctl: file and daemon socket paths or UDS timeout are invalid")
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
		dependencies.loadRelease == nil || dependencies.runID == nil || dependencies.hostID == nil ||
		dependencies.runnerBinaryDigest == nil || dependencies.targetInstanceID == nil || dependencies.buildUDSProbe == nil {
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
	udsProbe, err := dependencies.buildUDSProbe(doctoruds.Config{
		Endpoints: []doctoruds.Endpoint{
			{Name: doctoruds.Platformd, SocketPath: *platformdSocket, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD},
			{Name: doctoruds.Agentd, SocketPath: *agentdSocket, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD},
			{Name: doctoruds.Executord, SocketPath: *executordSocket, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD},
		},
		Timeout: *udsTimeout,
	})
	if err != nil {
		fmt.Fprintln(dependencies.stderr, "platformctl: configure daemon protocol probe")
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
	runnerBinaryDigest, err := dependencies.runnerBinaryDigest()
	if err != nil {
		fmt.Fprintln(dependencies.stderr, "platformctl: read doctor runner identity")
		return 1
	}
	targetInstanceID, err := dependencies.targetInstanceID()
	if err != nil {
		fmt.Fprintln(dependencies.stderr, "platformctl: read target instance identity")
		return 1
	}
	probes := make(
		[]doctor.Probe,
		0,
		len(hostProbes)+2+len(dependencies.additionalProbes),
	)
	probes = append(probes, hostProbes...)
	probes = append(probes, releaseProbe)
	probes = append(probes, udsProbe)
	probes = append(probes, dependencies.additionalProbes...)
	report, err := doctor.Run(ctx, doctor.Plan{
		RunID:              runID,
		Profile:            conformanceProfile,
		ConfigDigest:       configurationDigest,
		ReleaseDigest:      releaseDigest,
		HostID:             hostID,
		RunnerBinaryDigest: runnerBinaryDigest,
		TargetInstanceID:   targetInstanceID,
		Clock:              dependencies.clock,
		Probes:             probes,
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
					Class:        conformance.EvidenceClassExternal,
					BinaryDigest: digest,
					Version:      manifest.Release.Version,
					ArtifactReferences: []conformance.ArtifactReference{{
						Name:   "release-manifest.json",
						Digest: digest,
					}},
				},
			}
			if manifest.Release.Status == "development" {
				if production {
					result.Status = conformance.Fail
					result.Reason = "development release manifest cannot qualify a production profile"
				} else {
					result.Status = conformance.Pass
					result.Reason = ""
					result.Evidence.Class = conformance.EvidenceClassReferenceOnly
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
					result.Reason = ""
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
		runnerBinaryDigest: func() (string, error) {
			file, err := os.Open("/proc/self/exe")
			if err != nil {
				return "", err
			}
			hasher := sha256.New()
			_, readErr := io.Copy(hasher, file)
			closeErr := file.Close()
			if readErr != nil {
				return "", readErr
			}
			if closeErr != nil {
				return "", closeErr
			}
			return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
		},
		targetInstanceID: func() (string, error) {
			file, err := os.Open("/proc/sys/kernel/random/boot_id")
			if err != nil {
				return "", err
			}
			encoded, readErr := io.ReadAll(io.LimitReader(file, 129))
			closeErr := file.Close()
			if readErr != nil {
				return "", readErr
			}
			if closeErr != nil {
				return "", closeErr
			}
			bootID := strings.TrimSpace(string(encoded))
			if bootID == "" || len(encoded) > 128 || !utf8.ValidString(bootID) ||
				strings.IndexFunc(bootID, unicode.IsControl) >= 0 {
				return "", fmt.Errorf("boot identity is invalid")
			}
			digest := sha256.Sum256([]byte(bootID))
			return "boot-" + hex.EncodeToString(digest[:]), nil
		},
		buildUDSProbe: doctoruds.BuildProbe,
		getCapabilities: func(ctx context.Context, socketPath string) (*v1.GetCapabilitiesResponse, error) {
			client, err := controlrpc.NewClient(controlrpc.ClientConfig{
				SocketPath: socketPath,
				Peer:       v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL,
			})
			if err != nil {
				return nil, err
			}
			response, callErr := client.GetCapabilities(ctx)
			closeErr := client.Close()
			if callErr != nil {
				return nil, callErr
			}
			if closeErr != nil {
				return nil, closeErr
			}
			return response, nil
		},
	}
}
