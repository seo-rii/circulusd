// objectstore-qualify checks native S3 conditional-write behavior in one
// explicitly configured existing bucket. It creates only a random .doctor
// probe object and conditionally removes that object. It never provisions a
// bucket, changes policies, discovers credentials, or follows redirects.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/objectstore"
	"github.com/hancomac/circulusd/internal/strictjson"
	"golang.org/x/sys/unix"
)

const component = "object-store/s3-cas"

type credentialConfig struct {
	Source string `json:"source"`
	File   string `json:"file,omitempty"`
}
type qualificationConfig struct {
	SchemaVersion        int              `json:"schemaVersion"`
	Endpoint             string           `json:"endpoint"`
	Region               string           `json:"region"`
	Bucket               string           `json:"bucket"`
	Credentials          credentialConfig `json:"credentials"`
	RequestTimeoutMillis int64            `json:"requestTimeoutMillis,omitempty"`
	ProbeTimeoutMillis   int64            `json:"probeTimeoutMillis,omitempty"`
	CleanupTimeoutMillis int64            `json:"cleanupTimeoutMillis,omitempty"`
	MaximumObjectBytes   int64            `json:"maximumObjectBytes,omitempty"`
}
type credentialValues struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
}
type qualificationReport struct {
	SchemaVersion       int                            `json:"schemaVersion"`
	Result              conformance.Result             `json:"result"`
	Observations        []objectstore.ProbeObservation `json:"observations"`
	CredentialSource    string                         `json:"credentialSource,omitempty"`
	CredentialVariables []string                       `json:"credentialVariables,omitempty"`
	EndpointDigest      string                         `json:"endpointDigest,omitempty"`
	BucketDigest        string                         `json:"bucketDigest,omitempty"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	flags := flag.NewFlagSet("objectstore-qualify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "explicit JSON qualification configuration")
	outputPath := flags.String("output", "", "new private JSON report path")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *configPath == "" || *outputPath == "" {
		fmt.Fprintln(stderr, "object-store qualification: --config and --output are required")
		return 1
	}
	// Reserve a new 0600 report before performing any provider write. O_EXCL
	// refuses existing files and symlinks instead of clobbering other evidence.
	output, err := openPrivateReport(*outputPath)
	if err != nil {
		fmt.Fprintln(stderr, "object-store qualification: cannot create private report")
		return 1
	}
	defer output.Close()
	if output.Chmod(0600) != nil {
		fmt.Fprintln(stderr, "object-store qualification: cannot secure private report")
		return 1
	}
	report := qualificationReport{SchemaVersion: 1, Result: conformance.Result{Component: component, Status: conformance.Fail, Reason: "invalid qualification configuration"}, Observations: []objectstore.ProbeObservation{}}
	var config qualificationConfig
	if err := readJSONFile(*configPath, &config, false); err == nil {
		report = qualify(ctx, config, getenv)
	} else if errors.Is(err, os.ErrNotExist) {
		report.Result.Status = conformance.Unavailable
		report.Result.Reason = "explicit qualification configuration is unavailable"
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if encoder.Encode(report) != nil || output.Sync() != nil || output.Close() != nil {
		fmt.Fprintln(stderr, "object-store qualification: cannot persist private report")
		return 1
	}
	fmt.Fprintf(stdout, "object-store qualification: %s; credential source: %s\n", report.Result.Status, report.CredentialSource)
	switch report.Result.Status {
	case conformance.Pass:
		return 0
	case conformance.Unavailable:
		return 2
	default:
		return 1
	}
}

func qualify(ctx context.Context, config qualificationConfig, getenv func(string) string) qualificationReport {
	report := qualificationReport{SchemaVersion: 1, Result: conformance.Result{Component: component, Status: conformance.Fail, Reason: "invalid qualification configuration"}, Observations: []objectstore.ProbeObservation{}}
	if config.SchemaVersion != 1 || (config.Credentials.Source != "environment" && config.Credentials.Source != "file") || (config.Credentials.Source == "environment" && config.Credentials.File != "") || (config.Credentials.Source == "file" && config.Credentials.File == "") {
		return report
	}
	report.CredentialSource = config.Credentials.Source
	probeMillis := config.ProbeTimeoutMillis
	if probeMillis == 0 {
		probeMillis = 30000
	}
	cleanupMillis := config.CleanupTimeoutMillis
	if cleanupMillis == 0 {
		cleanupMillis = 5000
	}
	if config.RequestTimeoutMillis < 0 || config.RequestTimeoutMillis > 30000 || probeMillis < 1 || probeMillis > 120000 || cleanupMillis < 1 || cleanupMillis > 30000 {
		return report
	}
	options := objectstore.S3StoreOptions{Endpoint: config.Endpoint, Region: config.Region, Bucket: config.Bucket, RequestTimeout: time.Duration(config.RequestTimeoutMillis) * time.Millisecond, MaximumObjectBytes: config.MaximumObjectBytes, AccessKeyID: "configuration-validation", SecretAccessKey: "configuration-validation"}
	validation, err := objectstore.NewS3Store(options)
	if err != nil {
		return report
	}
	validation.Close()
	report.EndpointDigest = digest(config.Endpoint)
	report.BucketDigest = digest(config.Bucket)
	var values credentialValues
	if config.Credentials.Source == "environment" {
		report.CredentialVariables = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}
		values = credentialValues{AccessKeyID: getenv("AWS_ACCESS_KEY_ID"), SecretAccessKey: getenv("AWS_SECRET_ACCESS_KEY"), SessionToken: getenv("AWS_SESSION_TOKEN")}
		if values.AccessKeyID == "" || values.SecretAccessKey == "" {
			report.Result.Status = conformance.Unavailable
			report.Result.Reason = "explicit environment credentials are unavailable"
			return report
		}
	} else if err := readJSONFile(config.Credentials.File, &values, true); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			report.Result.Status = conformance.Unavailable
			report.Result.Reason = "explicit credential file is unavailable"
		} else {
			report.Result.Reason = "credential file must be private regular JSON"
		}
		return report
	}
	options.AccessKeyID = values.AccessKeyID
	options.SecretAccessKey = values.SecretAccessKey
	options.SessionToken = values.SessionToken
	// Validate complete credentials before a probe can create its isolated key.
	validation, err = objectstore.NewS3Store(options)
	if err != nil {
		report.Result.Reason = "invalid explicit credentials"
		return report
	}
	validation.Close()
	probeContext, cancel := context.WithTimeout(ctx, time.Duration(probeMillis)*time.Millisecond)
	defer cancel()
	report.Result = objectstore.ProbeCAS(probeContext, objectstore.ProbeConfig{Component: component, CleanupTimeout: time.Duration(cleanupMillis) * time.Millisecond, Observe: func(o objectstore.ProbeObservation) { report.Observations = append(report.Observations, o) }, Open: func(context.Context) (objectstore.Store, error) { return objectstore.NewS3Store(options) }})
	// This report contains live observations but cannot establish native celld
	// Storage conformance or confer AdmissionReady on the whole application.
	report.Result.Evidence.Class = conformance.EvidenceClassHostObservation
	return report
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func openPrivateReport(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parent, err := unix.Open(filepath.Dir(absolute), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	var information unix.Stat_t
	if unix.Fstat(parent, &information) != nil || information.Uid != uint32(os.Geteuid()) || information.Mode&0077 != 0 {
		return nil, errors.New("output directory must be private and owned by this user")
	}
	descriptor, err := unix.Openat(parent, filepath.Base(absolute), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), "qualification-report"), nil
}

func readJSONFile(path string, value any, private bool) error {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), "qualification-input")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return errors.New("invalid input file")
	}
	if private {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
			return errors.New("credential file is not private")
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return errors.New("invalid input file")
	}
	// One exact interpretation: no duplicate members, case-folded aliases,
	// unknown members or trailing values.
	if strictjson.Decode(data, value) != nil {
		return errors.New("invalid JSON input")
	}
	return nil
}
