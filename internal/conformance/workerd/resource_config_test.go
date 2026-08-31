package workerd

import (
	"strings"
	"testing"
	"time"
)

func TestParseResourceQualificationConfigAcceptsCanonicalOperatorInputs(t *testing.T) {
	t.Parallel()

	config, err := parseResourceQualificationConfig(strings.NewReader(validResourceQualificationJSON()))
	if err != nil {
		t.Fatalf("parseResourceQualificationConfig() error = %v", err)
	}
	if config.SchemaVersion != 1 || config.Architecture != "x86_64" ||
		config.Limits.CPUMaxQuotaMicros != 50_000 || config.Limits.CPUMaxPeriodMicros != 100_000 ||
		config.Limits.MemoryMaxBytes != 1_073_741_824 || config.Limits.MemorySwapMaxBytes != 0 ||
		config.Limits.PIDsMax != 128 || config.ColdStartSamples != 5 {
		t.Fatalf("parsed config = %#v", config)
	}
	if config.Timeouts.Readiness != 10*time.Second || config.Timeouts.Probe != time.Minute ||
		config.Timeouts.Drain != 30*time.Second || config.Timeouts.Total != 10*time.Minute {
		t.Fatalf("parsed timeouts = %#v", config.Timeouts)
	}
}

func TestParseResourceQualificationConfigRejectsCallerControlledIdentityAndLaunchInputs(t *testing.T) {
	t.Parallel()

	for _, field := range []string{
		`"expectedWorkerdDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
		`"expectedWorkerdVersion":"workerd 2026-08-25"`,
		`"sessionHostDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`,
		`"fixtureDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"`,
		`"workerdArguments":["serve","--unsafe"]`,
		`"childEnvironment":{"TOKEN":"caller-controlled"}`,
	} {
		field := field
		t.Run(strings.SplitN(field, ":", 2)[0], func(t *testing.T) {
			t.Parallel()
			input := strings.Replace(validResourceQualificationJSON(), "{", "{"+field+",", 1)
			if _, err := parseResourceQualificationConfig(strings.NewReader(input)); err == nil {
				t.Fatalf("parseResourceQualificationConfig() accepted caller field %s", field)
			}
		})
	}
}

func TestParseResourceQualificationConfigRejectsAmbiguousOrUnboundedDocuments(t *testing.T) {
	t.Parallel()

	valid := validResourceQualificationJSON()
	tests := []struct {
		name  string
		input string
	}{
		{name: "duplicate field", input: strings.Replace(valid, `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)},
		{name: "unknown nested field", input: strings.Replace(valid, `"limits":{`, `"limits":{"cpuMax":"max",`, 1)},
		{name: "unsupported schema", input: strings.Replace(valid, `"schemaVersion":1`, `"schemaVersion":2`, 1)},
		{name: "relative manifest", input: strings.Replace(valid, `"/usr/lib/pi-platform/release-manifest.json"`, `"release-manifest.json"`, 1)},
		{name: "unclean trust roots", input: strings.Replace(valid, `"/etc/pi-platform/release-trust-roots.json"`, `"/etc/pi-platform/../release-trust-roots.json"`, 1)},
		{name: "root workerd", input: strings.Replace(valid, `"/usr/lib/pi-platform/bin/workerd"`, `"/"`, 1)},
		{name: "invalid architecture", input: strings.Replace(valid, `"x86_64"`, `"X86 64"`, 1)},
		{name: "quota too small", input: strings.Replace(valid, `"cpuMaxQuotaMicros":50000`, `"cpuMaxQuotaMicros":999`, 1)},
		{name: "quota too large", input: strings.Replace(valid, `"cpuMaxQuotaMicros":50000`, `"cpuMaxQuotaMicros":1000000001`, 1)},
		{name: "period too small", input: strings.Replace(valid, `"cpuMaxPeriodMicros":100000`, `"cpuMaxPeriodMicros":999`, 1)},
		{name: "period too large", input: strings.Replace(valid, `"cpuMaxPeriodMicros":100000`, `"cpuMaxPeriodMicros":1000001`, 1)},
		{name: "zero memory", input: strings.Replace(valid, `"memoryMaxBytes":1073741824`, `"memoryMaxBytes":0`, 1)},
		{name: "zero pids", input: strings.Replace(valid, `"pidsMax":128`, `"pidsMax":0`, 1)},
		{name: "too few samples", input: strings.Replace(valid, `"coldStartSamples":5`, `"coldStartSamples":4`, 1)},
		{name: "too many samples", input: strings.Replace(valid, `"coldStartSamples":5`, `"coldStartSamples":101`, 1)},
		{name: "zero readiness", input: strings.Replace(valid, `"readiness":10000`, `"readiness":0`, 1)},
		{name: "individual equals total", input: strings.Replace(valid, `"probe":60000`, `"probe":600000`, 1)},
		{name: "total over fifteen minutes", input: strings.Replace(valid, `"total":600000`, `"total":900001`, 1)},
		{name: "trailing value", input: valid + `{}`},
		{name: "oversized", input: valid + strings.Repeat(" ", maximumResourceQualificationConfigBytes)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseResourceQualificationConfig(strings.NewReader(test.input)); err == nil {
				t.Fatal("parseResourceQualificationConfig() error = nil")
			}
		})
	}
}

func validResourceQualificationJSON() string {
	return `{
  "schemaVersion":1,
  "releaseManifestPath":"/usr/lib/pi-platform/release-manifest.json",
  "releaseTrustRootsPath":"/etc/pi-platform/release-trust-roots.json",
  "installedWorkerdPath":"/usr/lib/pi-platform/bin/workerd",
  "architecture":"x86_64",
  "cgroupRootPath":"/sys/fs/cgroup/pi-platform/qualification",
  "evidenceOutputDirectory":"/var/lib/pi-platform/qualification",
  "limits":{
    "cpuMaxQuotaMicros":50000,
    "cpuMaxPeriodMicros":100000,
    "memoryMaxBytes":1073741824,
    "memorySwapMaxBytes":0,
    "pidsMax":128
  },
  "timeoutsMillis":{
    "readiness":10000,
    "probe":60000,
    "drain":30000,
    "total":600000
  },
  "coldStartSamples":5
}`
}
