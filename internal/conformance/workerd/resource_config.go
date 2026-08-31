package workerd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	maximumResourceQualificationConfigBytes = 64 << 10
	maximumResourceQualificationJSONInteger = uint64(9_007_199_254_740_991)
	maximumResourceQualificationPIDs        = uint64(1_000_000)
	maximumResourceQualificationSamples     = uint64(100)
	maximumResourceQualificationTotalMillis = uint64((15 * time.Minute) / time.Millisecond)
)

var (
	errInvalidResourceQualificationConfig = errors.New("workerd resource qualification: invalid configuration")
	resourceQualificationArchitecture     = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
)

type resourceQualificationLimits struct {
	CPUMaxQuotaMicros  uint64 `json:"cpuMaxQuotaMicros"`
	CPUMaxPeriodMicros uint64 `json:"cpuMaxPeriodMicros"`
	MemoryMaxBytes     uint64 `json:"memoryMaxBytes"`
	MemorySwapMaxBytes uint64 `json:"memorySwapMaxBytes"`
	PIDsMax            uint64 `json:"pidsMax"`
}

type resourceQualificationTimeouts struct {
	Readiness time.Duration
	Probe     time.Duration
	Drain     time.Duration
	Total     time.Duration
}

type resourceQualificationConfig struct {
	SchemaVersion           uint64
	ReleaseManifestPath     string
	ReleaseTrustRootsPath   string
	InstalledWorkerdPath    string
	Architecture            string
	CgroupRootPath          string
	EvidenceOutputDirectory string
	Limits                  resourceQualificationLimits
	Timeouts                resourceQualificationTimeouts
	ColdStartSamples        uint64
}

type resourceQualificationDocument struct {
	SchemaVersion           uint64                               `json:"schemaVersion"`
	ReleaseManifestPath     string                               `json:"releaseManifestPath"`
	ReleaseTrustRootsPath   string                               `json:"releaseTrustRootsPath"`
	InstalledWorkerdPath    string                               `json:"installedWorkerdPath"`
	Architecture            string                               `json:"architecture"`
	CgroupRootPath          string                               `json:"cgroupRootPath"`
	EvidenceOutputDirectory string                               `json:"evidenceOutputDirectory"`
	Limits                  resourceQualificationLimits          `json:"limits"`
	TimeoutsMillis          resourceQualificationTimeoutDocument `json:"timeoutsMillis"`
	ColdStartSamples        uint64                               `json:"coldStartSamples"`
}

type resourceQualificationTimeoutDocument struct {
	Readiness uint64 `json:"readiness"`
	Probe     uint64 `json:"probe"`
	Drain     uint64 `json:"drain"`
	Total     uint64 `json:"total"`
}

func parseResourceQualificationConfig(reader io.Reader) (resourceQualificationConfig, error) {
	if reader == nil {
		return resourceQualificationConfig{}, errInvalidResourceQualificationConfig
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, maximumResourceQualificationConfigBytes+1))
	if err != nil {
		return resourceQualificationConfig{}, fmt.Errorf("%w: read document: %v", errInvalidResourceQualificationConfig, err)
	}
	if len(encoded) > maximumResourceQualificationConfigBytes {
		return resourceQualificationConfig{}, fmt.Errorf("%w: document exceeds %d bytes", errInvalidResourceQualificationConfig, maximumResourceQualificationConfigBytes)
	}

	type container struct {
		kind         json.Delim
		keys         map[string]struct{}
		expectingKey bool
	}
	tokenDecoder := json.NewDecoder(bytes.NewReader(encoded))
	tokenDecoder.UseNumber()
	containers := make([]container, 0, 8)
	completeValue := func() {
		if len(containers) == 0 {
			return
		}
		current := &containers[len(containers)-1]
		if current.kind == '{' && !current.expectingKey {
			current.expectingKey = true
		}
	}
	for {
		token, tokenErr := tokenDecoder.Token()
		if tokenErr == io.EOF {
			break
		}
		if tokenErr != nil {
			return resourceQualificationConfig{}, fmt.Errorf("%w: decode document: %v", errInvalidResourceQualificationConfig, tokenErr)
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				containers = append(containers, container{kind: delimiter, keys: make(map[string]struct{}), expectingKey: true})
			case '[':
				containers = append(containers, container{kind: delimiter})
			case '}', ']':
				if len(containers) == 0 || containers[len(containers)-1].kind+2 != delimiter {
					return resourceQualificationConfig{}, fmt.Errorf("%w: mismatched JSON container", errInvalidResourceQualificationConfig)
				}
				containers = containers[:len(containers)-1]
				completeValue()
			}
			continue
		}
		if len(containers) > 0 {
			current := &containers[len(containers)-1]
			if current.kind == '{' && current.expectingKey {
				key, ok := token.(string)
				if !ok {
					return resourceQualificationConfig{}, fmt.Errorf("%w: JSON object key is not a string", errInvalidResourceQualificationConfig)
				}
				if _, duplicate := current.keys[key]; duplicate {
					return resourceQualificationConfig{}, fmt.Errorf("%w: duplicate JSON member %q", errInvalidResourceQualificationConfig, key)
				}
				current.keys[key] = struct{}{}
				current.expectingKey = false
				continue
			}
		}
		completeValue()
	}
	if len(containers) != 0 {
		return resourceQualificationConfig{}, fmt.Errorf("%w: incomplete JSON container", errInvalidResourceQualificationConfig)
	}

	var document resourceQualificationDocument
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return resourceQualificationConfig{}, fmt.Errorf("%w: decode document: %v", errInvalidResourceQualificationConfig, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return resourceQualificationConfig{}, fmt.Errorf("%w: trailing JSON value", errInvalidResourceQualificationConfig)
		}
		return resourceQualificationConfig{}, fmt.Errorf("%w: decode document trailer: %v", errInvalidResourceQualificationConfig, err)
	}

	if document.SchemaVersion != 1 {
		return resourceQualificationConfig{}, fmt.Errorf("%w: unsupported schemaVersion", errInvalidResourceQualificationConfig)
	}
	paths := []string{
		document.ReleaseManifestPath,
		document.ReleaseTrustRootsPath,
		document.InstalledWorkerdPath,
		document.CgroupRootPath,
		document.EvidenceOutputDirectory,
	}
	seenPaths := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == string(filepath.Separator) || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
			return resourceQualificationConfig{}, fmt.Errorf("%w: path is not canonical and absolute", errInvalidResourceQualificationConfig)
		}
		if _, duplicate := seenPaths[path]; duplicate {
			return resourceQualificationConfig{}, fmt.Errorf("%w: paths must be distinct", errInvalidResourceQualificationConfig)
		}
		seenPaths[path] = struct{}{}
	}
	if !resourceQualificationArchitecture.MatchString(document.Architecture) {
		return resourceQualificationConfig{}, fmt.Errorf("%w: architecture is not canonical", errInvalidResourceQualificationConfig)
	}
	if document.Limits.CPUMaxQuotaMicros < 1_000 || document.Limits.CPUMaxQuotaMicros > 1_000_000_000 ||
		document.Limits.CPUMaxPeriodMicros < 1_000 || document.Limits.CPUMaxPeriodMicros > 1_000_000 ||
		document.Limits.MemoryMaxBytes == 0 || document.Limits.MemoryMaxBytes > maximumResourceQualificationJSONInteger ||
		document.Limits.MemorySwapMaxBytes > maximumResourceQualificationJSONInteger ||
		document.Limits.PIDsMax == 0 || document.Limits.PIDsMax > maximumResourceQualificationPIDs {
		return resourceQualificationConfig{}, fmt.Errorf("%w: resource limit is outside its bound", errInvalidResourceQualificationConfig)
	}
	if document.ColdStartSamples < 5 || document.ColdStartSamples > maximumResourceQualificationSamples {
		return resourceQualificationConfig{}, fmt.Errorf("%w: cold-start sample count is outside its bound", errInvalidResourceQualificationConfig)
	}
	timeouts := document.TimeoutsMillis
	if timeouts.Readiness == 0 || timeouts.Probe == 0 || timeouts.Drain == 0 || timeouts.Total == 0 ||
		timeouts.Total > maximumResourceQualificationTotalMillis || timeouts.Readiness >= timeouts.Total ||
		timeouts.Probe >= timeouts.Total || timeouts.Drain >= timeouts.Total {
		return resourceQualificationConfig{}, fmt.Errorf("%w: timeout is outside its bound", errInvalidResourceQualificationConfig)
	}

	return resourceQualificationConfig{
		SchemaVersion:           document.SchemaVersion,
		ReleaseManifestPath:     document.ReleaseManifestPath,
		ReleaseTrustRootsPath:   document.ReleaseTrustRootsPath,
		InstalledWorkerdPath:    document.InstalledWorkerdPath,
		Architecture:            document.Architecture,
		CgroupRootPath:          document.CgroupRootPath,
		EvidenceOutputDirectory: document.EvidenceOutputDirectory,
		Limits:                  document.Limits,
		Timeouts: resourceQualificationTimeouts{
			Readiness: time.Duration(timeouts.Readiness) * time.Millisecond,
			Probe:     time.Duration(timeouts.Probe) * time.Millisecond,
			Drain:     time.Duration(timeouts.Drain) * time.Millisecond,
			Total:     time.Duration(timeouts.Total) * time.Millisecond,
		},
		ColdStartSamples: document.ColdStartSamples,
	}, nil
}
