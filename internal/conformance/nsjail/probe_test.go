package nsjail

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/conformance"
)

type fakeProbe struct {
	provenance Provenance
	failID     string
	errorID    string
}

func (probe fakeProbe) Provenance() Provenance { return probe.provenance }

func (probe fakeProbe) RunCheck(_ context.Context, check Check) (CheckOutcome, error) {
	switch check.ID {
	case probe.errorID:
		return CheckOutcome{}, errors.New("probe transport error")
	case probe.failID:
		return CheckOutcome{Passed: false, Detail: "observed a permitted disallowed syscall"}, nil
	default:
		return CheckOutcome{Passed: true}, nil
	}
}

func mustCollect(t *testing.T, result conformance.Result) {
	t.Helper()
	collector := conformance.NewCollector()
	if err := collector.Add(result); err != nil {
		t.Fatalf("result failed conformance validation: %v", err)
	}
}

func TestQualifyWithoutProbeIsUnavailable(t *testing.T) {
	t.Parallel()
	result := Qualify(context.Background(), nil)
	if result.Component != Component || result.Status != conformance.Unavailable {
		t.Fatalf("result = %+v, want %s UNAVAILABLE", result, Component)
	}
	if strings.TrimSpace(result.Reason) == "" {
		t.Fatal("UNAVAILABLE result must carry a reason")
	}
	mustCollect(t, result)
}

func TestQualifyReferenceProbePassesButIsNotPromotable(t *testing.T) {
	t.Parallel()
	result := Qualify(context.Background(), fakeProbe{provenance: Provenance{Version: "3.4", Reference: true}})
	if result.Status != conformance.Pass {
		t.Fatalf("reference probe result = %+v, want PASS", result)
	}
	if !result.Evidence.Mock || result.Evidence.Class != conformance.EvidenceClassReferenceOnly {
		t.Fatalf("reference PASS evidence = %+v, want mock reference-only", result.Evidence)
	}
	mustCollect(t, result)

	// A production profile must reject this reference PASS as synthetic.
	collector := conformance.NewCollector()
	if err := collector.Add(result); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	profile := conformance.Profile{Name: "production", Production: true, Required: []string{Component}}
	if err := collector.Evaluate(profile); err == nil {
		t.Fatal("production profile accepted a reference/mock NsJail PASS")
	}
}

func TestQualifyNonReferenceProbeCarriesExternalEvidence(t *testing.T) {
	t.Parallel()
	result := Qualify(context.Background(), fakeProbe{provenance: Provenance{Version: "3.4", Reference: false}})
	if result.Status != conformance.Pass {
		t.Fatalf("result = %+v, want PASS", result)
	}
	if result.Evidence.Mock || result.Evidence.Class != conformance.EvidenceClassExternal {
		t.Fatalf("evidence = %+v, want external non-mock", result.Evidence)
	}
}

func TestQualifyFailsOnFailedCheck(t *testing.T) {
	t.Parallel()
	result := Qualify(context.Background(), fakeProbe{failID: "seccomp-deny"})
	if result.Status != conformance.Fail {
		t.Fatalf("result = %+v, want FAIL", result)
	}
	if !strings.Contains(result.Reason, "seccomp-deny") {
		t.Fatalf("reason %q should name the failed check", result.Reason)
	}
	mustCollect(t, result)
}

func TestQualifyUnavailableWhenCheckErrors(t *testing.T) {
	t.Parallel()
	result := Qualify(context.Background(), fakeProbe{errorID: "network-default-deny"})
	if result.Status != conformance.Unavailable {
		t.Fatalf("result = %+v, want UNAVAILABLE", result)
	}
	if !strings.Contains(result.Reason, "network-default-deny") {
		t.Fatalf("reason %q should name the check that could not run", result.Reason)
	}
	mustCollect(t, result)
}

func TestRequiredChecksCoverIsolationContract(t *testing.T) {
	t.Parallel()
	want := map[string]bool{
		"namespace-isolation":      false,
		"uid-gid-mapping":          false,
		"rootfs-read-only":         false,
		"write-confinement":        false,
		"host-path-nonexposure":    false,
		"no-new-privs":             false,
		"no-retained-capabilities": false,
		"seccomp-deny":             false,
		"cgroup-limits":            false,
		"network-default-deny":     false,
		"timeout-cancel-teardown":  false,
		"sandboxd-private-uds":     false,
	}
	seen := make(map[string]struct{})
	for _, check := range RequiredChecks() {
		if _, duplicate := seen[check.ID]; duplicate {
			t.Fatalf("duplicate check id %q", check.ID)
		}
		seen[check.ID] = struct{}{}
		if check.Reference == "" || check.Description == "" {
			t.Fatalf("check %q is missing its SPEC reference or description", check.ID)
		}
		if _, expected := want[check.ID]; expected {
			want[check.ID] = true
		}
	}
	for id, covered := range want {
		if !covered {
			t.Fatalf("required isolation check %q is missing", id)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("RequiredChecks returned %d checks, want exactly %d", len(seen), len(want))
	}
}
