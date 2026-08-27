package executor_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/executor"
	"github.com/hancomac/circulusd/internal/identity"
)

func TestHandleIssuerRejectsForgeryAndCrossProviderHandles(t *testing.T) {
	first := executor.NewHandleIssuer()
	second := executor.NewHandleIssuer()

	handle, err := first.Issue(7, 11)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	slot, generation, err := first.Resolve(handle)
	if err != nil || slot != 7 || generation != 11 {
		t.Fatalf("Resolve() = %d, %d, %v", slot, generation, err)
	}
	if _, _, err := second.Resolve(handle); !errors.Is(err, executor.ErrUnknownHandle) {
		t.Fatalf("cross-provider Resolve() error = %v, want ErrUnknownHandle", err)
	}
	if _, _, err := first.Resolve(executor.SandboxHandle{}); !errors.Is(err, executor.ErrUnknownHandle) {
		t.Fatalf("zero Resolve() error = %v, want ErrUnknownHandle", err)
	}
	if _, err := first.Issue(0, 1); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("Issue(slot 0) error = %v, want ErrInvalidSpec", err)
	}
	if _, err := first.Issue(1, 0); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("Issue(generation 0) error = %v, want ErrInvalidSpec", err)
	}
}

func TestLaunchFenceAdvancesMonotonicallyWithoutExposingTenant(t *testing.T) {
	tenant := mustIdentity(t, identity.Tenant, 0x31)
	otherTenant := mustIdentity(t, identity.Tenant, 0x32)
	first, err := executor.NewLaunchAuthority(tenant, 4)
	if err != nil {
		t.Fatalf("NewLaunchAuthority() error = %v", err)
	}
	same, _ := executor.NewLaunchAuthority(tenant, 4)
	newer, _ := executor.NewLaunchAuthority(tenant, 5)
	older, _ := executor.NewLaunchAuthority(tenant, 3)
	foreign, _ := executor.NewLaunchAuthority(otherTenant, 6)

	fence, err := executor.NewLaunchFence(first)
	if err != nil {
		t.Fatalf("NewLaunchFence() error = %v", err)
	}
	if !fence.Authorizes(same) || fence.Authorizes(newer) {
		t.Fatal("launch fence did not require the exact admitted generation")
	}
	if _, err := fence.Admit(older); !errors.Is(err, executor.ErrStaleAuthority) {
		t.Fatalf("Admit(older) error = %v, want ErrStaleAuthority", err)
	}
	if _, err := fence.Admit(foreign); !errors.Is(err, executor.ErrInvalidSpec) {
		t.Fatalf("Admit(foreign tenant) error = %v, want ErrInvalidSpec", err)
	}
	advanced, err := fence.Admit(newer)
	if err != nil || advanced.Generation() != 5 || !advanced.Authorizes(newer) || advanced.Authorizes(first) {
		t.Fatalf("Admit(newer) = %#v, %v", advanced, err)
	}
}

func TestProviderAuthoritiesRemainOpaqueWhenFormatted(t *testing.T) {
	tenant := mustIdentity(t, identity.Tenant, 0x41)
	authority, err := executor.NewLaunchAuthority(tenant, 9)
	if err != nil {
		t.Fatalf("NewLaunchAuthority() error = %v", err)
	}
	fence, err := executor.NewLaunchFence(authority)
	if err != nil {
		t.Fatalf("NewLaunchFence() error = %v", err)
	}
	issuer := executor.NewHandleIssuer()
	handle, err := issuer.Issue(17, 23)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	for name, value := range map[string]any{
		"fence":  fence,
		"issuer": issuer,
		"handle": handle,
	} {
		for _, formatted := range []string{
			fmt.Sprintf("%v", value),
			fmt.Sprintf("%#v", value),
		} {
			if strings.Contains(formatted, tenant.String()) ||
				strings.Contains(formatted, "providerID") ||
				strings.Contains(formatted, "slotID") {
				t.Fatalf("formatted %s leaked opaque authority fields: %q", name, formatted)
			}
		}
	}
}

func mustIdentity(t *testing.T, kind identity.Kind, fill byte) identity.ID {
	t.Helper()
	id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{fill}, 16))}).New(kind)
	if err != nil {
		t.Fatalf("generate %s identity: %v", kind, err)
	}
	return id
}
