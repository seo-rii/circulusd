package authority

import (
	"errors"
	"strings"
	"testing"
)

func TestSettlementEffectIdentityIsAuthenticatedByMAC(t *testing.T) {
	t.Parallel()

	validator := &Validator{secret: []byte(strings.Repeat("s", 32))}
	claims := authorityClaims{
		purpose:         purposeSettlement,
		effectID:        "effect-mac",
		invocationID:    "invocation-mac",
		requestDigest:   "sha256:" + strings.Repeat("a", 64),
		effectService:   EffectServiceExecutor,
		effectOperation: "executor.run",
		dispatchAttempt: 1,
	}

	tests := []struct {
		name   string
		mutate func(*authorityClaims)
	}{
		{name: "request digest", mutate: func(value *authorityClaims) { value.requestDigest = "sha256:" + strings.Repeat("b", 64) }},
		{name: "service", mutate: func(value *authorityClaims) { value.effectService = EffectServiceExternalTool }},
		{name: "operation", mutate: func(value *authorityClaims) { value.effectOperation = "executor.retry" }},
		{name: "dispatch attempt", mutate: func(value *authorityClaims) { value.dispatchAttempt++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signed := validator.signClaims(claims)
			test.mutate(&signed.claims)
			if _, err := validator.verifyClaims(signed); !errors.Is(err, ErrInvalidAuthority) {
				t.Fatalf("verifyClaims(tampered %s) error = %v, want ErrInvalidAuthority", test.name, err)
			}
		})
	}
}
