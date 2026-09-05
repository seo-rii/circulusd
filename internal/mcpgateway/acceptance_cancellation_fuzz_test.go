package mcpgateway

import (
	"context"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

// FuzzProviderAcceptanceCancellation varies cancellation/acceptance ordering,
// contradictory Start errors, provider identity boundaries, and binary input.
// A valid returned identity must be durable before cleanup/cancellation, and
// neither recovery nor replay may start the same provider attempt twice.
func FuzzProviderAcceptanceCancellation(f *testing.F) {
	for point := uint8(0); point <= uint8(acceptanceCancelDuringNext); point++ {
		for failure := uint8(0); failure < 6; failure++ {
			f.Add(point, failure, uint8(0), "accepted", []byte{0, '<', '\n', 0xff})
		}
	}
	for identityMode := uint8(1); identityMode < 8; identityMode++ {
		f.Add(uint8(acceptanceCancelBeforeStartReturns), uint8(0), identityMode, "identity", []byte{})
	}
	f.Fuzz(func(t *testing.T, point, failure, identityMode uint8, rawID string, payload []byte) {
		if len(rawID) > 126 {
			rawID = rawID[:126]
		}
		if len(payload) > 2048 {
			payload = payload[:2048]
		}
		// Construct known-valid and known-invalid identities independently of
		// the production validator, so weakening validation cannot satisfy the oracle.
		providerID := "rpc-" + hex.EncodeToString([]byte(rawID))
		validID := identityMode%8 < 2
		switch identityMode % 8 {
		case 1:
			providerID += strings.Repeat("r", 256-len(providerID))
		case 2:
			providerID = " " + providerID
		case 3:
			providerID = providerID + " "
		case 4:
			providerID = ""
		case 5:
			providerID = "rpc-\x00"
		case 6:
			providerID = "rpc-\xff"
		case 7:
			providerID += strings.Repeat("r", 257-len(providerID))
		}
		test := acceptanceCancellationCase{
			point: acceptanceCancellationPoint(point % 7), providerID: providerID, validID: validID,
			payload: payload,
		}
		switch failure % 6 {
		case 1:
			test.startErr = context.Canceled
		case 2:
			test.startErr = io.ErrUnexpectedEOF
		case 3:
			classified, err := NewProviderDispatchError(DispatchDefinitelyNotSent, "dispatch failed", io.ErrUnexpectedEOF)
			if err != nil {
				t.Fatal(err)
			}
			test.startErr = classified
		case 4:
			test.withoutCall = true
		case 5:
			test.startErr, test.withoutCall = context.Canceled, true
		}
		runAcceptanceCancellationCase(t, test)
	})
}
