package stateappbroker

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

func TestAcquireEngineStepEncodesBoundedDeadlineWithoutChangingReplayIdentity(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, bound := range []string{"lease", "admission"} {
		t.Run(bound, func(t *testing.T) {
			store, client, _ := makeStore(t)
			command := broker.AcquireStepCommand{
				Snapshot: broker.TurnSnapshot{TenantID: sid(identity.Tenant), WorkspaceID: sid(identity.Workspace), UserID: sid(identity.Subject),
					SessionID: sid(identity.Session), TurnID: sid(identity.Turn), Generations: broker.Generations{TurnLease: 3, Authorization: 7},
					CheckpointDigest: broker.Digest{1}, LeaseExpiresAt: now.Add(time.Minute)},
				Now: now, Budget: store.limits, OperationKey: "clamped-step", AbsoluteDeadline: now.Add(500 * time.Millisecond),
			}
			if bound == "lease" {
				command.Snapshot.LeaseExpiresAt = command.AbsoluteDeadline
			}
			// A deliberately invalid response isolates outbound encoding; the
			// adapter must reach the owner, then fail closed on the missing receipt.
			client.response = canonical.Map{}
			if _, err := store.AcquireEngineStep(context.Background(), command); err == nil || client.calls != 1 {
				t.Fatalf("first acquire: calls=%d error=%v", client.calls, err)
			}
			first := client.request.Body
			budget := first["budget"].(canonical.Map)
			anchor := first["nowUnixMs"].(int64)
			if budget["maximumWallClockMs"] != int64(1000) || anchor > now.UnixMilli() || anchor+budget["maximumWallClockMs"].(int64) != command.AbsoluteDeadline.UnixMilli() {
				t.Fatalf("wire budget/deadline widened: %#v", first)
			}
			command.Now = now.Add(time.Millisecond)
			if _, err := store.AcquireEngineStep(context.Background(), command); err == nil || client.calls != 2 {
				t.Fatalf("replayed acquire: calls=%d error=%v", client.calls, err)
			}
			if !reflect.DeepEqual(first, client.request.Body) {
				t.Fatalf("retry changed owner request identity: first=%#v replay=%#v", first, client.request.Body)
			}
		})
	}
}

func TestAcquireEngineStepRejectsInvalidAbsoluteDeadlineBeforeRPC(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*broker.AcquireStepCommand)
	}{
		{"missing deadline", func(c *broker.AcquireStepCommand) { c.AbsoluteDeadline = time.Time{} }},
		{"expired deadline", func(c *broker.AcquireStepCommand) { c.AbsoluteDeadline = now }},
		{"future budget anchor", func(c *broker.AcquireStepCommand) {
			c.AbsoluteDeadline = now.Add(c.Budget.MaximumWallClock + time.Millisecond)
		}},
		{"beyond lease", func(c *broker.AcquireStepCommand) {
			c.Snapshot.LeaseExpiresAt = c.AbsoluteDeadline.Add(-time.Millisecond)
		}},
		{"submillisecond deadline", func(c *broker.AcquireStepCommand) { c.AbsoluteDeadline = c.AbsoluteDeadline.Add(time.Nanosecond) }},
		{"missing current time", func(c *broker.AcquireStepCommand) { c.Now = time.Time{} }},
		{"invalid budget", func(c *broker.AcquireStepCommand) { c.Budget.MaximumWallClock = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, client, _ := makeStore(t)
			command := broker.AcquireStepCommand{
				Snapshot: broker.TurnSnapshot{TenantID: sid(identity.Tenant), WorkspaceID: sid(identity.Workspace), UserID: sid(identity.Subject),
					SessionID: sid(identity.Session), TurnID: sid(identity.Turn), Generations: broker.Generations{TurnLease: 3, Authorization: 7},
					CheckpointDigest: broker.Digest{1}, LeaseExpiresAt: now.Add(time.Minute)},
				Now: now, Budget: store.limits, OperationKey: "clamped-step", AbsoluteDeadline: now.Add(500 * time.Millisecond),
			}
			test.mutate(&command)
			if _, err := store.AcquireEngineStep(context.Background(), command); !errors.Is(err, broker.ErrInvalidRequest) || client.calls != 0 {
				t.Fatalf("invalid bound reached owner: calls=%d error=%v", client.calls, err)
			}
		})
	}
}
