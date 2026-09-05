package celldrepo_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/platformapi/celldrepo"
	"github.com/hancomac/circulusd/internal/sessionstate"
)

func TestCelldRepositoryFencesCreatePermitScope(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*platformapi.CreateTurnCommand)
	}{
		{"permit-tenant", func(cmd *platformapi.CreateTurnCommand) { cmd.Authorization.Principal.TenantID += "other" }},
		{"permit-subject", func(cmd *platformapi.CreateTurnCommand) { cmd.Authorization.Principal.SubjectID += "other" }},
		{"permit-session", func(cmd *platformapi.CreateTurnCommand) { cmd.Authorization.SessionID += "other" }},
		{"registered-tenant", func(cmd *platformapi.CreateTurnCommand) {
			cmd.TenantID += "other"
			cmd.Authorization.Principal.TenantID = cmd.TenantID
		}},
		{"registered-subject", func(cmd *platformapi.CreateTurnCommand) {
			cmd.SubjectID += "other"
			cmd.Authorization.Principal.SubjectID = cmd.SubjectID
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repo := newRegisteredRepository(t)
			command := platformapi.CreateTurnCommand{
				TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID,
				KeyDigest: "key-fenced", RequestDigest: "digest-fenced",
				ProposedTurn: platformapi.Turn{ID: "turn-fenced", TenantID: tenantID, SubjectID: subjectID,
					SessionID: sessionID, RequestDigest: "digest-fenced", Status: platformapi.TurnQueued},
				Authorization: permit(platformapi.OperationCreateTurn),
			}
			invalid := command
			test.mutate(&invalid)
			if _, _, err := repo.CreateTurn(context.Background(), invalid); !errors.Is(err, platformapi.ErrAccessDenied) {
				t.Fatalf("mismatched scope error = %v, want access denied", err)
			}
			if _, duplicate, err := repo.CreateTurn(context.Background(), command); err != nil || duplicate {
				t.Fatalf("rejected request left a creation receipt: duplicate=%t, %v", duplicate, err)
			}
		})
	}
}

func TestCelldHostReceiptReplayUsesCurrentAuthority(t *testing.T) {
	for _, test := range []struct {
		field  string
		value  canonical.Value
		denied error
	}{
		{"tenantId", tenantID + "other", celldrepo.ErrAccessDenied},
		{"subjectId", subjectID + "other", celldrepo.ErrAccessDenied},
		{"sessionId", sessionID + "other", celldrepo.ErrAccessDenied},
		{"runtimeRevision", runtimeRevision + "other", celldrepo.ErrAccessDenied},
		{"workspaceId", workspaceID + "other", celldrepo.ErrAccessDenied},
		{"placementGeneration", placementGen + 1, celldrepo.ErrStaleAuthority},
		{"authorizationGeneration", authorizationGen + 1, celldrepo.ErrStaleAuthority},
	} {
		t.Run(test.field, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storage := sessionstate.NewReferenceStorage()
			host := newHost(t, storage)
			mustRegister(t, host)
			if _, err := execCreate(t, host, "create-one", createInput("key-one", "digest-one", "turn-one")); err != nil {
				t.Fatal(err)
			}
			input := appendInput("turn-one", 0, eventAccepted, statusActive)
			if _, err := execAppend(t, host, "append-one", input); err != nil {
				t.Fatal(err)
			}
			// Keep the original receipt while replacing the current authority
			// in the committed snapshot. Replay must authorize the current
			// record rather than trusting that historical receipt.
			_, err := storage.Transaction(ctx, sessionID, func(tx celld.Transaction) error {
				encoded, err := tx.ReadState()
				if err != nil {
					return err
				}
				value, err := canonical.Decode(encoded, canonical.DefaultOptions())
				if err != nil {
					return err
				}
				fields := value.(canonical.Map)
				fields[test.field] = test.value
				encoded, err = canonical.Encode(fields, canonical.DefaultOptions())
				if err != nil {
					return err
				}
				return tx.WriteState(encoded)
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := execAppend(t, host, "append-one", input); !errors.Is(err, test.denied) {
				t.Fatalf("receipt bypassed changed %s: %v", test.field, err)
			}
			if test.field == "authorizationGeneration" {
				if _, err := execCreate(t, host, "create-one", createInput("key-one", "digest-one", "turn-one")); !errors.Is(err, test.denied) {
					t.Fatalf("creation receipt bypassed changed authorization: %v", err)
				}
			}
		})
	}
}

func TestCelldRepositoryFencesAppendScopeOnFirstWriteAndReplay(t *testing.T) {
	for _, replay := range []bool{false, true} {
		name := "first-write"
		if replay {
			name = "receipt-replay"
		}
		t.Run(name, func(t *testing.T) {
			for _, test := range []struct {
				name   string
				mutate func(*platformapi.EventAuthority)
			}{
				{"tenant", func(auth *platformapi.EventAuthority) { auth.Scope.TenantID += "other" }},
				{"user", func(auth *platformapi.EventAuthority) { auth.Scope.UserID += "other" }},
				{"runtime", func(auth *platformapi.EventAuthority) { auth.Scope.RuntimeRevision += "other" }},
				{"workspace", func(auth *platformapi.EventAuthority) { auth.Scope.WorkspaceID += "other" }},
			} {
				t.Run(test.name, func(t *testing.T) {
					t.Parallel()
					repo := newRegisteredRepository(t)
					createOneTurn(t, repo, "turn-one")
					command := platformapi.AppendEventCommand{
						Authority: repoEventAuthority("turn-one"), CommandID: newOp(t), CommandDigest: "sha256:accepted",
						ExpectedSequence: 0, Type: platformapi.EventTurnAccepted,
						Payload: `{"state":"active"}`, TurnStatus: platformapi.TurnActive,
					}
					if replay {
						if _, _, err := repo.AppendDurableEvent(context.Background(), command); err != nil {
							t.Fatal(err)
						}
					}
					invalid := command
					test.mutate(&invalid.Authority)
					if _, _, err := repo.AppendDurableEvent(context.Background(), invalid); !errors.Is(err, platformapi.ErrAccessDenied) {
						t.Fatalf("mismatched scope error = %v, want access denied", err)
					}
					if _, duplicate, err := repo.AppendDurableEvent(context.Background(), command); err != nil || duplicate != replay {
						t.Fatalf("rejected append changed durable state: duplicate=%t, %v", duplicate, err)
					}
				})
			}
		})
	}
}
