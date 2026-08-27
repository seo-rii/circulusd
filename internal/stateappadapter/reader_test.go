package stateappadapter

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

const maximumTestSharedInteger = uint64(9_007_199_254_740_991)

type recordingClient struct {
	mu       sync.Mutex
	requests []stateappclient.Request
	read     func(context.Context, stateappclient.Request) (canonical.Value, error)
}

type unusedAuthorizer struct{}

func (*unusedAuthorizer) Authorize(
	context.Context,
	platformapi.AuthorizationRequest,
) (platformapi.AuthorizationPermit, error) {
	panic("reference-only reader must be rejected before authorization")
}

func (client *recordingClient) ReadSessionEvents(
	ctx context.Context,
	request stateappclient.Request,
) (canonical.Value, error) {
	client.mu.Lock()
	client.requests = append(client.requests, request)
	client.mu.Unlock()
	return client.read(ctx, request)
}

func (client *recordingClient) callCount() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return len(client.requests)
}

func TestNewRequiresConcreteConfiguredClientButRemainsReferenceOnly(t *testing.T) {
	t.Parallel()
	var constructor func(*stateappclient.Client) (*Reader, error) = New
	_ = constructor

	if reader, err := New(nil); reader != nil || !errors.Is(err, platformapi.ErrInvalidConfig) {
		t.Fatalf("New(nil) = (%#v, %v), want nil ErrInvalidConfig", reader, err)
	}
	client, err := stateappclient.New(stateappclient.Config{
		Endpoint: "unix:///run/circulusd/state.sock",
		KeyID:    "state-current-1",
		RootKey:  make([]byte, 32),
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("stateappclient.New() error = %v", err)
	}
	t.Cleanup(client.Close)
	reader, err := New(client)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if evidence := reader.SessionEventReaderEvidence(); evidence != (platformapi.SessionEventReaderEvidence{
		ReferenceOnly: true,
	}) {
		t.Fatalf("unverified concrete-client evidence = %#v", evidence)
	}
	service, err := platformapi.NewSessionEventService(platformapi.SessionEventServiceConfig{
		Reader: reader, Authorizer: &unusedAuthorizer{}, MaximumPageEvents: 16,
	})
	if service != nil || !errors.Is(err, platformapi.ErrRepositoryNotDurable) {
		t.Fatalf("NewSessionEventService() = (%#v, %v), want nil ErrRepositoryNotDurable", service, err)
	}

	reference, err := newReferenceReaderForTest(&recordingClient{
		read: func(context.Context, stateappclient.Request) (canonical.Value, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("newReferenceReaderForTest() error = %v", err)
	}
	if evidence := reference.SessionEventReaderEvidence(); !evidence.ReferenceOnly ||
		evidence.CrashDurable || evidence.AuthoritativeSessionJournal ||
		evidence.AtomicAuthorizationGenerationFence {
		t.Fatalf("reference evidence = %#v", evidence)
	}
}

func TestReaderRefencesPermitAndConvertsEveryPublicEventFamily(t *testing.T) {
	t.Parallel()
	tenantID := validTestID("tenant", 1)
	subjectID := validTestID("subject", 1)
	sessionID := validTestID("sess", 1)
	turnID := validTestID("turn", 1)
	effectID := validTestID("effect", 1)
	invocationID := validTestID("inv", 1)
	client := &recordingClient{read: func(_ context.Context, request stateappclient.Request) (canonical.Value, error) {
		return canonical.Map{
			"snapshot": canonical.Map{
				"sessionId": sessionID, "activeTurnId": turnID,
				"turnStatus": "needs_confirmation", "lastEventSequence": int64(10),
			},
			"events": canonical.Array{
				canonical.Map{"sequence": int64(1), "type": "turn.accepted", "turnId": turnID, "turnSequence": int64(0), "status": "queued"},
				canonical.Map{"sequence": int64(2), "type": "model.effect.prepared", "turnId": turnID, "turnSequence": int64(0), "effectId": effectID, "invocationId": invocationID, "service": "model", "operation": "complete"},
				canonical.Map{"sequence": int64(3), "type": "model.settled", "turnId": turnID, "turnSequence": int64(0), "effectId": effectID, "invocationId": invocationID, "service": "model", "operation": "complete", "settlementKind": "success"},
				canonical.Map{"sequence": int64(4), "type": "tool.effect.prepared", "turnId": turnID, "turnSequence": int64(0), "effectId": effectID, "invocationId": invocationID, "service": "workspace", "operation": "write"},
				canonical.Map{"sequence": int64(5), "type": "tool.externally_committed", "turnId": turnID, "turnSequence": int64(0), "effectId": effectID, "invocationId": invocationID, "service": "external-tool", "operation": "send", "externalCommitId": "commit-one", "resultRef": "result-one"},
				canonical.Map{"sequence": int64(6), "type": "tool.settled", "turnId": turnID, "turnSequence": int64(0), "effectId": effectID, "invocationId": invocationID, "service": "executor", "operation": "run", "settlementKind": "interrupted_unknown"},
				canonical.Map{"sequence": int64(7), "type": "turn.needs_confirmation", "turnId": turnID, "turnSequence": int64(0), "effectId": effectID, "invocationId": invocationID, "service": "mcp", "operation": "confirm"},
				canonical.Map{"sequence": int64(8), "type": "turn.completed", "turnId": turnID, "turnSequence": int64(0)},
				canonical.Map{"sequence": int64(9), "type": "turn.failed", "turnId": turnID, "turnSequence": int64(0)},
				canonical.Map{"sequence": int64(10), "type": "turn.aborted", "turnId": turnID, "turnSequence": int64(0)},
			},
		}, nil
	}}
	reader := mustReferenceReader(t, client)
	permit := validTestPermit(tenantID, subjectID, sessionID, 41)

	page, err := reader.ReadSessionEventPage(context.Background(), platformapi.AuthorizedSessionEventPageRequest{
		Authorization: permit, SessionID: sessionID, AfterSequence: 0, Limit: 10,
	})
	if err != nil {
		t.Fatalf("ReadSessionEventPage() error = %v", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("client calls = %d, want 1", client.callCount())
	}
	client.mu.Lock()
	wantRequest := stateappclient.Request{
		TenantID: tenantID, ActorSubjectID: subjectID, SessionID: sessionID,
		ExpectedAuthorizationGeneration: 41, AfterSequence: 0, Limit: 10,
	}
	if client.requests[0] != wantRequest {
		t.Fatalf("state-app request = %#v, want %#v", client.requests[0], wantRequest)
	}
	client.mu.Unlock()
	if page.Snapshot.SessionID != sessionID || page.Snapshot.ActiveTurnID == nil ||
		*page.Snapshot.ActiveTurnID != turnID || page.Snapshot.TurnStatus == nil ||
		*page.Snapshot.TurnStatus != platformapi.TurnNeedsConfirmation ||
		page.Snapshot.LastEventSequence != 10 || len(page.Events) != 10 {
		t.Fatalf("converted page = %#v", page)
	}
	wantTypes := []platformapi.EventType{
		platformapi.EventTurnAccepted, platformapi.EventModelEffectPrepared,
		platformapi.EventModelSettled, platformapi.EventToolEffectPrepared,
		platformapi.EventToolExternallyCommit, platformapi.EventToolSettled,
		platformapi.EventTurnNeedsConfirmation, platformapi.EventTurnCompleted,
		platformapi.EventTurnFailed, platformapi.EventTurnAborted,
	}
	for index, wantType := range wantTypes {
		if page.Events[index].Type != wantType {
			t.Fatalf("event %d type = %q, want %q", index, page.Events[index].Type, wantType)
		}
	}
	if page.Events[0].Status != platformapi.TurnQueued ||
		page.Events[1].Service != platformapi.SessionEffectModel ||
		page.Events[4].ExternalCommitID != "commit-one" || page.Events[4].ResultRef != "result-one" ||
		page.Events[5].SettlementKind != platformapi.SessionSettlementInterruptedUnknown {
		t.Fatalf("event family fields were not preserved: %#v", page.Events)
	}
}

func TestReaderRejectsInvalidPermitCursorAndLimitBeforeIngress(t *testing.T) {
	t.Parallel()
	tenantID := validTestID("tenant", 2)
	subjectID := validTestID("subject", 2)
	sessionID := validTestID("sess", 2)
	base := platformapi.AuthorizedSessionEventPageRequest{
		Authorization: validTestPermit(tenantID, subjectID, sessionID, 7),
		SessionID:     sessionID, AfterSequence: 0, Limit: 16,
	}
	tests := map[string]struct {
		edit func(*platformapi.AuthorizedSessionEventPageRequest)
		want error
	}{
		"wrong operation": {edit: func(request *platformapi.AuthorizedSessionEventPageRequest) {
			request.Authorization.Operation = platformapi.OperationCreateTurn
		}, want: platformapi.ErrAccessDenied},
		"invalid tenant": {edit: func(request *platformapi.AuthorizedSessionEventPageRequest) {
			request.Authorization.Principal.TenantID = "tenant-invalid"
		}, want: platformapi.ErrAccessDenied},
		"invalid subject": {edit: func(request *platformapi.AuthorizedSessionEventPageRequest) {
			request.Authorization.Principal.SubjectID = "subject-invalid"
		}, want: platformapi.ErrAccessDenied},
		"permit session mismatch": {edit: func(request *platformapi.AuthorizedSessionEventPageRequest) {
			request.Authorization.SessionID = validTestID("sess", 3)
		}, want: platformapi.ErrAccessDenied},
		"request session invalid": {edit: func(request *platformapi.AuthorizedSessionEventPageRequest) { request.SessionID = "sess-invalid" }, want: platformapi.ErrAccessDenied},
		"zero generation": {edit: func(request *platformapi.AuthorizedSessionEventPageRequest) {
			request.Authorization.AuthorizationGeneration = 0
		}, want: platformapi.ErrAccessDenied},
		"unsafe generation": {edit: func(request *platformapi.AuthorizedSessionEventPageRequest) {
			request.Authorization.AuthorizationGeneration = maximumTestSharedInteger + 1
		}, want: platformapi.ErrAccessDenied},
		"zero proof": {edit: func(request *platformapi.AuthorizedSessionEventPageRequest) {
			request.Authorization.Proof = platformapi.OpaqueAuthorizationProof{}
		}, want: platformapi.ErrAccessDenied},
		"unsafe cursor": {edit: func(request *platformapi.AuthorizedSessionEventPageRequest) {
			request.AfterSequence = maximumTestSharedInteger + 1
		}, want: platformapi.ErrInvalidCursor},
		"zero limit":      {edit: func(request *platformapi.AuthorizedSessionEventPageRequest) { request.Limit = 0 }, want: platformapi.ErrInvalidCursor},
		"excessive limit": {edit: func(request *platformapi.AuthorizedSessionEventPageRequest) { request.Limit = 257 }, want: platformapi.ErrInvalidCursor},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := &recordingClient{read: func(context.Context, stateappclient.Request) (canonical.Value, error) {
				t.Fatal("invalid request reached state-app ingress")
				return nil, nil
			}}
			request := base
			test.edit(&request)
			_, err := mustReferenceReader(t, client).ReadSessionEventPage(context.Background(), request)
			if !errors.Is(err, test.want) || client.callCount() != 0 {
				t.Fatalf("ReadSessionEventPage() error/calls = %v/%d, want %v/0", err, client.callCount(), test.want)
			}
		})
	}
}

func TestReaderRejectsMalformedCanonicalPageAndEventFamilies(t *testing.T) {
	t.Parallel()
	tenantID := validTestID("tenant", 4)
	subjectID := validTestID("subject", 4)
	sessionID := validTestID("sess", 4)
	turnID := validTestID("turn", 4)
	baseEvent := canonical.Map{
		"sequence": int64(1), "type": "turn.accepted", "turnId": turnID,
		"turnSequence": int64(0), "status": "active",
	}
	baseResult := canonical.Map{
		"snapshot": canonical.Map{
			"sessionId": sessionID, "activeTurnId": nil,
			"turnStatus": nil, "lastEventSequence": int64(1),
		},
		"events": canonical.Array{baseEvent},
	}
	tests := map[string]canonical.Value{
		"non-map result":              canonical.Array{},
		"missing result field":        canonical.Map{"snapshot": baseResult["snapshot"]},
		"unknown result field":        canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{}, "extra": nil},
		"non-map snapshot":            canonical.Map{"snapshot": nil, "events": canonical.Array{}},
		"unknown snapshot field":      canonical.Map{"snapshot": canonical.Map{"sessionId": sessionID, "activeTurnId": nil, "turnStatus": nil, "lastEventSequence": int64(0), "extra": nil}, "events": canonical.Array{}},
		"snapshot session mismatch":   canonical.Map{"snapshot": canonical.Map{"sessionId": validTestID("sess", 40), "activeTurnId": nil, "turnStatus": nil, "lastEventSequence": int64(0)}, "events": canonical.Array{}},
		"invalid snapshot session id": canonical.Map{"snapshot": canonical.Map{"sessionId": "sess-invalid", "activeTurnId": nil, "turnStatus": nil, "lastEventSequence": int64(0)}, "events": canonical.Array{}},
		"negative snapshot integer":   canonical.Map{"snapshot": canonical.Map{"sessionId": sessionID, "activeTurnId": nil, "turnStatus": nil, "lastEventSequence": int64(-1)}, "events": canonical.Array{}},
		"unsafe snapshot integer":     canonical.Map{"snapshot": canonical.Map{"sessionId": sessionID, "activeTurnId": nil, "turnStatus": nil, "lastEventSequence": maximumTestSharedInteger + 1}, "events": canonical.Array{}},
		"wrong active turn type":      canonical.Map{"snapshot": canonical.Map{"sessionId": sessionID, "activeTurnId": int64(1), "turnStatus": nil, "lastEventSequence": int64(0)}, "events": canonical.Array{}},
		"invalid active status":       canonical.Map{"snapshot": canonical.Map{"sessionId": sessionID, "activeTurnId": turnID, "turnStatus": "completed", "lastEventSequence": int64(0)}, "events": canonical.Array{}},
		"non-array events":            canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Map{}},
		"non-map event":               canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{"event"}},
		"missing event field":         canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{canonical.Map{"sequence": int64(1), "type": "turn.completed", "turnId": turnID}}},
		"unknown event field":         canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{canonical.Map{"sequence": int64(1), "type": "turn.completed", "turnId": turnID, "turnSequence": int64(0), "extra": nil}}},
		"negative event integer":      canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{canonical.Map{"sequence": int64(-1), "type": "turn.completed", "turnId": turnID, "turnSequence": int64(0)}}},
		"unsafe event integer":        canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{canonical.Map{"sequence": maximumTestSharedInteger + 1, "type": "turn.completed", "turnId": turnID, "turnSequence": int64(0)}}},
		"unknown event type":          canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{canonical.Map{"sequence": int64(1), "type": "model.delta", "turnId": turnID, "turnSequence": int64(0)}}},
		"accepted wrong status":       canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{canonical.Map{"sequence": int64(1), "type": "turn.accepted", "turnId": turnID, "turnSequence": int64(0), "status": "completed"}}},
		"prepared missing field":      canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{canonical.Map{"sequence": int64(1), "type": "model.effect.prepared", "turnId": turnID, "turnSequence": int64(0), "effectId": "effect", "invocationId": "inv", "service": "model"}}},
		"prepared extra family field": canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{canonical.Map{"sequence": int64(1), "type": "model.effect.prepared", "turnId": turnID, "turnSequence": int64(0), "effectId": "effect", "invocationId": "inv", "service": "model", "operation": "complete", "resultRef": "result"}}},
		"external missing result":     canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{canonical.Map{"sequence": int64(1), "type": "tool.externally_committed", "turnId": turnID, "turnSequence": int64(0), "effectId": "effect", "invocationId": "inv", "service": "workspace", "operation": "write", "externalCommitId": "commit"}}},
		"settled invalid kind":        canonical.Map{"snapshot": baseResult["snapshot"], "events": canonical.Array{canonical.Map{"sequence": int64(1), "type": "tool.settled", "turnId": turnID, "turnSequence": int64(0), "effectId": "effect", "invocationId": "inv", "service": "workspace", "operation": "write", "settlementKind": "unknown"}}},
	}
	tooMany := make(canonical.Array, 17)
	for index := range tooMany {
		tooMany[index] = baseEvent
	}
	tests["event count exceeds request limit"] = canonical.Map{
		"snapshot": baseResult["snapshot"], "events": tooMany,
	}

	for name, result := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := &recordingClient{read: func(context.Context, stateappclient.Request) (canonical.Value, error) {
				return result, nil
			}}
			_, err := mustReferenceReader(t, client).ReadSessionEventPage(
				context.Background(),
				platformapi.AuthorizedSessionEventPageRequest{
					Authorization: validTestPermit(tenantID, subjectID, sessionID, 7),
					SessionID:     sessionID, AfterSequence: 0, Limit: 16,
				},
			)
			if !errors.Is(err, platformapi.ErrRepositoryFailure) {
				t.Fatalf("ReadSessionEventPage() error = %v, want ErrRepositoryFailure", err)
			}
		})
	}
}

func TestReaderMapsOnlyAllowlistedRemoteAndContextErrors(t *testing.T) {
	t.Parallel()
	tenantID := validTestID("tenant", 5)
	subjectID := validTestID("subject", 5)
	sessionID := validTestID("sess", 5)
	request := platformapi.AuthorizedSessionEventPageRequest{
		Authorization: validTestPermit(tenantID, subjectID, sessionID, 7),
		SessionID:     sessionID, Limit: 16,
	}
	tests := map[string]struct {
		err  error
		want error
	}{
		"not found":                {err: &stateappclient.RemoteError{Code: "NOT_FOUND", Status: 200}, want: platformapi.ErrSessionNotFound},
		"not initialized":          {err: &stateappclient.RemoteError{Code: "NOT_INITIALIZED", Status: 200}, want: platformapi.ErrSessionNotFound},
		"permission denied":        {err: &stateappclient.RemoteError{Code: "PERMISSION_DENIED", Status: 200}, want: platformapi.ErrAccessDenied},
		"stale generation":         {err: &stateappclient.RemoteError{Code: "STALE_GENERATION", Status: 200}, want: platformapi.ErrStaleAuthority},
		"host invalid argument":    {err: &stateappclient.RemoteError{Code: "INVALID_ARGUMENT", Status: 200}, want: platformapi.ErrInvalidCursor},
		"ingress invalid argument": {err: &stateappclient.RemoteError{Code: "INVALID_ARGUMENT", Status: 400}, want: platformapi.ErrRepositoryFailure},
		"other remote":             {err: &stateappclient.RemoteError{Code: "INTERNAL_ERROR", Status: 500}, want: platformapi.ErrRepositoryFailure},
		"transport":                {err: stateappclient.ErrTransport, want: platformapi.ErrRepositoryFailure},
		"invalid response":         {err: stateappclient.ErrInvalidResponse, want: platformapi.ErrRepositoryFailure},
		"foreign":                  {err: errors.New("private backend detail"), want: platformapi.ErrRepositoryFailure},
		"canceled":                 {err: context.Canceled, want: context.Canceled},
		"deadline":                 {err: context.DeadlineExceeded, want: context.DeadlineExceeded},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := &recordingClient{read: func(context.Context, stateappclient.Request) (canonical.Value, error) {
				return nil, test.err
			}}
			_, err := mustReferenceReader(t, client).ReadSessionEventPage(context.Background(), request)
			if !errors.Is(err, test.want) {
				t.Fatalf("ReadSessionEventPage() error = %v, want %v", err, test.want)
			}
			if test.want == platformapi.ErrRepositoryFailure && err != platformapi.ErrRepositoryFailure {
				t.Fatalf("repository error leaked backend detail: %v", err)
			}
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	client := &recordingClient{read: func(context.Context, stateappclient.Request) (canonical.Value, error) {
		t.Fatal("pre-canceled context reached client")
		return nil, nil
	}}
	if _, err := mustReferenceReader(t, client).ReadSessionEventPage(canceled, request); !errors.Is(err, context.Canceled) || client.callCount() != 0 {
		t.Fatalf("pre-canceled read error/calls = %v/%d", err, client.callCount())
	}
}

func TestReaderKeepsSixtyFourConcurrentRequestsIsolated(t *testing.T) {
	t.Parallel()
	client := &recordingClient{read: func(_ context.Context, request stateappclient.Request) (canonical.Value, error) {
		return canonical.Map{
			"snapshot": canonical.Map{
				"sessionId": request.SessionID, "activeTurnId": nil,
				"turnStatus": nil, "lastEventSequence": int64(request.AfterSequence),
			},
			"events": canonical.Array{},
		}, nil
	}}
	reader := mustReferenceReader(t, client)
	var wait sync.WaitGroup
	errorsByRequest := make(chan error, 64)
	for index := uint64(0); index < 64; index++ {
		wait.Add(1)
		go func(index uint64) {
			defer wait.Done()
			tenantID := validTestID("tenant", index+100)
			subjectID := validTestID("subject", index+100)
			sessionID := validTestID("sess", index+100)
			page, err := reader.ReadSessionEventPage(context.Background(), platformapi.AuthorizedSessionEventPageRequest{
				Authorization: validTestPermit(tenantID, subjectID, sessionID, index+1),
				SessionID:     sessionID, AfterSequence: index, Limit: 1,
			})
			if err != nil {
				errorsByRequest <- err
				return
			}
			if page.Snapshot.SessionID != sessionID || page.Snapshot.LastEventSequence != index || len(page.Events) != 0 {
				errorsByRequest <- errors.New("concurrent response crossed request boundary")
			}
		}(index)
	}
	wait.Wait()
	close(errorsByRequest)
	for err := range errorsByRequest {
		t.Error(err)
	}
	if client.callCount() != 64 {
		t.Fatalf("client calls = %d, want 64", client.callCount())
	}
}

func mustReferenceReader(t *testing.T, client sessionEventClient) *Reader {
	t.Helper()
	reader, err := newReferenceReaderForTest(client)
	if err != nil {
		t.Fatalf("newReferenceReaderForTest() error = %v", err)
	}
	return reader
}

func validTestPermit(
	tenantID string,
	subjectID string,
	sessionID string,
	generation uint64,
) platformapi.AuthorizationPermit {
	return platformapi.AuthorizationPermit{
		Operation: platformapi.OperationReadEvents,
		Principal: platformapi.Principal{TenantID: tenantID, SubjectID: subjectID},
		SessionID: sessionID, AuthorizationGeneration: generation,
		Proof: platformapi.OpaqueAuthorizationProof{1},
	}
}

func validTestID(prefix string, index uint64) string {
	var entropy [16]byte
	binary.BigEndian.PutUint64(entropy[8:], index)
	return prefix + "_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy[:])
}
