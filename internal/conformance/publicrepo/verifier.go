// Package publicrepo defines the durable public-API Repository conformance gate
// (Unit 12.3). It is the platformapi.Repository analogue of
// internal/conformance/celld: it pins the durable contract a public turn/event
// Repository must satisfy (SPEC §36 idempotency, §53.16 durable public
// idempotency and event replay) and produces a conformance.Result.
//
// Unlike celld's out-of-process durability, platformapi.Repository is an
// in-process Go interface, so the behavioral check logic lives here and is
// shared by every backend. A Harness provisions a fresh, session-bound
// repository under test; the verifier then drives the interface directly.
//
// The non-durable MemoryStore reference fails the crash-durable check and any
// reference/mock Harness produces only reference-only (non-promotable)
// evidence. §53.16 therefore stays NOT_RUN and the public API stays unwired
// until a real celld-backed Repository passes this gate from a served graph.
package publicrepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hancomac/circulusd/internal/authority"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/idempotency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/platformapi"
)

// Component is the conformance component id for the durable Repository gate.
const Component = "state.public-repository"

var conformanceSecret = bytes.Repeat([]byte{0x7c}, 32)

// Check is one required durable-Repository contract property.
type Check struct {
	ID          string
	Reference   string // the SPEC clause the check enforces
	Description string
}

// RequiredChecks returns the durable contract properties every backing
// Repository must satisfy. All must hold for the gate to PASS.
func RequiredChecks() []Check {
	return []Check{
		{
			ID:          "atomic-idempotency",
			Reference:   "SPEC §36 / §53.16",
			Description: "a repeated (subject, key) with the same request digest returns the same durable turn; a different request digest conflicts",
		},
		{
			ID:          "atomic-event-sequence",
			Reference:   "SPEC §53.16",
			Description: "durable event sequence is fenced: a second append at an already-used expected sequence conflicts",
		},
		{
			ID:          "atomic-replay-subscribe",
			Reference:   "SPEC §36.6 / §53.16",
			Description: "a caught-up replay opens a live subscription atomically; a replay behind head returns no subscription so the client reconnects without a silent gap",
		},
		{
			ID:          "atomic-authorization-fence",
			Reference:   "SPEC §36 / §53.16",
			Description: "creation permits and event authority must match current principal, session, runtime, workspace, and generations before any durable write",
		},
		{
			ID:          "crash-durable",
			Reference:   "SPEC §53.16",
			Description: "the repository self-reports crash durability; a non-durable reference store cannot promote §53.16",
		},
	}
}

// Provenance is the release and host identity of the qualified Repository.
// Reference marks a non-production (reference or mock) Harness whose PASS is not
// promotable.
type Provenance struct {
	Version           string
	BinaryDigest      string // canonical sha256:... or empty
	EnvironmentDigest string // canonical sha256:... or empty
	Kernel            string
	Architecture      string
	Reference         bool
}

// CheckOutcome is the result of running one contract check.
type CheckOutcome struct {
	Passed bool
	Detail string
}

// Subject is a freshly provisioned, session-bound repository under test plus the
// fixture material only the Harness can mint (a permit the repository accepts).
type Subject struct {
	Repository              platformapi.Repository
	TenantID                string
	SubjectID               string
	SessionID               string
	WorkspaceID             string
	RuntimeRevision         string
	PlacementGeneration     uint64
	AuthorizationGeneration uint64
	// Permit returns an authorization permit the repository accepts for op on
	// this session at its current authorization generation.
	Permit func(op platformapi.Operation) platformapi.AuthorizationPermit
}

// Harness provisions independent subjects for the Repository under test. Each
// NewSubject call must return fresh, isolated durable state.
type Harness interface {
	NewSubject(ctx context.Context) (*Subject, error)
	Provenance() Provenance
}

// Qualify runs the durable Repository gate. A nil Harness yields UNAVAILABLE; a
// check that cannot run (a harness/setup failure) yields UNAVAILABLE; a check
// that does not hold yields FAIL; all checks holding yields PASS with evidence
// whose class reflects whether the Harness was a real external backend or a
// reference one.
func Qualify(ctx context.Context, harness Harness) conformance.Result {
	if harness == nil {
		return conformance.Result{
			Component: Component,
			Status:    conformance.Unavailable,
			Reason:    "no durable Repository harness: the gate requires a provisioned celld-backed platformapi.Repository; record UNAVAILABLE and leave Unit 12 incomplete",
			Evidence:  conformance.Evidence{Class: conformance.EvidenceClassExternal, ArtifactReferences: []conformance.ArtifactReference{}},
		}
	}

	provenance := harness.Provenance()
	for _, check := range RequiredChecks() {
		outcome, err := runCheck(ctx, harness, check)
		if err != nil {
			return conformance.Result{
				Component: Component,
				Status:    conformance.Unavailable,
				Reason:    fmt.Sprintf("contract check %q could not run: %v", check.ID, err),
				Evidence:  evidence(provenance),
			}
		}
		if !outcome.Passed {
			reason := fmt.Sprintf("contract check %q (%s) failed", check.ID, check.Reference)
			if detail := strings.TrimSpace(outcome.Detail); detail != "" {
				reason += ": " + detail
			}
			return conformance.Result{
				Component: Component,
				Status:    conformance.Fail,
				Reason:    reason,
				Evidence:  evidence(provenance),
			}
		}
	}
	return conformance.Result{
		Component: Component,
		Status:    conformance.Pass,
		Evidence:  evidence(provenance),
	}
}

func runCheck(ctx context.Context, harness Harness, check Check) (CheckOutcome, error) {
	subject, err := harness.NewSubject(ctx)
	if err != nil {
		return CheckOutcome{}, fmt.Errorf("provision subject: %w", err)
	}
	if subject == nil || subject.Repository == nil || subject.Permit == nil {
		return CheckOutcome{}, errors.New("harness returned an incomplete subject")
	}
	switch check.ID {
	case "atomic-idempotency":
		return checkIdempotency(ctx, subject)
	case "atomic-event-sequence":
		return checkEventSequence(ctx, subject)
	case "atomic-replay-subscribe":
		return checkReplaySubscribe(ctx, subject)
	case "atomic-authorization-fence":
		return checkAuthorizationFence(ctx, subject)
	case "crash-durable":
		return checkCrashDurable(subject)
	default:
		return CheckOutcome{}, fmt.Errorf("unknown check %q", check.ID)
	}
}

func checkIdempotency(ctx context.Context, subject *Subject) (CheckOutcome, error) {
	keyDigest, err := idempotency.DigestKey(conformanceSecret, "conformance-idempotency-key")
	if err != nil {
		return CheckOutcome{}, err
	}
	digestA, err := canonical.StructuredDigest("circulusd.conformance.request", 1, canonical.Map{"body": "A"})
	if err != nil {
		return CheckOutcome{}, err
	}
	digestB, err := canonical.StructuredDigest("circulusd.conformance.request", 1, canonical.Map{"body": "B"})
	if err != nil {
		return CheckOutcome{}, err
	}
	proposedA, err := subject.proposedTurn(digestA)
	if err != nil {
		return CheckOutcome{}, err
	}
	proposedB, err := subject.proposedTurn(digestA)
	if err != nil {
		return CheckOutcome{}, err
	}
	permit := subject.Permit(platformapi.OperationCreateTurn)

	first, dedup, err := subject.Repository.CreateTurn(ctx, platformapi.CreateTurnCommand{
		TenantID: subject.TenantID, SubjectID: subject.SubjectID, SessionID: subject.SessionID,
		KeyDigest: keyDigest, RequestDigest: digestA, ProposedTurn: proposedA, Authorization: permit,
	})
	if err != nil {
		return CheckOutcome{}, fmt.Errorf("initial CreateTurn: %w", err)
	}
	if dedup {
		return CheckOutcome{Passed: false, Detail: "the initial CreateTurn was reported as a duplicate"}, nil
	}

	// A repeat under the same key and request digest, even with a different
	// proposed turn, must return the already-committed turn and deduplicate.
	repeat, dedup, err := subject.Repository.CreateTurn(ctx, platformapi.CreateTurnCommand{
		TenantID: subject.TenantID, SubjectID: subject.SubjectID, SessionID: subject.SessionID,
		KeyDigest: keyDigest, RequestDigest: digestA, ProposedTurn: proposedB, Authorization: permit,
	})
	if err != nil {
		return CheckOutcome{}, fmt.Errorf("duplicate CreateTurn: %w", err)
	}
	if !dedup || repeat.ID != first.ID {
		return CheckOutcome{Passed: false, Detail: fmt.Sprintf(
			"duplicate key returned turn %q dedup=%t, want the committed turn %q dedup=true",
			repeat.ID, dedup, first.ID)}, nil
	}

	// The same key with a different request digest must conflict, not fork.
	_, _, err = subject.Repository.CreateTurn(ctx, platformapi.CreateTurnCommand{
		TenantID: subject.TenantID, SubjectID: subject.SubjectID, SessionID: subject.SessionID,
		KeyDigest: keyDigest, RequestDigest: digestB, ProposedTurn: proposedB, Authorization: permit,
	})
	if !errors.Is(err, platformapi.ErrIdempotencyConflict) {
		return CheckOutcome{Passed: false, Detail: fmt.Sprintf(
			"same key with a different body returned %v, want ErrIdempotencyConflict", err)}, nil
	}
	return CheckOutcome{Passed: true}, nil
}

func checkEventSequence(ctx context.Context, subject *Subject) (CheckOutcome, error) {
	turnID, err := subject.createTurn(ctx, "conformance-sequence-key", "seq")
	if err != nil {
		return CheckOutcome{}, err
	}
	auth := subject.authority(turnID, subject.PlacementGeneration)

	first, err := subject.appendAccepted(ctx, auth, 0)
	if err != nil {
		return CheckOutcome{}, fmt.Errorf("first append: %w", err)
	}
	if first.Sequence != 1 {
		return CheckOutcome{Passed: false, Detail: fmt.Sprintf("first durable event sequence = %d, want 1", first.Sequence)}, nil
	}
	// A distinct command reusing the already-consumed expected sequence must
	// lose the fence rather than double-write.
	_, err = subject.appendAccepted(ctx, auth, 0)
	if !errors.Is(err, platformapi.ErrSequenceConflict) {
		return CheckOutcome{Passed: false, Detail: fmt.Sprintf(
			"re-used expected sequence returned %v, want ErrSequenceConflict", err)}, nil
	}
	return CheckOutcome{Passed: true}, nil
}

func checkReplaySubscribe(ctx context.Context, subject *Subject) (CheckOutcome, error) {
	turnID, err := subject.createTurn(ctx, "conformance-replay-key", "replay")
	if err != nil {
		return CheckOutcome{}, err
	}
	auth := subject.authority(turnID, subject.PlacementGeneration)
	if _, err := subject.appendAccepted(ctx, auth, 0); err != nil {
		return CheckOutcome{}, fmt.Errorf("append accepted: %w", err)
	}
	if _, err := subject.appendActive(ctx, auth, 1, platformapi.EventModelEffectPrepared); err != nil {
		return CheckOutcome{}, fmt.Errorf("append model prepared: %w", err)
	}

	readPermit := subject.Permit(platformapi.OperationReadEvents)
	head := uint64(2)

	// Caught up at head: an atomic live subscription is opened.
	caughtUp, err := subject.Repository.OpenEventStream(ctx, platformapi.ReplayQuery{
		TenantID: subject.TenantID, SubjectID: subject.SubjectID, SessionID: subject.SessionID,
		AfterSequence: head, Limit: 16, Authorization: readPermit,
	})
	if err != nil {
		return CheckOutcome{}, fmt.Errorf("caught-up OpenEventStream: %w", err)
	}
	defer closeSubscription(caughtUp.Subscription)
	if !caughtUp.CaughtUp || caughtUp.Subscription == nil ||
		caughtUp.Replay.Snapshot.LastDurableSequence != head {
		return CheckOutcome{Passed: false, Detail: fmt.Sprintf(
			"caught-up stream = caughtUp:%t subscription:%t last:%d, want a live subscription at head %d",
			caughtUp.CaughtUp, caughtUp.Subscription != nil, caughtUp.Replay.Snapshot.LastDurableSequence, head)}, nil
	}

	// Behind head: no subscription, so the client reconnects rather than
	// silently missing the gap.
	behind, err := subject.Repository.OpenEventStream(ctx, platformapi.ReplayQuery{
		TenantID: subject.TenantID, SubjectID: subject.SubjectID, SessionID: subject.SessionID,
		AfterSequence: 0, Limit: 1, Authorization: readPermit,
	})
	if err != nil {
		return CheckOutcome{}, fmt.Errorf("behind-head OpenEventStream: %w", err)
	}
	defer closeSubscription(behind.Subscription)
	if behind.CaughtUp || behind.Subscription != nil {
		return CheckOutcome{Passed: false, Detail: "a stream behind head returned a subscription instead of forcing a reconnect"}, nil
	}
	return CheckOutcome{Passed: true}, nil
}

func checkAuthorizationFence(ctx context.Context, subject *Subject) (CheckOutcome, error) {
	if subject.PlacementGeneration == 0 || subject.AuthorizationGeneration == 0 {
		return CheckOutcome{}, errors.New("subject generations must be non-zero to fence")
	}
	turnID, err := subject.createTurn(ctx, "conformance-fence-key", "fence")
	if err != nil {
		return CheckOutcome{}, err
	}
	stale := subject.authority(turnID, subject.PlacementGeneration-1)
	_, err = subject.appendAccepted(ctx, stale, 0)
	if !errors.Is(err, platformapi.ErrStaleAuthority) {
		return CheckOutcome{Passed: false, Detail: fmt.Sprintf(
			"append under a stale placement generation returned %v, want ErrStaleAuthority", err)}, nil
	}
	stale = subject.authority(turnID, subject.PlacementGeneration)
	stale.AuthorizationGeneration++
	if _, err := subject.appendAccepted(ctx, stale, 0); !errors.Is(err, platformapi.ErrStaleAuthority) {
		return CheckOutcome{Detail: fmt.Sprintf("append under a mismatched authorization generation returned %v", err)}, nil
	}
	for _, kind := range []identity.Kind{identity.Tenant, identity.Subject, identity.RuntimeRevision, identity.Workspace} {
		other, err := identity.New(kind)
		if err != nil {
			return CheckOutcome{}, err
		}
		mismatch := subject.authority(turnID, subject.PlacementGeneration)
		switch kind {
		case identity.Tenant:
			mismatch.Scope.TenantID = other.String()
		case identity.Subject:
			mismatch.Scope.UserID = other.String()
		case identity.RuntimeRevision:
			mismatch.Scope.RuntimeRevision = other.String()
		case identity.Workspace:
			mismatch.Scope.WorkspaceID = other.String()
		}
		if _, err := subject.appendAccepted(ctx, mismatch, 0); !errors.Is(err, platformapi.ErrAccessDenied) {
			return CheckOutcome{Detail: fmt.Sprintf("append under mismatched %s scope returned %v", kind, err)}, nil
		}
	}
	keyDigest, err := idempotency.DigestKey(conformanceSecret, "conformance-permit-binding-key")
	if err != nil {
		return CheckOutcome{}, err
	}
	digest, err := canonical.StructuredDigest("circulusd.conformance.request", 1, canonical.Map{"body": "permit-binding"})
	if err != nil {
		return CheckOutcome{}, err
	}
	proposed, err := subject.proposedTurn(digest)
	if err != nil {
		return CheckOutcome{}, err
	}
	command := platformapi.CreateTurnCommand{
		TenantID: subject.TenantID, SubjectID: subject.SubjectID, SessionID: subject.SessionID,
		KeyDigest: keyDigest, RequestDigest: digest, ProposedTurn: proposed,
		Authorization: subject.Permit(platformapi.OperationCreateTurn),
	}
	for _, kind := range []identity.Kind{identity.Tenant, identity.Subject, identity.Session} {
		other, err := identity.New(kind)
		if err != nil {
			return CheckOutcome{}, err
		}
		mismatch := command
		switch kind {
		case identity.Tenant:
			mismatch.Authorization.Principal.TenantID = other.String()
		case identity.Subject:
			mismatch.Authorization.Principal.SubjectID = other.String()
		case identity.Session:
			mismatch.Authorization.SessionID = other.String()
		}
		if _, _, err := subject.Repository.CreateTurn(ctx, mismatch); !errors.Is(err, platformapi.ErrAccessDenied) {
			return CheckOutcome{Detail: fmt.Sprintf("create with mismatched %s permit returned %v", kind, err)}, nil
		}
	}
	if _, duplicate, err := subject.Repository.CreateTurn(ctx, command); err != nil || duplicate {
		return CheckOutcome{Detail: fmt.Sprintf("rejected permits changed creation state: duplicate=%t, error=%v", duplicate, err)}, nil
	}
	if _, err := subject.appendAccepted(ctx, subject.authority(turnID, subject.PlacementGeneration), 0); err != nil {
		return CheckOutcome{Detail: fmt.Sprintf("rejected authorities changed event state: %v", err)}, nil
	}
	return CheckOutcome{Passed: true}, nil
}

func checkCrashDurable(subject *Subject) (CheckOutcome, error) {
	durability := subject.Repository.Durability()
	if !durability.CrashDurable {
		return CheckOutcome{Passed: false, Detail: "Durability().CrashDurable is false: a non-durable reference store cannot promote §53.16"}, nil
	}
	return CheckOutcome{Passed: true}, nil
}

func (subject *Subject) proposedTurn(requestDigest string) (platformapi.Turn, error) {
	id, err := identity.New(identity.Turn)
	if err != nil {
		return platformapi.Turn{}, err
	}
	return platformapi.Turn{
		ID: id.String(), TenantID: subject.TenantID, SubjectID: subject.SubjectID,
		SessionID: subject.SessionID, RequestDigest: requestDigest, Status: platformapi.TurnQueued,
	}, nil
}

func (subject *Subject) createTurn(ctx context.Context, rawKey string, body string) (string, error) {
	keyDigest, err := idempotency.DigestKey(conformanceSecret, rawKey)
	if err != nil {
		return "", err
	}
	requestDigest, err := canonical.StructuredDigest("circulusd.conformance.request", 1, canonical.Map{"body": body})
	if err != nil {
		return "", err
	}
	proposed, err := subject.proposedTurn(requestDigest)
	if err != nil {
		return "", err
	}
	turn, _, err := subject.Repository.CreateTurn(ctx, platformapi.CreateTurnCommand{
		TenantID: subject.TenantID, SubjectID: subject.SubjectID, SessionID: subject.SessionID,
		KeyDigest: keyDigest, RequestDigest: requestDigest, ProposedTurn: proposed,
		Authorization: subject.Permit(platformapi.OperationCreateTurn),
	})
	if err != nil {
		return "", fmt.Errorf("CreateTurn: %w", err)
	}
	return turn.ID, nil
}

func (subject *Subject) authority(turnID string, placementGeneration uint64) platformapi.EventAuthority {
	return platformapi.EventAuthority{
		Scope: authority.Scope{
			TenantID: subject.TenantID, UserID: subject.SubjectID, SessionID: subject.SessionID,
			TurnID: turnID, RuntimeRevision: subject.RuntimeRevision, WorkspaceID: subject.WorkspaceID,
		},
		PlacementGeneration: placementGeneration, AuthorizationGeneration: subject.AuthorizationGeneration,
	}
}

func (subject *Subject) appendAccepted(
	ctx context.Context,
	auth platformapi.EventAuthority,
	expectedSequence uint64,
) (platformapi.Event, error) {
	return subject.appendActive(ctx, auth, expectedSequence, platformapi.EventTurnAccepted)
}

func (subject *Subject) appendActive(
	ctx context.Context,
	auth platformapi.EventAuthority,
	expectedSequence uint64,
	eventType platformapi.EventType,
) (platformapi.Event, error) {
	commandID, err := identity.New(identity.Operation)
	if err != nil {
		return platformapi.Event{}, err
	}
	commandDigest, err := canonical.StructuredDigest("circulusd.conformance.event", 1, canonical.Map{
		"commandId": commandID.String(), "expectedSequence": expectedSequence, "type": string(eventType),
	})
	if err != nil {
		return platformapi.Event{}, err
	}
	event, _, err := subject.Repository.AppendDurableEvent(ctx, platformapi.AppendEventCommand{
		Authority: auth, CommandID: commandID.String(), CommandDigest: commandDigest,
		ExpectedSequence: expectedSequence, Type: eventType, Payload: `{"conformance":true}`,
		TurnStatus: platformapi.TurnActive,
	})
	return event, err
}

func closeSubscription(subscription platformapi.EventSubscription) {
	if subscription != nil {
		subscription.Close()
	}
}

func evidence(provenance Provenance) conformance.Evidence {
	result := conformance.Evidence{
		Version:            provenance.Version,
		BinaryDigest:       provenance.BinaryDigest,
		EnvironmentDigest:  provenance.EnvironmentDigest,
		Kernel:             provenance.Kernel,
		Architecture:       provenance.Architecture,
		ArtifactReferences: []conformance.ArtifactReference{},
	}
	if provenance.Reference {
		// A reference harness can never carry external evidence: mark it mock and
		// reference-only so the production profile rejects it.
		result.Class = conformance.EvidenceClassReferenceOnly
		result.Mock = true
		result.BinaryDigest = ""
		result.EnvironmentDigest = ""
	} else {
		result.Class = conformance.EvidenceClassExternal
	}
	return result
}
