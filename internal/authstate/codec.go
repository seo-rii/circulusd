package authstate

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/text/unicode/norm"
)

const (
	maximumInteger      = uint64(9_007_199_254_740_991)
	maximumRecords      = 4096
	maximumAuditEntries = 65_536
	maximumStateBytes   = 16 << 20
	zeroDigest          = "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"
)

type limits struct{ records, auditEntries, stateBytes int }

func configuredLimits(config Config) (limits, error) {
	result := limits{config.MaximumRecords, config.MaximumAuditEntries, config.MaximumStateBytes}
	if result.records == 0 {
		result.records = maximumRecords
	}
	if result.auditEntries == 0 {
		result.auditEntries = maximumAuditEntries
	}
	if result.stateBytes == 0 {
		result.stateBytes = maximumStateBytes
	}
	if result.records < 1 || result.records > maximumRecords || result.auditEntries < 1 || result.auditEntries > maximumAuditEntries ||
		result.stateBytes < 1024 || result.stateBytes > maximumStateBytes {
		return limits{}, ErrInvalidConfiguration
	}
	return result, nil
}

type durableState struct {
	tenantID  string
	rawDigest [32]byte
	records   []auth.PATRecord
	audit     []AuditEntry
}

func (state *durableState) headDigest() string {
	if len(state.audit) == 0 {
		return zeroDigest
	}
	return state.audit[len(state.audit)-1].Digest
}

func (state *durableState) appendAudit(event auth.PATAuditEvent, version uint64, now time.Time, bound limits) error {
	if len(state.audit) >= bound.auditEntries {
		return ErrCapacity
	}
	if !validNow(now) || (len(state.audit) > 0 && now.Before(state.audit[len(state.audit)-1].CommittedAt)) {
		return ErrUnavailable
	}
	entry := AuditEntry{Sequence: uint64(len(state.audit) + 1), PreviousDigest: state.headDigest(), CredentialVersion: version,
		CommittedAt: now, Event: event}
	digest, err := canonical.StructuredDigest("circulusd.auth.pat-audit-entry", 1, auditValue(entry, false))
	if err != nil {
		return ErrInvalidRequest
	}
	entry.Digest = digest
	state.audit = append(state.audit, entry)
	return nil
}

func encodeState(state *durableState, bound limits) ([]byte, error) {
	sort.Slice(state.records, func(i, j int) bool { return state.records[i].ID < state.records[j].ID })
	if err := validateState(state, bound); err != nil {
		return nil, err
	}
	records := make(canonical.Array, len(state.records))
	for i, record := range state.records {
		records[i] = recordValue(record)
	}
	audit := make(canonical.Array, len(state.audit))
	for i, entry := range state.audit {
		audit[i] = auditValue(entry, true)
	}
	bytes, err := canonical.Encode(canonical.Map{"version": int64(1), "tenantId": state.tenantID,
		"records": records, "audit": audit, "headSequence": uint64(len(state.audit)), "headDigest": state.headDigest()}, stateOptions(bound))
	if err != nil {
		return nil, ErrCapacity
	}
	return bytes, nil
}

func decodeState(bytes []byte, tenant string, bound limits) (*durableState, error) {
	if len(bytes) == 0 {
		return &durableState{tenantID: tenant, rawDigest: sha256.Sum256(bytes)}, nil
	}
	if len(bytes) > bound.stateBytes {
		return nil, ErrCapacity
	}
	value, err := canonical.Decode(bytes, stateOptions(bound))
	if err != nil {
		return nil, ErrCorruptState
	}
	m, ok := exactMap(value, "version", "tenantId", "records", "audit", "headSequence", "headDigest")
	if !ok || m["version"] != int64(1) || m["tenantId"] != tenant {
		return nil, ErrCorruptState
	}
	records, ok := m["records"].(canonical.Array)
	if !ok || len(records) > bound.records {
		return nil, ErrCorruptState
	}
	audit, ok := m["audit"].(canonical.Array)
	if !ok || len(audit) > bound.auditEntries {
		return nil, ErrCorruptState
	}
	state := &durableState{tenantID: tenant, records: make([]auth.PATRecord, len(records)), audit: make([]AuditEntry, len(audit))}
	state.rawDigest = sha256.Sum256(bytes)
	for i, value := range records {
		record, err := parseRecord(value)
		if err != nil {
			return nil, err
		}
		state.records[i] = record
	}
	for i, value := range audit {
		entry, err := parseAudit(value)
		if err != nil {
			return nil, err
		}
		state.audit[i] = entry
	}
	sequence, ok := integer(m["headSequence"])
	if !ok || sequence != uint64(len(state.audit)) || m["headDigest"] != state.headDigest() {
		return nil, ErrCorruptState
	}
	if err := validateState(state, bound); err != nil {
		return nil, err
	}
	return state, nil
}

func stateOptions(bound limits) canonical.Options {
	return canonical.Options{MaxBytes: bound.stateBytes, MaxDepth: 12, MaxItems: 1_000_000}
}

func validateState(state *durableState, bound limits) error {
	if len(state.records) > bound.records || len(state.audit) > bound.auditEntries {
		return ErrCapacity
	}
	records := make(map[string]auth.PATRecord, len(state.records))
	digests := make(map[string]bool, len(state.records))
	for i, record := range state.records {
		if !validRecord(record, state.tenantID) || (i > 0 && record.ID <= state.records[i-1].ID) || digests[record.Digest] {
			return ErrCorruptState
		}
		records[record.ID], digests[record.Digest] = record, true
	}
	type occurrence struct {
		version, uses    uint64
		issued, lastUsed time.Time
		revoked          *time.Time
	}
	seen := make(map[string]*occurrence, len(records))
	previous := zeroDigest
	var committed time.Time
	for i, entry := range state.audit {
		record, found := records[entry.Event.PATID]
		if !found || !matchesEvent(record, entry.Event) || entry.Sequence != uint64(i+1) ||
			entry.PreviousDigest != previous || !validDigest(entry.Digest) || !validNow(entry.CommittedAt) ||
			entry.CommittedAt.Before(entry.Event.At) || (!committed.IsZero() && entry.CommittedAt.Before(committed)) {
			return ErrCorruptState
		}
		digest, err := canonical.StructuredDigest("circulusd.auth.pat-audit-entry", 1, auditValue(entry, false))
		if err != nil || digest != entry.Digest {
			return ErrCorruptState
		}
		history := seen[record.ID]
		if history == nil {
			history = &occurrence{}
			seen[record.ID] = history
		}
		if entry.CredentialVersion != history.version+1 {
			return ErrCorruptState
		}
		switch entry.Event.Kind {
		case auth.PATAuditIssued:
			if history.version != 0 || entry.Event.Scope != "" || !entry.Event.At.Equal(record.IssuedAt) {
				return ErrCorruptState
			}
			history.issued = entry.Event.At
		case auth.PATAuditUsed:
			if history.version == 0 || history.revoked != nil || !slices.Contains(record.Scopes, entry.Event.Scope) ||
				entry.Event.At.Before(history.issued) || entry.Event.At.Before(history.lastUsed) || !entry.Event.At.Before(record.ExpiresAt) {
				return ErrCorruptState
			}
			history.uses++
			history.lastUsed = entry.Event.At
		case auth.PATAuditRevoked:
			if history.version == 0 || history.revoked != nil || entry.Event.Scope != "" || entry.Event.At.Before(history.issued) || entry.Event.At.Before(history.lastUsed) {
				return ErrCorruptState
			}
			at := entry.Event.At
			history.revoked = &at
		default:
			return ErrCorruptState
		}
		history.version++
		previous, committed = entry.Digest, entry.CommittedAt
	}
	for id, record := range records {
		history := seen[id]
		if history == nil || history.version != record.Version || history.uses != record.UseCount ||
			!history.lastUsed.Equal(record.LastUsedAt) || !equalOptionalTime(history.revoked, record.RevokedAt) {
			return ErrCorruptState
		}
	}
	return nil
}

func recordValue(record auth.PATRecord) canonical.Map {
	scopes := make(canonical.Array, len(record.Scopes))
	for i, scope := range record.Scopes {
		scopes[i] = scope
	}
	var revoked canonical.Value
	if record.RevokedAt != nil {
		revoked = timeText(*record.RevokedAt)
	}
	var used canonical.Value
	if !record.LastUsedAt.IsZero() {
		used = timeText(record.LastUsedAt)
	}
	return canonical.Map{"id": record.ID, "tenantId": record.TenantID, "userId": record.UserID, "digest": record.Digest,
		"scopes": scopes, "issuedAt": timeText(record.IssuedAt), "expiresAt": timeText(record.ExpiresAt),
		"revokedAt": revoked, "lastUsedAt": used, "useCount": record.UseCount, "version": record.Version}
}

func parseRecord(value canonical.Value) (auth.PATRecord, error) {
	r := auth.PATRecord{}
	m, ok := exactMap(value, "id", "tenantId", "userId", "digest", "scopes", "issuedAt", "expiresAt", "revokedAt", "lastUsedAt", "useCount", "version")
	if !ok {
		return r, ErrCorruptState
	}
	for key, target := range map[string]*string{"id": &r.ID, "tenantId": &r.TenantID, "userId": &r.UserID, "digest": &r.Digest} {
		text, ok := m[key].(string)
		if !ok {
			return r, ErrCorruptState
		}
		*target = text
	}
	scopes, ok := m["scopes"].(canonical.Array)
	if !ok || len(scopes) == 0 || len(scopes) > 128 {
		return r, ErrCorruptState
	}
	r.Scopes = make([]string, len(scopes))
	for i, value := range scopes {
		text, ok := value.(string)
		if !ok {
			return r, ErrCorruptState
		}
		r.Scopes[i] = text
	}
	if r.IssuedAt, ok = parseTime(m["issuedAt"]); !ok {
		return r, ErrCorruptState
	}
	if r.ExpiresAt, ok = parseTime(m["expiresAt"]); !ok {
		return r, ErrCorruptState
	}
	if m["revokedAt"] != nil {
		at, ok := parseTime(m["revokedAt"])
		if !ok {
			return r, ErrCorruptState
		}
		r.RevokedAt = &at
	}
	if m["lastUsedAt"] != nil {
		if r.LastUsedAt, ok = parseTime(m["lastUsedAt"]); !ok {
			return r, ErrCorruptState
		}
	}
	if r.UseCount, ok = integer(m["useCount"]); !ok {
		return r, ErrCorruptState
	}
	if r.Version, ok = integer(m["version"]); !ok {
		return r, ErrCorruptState
	}
	return r, nil
}

func auditValue(entry AuditEntry, withDigest bool) canonical.Map {
	value := canonical.Map{"sequence": entry.Sequence, "previousDigest": entry.PreviousDigest, "credentialVersion": entry.CredentialVersion,
		"committedAt": timeText(entry.CommittedAt), "event": canonical.Map{"at": timeText(entry.Event.At), "kind": string(entry.Event.Kind),
			"patId": entry.Event.PATID, "tenantId": entry.Event.TenantID, "userId": entry.Event.UserID, "scope": entry.Event.Scope}}
	if withDigest {
		value["digest"] = entry.Digest
	}
	return value
}

func parseAudit(value canonical.Value) (AuditEntry, error) {
	r := AuditEntry{}
	m, ok := exactMap(value, "sequence", "previousDigest", "digest", "credentialVersion", "committedAt", "event")
	if !ok {
		return r, ErrCorruptState
	}
	if r.Sequence, ok = integer(m["sequence"]); !ok {
		return r, ErrCorruptState
	}
	if r.CredentialVersion, ok = integer(m["credentialVersion"]); !ok {
		return r, ErrCorruptState
	}
	if r.PreviousDigest, ok = m["previousDigest"].(string); !ok {
		return r, ErrCorruptState
	}
	if r.Digest, ok = m["digest"].(string); !ok {
		return r, ErrCorruptState
	}
	if r.CommittedAt, ok = parseTime(m["committedAt"]); !ok {
		return r, ErrCorruptState
	}
	e, ok := exactMap(m["event"], "at", "kind", "patId", "tenantId", "userId", "scope")
	if !ok {
		return r, ErrCorruptState
	}
	if r.Event.At, ok = parseTime(e["at"]); !ok {
		return r, ErrCorruptState
	}
	kind, ok := e["kind"].(string)
	if !ok {
		return r, ErrCorruptState
	}
	r.Event.Kind = auth.PATAuditKind(kind)
	for key, target := range map[string]*string{"patId": &r.Event.PATID, "tenantId": &r.Event.TenantID, "userId": &r.Event.UserID, "scope": &r.Event.Scope} {
		text, ok := e[key].(string)
		if !ok {
			return r, ErrCorruptState
		}
		*target = text
	}
	return r, nil
}

func validRecord(record auth.PATRecord, tenant string) bool {
	if record.TenantID != tenant || !validDigest(record.Digest) || record.ID != "patid_"+strings.TrimPrefix(record.Digest, "sha256:")[:32] ||
		record.Version < 1 || record.Version > maximumInteger || record.UseCount >= maximumInteger-1 ||
		!validNow(record.IssuedAt) || !validNow(record.ExpiresAt) || !record.ExpiresAt.After(record.IssuedAt) || record.ExpiresAt.Sub(record.IssuedAt) > 366*24*time.Hour {
		return false
	}
	if _, err := identity.Parse(identity.Subject, record.UserID); err != nil {
		return false
	}
	if len(record.Scopes) < 1 || len(record.Scopes) > 128 || !slices.IsSorted(record.Scopes) {
		return false
	}
	for i, scope := range record.Scopes {
		if !validText(scope) || (i > 0 && scope == record.Scopes[i-1]) {
			return false
		}
	}
	if record.UseCount == 0 {
		if !record.LastUsedAt.IsZero() {
			return false
		}
	} else if !validNow(record.LastUsedAt) ||
		record.LastUsedAt.Before(record.IssuedAt) || !record.LastUsedAt.Before(record.ExpiresAt) {
		return false
	}
	version := uint64(1) + record.UseCount
	if record.RevokedAt != nil {
		if !validNow(*record.RevokedAt) || record.RevokedAt.Before(record.IssuedAt) || record.RevokedAt.Before(record.LastUsedAt) {
			return false
		}
		version++
	}
	return record.Version == version
}

func validTransition(current, next auth.PATRecord, event auth.PATAuditEvent, now time.Time) bool {
	if current.ID != next.ID || current.TenantID != next.TenantID || current.UserID != next.UserID || current.Digest != next.Digest ||
		!slices.Equal(current.Scopes, next.Scopes) || !current.IssuedAt.Equal(next.IssuedAt) || !current.ExpiresAt.Equal(next.ExpiresAt) ||
		next.Version != current.Version+1 || current.RevokedAt != nil || !validNow(now) || now.Before(event.At) {
		return false
	}
	switch event.Kind {
	case auth.PATAuditUsed:
		return next.RevokedAt == nil && next.UseCount == current.UseCount+1 && next.LastUsedAt.Equal(event.At) &&
			!event.At.Before(current.IssuedAt) && !event.At.Before(current.LastUsedAt) && !now.Before(current.IssuedAt) &&
			now.Before(current.ExpiresAt) && slices.Contains(current.Scopes, event.Scope)
	case auth.PATAuditRevoked:
		return event.Scope == "" && next.UseCount == current.UseCount && next.LastUsedAt.Equal(current.LastUsedAt) &&
			next.RevokedAt != nil && next.RevokedAt.Equal(event.At) && !event.At.Before(current.IssuedAt) && !event.At.Before(current.LastUsedAt)
	}
	return false
}

func matchesEvent(record auth.PATRecord, event auth.PATAuditEvent) bool {
	return event.PATID == record.ID && event.TenantID == record.TenantID && event.UserID == record.UserID && validNow(event.At)
}

func validPATID(id string) bool {
	if len(id) != 38 || !strings.HasPrefix(id, "patid_") {
		return false
	}
	bytes, err := hex.DecodeString(id[6:])
	return err == nil && hex.EncodeToString(bytes) == id[6:]
}

func validDigest(text string) bool {
	if len(text) != 71 || !strings.HasPrefix(text, "sha256:") {
		return false
	}
	bytes, err := hex.DecodeString(text[7:])
	return err == nil && hex.EncodeToString(bytes) == text[7:] && text != zeroDigest
}

func validText(text string) bool {
	if text == "" || len(text) > 256 || !utf8.ValidString(text) || !norm.NFC.IsNormalString(text) {
		return false
	}
	for _, c := range text {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func validNow(at time.Time) bool   { return !at.IsZero() && at.Year() >= 1970 && at.Year() <= 9999 }
func timeText(at time.Time) string { return at.UTC().Format(time.RFC3339Nano) }
func parseTime(value canonical.Value) (time.Time, bool) {
	text, ok := value.(string)
	if !ok {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, text)
	return at, err == nil && validNow(at) && timeText(at) == text
}
func equalOptionalTime(a, b *time.Time) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && a.Equal(*b))
}
func cloneRecord(record auth.PATRecord) auth.PATRecord {
	record.Scopes = slices.Clone(record.Scopes)
	if record.RevokedAt != nil {
		at := *record.RevokedAt
		record.RevokedAt = &at
	}
	return record
}
func exactMap(value canonical.Value, keys ...string) (canonical.Map, bool) {
	m, ok := value.(canonical.Map)
	if !ok || len(m) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return nil, false
		}
	}
	return m, true
}
func integer(value canonical.Value) (uint64, bool) {
	n, ok := value.(int64)
	return uint64(n), ok && n >= 0 && uint64(n) <= maximumInteger
}
