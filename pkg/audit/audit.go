// Package audit emits hash-chained governance events compatible with
// audit-stream-py and the rest of the Kinetic Gain Protocol Suite.
//
// Same canonical-JSON SHA-256 + prev_hash convention every Suite producer
// uses, so events from this validator append to the buyer's audit-stream
// alongside Decision Card events, reveal events, attestation events, etc.
//
// Behavior on emission failure is FAIL-SAFE: the validator's allow/deny
// decision is computed and returned regardless of whether the audit-stream
// is reachable. If emission fails, we log to stderr (or the configured
// logger) and set the AuditDegraded flag on the response — the buyer's
// monitoring picks it up but tenant traffic isn't blocked.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Event is one audit-stream record. Shape matches audit-stream-py's
// expected ingest payload. The hash field is computed by Emit using the
// canonical-JSON SHA-256 convention.
type Event struct {
	EventID   string         `json:"event_id"`
	Sequence  int64          `json:"sequence"`
	Timestamp string         `json:"timestamp"`
	Kind      string         `json:"kind"`
	Source    string         `json:"source"`
	Payload   map[string]any `json:"payload"`
	PrevHash  string         `json:"prev_hash"`
	Hash      string         `json:"hash"`
}

// Emitter ships events to the audit-stream. Safe for concurrent use; the
// hash chain is serialized via an internal mutex so prev_hash is correct
// even under multi-request load.
type Emitter struct {
	URL     string
	Source  string
	Timeout time.Duration

	mu       sync.Mutex
	prevHash string
	sequence int64
	client   *http.Client
}

// NewEmitter constructs an Emitter. If url is empty, Emit becomes a no-op
// that returns ErrEmissionDegraded but still computes the hash chain.
func NewEmitter(url, source string) *Emitter {
	return &Emitter{
		URL:      url,
		Source:   source,
		Timeout:  5 * time.Second,
		prevHash: zeroHash,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

// ErrEmissionDegraded is returned when the audit-stream is unreachable.
// The Event is still constructed and the local chain is advanced; only
// the network write failed. Callers treat this as a warning, NOT a
// decision blocker.
var ErrEmissionDegraded = fmt.Errorf("audit: emission degraded — event constructed but stream unreachable")

// Emit builds an Event with the next sequence + hash, ships it to the
// configured audit-stream URL, and returns the constructed Event.
// Returns ErrEmissionDegraded if the URL is empty or the stream is
// unreachable; in both cases the local chain is still advanced.
func (e *Emitter) Emit(ctx context.Context, kind string, payload map[string]any) (*Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.sequence++
	now := time.Now().UTC().Format(time.RFC3339Nano)

	body := map[string]any{
		"event_id":  buildEventID(e.sequence, now),
		"sequence":  e.sequence,
		"timestamp": now,
		"kind":      kind,
		"source":    e.Source,
		"payload":   payload,
		"prev_hash": e.prevHash,
	}
	hash := canonicalHash(body)
	body["hash"] = hash

	ev := &Event{
		EventID:   body["event_id"].(string),
		Sequence:  e.sequence,
		Timestamp: now,
		Kind:      kind,
		Source:    e.Source,
		Payload:   payload,
		PrevHash:  e.prevHash,
		Hash:      hash,
	}
	e.prevHash = hash

	if e.URL == "" {
		return ev, ErrEmissionDegraded
	}
	if err := e.ship(ctx, ev); err != nil {
		return ev, fmt.Errorf("%w: %v", ErrEmissionDegraded, err)
	}
	return ev, nil
}

func (e *Emitter) ship(ctx context.Context, ev *Event) error {
	buf, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", e.URL+"/events", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("audit-stream returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// CanonicalJSON returns a deterministic JSON encoding of v: object keys
// sorted ascending, no whitespace. Matches the convention used by
// audit-stream-py, hash-attestation-rs, and the visualizer's
// audit-chain.ts so all Suite producers agree on hash inputs.
func CanonicalJSON(v any) []byte {
	// json.Marshal sorts map keys ascending and emits no whitespace already
	// for any map[string]any tree. For nested structures we re-encode through
	// a generic decode to land everything in maps so the property holds.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return raw
	}
	return canonicalEncode(generic)
}

func canonicalEncode(v any) []byte {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf bytes.Buffer
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			buf.Write(canonicalEncode(val[k]))
		}
		buf.WriteByte('}')
		return buf.Bytes()
	case []any:
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, el := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.Write(canonicalEncode(el))
		}
		buf.WriteByte(']')
		return buf.Bytes()
	default:
		raw, _ := json.Marshal(val)
		return raw
	}
}

func canonicalHash(v any) string {
	sum := sha256.Sum256(canonicalEncode(v))
	return hex.EncodeToString(sum[:])
}

// buildEventID produces a sortable event id: timestamp + sequence, hashed.
// Doesn't need to be globally unique (sequence per emitter is enough), but
// we hash so consumers don't infer load from raw counters.
func buildEventID(seq int64, ts string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s::%d", ts, seq)))
	return hex.EncodeToString(sum[:8]) // 16-char short id
}
