package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestEmit_LocalChainAdvances(t *testing.T) {
	em := NewEmitter("", "kg-token-validator-test")
	ev1, err := em.Emit(context.Background(), "k1", map[string]any{"x": 1})
	if !errors.Is(err, ErrEmissionDegraded) {
		t.Fatalf("want ErrEmissionDegraded (no url), got %v", err)
	}
	if ev1.PrevHash != strings.Repeat("0", 64) {
		t.Errorf("first event prev_hash should be zero, got %s", ev1.PrevHash)
	}
	ev2, _ := em.Emit(context.Background(), "k2", map[string]any{"x": 2})
	if ev2.PrevHash != ev1.Hash {
		t.Errorf("chain broken: ev2.prev_hash=%s, want %s", ev2.PrevHash, ev1.Hash)
	}
	if ev2.Sequence != 2 {
		t.Errorf("sequence: want 2, got %d", ev2.Sequence)
	}
}

func TestCanonicalEncode_DeterministicAcrossKeyOrder(t *testing.T) {
	a := map[string]any{"b": 2, "a": 1, "c": map[string]any{"y": "two", "x": "one"}}
	b := map[string]any{"c": map[string]any{"x": "one", "y": "two"}, "a": 1, "b": 2}
	if string(canonicalEncode(a)) != string(canonicalEncode(b)) {
		t.Errorf("canonical encoding non-deterministic")
	}
}

func TestCanonicalHash_MatchesKnownConvention(t *testing.T) {
	v := map[string]any{"a": 1, "b": "two"}
	want := sha256Hex(`{"a":1,"b":"two"}`)
	got := canonicalHash(v)
	if got != want {
		t.Errorf("canonical hash mismatch:\n got %s\nwant %s", got, want)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
