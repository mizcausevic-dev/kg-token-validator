// Package jwks fetches a buyer's JWKS endpoint and caches public keys for
// JWT verification. Refreshes on TTL or on key-not-found (so a key
// rotation propagates within one verification cycle).
//
// Deliberately small: RS256, RS384, RS512, ES256, ES384, ES512 only. No
// HS* — symmetric secrets shouldn't be shipped over JWKS anyway and the
// buyer's identity provider doesn't publish them.
package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// Set holds the active JWKS for a single configured issuer.
type Set struct {
	URL string

	mu          sync.RWMutex
	keys        map[string]any // kid → *rsa.PublicKey | *ecdsa.PublicKey
	lastFetched time.Time
	ttl         time.Duration
	client      *http.Client
}

// New constructs a Set that refreshes from url at most every ttl.
// ttl defaults to 5 minutes if zero.
func New(url string, ttl time.Duration) *Set {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	return &Set{
		URL:    url,
		ttl:    ttl,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Key returns the public key for the given kid, refreshing the JWKS if
// the cache is stale OR if the kid is unknown (kid not found triggers a
// forced refresh so rotations propagate without restart).
func (s *Set) Key(ctx context.Context, kid string) (any, error) {
	s.mu.RLock()
	k, ok := s.keys[kid]
	stale := time.Since(s.lastFetched) > s.ttl
	s.mu.RUnlock()

	if ok && !stale {
		return k, nil
	}
	if err := s.refresh(ctx); err != nil {
		// If we have a cached key (even stale), prefer it to a hard fail —
		// this keeps the gate up during transient JWKS outages.
		if ok {
			return k, nil
		}
		return nil, err
	}
	s.mu.RLock()
	k, ok = s.keys[kid]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("jwks: kid %q not in JWKS", kid)
	}
	return k, nil
}

func (s *Set) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
	if err != nil {
		return fmt.Errorf("jwks: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: fetch %s: %w", s.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: fetch %s: status %d", s.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("jwks: read body: %w", err)
	}
	var wire struct {
		Keys []rawKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return fmt.Errorf("jwks: parse: %w", err)
	}
	parsed := make(map[string]any, len(wire.Keys))
	for _, k := range wire.Keys {
		key, err := k.parse()
		if err != nil {
			// Skip unparseable keys but keep going; one malformed entry
			// shouldn't take down the whole JWKS.
			continue
		}
		parsed[k.Kid] = key
	}
	s.mu.Lock()
	s.keys = parsed
	s.lastFetched = time.Now()
	s.mu.Unlock()
	return nil
}

type rawKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	Crv string `json:"crv,omitempty"` // EC curve
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func (k rawKey) parse() (any, error) {
	switch k.Kty {
	case "RSA":
		return parseRSA(k)
	case "EC":
		return parseEC(k)
	default:
		return nil, fmt.Errorf("jwks: unsupported kty %q", k.Kty)
	}
}

func parseRSA(k rawKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("jwks: rsa n decode: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("jwks: rsa e decode: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("jwks: rsa exponent too large")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func parseEC(k rawKey) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("jwks: unsupported EC curve %q", k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("jwks: ec x decode: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("jwks: ec y decode: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
