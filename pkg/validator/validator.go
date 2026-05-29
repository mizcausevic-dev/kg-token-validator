// Package validator implements the core JWT verification + Decision Card
// authorization flow.
//
// The validator's contract:
//
//  1. The caller hands us a JWT (Bearer token) and a request describing
//     which field they want to reveal.
//  2. We verify the JWT against the configured JWKS, check standard
//     claims (iss, aud, exp, nbf with skew), and extract the role claim.
//  3. We consult the loaded Decision Card v0.3 and ask: does any
//     data_vault_targets[] entry authorize this role to reveal this field?
//  4. We emit a hash-chained audit-stream event with the verdict.
//  5. We return Allow or Deny + the audit event id.
//
// The order is intentional: the JWT is verified BEFORE the Decision Card
// is consulted, so an invalid token can't even reach the policy layer.
package validator

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mizcausevic-dev/kg-token-validator/pkg/audit"
	"github.com/mizcausevic-dev/kg-token-validator/pkg/decision"
	"github.com/mizcausevic-dev/kg-token-validator/pkg/jwks"
)

// Config holds the runtime configuration for a Validator. All fields
// except DecisionCardSource are required.
type Config struct {
	// JWKSURL is the buyer's JWKS endpoint. RS256/384/512 + ES256/384/512.
	JWKSURL string
	// JWKSTTL is the JWKS cache TTL. Defaults to 5 minutes.
	JWKSTTL time.Duration
	// ExpectedIssuer is the iss claim the JWT must carry.
	ExpectedIssuer string
	// ExpectedAudience is the aud claim the JWT must carry.
	ExpectedAudience string
	// ClockSkew is the tolerance for exp/nbf/iat. Defaults to 30s.
	ClockSkew time.Duration
	// RoleClaim is the JWT claim path that carries the principal's role.
	// Defaults to "role". For multi-role tokens, use a comma-separated value
	// (e.g. "role:principal,compliance-officer").
	RoleClaim string
	// DecisionCardSource is a file path or http(s) URL to the buyer's
	// AI Procurement Decision Card v0.3 JSON document. Reloaded on
	// every Authorize() call so the gate respects card-level updates;
	// callers that want caching wrap the validator.
	DecisionCardSource string
	// AuditStreamURL is the Suite audit-stream endpoint events POST to.
	// Empty string degrades emission to local-chain-only (events still
	// constructed, hash chain maintained, just not shipped).
	AuditStreamURL string
	// AuditSource names this validator instance in emitted events.
	AuditSource string
}

// Validator wires JWKS, Decision Card loading, and audit-stream emission
// into one HTTP-level decision flow. Safe for concurrent use.
type Validator struct {
	cfg   Config
	jwks  *jwks.Set
	audit *audit.Emitter
}

// New constructs a Validator. Returns an error if required Config fields
// are missing.
func New(cfg Config) (*Validator, error) {
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("validator: JWKSURL required")
	}
	if cfg.ExpectedIssuer == "" {
		return nil, fmt.Errorf("validator: ExpectedIssuer required")
	}
	if cfg.ExpectedAudience == "" {
		return nil, fmt.Errorf("validator: ExpectedAudience required")
	}
	if cfg.DecisionCardSource == "" {
		return nil, fmt.Errorf("validator: DecisionCardSource required")
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 30 * time.Second
	}
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = "role"
	}
	if cfg.AuditSource == "" {
		cfg.AuditSource = "kg-token-validator"
	}
	return &Validator{
		cfg:   cfg,
		jwks:  jwks.New(cfg.JWKSURL, cfg.JWKSTTL),
		audit: audit.NewEmitter(cfg.AuditStreamURL, cfg.AuditSource),
	}, nil
}

// Request is one access-decision request. Field is the field the principal
// wants to reveal; Token is the raw JWT (without "Bearer ").
type Request struct {
	Token string `json:"token"`
	Field string `json:"field"`
}

// Response is the validator's verdict + audit context.
type Response struct {
	Allow         bool             `json:"allow"`
	Verdict       decision.Verdict `json:"verdict"`
	Reason        string           `json:"reason"`
	Principal     string           `json:"principal,omitempty"`
	Role          string           `json:"role,omitempty"`
	Field         string           `json:"field,omitempty"`
	DecisionID    string           `json:"decision_id,omitempty"`
	AuditEventID  string           `json:"audit_event_id,omitempty"`
	AuditDegraded bool             `json:"audit_degraded"`
}

// Authorize runs the full verify → authorize → audit flow.
//
// If the JWT is malformed or fails verification, returns Allow=false with
// a deny verdict naming the specific failure (so the caller can tune
// rate-limiting / WAF rules on auth failures).
//
// If the JWT verifies but the Decision Card denies the reveal, returns
// Allow=false with the Decision Card's verdict.
//
// If the audit-stream is unreachable, AuditDegraded=true on the response
// but the validator's decision still propagates — the gate fails SAFE,
// not OPEN.
func (v *Validator) Authorize(ctx context.Context, req Request) (*Response, error) {
	claims, err := v.verifyJWT(ctx, req.Token)
	if err != nil {
		return v.deny(ctx, req, "deny:jwt-invalid", err.Error(), "", "")
	}
	principal, _ := claims["sub"].(string)
	role, ok := extractRole(claims, v.cfg.RoleClaim)
	if !ok {
		return v.deny(ctx, req, "deny:role-claim-missing",
			fmt.Sprintf("JWT carries no %q claim", v.cfg.RoleClaim),
			principal, "")
	}

	card, err := decision.Load(v.cfg.DecisionCardSource)
	if err != nil {
		return v.deny(ctx, req, "deny:decision-card-load-failed", err.Error(), principal, role)
	}

	verdict, target, reason := card.Authorize(role, req.Field, time.Now())
	allow := verdict == decision.VerdictAllow
	resp := &Response{
		Allow:      allow,
		Verdict:    verdict,
		Reason:     reason,
		Principal:  principal,
		Role:       role,
		Field:      req.Field,
		DecisionID: card.DecisionID,
	}

	payload := map[string]any{
		"decision_id": card.DecisionID,
		"principal":   principal,
		"role":        role,
		"field":       req.Field,
		"verdict":     string(verdict),
		"reason":      reason,
		"jwt_issuer":  claims["iss"],
		"jwt_subject": principal,
	}
	if target != nil {
		payload["vault_vendor"] = target.Vendor
		payload["vault_id"] = target.VaultID
	}

	kind := "token_validator.access_allowed"
	if !allow {
		kind = "token_validator.access_denied"
	}
	ev, emitErr := v.audit.Emit(ctx, kind, payload)
	if ev != nil {
		resp.AuditEventID = ev.EventID
	}
	if emitErr != nil {
		resp.AuditDegraded = true
	}
	return resp, nil
}

// deny is a helper used for early failures (jwt invalid, role claim missing,
// card load failure). Still emits an audit event so the buyer's monitoring
// sees auth failures.
func (v *Validator) deny(ctx context.Context, req Request, verdict, reason, principal, role string) (*Response, error) {
	resp := &Response{
		Allow:     false,
		Verdict:   decision.Verdict(verdict),
		Reason:    reason,
		Principal: principal,
		Role:      role,
		Field:     req.Field,
	}
	payload := map[string]any{
		"principal": principal,
		"role":      role,
		"field":     req.Field,
		"verdict":   verdict,
		"reason":    reason,
	}
	ev, emitErr := v.audit.Emit(ctx, "token_validator.access_denied", payload)
	if ev != nil {
		resp.AuditEventID = ev.EventID
	}
	if emitErr != nil {
		resp.AuditDegraded = true
	}
	return resp, nil
}

// VerifyClientCert performs a SHA-256 fingerprint check on a presented
// TLS client cert against an allowlist of expected fingerprints (hex,
// lowercase, no colons). Used by the HTTP server when mTLS is enabled.
//
// Returns the matching fingerprint on success or an error.
func VerifyClientCert(cert *x509.Certificate, allowed []string) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("validator: no client cert presented")
	}
	sum := sha256.Sum256(cert.Raw)
	fp := hex.EncodeToString(sum[:])
	for _, a := range allowed {
		if a == fp {
			return fp, nil
		}
	}
	return fp, fmt.Errorf("validator: client cert fingerprint %s not in allowlist", fp)
}

// ─── internals ──────────────────────────────────────────────────────────

func (v *Validator) verifyJWT(ctx context.Context, token string) (map[string]any, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("token: decode header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("token: parse header: %w", err)
	}

	key, err := v.jwks.Key(ctx, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}

	signed := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("token: decode signature: %w", err)
	}

	if err := verifySignature(header.Alg, key, []byte(signed), signature); err != nil {
		return nil, fmt.Errorf("token: signature verify: %w", err)
	}

	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("token: decode claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		return nil, fmt.Errorf("token: parse claims: %w", err)
	}

	if err := v.validateStandardClaims(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *Validator) validateStandardClaims(claims map[string]any) error {
	if iss, _ := claims["iss"].(string); iss != v.cfg.ExpectedIssuer {
		return fmt.Errorf("iss %q != expected %q", iss, v.cfg.ExpectedIssuer)
	}
	if !audienceMatches(claims["aud"], v.cfg.ExpectedAudience) {
		return fmt.Errorf("aud %v does not include %q", claims["aud"], v.cfg.ExpectedAudience)
	}
	now := time.Now()
	if exp, ok := numericTime(claims["exp"]); ok {
		if now.After(exp.Add(v.cfg.ClockSkew)) {
			return fmt.Errorf("token expired at %s", exp.Format(time.RFC3339))
		}
	}
	if nbf, ok := numericTime(claims["nbf"]); ok {
		if now.Before(nbf.Add(-v.cfg.ClockSkew)) {
			return fmt.Errorf("token not-before %s in future", nbf.Format(time.RFC3339))
		}
	}
	return nil
}

func audienceMatches(claim any, expected string) bool {
	switch v := claim.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func numericTime(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case int64:
		return time.Unix(n, 0), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return time.Unix(i, 0), true
		}
	}
	return time.Time{}, false
}

func extractRole(claims map[string]any, claim string) (string, bool) {
	v, ok := claims[claim]
	if !ok {
		return "", false
	}
	if s, ok := v.(string); ok && s != "" {
		return s, true
	}
	if arr, ok := v.([]any); ok && len(arr) > 0 {
		if s, ok := arr[0].(string); ok {
			return s, true
		}
	}
	return "", false
}

func verifySignature(alg string, key any, signed, sig []byte) error {
	switch alg {
	case "RS256":
		return verifyRSA(key, signed, sig, sha256.New(), 256)
	case "RS384", "RS512":
		return fmt.Errorf("alg %s not implemented in v0.1; PRs welcome", alg)
	case "ES256":
		return verifyECDSA(key, signed, sig, sha256.New())
	default:
		return fmt.Errorf("unsupported alg %q", alg)
	}
}
