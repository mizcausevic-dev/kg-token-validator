package validator

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mizcausevic-dev/kg-token-validator/pkg/decision"
)

func TestEndToEnd_AllowAndDeny(t *testing.T) {
	// Generate an RSA keypair, mount a JWKS server with the public key,
	// mint two JWTs (one for "principal", one for "janitor"), point a
	// Validator at the JWKS + a Decision Card on disk, and check that
	// the principal is authorized for student.email but the janitor is not.
	priv, pub := mustGenerateRSAKey(t, 2048)
	const kid = "test-kid-1"

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": kid,
					"alg": "RS256",
					"use": "sig",
					"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		})
	}))
	defer jwksSrv.Close()

	cardDir := t.TempDir()
	cardPath := filepath.Join(cardDir, "card.json")
	if err := os.WriteFile(cardPath, []byte(sampleCardJSON()), 0o600); err != nil {
		t.Fatal(err)
	}

	v, err := New(Config{
		JWKSURL:            jwksSrv.URL,
		ExpectedIssuer:     "https://buyer.example/",
		ExpectedAudience:   "kg-token-validator",
		DecisionCardSource: cardPath,
		AuditStreamURL:     "", // emit to local chain only
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	principalJWT := mustSignJWT(t, priv, kid, map[string]any{
		"iss":  "https://buyer.example/",
		"aud":  "kg-token-validator",
		"sub":  "user-principal-1",
		"role": "principal",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	janitorJWT := mustSignJWT(t, priv, kid, map[string]any{
		"iss":  "https://buyer.example/",
		"aud":  "kg-token-validator",
		"sub":  "user-janitor-1",
		"role": "janitor",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	ctx := context.Background()

	// Principal asking for student.email → ALLOW
	resp, err := v.Authorize(ctx, Request{Token: principalJWT, Field: "student.email"})
	if err != nil {
		t.Fatalf("authorize principal: %v", err)
	}
	if !resp.Allow {
		t.Errorf("principal: want allow, got %s (reason: %s)", resp.Verdict, resp.Reason)
	}
	if resp.AuditEventID == "" {
		t.Errorf("principal: expected an audit event id")
	}

	// Janitor asking for student.email → DENY (role-not-permitted)
	resp, err = v.Authorize(ctx, Request{Token: janitorJWT, Field: "student.email"})
	if err != nil {
		t.Fatalf("authorize janitor: %v", err)
	}
	if resp.Allow {
		t.Errorf("janitor: want deny, got allow")
	}
	if resp.Verdict != decision.VerdictDenyRoleNotPermitted {
		t.Errorf("janitor: want role-not-permitted, got %s", resp.Verdict)
	}

	// Principal asking for student.ssn (not in card) → DENY (field-not-vaulted)
	resp, _ = v.Authorize(ctx, Request{Token: principalJWT, Field: "student.ssn"})
	if resp.Allow {
		t.Errorf("principal/student.ssn: want deny, got allow")
	}
	if resp.Verdict != decision.VerdictDenyFieldNotVaulted {
		t.Errorf("principal/student.ssn: want field-not-vaulted, got %s", resp.Verdict)
	}
}

func TestAuthorize_RejectsExpiredJWT(t *testing.T) {
	priv, pub := mustGenerateRSAKey(t, 2048)
	const kid = "k"

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
					"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		})
	}))
	defer jwksSrv.Close()

	cardPath := writeTempCard(t, sampleCardJSON())
	v, err := New(Config{
		JWKSURL: jwksSrv.URL, ExpectedIssuer: "https://buyer.example/",
		ExpectedAudience: "x", DecisionCardSource: cardPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	expired := mustSignJWT(t, priv, kid, map[string]any{
		"iss": "https://buyer.example/", "aud": "x", "sub": "u", "role": "principal",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	resp, _ := v.Authorize(context.Background(), Request{Token: expired, Field: "student.email"})
	if resp.Allow {
		t.Errorf("expired JWT was allowed")
	}
	if !strings.Contains(resp.Reason, "expired") {
		t.Errorf("expected 'expired' in reason, got: %s", resp.Reason)
	}
}

func TestAuthorize_RejectsBadIssuer(t *testing.T) {
	priv, pub := mustGenerateRSAKey(t, 2048)
	const kid = "k"
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	}))
	defer jwksSrv.Close()
	cardPath := writeTempCard(t, sampleCardJSON())
	v, _ := New(Config{
		JWKSURL: jwksSrv.URL, ExpectedIssuer: "https://expected.example/",
		ExpectedAudience: "x", DecisionCardSource: cardPath,
	})
	tok := mustSignJWT(t, priv, kid, map[string]any{
		"iss": "https://attacker.example/", "aud": "x", "sub": "u", "role": "principal",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	resp, _ := v.Authorize(context.Background(), Request{Token: tok, Field: "student.email"})
	if resp.Allow {
		t.Errorf("wrong issuer was allowed")
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────

func mustGenerateRSAKey(t *testing.T, bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return priv, &priv.PublicKey
}

func mustSignJWT(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	signedInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signedInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signedInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writeTempCard(t *testing.T, raw string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "card.json")
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func sampleCardJSON() string {
	return fmt.Sprintf(`{
		"decision_card_version": "0.3",
		"decision_id": "TEST-DEC-2026-001",
		"issued_at": "2026-05-14T19:00:00Z",
		"buyer": { "name": "Test USD" },
		"decision": { "status": "approved-with-conditions" },
		"data_vault_targets": [
			{
				"vendor": "skyyflow",
				"vault_id": "v_abc",
				"fields_authorized": ["student.email", "student.parent_email"],
				"reveal_roles": ["principal", "compliance-officer"]
			}
		]
	}`)
}
