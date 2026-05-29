package decision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthorize_Allow(t *testing.T) {
	c := mustParseCard(t, sampleCardJSON())
	v, target, _ := c.Authorize("principal", "student.email", time.Now())
	if v != VerdictAllow {
		t.Fatalf("want allow, got %s", v)
	}
	if target == nil {
		t.Fatalf("want target, got nil")
	}
	if target.Vendor != "skyyflow" {
		t.Errorf("want vendor=skyyflow, got %s", target.Vendor)
	}
}

func TestAuthorize_DenyFieldNotVaulted(t *testing.T) {
	c := mustParseCard(t, sampleCardJSON())
	v, _, _ := c.Authorize("principal", "student.ssn", time.Now())
	if v != VerdictDenyFieldNotVaulted {
		t.Fatalf("want field-not-vaulted, got %s", v)
	}
}

func TestAuthorize_DenyRoleNotPermitted(t *testing.T) {
	c := mustParseCard(t, sampleCardJSON())
	v, _, _ := c.Authorize("janitor", "student.email", time.Now())
	if v != VerdictDenyRoleNotPermitted {
		t.Fatalf("want role-not-permitted, got %s", v)
	}
}

func TestAuthorize_DenyDecisionWithdrawn(t *testing.T) {
	c := mustParseCard(t, sampleCardJSON())
	c.Decision.Status = "withdrawn"
	v, _, _ := c.Authorize("principal", "student.email", time.Now())
	if v != VerdictDenyDecisionWithdrawn {
		t.Fatalf("want decision-withdrawn, got %s", v)
	}
}

func TestAuthorize_DenyDecisionExpired(t *testing.T) {
	c := mustParseCard(t, sampleCardJSON())
	c.Decision.EffectiveUntil = "2020-01-01T00:00:00Z"
	v, _, _ := c.Authorize("principal", "student.email", time.Now())
	if v != VerdictDenyDecisionExpired {
		t.Fatalf("want decision-expired, got %s", v)
	}
}

func TestAuthorize_DenyNoVaultTargets(t *testing.T) {
	c := mustParseCard(t, sampleCardJSON())
	c.DataVaultTargets = nil
	v, _, _ := c.Authorize("principal", "student.email", time.Now())
	if v != VerdictDenyNoVaultTargets {
		t.Fatalf("want no-vault-targets, got %s", v)
	}
}

func TestLoad_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "card.json")
	if err := os.WriteFile(path, []byte(sampleCardJSON()), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DecisionID != "SPRINGFIELD-DEC-2026-001" {
		t.Errorf("decision_id mismatch: %s", c.DecisionID)
	}
}

func TestValidateMinimal_RejectsBadVersion(t *testing.T) {
	var c Card
	if err := json.Unmarshal([]byte(`{"decision_card_version":"0.9","decision_id":"X"}`), &c); err != nil {
		t.Fatal(err)
	}
	if err := c.validateMinimal(); err == nil {
		t.Fatal("want version error, got nil")
	}
}

// ─── fixtures ────────────────────────────────────────────────────────────

func mustParseCard(t *testing.T, raw string) *Card {
	t.Helper()
	var c Card
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &c
}

func sampleCardJSON() string {
	return `{
		"decision_card_version": "0.3",
		"decision_id": "SPRINGFIELD-DEC-2026-001",
		"issued_at": "2026-05-14T19:00:00Z",
		"buyer": { "name": "Springfield USD" },
		"decision": { "status": "approved-with-conditions" },
		"data_vault_targets": [
			{
				"vendor": "skyyflow",
				"vault_id": "v_abc",
				"fields_authorized": ["student.email", "student.parent_email"],
				"reveal_roles": ["principal", "compliance-officer"]
			}
		]
	}`
}
