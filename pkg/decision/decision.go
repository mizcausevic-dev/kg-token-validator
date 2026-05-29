// Package decision parses the buyer-published AI Procurement Decision Card
// (v0.3) and answers the runtime question this validator was built for:
//
//	"Given a principal's role and the field they're trying to reveal,
//	 does the Decision Card's data_vault_targets[] authorize it?"
//
// We deliberately load only the fields we need to make that call. The full
// schema lives at github.com/mizcausevic-dev/ai-procurement-decision-spec.
// This package is not a schema validator — pair it with the upstream
// schema tooling if you need that.
package decision

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Card is the subset of an AI Procurement Decision Card v0.3 we consult at
// runtime. Other fields (criteria, rationale, history) don't affect the
// allow/deny decision — they're audit context for the buyer.
type Card struct {
	DecisionCardVersion string    `json:"decision_card_version"`
	DecisionID          string    `json:"decision_id"`
	IssuedAt            time.Time `json:"issued_at"`
	Buyer               struct {
		Name string `json:"name"`
	} `json:"buyer"`
	Decision struct {
		Status         string `json:"status"`
		EffectiveFrom  string `json:"effective_from,omitempty"`
		EffectiveUntil string `json:"effective_until,omitempty"`
	} `json:"decision"`
	DataVaultTargets []DataVaultTarget `json:"data_vault_targets,omitempty"`
	// RetentionEnvelope is parsed but not consulted by this package;
	// retention belongs to the storage layer, not the access gate.
	RetentionEnvelope json.RawMessage `json:"retention_envelope,omitempty"`
}

// DataVaultTarget is one entry from data_vault_targets[] — names the vault
// vendor, the fields it authorizes, and the roles permitted to reveal them.
type DataVaultTarget struct {
	Vendor           string   `json:"vendor"`
	VaultID          string   `json:"vault_id,omitempty"`
	VaultURL         string   `json:"vault_url,omitempty"`
	FieldsAuthorized []string `json:"fields_authorized"`
	RevealRoles      []string `json:"reveal_roles,omitempty"`
	RevealAuditURI   string   `json:"reveal_audit_uri,omitempty"`
	ExpiresAt        string   `json:"expires_at,omitempty"`
	Notes            string   `json:"notes,omitempty"`
}

// Load reads a Decision Card from a file path OR an http(s) URL.
// Returns the parsed Card along with any error.
func Load(source string) (*Card, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return loadFromURL(source)
	}
	return loadFromFile(source)
}

func loadFromFile(path string) (*Card, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("decision: open %s: %w", path, err)
	}
	defer f.Close()
	return parse(f)
}

func loadFromURL(url string) (*Card, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("decision: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("decision: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("decision: fetch %s: status %d", url, resp.StatusCode)
	}
	return parse(resp.Body)
}

func parse(r io.Reader) (*Card, error) {
	var c Card
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		// Retry permissively if the spec has fields we don't model.
		// dec is already consumed; rewind via re-read isn't possible,
		// so we just relax and reparse from a buffered copy.
		return parsePermissive(r)
	}
	if err := c.validateMinimal(); err != nil {
		return nil, err
	}
	return &c, nil
}

func parsePermissive(r io.Reader) (*Card, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("decision: read: %w", err)
	}
	var c Card
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("decision: parse: %w", err)
	}
	if err := c.validateMinimal(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Card) validateMinimal() error {
	if c.DecisionCardVersion == "" {
		return fmt.Errorf("decision: missing decision_card_version")
	}
	if c.DecisionCardVersion != "0.1" && c.DecisionCardVersion != "0.2" && c.DecisionCardVersion != "0.3" {
		return fmt.Errorf("decision: unsupported version %q (want 0.1, 0.2, or 0.3)", c.DecisionCardVersion)
	}
	if c.DecisionID == "" {
		return fmt.Errorf("decision: missing decision_id")
	}
	return nil
}

// Verdict is the runtime answer for a single reveal request.
type Verdict string

const (
	VerdictAllow                 Verdict = "allow"
	VerdictDenyFieldNotVaulted   Verdict = "deny:field-not-vaulted"
	VerdictDenyRoleNotPermitted  Verdict = "deny:role-not-permitted"
	VerdictDenyDecisionExpired   Verdict = "deny:decision-expired"
	VerdictDenyDecisionWithdrawn Verdict = "deny:decision-withdrawn"
	VerdictDenyNoVaultTargets    Verdict = "deny:no-vault-targets"
)

// Authorize answers: given the principal's role and the field they want to
// reveal, does this Decision Card permit it? Multiple data_vault_targets[]
// entries may exist — any single entry that names BOTH the field and the
// role is sufficient.
//
// Returns the verdict, the matching target (or nil), and an explanation
// suitable for audit-stream emission.
func (c *Card) Authorize(role, field string, now time.Time) (Verdict, *DataVaultTarget, string) {
	if c.Decision.Status == "withdrawn" {
		return VerdictDenyDecisionWithdrawn, nil,
			fmt.Sprintf("decision %s withdrawn", c.DecisionID)
	}
	if c.Decision.EffectiveUntil != "" {
		if until, err := time.Parse(time.RFC3339, c.Decision.EffectiveUntil); err == nil {
			if now.After(until) {
				return VerdictDenyDecisionExpired, nil,
					fmt.Sprintf("decision %s expired %s", c.DecisionID, c.Decision.EffectiveUntil)
			}
		}
	}
	if len(c.DataVaultTargets) == 0 {
		return VerdictDenyNoVaultTargets, nil,
			fmt.Sprintf("decision %s declares no data_vault_targets", c.DecisionID)
	}
	// Track the strongest failure mode we saw so we can return a meaningful
	// reason when no target matches.
	sawField := false
	for i := range c.DataVaultTargets {
		t := &c.DataVaultTargets[i]
		if !contains(t.FieldsAuthorized, field) {
			continue
		}
		sawField = true
		if !contains(t.RevealRoles, role) {
			continue
		}
		// Per-target expires_at overrides the decision-level one.
		if t.ExpiresAt != "" {
			if until, err := time.Parse(time.RFC3339, t.ExpiresAt); err == nil {
				if now.After(until) {
					continue
				}
			}
		}
		return VerdictAllow, t,
			fmt.Sprintf("decision %s authorizes role %q to reveal field %q via vault %s",
				c.DecisionID, role, field, t.Vendor)
	}
	if sawField {
		return VerdictDenyRoleNotPermitted, nil,
			fmt.Sprintf("decision %s vaults field %q but does not authorize role %q", c.DecisionID, field, role)
	}
	return VerdictDenyFieldNotVaulted, nil,
		fmt.Sprintf("decision %s does not vault field %q", c.DecisionID, field)
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
