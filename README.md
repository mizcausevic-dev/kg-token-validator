# kg-token-validator

> **v0.1 draft.** Single-binary JWT validator + AI Procurement Decision Card v0.3 reveal-role enforcement gate. Verifies an incoming JWT against a JWKS endpoint, asks the buyer's signed Decision Card whether the principal's role is permitted to reveal the requested field, and emits a hash-chained governance event into the [Kinetic Gain Suite audit-stream](https://github.com/mizcausevic-dev/audit-stream-py).

Part of the [Kinetic Gain Protocol Suite](https://suite.kineticgain.com). First Go binary in the portfolio.

```
                    ┌─────────────────────────────┐
                    │     buyer's host app        │
                    └────────────┬────────────────┘
                          JWT (Bearer)
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                       kg-token-validator                        │
   │                                                                 │
   │  1.  verify JWT against JWKS  (RS256 / ES256, kid rotation)     │
   │  2.  check iss · aud · exp · nbf  (with configurable skew)      │
   │  3.  load Decision Card v0.3, look up data_vault_targets[]       │
   │  4.  does ANY target authorize this (role, field) pair?         │
   │  5.  emit token_validator.access_{allowed,denied} → audit-stream │
   │                                                                 │
   │      ALLOW  →  HTTP 200 with verdict + audit_event_id           │
   │      DENY   →  HTTP 403 with verdict + reason                   │
   └─────────────────────────────────────────────────────────────────┘
```

## Why it exists

Every Decision Card in the Suite declares `data_vault_targets[]` (v0.2) — which fields a vendor may reveal, and which roles may detokenize. But the spec doesn't run anything. A buyer publishes a signed Decision Card; somebody has to *enforce* it at request time.

`kg-token-validator` is that enforcement layer, in the smallest possible form. It plugs in:

- **In front of any service that needs to reveal vaulted PII** — sits as a sidecar / a small mTLS-fronted Go binary in the buyer's perimeter, validates the call, returns allow/deny.
- **As the audit emitter** — every decision is a hash-chained event on the same audit-stream the rest of the Suite uses (Decision Card drafted, attestation verified, retention deletion proven). One verifiable record across the whole vault contract lifecycle.

The CyberArk-shaped DNA shows up here: identity propagation + privileged-access enforcement + tamper-evident audit are the boring-and-correct way to do this, not a bespoke RBAC layer per surface.

## Quick start

```bash
# Build (single binary, no runtime deps)
go build -o kg-token-validator ./cmd/kg-token-validator

# Run against the example Decision Card
./kg-token-validator \
  --addr :8080 \
  --jwks-url https://buyer.example/.well-known/jwks.json \
  --issuer https://buyer.example/ \
  --audience kg-token-validator \
  --decision-card ./examples/sample-decision-card.json \
  --audit-stream-url http://audit-stream:8080 \
  --audit-source kg-token-validator-prod-us-east

# Authorize a reveal
curl -X POST http://localhost:8080/authorize \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"field": "student.email"}'

# → HTTP 200
# {
#   "allow": true,
#   "verdict": "allow",
#   "reason": "decision SPRINGFIELD-DEC-2026-001 authorizes role \"principal\" to reveal field \"student.email\" via vault skyyflow",
#   "principal": "user-9001",
#   "role": "principal",
#   "field": "student.email",
#   "decision_id": "SPRINGFIELD-DEC-2026-001",
#   "audit_event_id": "f3a8c2b1c4d5e6f7",
#   "audit_degraded": false
# }
```

## What's in the binary

| Package | Purpose |
| --- | --- |
| `pkg/decision` | Parses the AI Procurement Decision Card v0.3, answers `Authorize(role, field, now)` against `data_vault_targets[]`. Distinct verdicts for *field-not-vaulted*, *role-not-permitted*, *decision-withdrawn*, *decision-expired*, *no-vault-targets*. |
| `pkg/jwks` | Fetches + caches a JWKS endpoint. RS256 + ES256/384/521. Stale-on-error fallback. kid-miss triggers refresh so rotations propagate without a restart. |
| `pkg/audit` | Hash-chained event emitter matching audit-stream-py's canonical-JSON SHA-256 + `prev_hash` convention. Fail-safe: events are still computed locally and the chain advances even if the network write fails (returns `ErrEmissionDegraded`, sets `audit_degraded: true` on the response). |
| `pkg/validator` | Wires the above into one `Authorize(ctx, Request)` call. Also exposes `VerifyClientCert(cert, allowed)` for mTLS sidecar use. |
| `internal/server` | Tiny `net/http` handler. `POST /authorize`, `GET /healthz`. No middleware beyond a request log. |
| `cmd/kg-token-validator` | The binary entry. Pure flag-driven config. |

## Configuration flags

| Flag | Required | Default | Purpose |
| --- | :---: | --- | --- |
| `--addr` | | `:8080` | Listen address |
| `--jwks-url` | ✓ | | Buyer's JWKS endpoint |
| `--jwks-ttl` | | `5m` | JWKS cache TTL |
| `--issuer` | ✓ | | Expected JWT `iss` claim |
| `--audience` | ✓ | | Expected JWT `aud` claim |
| `--clock-skew` | | `30s` | `exp` / `nbf` tolerance |
| `--role-claim` | | `role` | JWT claim that names the principal's role |
| `--decision-card` | ✓ | | File path OR http(s) URL of the Decision Card v0.3 |
| `--audit-stream-url` | | (none) | Suite audit-stream endpoint. Empty → emit to local chain only |
| `--audit-source` | | `kg-token-validator` | Name this instance in emitted events |

## Verdicts

| Verdict | HTTP | Meaning |
| --- | :---: | --- |
| `allow` | 200 | A data_vault_target authorizes this role for this field |
| `deny:field-not-vaulted` | 403 | No target lists this field in `fields_authorized` |
| `deny:role-not-permitted` | 403 | Field is vaulted, but no target lists this role in `reveal_roles` |
| `deny:decision-expired` | 403 | `decision.effective_until` (or per-target `expires_at`) has passed |
| `deny:decision-withdrawn` | 403 | `decision.status == "withdrawn"` |
| `deny:no-vault-targets` | 403 | Decision Card declares no `data_vault_targets[]` at all |
| `deny:jwt-invalid` | 403 | JWT signature, claims, or kid lookup failed |
| `deny:role-claim-missing` | 403 | JWT verified but carries no `role` claim |
| `deny:decision-card-load-failed` | 403 | Decision Card source unreachable or unparseable |

Every verdict — allow and deny alike — emits a `token_validator.access_allowed` or `token_validator.access_denied` event on the audit-stream with the principal, role, field, verdict, reason, and the JWT issuer.

## Failure modes

- **JWKS unreachable** + previously-cached key → use the cached key (stale-on-error). No window where the gate is down because of a transient JWKS hiccup.
- **JWKS unreachable** + no cached key → deny everything with `deny:jwt-invalid`. Fail closed.
- **Audit-stream unreachable** → still return the verdict. Set `audit_degraded: true` on the response. The local hash chain advances so once the stream comes back, no events are lost (Phase 1 will add a buffered re-emit).
- **Decision Card source unreachable** → deny everything with `deny:decision-card-load-failed`. Fail closed.

## What this is NOT (v0.1)

- **Not a Decision Card schema validator.** Pair with [`ai-procurement-decision-spec`](https://github.com/mizcausevic-dev/ai-procurement-decision-spec)'s `decision-card.schema.json` if you need that.
- **Not a vault.** It tells the *caller* whether they may reveal; the vault still has to honor the verdict. Skyflow / Piiano / VGS / etc. integrations are upstream of this gate.
- **Not a retention enforcer.** Retention is the storage layer's job. See [`phi-vault-contract-profile`](https://github.com/mizcausevic-dev/phi-vault-contract-profile) + the Decision Card's `retention_envelope[]` for the retention side.
- **Not an OIDC provider.** It consumes JWTs the buyer's identity provider mints.

## Composes with

| Repo | Role |
| --- | --- |
| [`ai-procurement-decision-spec`](https://github.com/mizcausevic-dev/ai-procurement-decision-spec) (v0.3) | The buyer-side artifact this gate consults |
| [`phi-vault-contract-profile`](https://github.com/mizcausevic-dev/phi-vault-contract-profile) | Healthcare profile of the v0.3 vault contract |
| [`fhir-resource-access-audit`](https://github.com/mizcausevic-dev/fhir-resource-access-audit) | Emits audit events on the same audit-stream this binary writes to |
| [`audit-stream-py`](https://github.com/mizcausevic-dev/audit-stream-py) | The hash-chained log every verdict lands on |
| [`hash-attestation-rs`](https://github.com/mizcausevic-dev/hash-attestation-rs) | Sibling: ed25519 attestation primitives, same canonical-JSON SHA-256 convention |
| [`mcp-permission-broker`](https://github.com/mizcausevic-dev/mcp-permission-broker) | Sibling enforcement layer for MCP tool calls (Python). Different surface, same Decision Card |

## Phase 1 roadmap

- `pkg/validator.VerifyClientCert` is implemented but the binary doesn't yet require it. Phase 1 wires `tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}` behind an `--mtls-cert-allowlist` flag.
- Multi-region Decision Card cache (Phase 0 reloads on every call).
- RS384/RS512 support (Phase 0 ships RS256 + ES256 only).
- Prometheus metrics endpoint.
- Phase 0 → v1.0-prod hardening pass (per the standing squad-hardening discipline).

## Compliance posture

Audit-stream readiness scaffolding. The gate's verdicts and the audit-stream record support a covered entity's HIPAA Security Rule §164.312(a)(1) (Access Control), §164.312(b) (Audit Controls), and §164.312(d) (Person or Entity Authentication) program — but do not by themselves establish compliance. Per the standing public-language guardrail: *readiness · evidence · posture · controls · scaffolding* — never "HIPAA-compliant" without an external attestation.

## License

MIT.
