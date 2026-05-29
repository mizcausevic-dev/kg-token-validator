# Changelog — kg-token-validator

## v0.1 — 2026-05-29 (draft)

First Go binary in the portfolio. JWT validator + AI Procurement Decision Card v0.3 reveal-role enforcement + Suite audit-stream hash-chained emitter, in one ~1500-LOC single binary.

What landed:

- `pkg/decision` — parses Decision Card v0.3, answers `Authorize(role, field, now)` with five distinct deny verdicts + one allow
- `pkg/jwks` — JWKS fetcher with TTL cache, stale-on-error fallback, kid-miss-triggers-refresh. RS256 + ES256 verification today (RS384/512 + ES384/521 noted in code)
- `pkg/audit` — hash-chained audit-stream emitter matching audit-stream-py canonical-JSON SHA-256 + prev_hash. Fail-safe: chain advances locally even on emission failure (ErrEmissionDegraded)
- `pkg/validator` — wires JWKS, decision, audit into one Authorize call. mTLS client-cert fingerprint helper present, not yet wired into the listener
- `internal/server` — small `net/http` mux: `POST /authorize` + `GET /healthz`
- `cmd/kg-token-validator` — flag-driven binary, single-binary deploy
- `examples/sample-decision-card.json` — Springfield USD × AcmeTutor v0.3 Decision Card
- `Dockerfile` — multi-stage distroless build, nonroot, ~10 MB final image
- `Makefile`, `.github/workflows/ci.yml` (matrix Go 1.22 + 1.23), `README.md`, `LICENSE` (MIT), `.gitignore`

Tests:
- `pkg/audit` — local-chain advancement, canonical encoding determinism, canonical-hash matches the known convention
- `pkg/decision` — every verdict path covered, file load round-trip
- `pkg/validator` — end-to-end with a real in-memory RSA keypair + httptest JWKS + a real signed JWT, allow/deny/expired/bad-issuer paths

Phase 1 roadmap (in README):
- Wire mTLS into the listener (`pkg/validator.VerifyClientCert` already implemented)
- Multi-region Decision Card cache (Phase 0 reloads on every request)
- RS384 / RS512 / ES384 / ES521
- Prometheus metrics endpoint
- Hardening pass to v1.0-prod
