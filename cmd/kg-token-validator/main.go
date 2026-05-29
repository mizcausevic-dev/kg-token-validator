// kg-token-validator is a single-binary JWT validator + Decision Card
// reveal-role enforcement gate.
//
// It runs in front of any service that consumes vaulted PII: it verifies
// the incoming JWT, asks the buyer's published AI Procurement Decision
// Card v0.3 whether the principal's role is permitted to reveal the
// requested field, and emits a hash-chained governance event into the
// Suite audit-stream. Every decision lands on the same chain as the
// rest of the buyer's governance events (Decision Card drafted, policy
// bundle minted, reveal authorized, attestation verified).
//
// Usage:
//
//	kg-token-validator \
//	  --addr :8080 \
//	  --jwks-url https://buyer.example/.well-known/jwks.json \
//	  --issuer https://buyer.example/ \
//	  --audience kinetic-gain-token-validator \
//	  --decision-card https://buyer.example/.well-known/decisions/X.json \
//	  --audit-stream-url http://audit-stream:8080 \
//	  --audit-source kg-token-validator-prod-us-east
//
// Phase 0 ships HTTP only. mTLS support is in pkg/validator (VerifyClientCert)
// but wiring it to a tls.Config in this binary is a Phase 1 deliverable —
// listed in docs/AMBIGUITIES.md (when this repo grows that file).
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mizcausevic-dev/kg-token-validator/internal/server"
	"github.com/mizcausevic-dev/kg-token-validator/pkg/validator"
)

func main() {
	var (
		addr            = flag.String("addr", ":8080", "address to listen on")
		jwksURL         = flag.String("jwks-url", "", "buyer's JWKS endpoint")
		jwksTTL         = flag.Duration("jwks-ttl", 5*time.Minute, "JWKS cache TTL")
		issuer          = flag.String("issuer", "", "expected JWT iss claim")
		audience        = flag.String("audience", "", "expected JWT aud claim")
		clockSkew       = flag.Duration("clock-skew", 30*time.Second, "exp/nbf tolerance")
		roleClaim       = flag.String("role-claim", "role", "JWT claim that names the principal's role")
		decisionCardSrc = flag.String("decision-card", "", "file path or http(s) URL of the buyer's Decision Card v0.3")
		auditStreamURL  = flag.String("audit-stream-url", "", "Suite audit-stream endpoint (empty: degrade to local chain)")
		auditSource     = flag.String("audit-source", "kg-token-validator", "name this validator instance in emitted events")
	)
	flag.Parse()

	if *jwksURL == "" || *issuer == "" || *audience == "" || *decisionCardSrc == "" {
		log.Println("error: --jwks-url, --issuer, --audience, and --decision-card are required")
		flag.Usage()
		os.Exit(2)
	}

	v, err := validator.New(validator.Config{
		JWKSURL:            *jwksURL,
		JWKSTTL:            *jwksTTL,
		ExpectedIssuer:     *issuer,
		ExpectedAudience:   *audience,
		ClockSkew:          *clockSkew,
		RoleClaim:          *roleClaim,
		DecisionCardSource: *decisionCardSrc,
		AuditStreamURL:     *auditStreamURL,
		AuditSource:        *auditSource,
	})
	if err != nil {
		log.Fatalf("validator init: %v", err)
	}

	handler := server.New(v)

	log.Printf("kg-token-validator listening on %s", *addr)
	log.Printf("  iss=%s aud=%s", *issuer, *audience)
	log.Printf("  decision-card=%s", *decisionCardSrc)
	if *auditStreamURL == "" {
		log.Printf("  audit-stream=<none — emitting to local chain only>")
	} else {
		log.Printf("  audit-stream=%s (source=%s)", *auditStreamURL, *auditSource)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
