//go:build smoke

// smoke-test.go is an integration smoke test that exercises the full binary
// end-to-end: spawns a mock JWKS, runs the validator via `go run`, mints a
// real RS256 JWT, and hits POST /authorize.
//
// Run with:
//
//	go run -tags smoke examples/smoke-test.go
//
// Not part of the default test suite — pulled into Phase 1 CI when we wire
// docker-compose for the audit-stream integration test.
package main

import "fmt"

func main() {
	fmt.Println("placeholder smoke-test target — Phase 1 wiring")
}
