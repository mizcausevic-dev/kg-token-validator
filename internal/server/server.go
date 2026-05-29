// Package server exposes the validator as a small HTTP service.
//
// Two endpoints:
//
//	POST /authorize   → { token, field } → { allow, verdict, reason, ... }
//	GET  /healthz     → 200 with build info
//
// The server is single-purpose: it does NOT serve the Decision Card,
// proxy requests to backends, or implement IAM. It answers the one
// question: "given this token and field, does the buyer's signed
// Decision Card authorize the reveal?"
package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/mizcausevic-dev/kg-token-validator/pkg/validator"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// New returns an http.Handler wiring the routes. Use http.ListenAndServe
// (plain HTTP) or http.ListenAndServeTLS (mTLS — see cmd/kg-token-validator
// for the listener config that requires client cert).
func New(v *validator.Validator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /authorize", authorizeHandler(v))
	mux.HandleFunc("GET /healthz", healthzHandler())
	return logRequests(mux)
}

func authorizeHandler(v *validator.Validator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req validator.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid JSON body",
			})
			return
		}
		// Allow Bearer-token convention as fallback if not in body.
		if req.Token == "" {
			if h := r.Header.Get("Authorization"); h != "" {
				if len(h) > 7 && h[:7] == "Bearer " {
					req.Token = h[7:]
				}
			}
		}
		if req.Token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "missing token (body or Authorization: Bearer)",
			})
			return
		}
		if req.Field == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "missing field",
			})
			return
		}
		resp, err := v.Authorize(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": err.Error(),
			})
			return
		}
		status := http.StatusForbidden
		if resp.Allow {
			status = http.StatusOK
		}
		writeJSON(w, status, resp)
	}
}

func healthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"version": Version,
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// logRequests is a tiny middleware that prints method + path + status.
// Stays out of the audit-stream — that's reserved for governance events,
// not HTTP access logs.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(ww, r)
		log.Printf("%s %s → %d (%s)", r.Method, r.URL.Path, ww.status, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
