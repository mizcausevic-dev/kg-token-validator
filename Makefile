# kg-token-validator — Makefile
#
# Standard targets: build / test / lint / run / docker.

BINARY := kg-token-validator
VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X github.com/mizcausevic-dev/kg-token-validator/internal/server.Version=$(VERSION)"

.PHONY: build test lint run docker clean

build: ## compile single binary into ./bin/
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/$(BINARY)
	@echo "→ built bin/$(BINARY) ($(VERSION))"

test: ## run all tests with race detector
	go test -race -timeout 60s ./...

lint: ## vet + format check
	go vet ./...
	@gofmt -l . | grep -v vendor | tee /tmp/gofmt-out
	@test -z "$$(cat /tmp/gofmt-out)" || (echo "gofmt issues — run 'gofmt -w .'"; exit 1)

run: build ## run against the example Decision Card (needs JWKS_URL etc. set)
	./bin/$(BINARY) \
	  --addr :8080 \
	  --jwks-url "$$JWKS_URL" \
	  --issuer "$$ISSUER" \
	  --audience "$$AUDIENCE" \
	  --decision-card ./examples/sample-decision-card.json

docker: ## build a minimal docker image
	docker build -t $(BINARY):$(VERSION) .

clean:
	rm -rf bin/
