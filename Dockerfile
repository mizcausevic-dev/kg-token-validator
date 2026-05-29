# syntax=docker/dockerfile:1.6

# ─── build stage ────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .

ARG VERSION=docker
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build \
      -trimpath \
      -ldflags="-s -w -X github.com/mizcausevic-dev/kg-token-validator/internal/server.Version=${VERSION}" \
      -o /out/kg-token-validator \
      ./cmd/kg-token-validator

# ─── runtime stage ──────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/kg-token-validator /kg-token-validator

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/kg-token-validator"]
