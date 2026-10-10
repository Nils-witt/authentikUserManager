# Go packages are listed explicitly: agent/skills contains example .go files
# that are not part of this application.
GO_PKGS := ./cmd/... ./internal/...
BIN     := bin/authentik-manager

.PHONY: all build build-backend build-frontend dev-backend dev-frontend run test lint fmt vuln hooks clean

all: build

build: build-frontend build-backend

build-backend:
	go build -o $(BIN) ./cmd/authentik-manager

build-frontend:
	cd frontend && npm ci && npm run build

## Run the API on 127.0.0.1:8080 (needs AUTHENTIK_URL and AUTHENTIK_TOKEN).
dev-backend:
	go run ./cmd/authentik-manager

## Run the Vite dev server; /api is proxied to the backend.
dev-frontend:
	cd frontend && npm run dev

## Serve the built frontend from the Go binary.
run: build
	STATIC_DIR=frontend/dist ./$(BIN)

test:
	go vet $(GO_PKGS)
	go test -race $(GO_PKGS)

lint:
	golangci-lint run $(GO_PKGS)
	cd frontend && npm run lint

fmt:
	golangci-lint fmt cmd internal

## Report known vulnerabilities reachable from the code.
vuln:
	govulncheck $(GO_PKGS)

## Enable the versioned git hooks in .githooks (pre-commit: lint + govulncheck).
hooks:
	git config core.hooksPath .githooks

clean:
	rm -rf bin frontend/dist
