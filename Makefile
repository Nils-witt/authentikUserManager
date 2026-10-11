# Go packages are listed explicitly: agent/skills contains example .go files
# that are not part of this application.
GO_PKGS := ./cmd/... ./internal/...
BIN     := bin/authentik-manager
# Vite build output, embedded into the binary by internal/web.
DIST    := internal/web/dist
# Shown in the UI footer (internal/buildinfo); go build stamps the commit itself.
TAG     := $(shell git describe --tags --exact-match 2>/dev/null)
LDFLAGS := -X authentikManager/internal/buildinfo.tag=$(TAG)

.PHONY: all build build-backend build-frontend dev-backend dev-frontend dev-db run test test-integration lint fmt vuln hooks clean

# Throwaway PostgreSQL for test-integration.
TEST_PG := authentik-manager-test-pg

all: build

build: build-frontend build-backend

build-backend: $(DIST)/index.html
	go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/authentik-manager

build-frontend:
	cd frontend && npm ci && npm run build

# Compiling internal/web needs the frontend build; create it once if missing.
$(DIST)/index.html:
	$(MAKE) build-frontend

## Run the API on 127.0.0.1:8080 (needs AUTHENTIK_URL and AUTHENTIK_TOKEN).
dev-backend: $(DIST)/index.html
	go run ./cmd/authentik-manager

## Run the Vite dev server; /api is proxied to the backend.
dev-frontend:
	cd frontend && npm run dev

## Start PostgreSQL for development (compose.yaml).
dev-db:
	docker compose up -d db

## Build and run the binary with the embedded frontend.
run: build
	./$(BIN)

test: $(DIST)/index.html
	go vet $(GO_PKGS)
	go test -race $(GO_PKGS)

## Run all tests, including the PostgreSQL ones, against a temporary container.
test-integration: $(DIST)/index.html
	docker run -d --rm --name $(TEST_PG) -e POSTGRES_PASSWORD=test -e POSTGRES_DB=am_test \
		-p 127.0.0.1:55433:5432 postgres:17-alpine
	until docker exec $(TEST_PG) pg_isready -h 127.0.0.1 -U postgres -d am_test >/dev/null 2>&1; do sleep 1; done
	TEST_DATABASE_URL='postgres://postgres:test@127.0.0.1:55433/am_test?sslmode=disable' \
		go test -race -count=1 $(GO_PKGS); status=$$?; docker stop $(TEST_PG) >/dev/null; exit $$status

lint: $(DIST)/index.html
	golangci-lint run $(GO_PKGS)
	cd frontend && npm run lint && npm run format:check

fmt:
	golangci-lint fmt cmd internal
	cd frontend && npm run format

## Report known vulnerabilities reachable from the code.
vuln: $(DIST)/index.html
	govulncheck $(GO_PKGS)

## Enable the versioned git hooks in .githooks (pre-commit: lint + govulncheck).
hooks:
	git config core.hooksPath .githooks

clean:
	rm -rf bin $(DIST)
