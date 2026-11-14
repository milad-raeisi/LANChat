MODULE   := github.com/milad-raeisi/LANChat
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w \
	-X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(MODULE)/internal/buildinfo.Date=$(DATE)
GOFLAGS  := -trimpath
BIN      := bin

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0

.PHONY: all build install test race unit integration e2e fuzz bench lint fmt vet staticcheck vuln invisible cross snapshot docker-discovery clean help

all: lint test build ## Lint, test and build

build: ## Build lanchat and lanchat-discovery into ./bin
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/ ./cmd/lanchat ./cmd/lanchat-discovery

install: ## Install lanchat into $GOBIN
	CGO_ENABLED=0 go install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/lanchat

test: ## Run all tests
	go test ./...

race: ## Run all tests with the race detector
	go test -race ./...

unit: ## Run unit tests only
	go test ./internal/... ./cmd/...

integration: ## Run multi-node integration tests (real TLS sockets on loopback)
	go test -race -count=1 ./tests/integration/

e2e: ## Build the binary and run end-to-end CLI tests
	go test -count=1 ./tests/e2e/

fuzz: ## Run each fuzz target for 30 seconds
	go test -run=XXX -fuzz=FuzzReader -fuzztime=30s ./internal/protocol/
	go test -run=XXX -fuzz=FuzzChatBody -fuzztime=30s ./internal/protocol/
	go test -run=XXX -fuzz=FuzzText -fuzztime=30s ./internal/textsafe/

bench: ## Run benchmarks
	go test -run=XXX -bench=. -benchtime=2s ./internal/protocol/ ./internal/tui/
	go test -run=XXX -bench='NodeStart|FileTransfer' -benchtime=3x ./tests/integration/
	go test -run=XXX -bench='MessageDelivery|MessageThroughput' -benchtime=2000x ./tests/integration/

lint: fmt vet staticcheck invisible ## Run all static checks

fmt: ## Fail if code is not gofmt-formatted
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet: ## go vet
	go vet ./...

staticcheck: ## staticcheck (pinned version)
	go run $(STATICCHECK) ./...

vuln: ## Check dependencies for known vulnerabilities
	go run $(GOVULNCHECK) ./...

invisible: ## Reject invisible/bidirectional Unicode in source files
	./scripts/check-invisible.sh

cross: ## Cross-compile for every supported platform
	@for t in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o /dev/null ./cmd/lanchat || exit 1; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -o /dev/null ./cmd/lanchat-discovery || exit 1; \
	done

snapshot: ## Build release artifacts locally with GoReleaser (no publishing)
	goreleaser release --snapshot --clean

docker-discovery: ## Build the managed discovery server image
	docker build -f deploy/discovery/Dockerfile -t lanchat-discovery:$(VERSION) .

clean: ## Remove build output
	rm -rf $(BIN) dist

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'
