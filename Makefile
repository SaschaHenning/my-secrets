GO       ?= /opt/homebrew/bin/go
BIN_DIR  := bin
BIN      := $(BIN_DIR)/mys
PKG      := ./...
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -ldflags "-X main.Version=$(VERSION)"

.PHONY: all build test vet lint run run-web run-mcp e2e clean

all: build

build: $(BIN)

$(BIN): $(shell find . -name '*.go' -not -path './vendor/*')
	@mkdir -p $(BIN_DIR)
	$(GO) build $(LDFLAGS) -o $(BIN) ./cmd/mys
	@# macOS 15+/26 runs a codesigning monitor that SIGKILLs binaries
	@# whose ad-hoc signature it won't accept; an explicit re-sign fixes
	@# it. cp preserves the embedded signature, so any later copy (e.g.
	@# ~/.local/bin/mys) inherits it — no manual codesign step needed.
	@# No-op on non-Darwin or where codesign is absent.
	@if [ "$$(uname -s)" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then \
		codesign --sign - --force $(BIN) && echo "codesigned $(BIN) (ad-hoc)"; \
	fi

test:
	$(GO) test -race -count=1 $(PKG)

vet:
	$(GO) vet $(PKG)

lint: vet
	@command -v staticcheck >/dev/null 2>&1 && staticcheck $(PKG) || echo "staticcheck not installed — skipping"

run: build
	$(BIN) --help

run-web: build
	$(BIN) web --port 7823

run-mcp: build
	$(BIN) mcp

e2e: build
	@echo "Setting up throwaway test store in /tmp/mys-e2e"
	./scripts/setup_test_store.sh /tmp/mys-e2e
	@echo "Running E2E scenarios — see output"
	GNUPGHOME=/tmp/mys-e2e/gnupg ./scripts/run_e2e.sh

clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out
