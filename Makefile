# =============================================================================
# orkowatch Makefile
# Dev build/install helpers.
#    - End-user install scripts live under scripts/linux/ and scripts/windows/.
# Intended for use on Linux, macOS, and WSL.
#
# install/uninstall are Unix-oriented and target /usr/local/bin.
# On native Windows or Git Bash outside WSL, use scripts/windows/install.ps1
# instead.
#
# Contributor Onboarding
# ----------------------
# Prerequisites:
#   - Go 1.23+         https://go.dev/dl/
#   - golangci-lint    https://golangci-lint.run/usage/install/
#   - shfmt            https://github.com/mvdan/sh/releases
#   - shellcheck       https://www.shellcheck.net/
#
# Quick start:
#   make build         build for current platform
#   make check         run all local quality gates (mirrors CI)
#   make install       install binary to /usr/local/bin (Unix/WSL only)
#
# All targets mirror the CI pipeline. If make check passes locally, the 
# pipeline should pass on push.
# =============================================================================

BINARY_NAME := owatch
BUILD_DIR   := bin
MAIN_PKG    := ./cmd/owatch/main.go
INSTALL_DIR := /usr/local/bin

# Current Go target
GOOS    := $(shell go env GOOS)
GOARCH  := $(shell go env GOARCH)

# Windows builds need .exe
ifeq ($(GOOS), windows)
	BINARY := $(BUILD_DIR)/$(BINARY_NAME).exe
else
	BINARY := $(BUILD_DIR)/$(BINARY_NAME)
endif

# Use sudo unless already root
SUDO := $(shell [ "$$(id -u)" -eq 0 ] && echo "" || echo "sudo")

# Resolves the current version from git:
#   - Exactly at a tag:               v1.0.0
#   - N commits ahead of last tag:    v1.0.0-N-g<hash>
#   - No tags exist yet:              g<hash>
#   - Uncommitted changes present:    <above>-dirty
# Falls back to "dev" if git is unavailable
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Cross-platform release targets (mirrors CI cross-build matrix)
RELEASE_TARGETS := \
	linux/amd64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

# =============================================================================
# Targets
# =============================================================================

.PHONY: build install uninstall clean help fmt fmt-check vet lint test check docs build-all shell-lint ps-lint

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------

## build: compile the binary for the current platform into bin/
build:
	@echo "[*] Building $(BINARY_NAME) ($(GOOS)/$(GOARCH)) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build \
		-ldflags "-X github.com/papa0four/orkowatch/cmd/commands.Version=$(VERSION)" \
		-o $(BINARY) $(MAIN_PKG)
	@echo "[+] Binary written to $(BINARY)"

## build-all: cross-compile for all release targets into bin/
build-all:
	@echo "[*] Building all release targets..."
	@mkdir -p $(BUILD_DIR)
	@$(foreach target,$(RELEASE_TARGETS), \
		$(eval GOOS_T   := $(word 1,$(subst /, ,$(target)))) \
		$(eval GOARCH_T := $(word 2,$(subst /, ,$(target)))) \
		$(eval EXT      := $(if $(filter windows,$(GOOS_T)),.exe,)) \
		echo "[*] Building $(GOOS_T)/$(GOARCH_T)..."; \
		CGO_ENABLED=0 GOOS=$(GOOS_T) GOARCH=$(GOARCH_T) go build \
			-ldflags "-X github.com/papa0four/orkowatch/cmd/commands.Version=$(VERSION)" \
			-o $(BUILD_DIR)/$(BINARY_NAME)_$(GOOS_T)_$(GOARCH_T)$(EXT) \
			$(MAIN_PKG) && echo "[+] Done: $(BINARY_NAME)_$(GOOS_T)_$(GOARCH_T)$(EXT)"; \
	)
	@echo "[+] All targets built."

# -----------------------------------------------------------------------------
# Install / Uninstall
# -----------------------------------------------------------------------------

## install: build and install the binary to $(INSTALL_DIR) - Unix/WSL only
install: build
ifeq ($(GOOS), windows)
	@echo "[-] install is not supported on native Windows or Git Bash outside WSL."
	@echo "    Use scripts/windows/install.ps1 instead, or run this target from WSL."
	@exit 1
else
	@echo "[*] Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	$(SUDO) cp $(BINARY) $(INSTALL_DIR)/$(BINARY_NAME)
	$(SUDO) chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "[+] $(BINARY_NAME) installed. Run '$(BINARY_NAME) --help' to verify."
endif

## uninstall: remove the installed binary from $(INSTALL_DIR) - Unix/WSL only
uninstall:
ifeq ($(GOOS), windows)
	@echo "[-] uninstall is not supported on native Windows or Git Bash outside WSL."
	@echo "    Use scripts/windows/uninstall.ps1 instead, or run this target from WSL."
	@exit 1
else
	@echo "[*] Removing $(BINARY_NAME) from $(INSTALL_DIR)..."
	$(SUDO) rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "[+] $(BINARY_NAME) removed."
endif

# -----------------------------------------------------------------------------
# Quality Gates (mirror CI pipeline)
# -----------------------------------------------------------------------------

## fmt: format all Go source files in place
fmt:
	@echo "[*] Formatting Go source files..."
	@gofmt -w .
	@echo "[+] Formatting complete."

## fmt-check: verify Go formatting without modifying files (mirrors CI)
fmt-check:
	@echo "[*] Checking Go formatting..."
	@if [ "$$(gofmt -l . | wc -l)" -gt 0 ]; then \
		echo "[-] The following files are not formatted correctly:"; \
		gofmt -l .; \
		exit 1; \
	fi
	@echo "[+] All files correctly formatted."

## vet: run go vet across all packages
vet:
	@echo "[*] Running go vet..."
	@go vet ./...
	@echo "[+] vet passed."

## lint: run golangci-lint (requires golangci-lint to be installed)
lint:
	@echo "[*] Running golangci-lint..."
	@golangci-lint run --timeout=5m
	@echo "[+] lint passed."

## test: run all tests with race detector
test:
	@echo "[*] Running tests..."
	@go test -race -count=1 ./...
	@echo "[+] All tests passed."

## makefile-check: validate Makefile syntax and style
makefile-check:
	@echo "[*] Validating Makefile syntax..."
	@$(MAKE) -f Makefile help > /dev/null && echo "[+] Makefile syntax OK." || (echo "[-] Makefile syntax error." && exit 1)
	@echo "[*] Validating Makefile execution graph..."
	@$(MAKE) -n build > /dev/null && echo "[+] Makefile dry run OK." || (echo "[-] Makefile dry run failed." && exit 1)
	@echo "[*] Running checkmake..."
	@checkmake Makefile
	@echo "[+] checkmake passed."

## check: run all quality gates in sequence (fmt-check, vet, lint, test)
check: makefile-check fmt-check vet lint test
	@echo ""
	@echo "[+] All quality gates passed."

# -----------------------------------------------------------------------------
# Shell Script Linting (mirrors CI shell-lint job)
# Requires: shfmt, shellcheck
# -----------------------------------------------------------------------------

## shell-lint: lint and format-check all shell scripts in scripts/linux/
shell-lint:
	@echo "[*] Checking shell script formatting with shfmt..."
	@shfmt -ln bash -d scripts/linux/
	@echo "[*] Running shellcheck..."
	@shellcheck --severity=warning --shell=bash scripts/linux/*.sh
	@echo "[+] Shell lint passed."

# -----------------------------------------------------------------------------
# PowerShell Linting (mirrors CI ps-lint job)
# Requires: PSScriptAnalyzer (Windows / pwsh only)
# Run from a PowerShell prompt — this target is a no-op on Linux/macOS
# -----------------------------------------------------------------------------

## ps-lint: lint PowerShell scripts in scripts/windows/ (Windows/pwsh only)
ps-lint:
ifeq ($(GOOS), windows)
	@echo "[*] Running PSScriptAnalyzer..."
	@powershell -Command "\
		\$$results = Invoke-ScriptAnalyzer \
			-Path ./scripts/windows \
			-Recurse \
			-Severity Error,Warning \
			-Settings ./scripts/windows/.psscriptanalyzerconfig; \
		if (\$$results) { \
			\$$results | Format-Table RuleName,Severity,ScriptName,Line,Message -AutoSize; \
			exit 1; \
		} \
		Write-Host '[+] PSScriptAnalyzer passed.'"
else
	@echo "[*] ps-lint skipped — not running on Windows."
	@echo "    Run this target from a Windows PowerShell prompt to lint PS1 scripts."
endif

# -----------------------------------------------------------------------------
# Documentation
# -----------------------------------------------------------------------------

## docs: serve godoc locally at http://localhost:6060
docs:
	@echo "[*] Starting godoc server at http://localhost:6060"
	@echo "    Press Ctrl+C to stop."
	@godoc -http=:6060

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------

## clean: remove all build artifacts
clean:
	@echo "[*] Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	@echo "[+] Clean complete."

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------

## help: list all available targets with descriptions
help:
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Build:"
	@grep -E '^## (build|build-all|install|uninstall):' $(MAKEFILE_LIST) | sed 's/## /  /'
	@echo ""
	@echo "Quality Gates:"
	@grep -E '^## (fmt|fmt-check|vet|lint|test|check):' $(MAKEFILE_LIST) | sed 's/## /  /'
	@echo ""
	@echo "Linting:"
	@grep -E '^## (shell-lint|ps-lint):' $(MAKEFILE_LIST) | sed 's/## /  /'
	@echo ""
	@echo "Documentation:"
	@grep -E '^## docs:' $(MAKEFILE_LIST) | sed 's/## /  /'
	@echo ""
	@echo "Utilities:"
	@grep -E '^## (clean|help):' $(MAKEFILE_LIST) | sed 's/## /  /'
	@echo ""