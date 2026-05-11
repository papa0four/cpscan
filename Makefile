# =============================================================================
# cpscan Makefile
# Developer-facing build, install, and cleanup targets.
# Intended for use on Linux, macOS, and WSL.
#
# install/uninstall are Unix-oriented and target /usr/local/bin.
# On native Windows or Git Bash outside WSL, use windows/install.ps1 instead.
# =============================================================================

BINARY_NAME := cpscan
BUILD_DIR   := bin
MAIN_PKG    := ./cmd/cpscan/main.go
INSTALL_DIR := /usr/local/bin

# Detect current platform for binary naming and install behavior
GOOS    := $(shell go env GOOS)
GOARCH  := $(shell go env GOARCH)

# Append .exe on Windows
ifeq ($(GOOS), windows)
	BINARY := $(BUILD_DIR)/$(BINARY_NAME).exe
else
	BINARY := $(BUILD_DIR)/$(BINARY_NAME)
endif

# Use sudo only when not already in running as root
SUDO := $(shell [ "$$(id -u)" -eq 0 ] && echo "" || echo "sudo")

# ================================================================================
# Targets
# ================================================================================

.PHONY: build install uninstall clean help

## build: compile the binary for the current platform into bin/
build:
	@echo "[*] Building $(BINARY_NAME) ($(GOOS)/$(GOARCH))..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -o $(BINARY) $(MAIN_PKG)
	@echo "[+] Binary written to $(BINARY)"

## install: build and install the binary to $(INSTALL_DIR) - Unix/WSL only
install: build
ifeq ($(GOOS), windows)
	@echo "[-] install is not support on native Windows or Git Bash outside WSL."
	@echo "    Use windows/install.ps1 instead, or run this target from WSL."
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
	@echo "    Use windows/uninstall.ps1 instead, or run this target from WSL."
	@exit 1
else
	@echo "[*] Removing $(BINARY_NAME) from $(INSTALL_DIR)..."
	$(SUDO) rm -f $(INSTALL_DIR)$(BINARY_NAME)
	@echo "[+] $(BINARY_NAME) removed."
endif

## clean: remove all build artifacts
clean:
	@echo "[*] Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	@echo "[+] Clean complete."

## help: list available targets
help:
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
	@echo ""