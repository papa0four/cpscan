#!/bin/bash
set -euo pipefail

# =============================================================================
# cpscan uninstall script
# Completely removes cpscan from the target machine.
# =============================================================================

INSTALL_DIR="/usr/local/bin"
BINARY_NAME="cpscan"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"

# Check for root user in current session
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# =============================================================================
# Verify Target
# Confirm cpscan is actually installed before attempting removal
# =============================================================================

verify_and_remove() {
    if [ ! -f "$BINARY_PATH" ]; then
        echo "[!] cpscan is not installed at $BINARY_PATH"
        echo "    Nothing to uninstall."
        exit 0
    fi

    echo "[*] Removing cpscan from $BINARY_PATH..."
    $SUDO rm -f "$BINARY_PATH"
}

# =============================================================================
# Verify Removal
# Confirms no trace of the binary remains and cpscan is no longer resolvable
# =============================================================================

confirm_removal() {
    echo "[*] Verifying removal..."

    if [ -f "$BINARY_PATH" ]; then
        echo "[-] Uninstall failed: binary still present at $BINARY_PATH"
        exit 1
    fi

    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        echo "[-] Uninstall failed: cpscan is still resolvable in PATH at:"
        echo "    $(command -v "$BINARY_NAME")"
        echo "    A second installation may exist at this location."
        exit 1
    fi

    echo "[+] Verification successful. cpscan has been completely removed."
}

main() {
    echo "============================================="
    echo "  cpscan Uninstaller"
    echo "============================================="
    echo ""
 
    verify_and_remove
    confirm_removal
 
    echo ""
    echo "[+] Uninstall complete."
}

main
