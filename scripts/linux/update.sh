#!/bin/bash
set -euo pipefail

# orkowatch update script
# For end-users only. Checks for a newer release and updates if one exists.
# Developers and contributors should use: git pull && make install

GITHUB_REPO="papa0four/orkowatch"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="owatch"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
BACKUP_PATH="${BINARY_PATH}.bak"

# Check for root user in current session
if [ "$(id -u)" -eq 0 ]; then
	SUDO=""
else
	SUDO="sudo"
fi

DOWNLOADER=""

# Assumes that if orkowatch is installed, a downloader
# almost certainly exists already. If not, prompt user to
# manually install after exit.
ensure_downloader() {
	if command -v curl >/dev/null 2>&1; then
		DOWNLOADER="curl"
	elif command -v wget >/dev/null 2>&1; then
		DOWNLOADER="wget"
	else
		echo "[-] Neither curl nor wget found. Cannot proceed with update."
		echo "[!] Manually install curl or wget and try again."
		exit 1
	fi
}

download() {
	local url="$1"
	local dest="$2"

	if [ "$DOWNLOADER" = "curl" ]; then
		curl -fsSL "$url" -o "$dest"
	else
		wget -q "$url" -O "$dest"
	fi
}

fetch_text() {
	local url="$1"

	if [ "$DOWNLOADER" = "curl" ]; then
		curl -fsSL "$url"
	else
		wget -qO- "$url"
	fi
}

# Maps uname -m output to Go's architecture naming convention
detect_arch() {
	case "$(uname -m)" in
	x86_64) echo "amd64" ;;
	aarch64) echo "arm64" ;;
	armv7l) echo "armv6l" ;;
	i386 | i686) echo "386" ;;
	*)
		echo "[-] Unsupported architecture: $(uname -m)" >&2
		exit 1
		;;
	esac
}

# Returns the version string of the currently installed binary
get_installed_version() {
	"$BINARY_PATH" --version 2>/dev/null | awk '{print $NF}' || echo ""
}

# Resolves the latest release tag from the GitHub API
get_latest_version() {
	local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
	local version

	version=$(fetch_text "$api_url" | grep '"tag_name"' | cut -d'"' -f4)
	echo "$version"
}

# Backs up the current binary before attempting replacement
backup_binary() {
	"$SUDO" cp "$BINARY_PATH" "$BACKUP_PATH"
}

# Restores the backed up binary — called on any failure after backup
restore_binary() {
	if [ -f "$BACKUP_PATH" ]; then
		echo "[!] Restoring previous version..."
		"$SUDO" mv "$BACKUP_PATH" "$BINARY_PATH"
		"$SUDO" chmod +x "$BINARY_PATH"
		echo "[+] Previous version restored."
	fi
}

# Downloads the specified release and replaces the installed binary
update_binary() {
	local version="$1"
	local arch
	arch=$(detect_arch)

	local binary_filename="${BINARY_NAME}_linux_${arch}"
	local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/${binary_filename}"
	local tmp_binary
	tmp_binary=$(mktemp)

	echo "[*] Downloading orkowatch $version (linux/$arch)..."

	download "$download_url" "$tmp_binary" || {
		echo "[-] Failed to download update."
		echo "    URL: $download_url"
		echo "    Check your internet connection or verify the release exists."
		rm -f "$tmp_binary"
		restore_binary
		exit 1
	}

	"$SUDO" mv "$tmp_binary" "$BINARY_PATH" || {
		echo "[-] Failed to replace binary."
		rm -f "$tmp_binary"
		restore_binary
		exit 1
	}

	"$SUDO" chmod +x "$BINARY_PATH"
}

# Confirms the installed binary reports the expected version after update
confirm_update() {
	local expected="$1"
	local actual
	actual=$("$BINARY_PATH" --version 2>/dev/null | awk '{print $NF}')

	if [ "$actual" != "$expected" ]; then
		echo "[-] Update verification failed."
		echo "    Expected: $expected"
		echo "    Got:      $actual"
		restore_binary
		exit 1
	fi

	# Backup is no longer needed once update is confirmed
	"$SUDO" rm -f "$BACKUP_PATH"

	echo "[+] orkowatch updated to $actual"
	echo "    Run 'owatch --help' to see available commands."
}

main() {
	echo "============================================="
	echo "  orkowatch Updater"
	echo "============================================="
	echo ""

	ensure_downloader

	# Confirm orkowatch is installed before proceeding
	if [ ! -f "$BINARY_PATH" ]; then
		echo "[-] orkowatch is not installed."
		echo "    Run install.sh to install orkowatch first."
		exit 1
	fi

	local installed_version
	installed_version=$(get_installed_version)

	# Dev builds are not managed by this script
	if [[ "$installed_version" != v* ]]; then
		echo "[!] orkowatch $installed_version appears to be a developer build."
		echo "    This script manages release versions only."
		echo "    To update a developer build: git pull && make install"
		exit 0
	fi

	echo "[*] Installed version: $installed_version"

	local latest_version
	latest_version=$(get_latest_version)

	# No release exists yet
	if [ "$latest_version" = "" ]; then
		echo "[!] No stable release found for ${GITHUB_REPO}."
		echo "    Visit https://github.com/${GITHUB_REPO}/releases for status."
		exit 0
	fi

	echo "[*] Latest version:    $latest_version"

	# Already on latest
	if [ "$installed_version" = "$latest_version" ]; then
		echo "[+] orkowatch is already up to date."
		exit 0
	fi

	# Offer the update
	echo ""
	echo "[!] A new version is available: $latest_version"
	read -rp "    Update orkowatch from $installed_version to $latest_version? (y/n) " -n 1
	echo ""

	if [[ ! $REPLY =~ ^[Yy]$ ]]; then
		echo "[*] Update declined. Staying on $installed_version."
		exit 0
	fi

	backup_binary
	update_binary "$latest_version"
	confirm_update "$latest_version"
}

main
