#!/bin/bash
set -euo pipefail

# =============================================================================
# 'orkowatch' install script
# Downloads the latest pre-built release binary from GitHub Releases.
# Supported distros: Ubuntu, Debian, Fedora, RHEL/CentOS/Rocky, Arch,
#                    openSUSE, Alpine
# Supported package managers: apt, dnf/yum, pacman, zypper, and apk-based distros.
# =============================================================================

GITHUB_REPO="papa0four/orkowatch"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="owatch"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"

# Check for root user in current session
if [ "$(id -u)" -eq 0 ]; then
	SUDO=""
else
	SUDO="sudo"
fi

# =============================================================================
# Needed only if the host lacks both curl and wget
# =============================================================================

PKG_MANAGER=""

detect_package_manager() {
	if command -v apt-get >/dev/null 2>&1; then
		PKG_MANAGER="apt"
	elif command -v dnf >/dev/null 2>&1; then
		PKG_MANAGER="dnf"
	elif command -v yum >/dev/null 2>&1; then
		PKG_MANAGER="yum"
	elif command -v pacman >/dev/null 2>&1; then
		PKG_MANAGER="pacman"
	elif command -v zypper >/dev/null 2>&1; then
		PKG_MANAGER="zypper"
	elif command -v apk >/dev/null 2>&1; then
		PKG_MANAGER="apk"
	else
		echo "[-] No supported package manager found."
		echo "    Please install curl or wget manually and re-run this script."
		exit 1
	fi
}

install_package() {
	local pkg="$1"
	echo "[*] Installing $pkg..."
	case "$PKG_MANAGER" in
	apt) "$SUDO" apt-get update -y && "$SUDO" apt-get install -y "$pkg" ;;
	dnf) "$SUDO" dnf install -y "$pkg" ;;
	yum) "$SUDO" yum install -y "$pkg" ;;
	pacman) "$SUDO" pacman -Sy --noconfirm "$pkg" ;;
	zypper) "$SUDO" zypper install -y "$pkg" ;;
	apk) "$SUDO" apk update && "$SUDO" apk add "$pkg" ;;
	esac
}

# =============================================================================
# Downloader:
#      - tries curl
#      - falls back to wget
#      - installs curl if neither is present
# =============================================================================

DOWNLOADER=""

ensure_downloader() {
	if command -v curl >/dev/null 2>&1; then
		DOWNLOADER="curl"
	elif command -v wget >/dev/null 2>&1; then
		DOWNLOADER="wget"
	else
		echo "[!] Neither curl nor wget found. Attempting to install curl..."
		detect_package_manager
		install_package "curl"
		DOWNLOADER="curl"
	fi
	echo "[*] Using $DOWNLOADER for downloads."
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

# =============================================================================
# Architecture Detection
# Maps uname -m output to Go's architecture naming convention
# =============================================================================

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

# =============================================================================
# Resolve the latest GitHub release tag.
# GoReleaser injects version metadata into release binaries, or
# Version == 'dev' during updates and development.
# =============================================================================

resolve_version() {
	local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
	local response
	local version

	response=$(fetch_text "$api_url")

	if [ "$response" = "" ]; then
		echo "[-] Failed to reach GitHub API." >&2
		echo "    Check your internet connection and try again." >&2
		exit 1
	fi

	version=$(fetch_text "$api_url" | grep '"tag_name"' | cut -d '"' -f4)

	if [ "$version" = "" ]; then
		echo "[-] No releases found for ${GITHUB_REPO}." >&2
		echo "    This project may not have a stable release yet." >&2
		echo "    Visit https://github.com/${GITHUB_REPO}/releases for status." >&2
		exit 1
	fi

	echo "$version"
}

# =============================================================================
# Verify the release asset against GoReleaser checksums.txt when available
# =============================================================================

verify_checksum() {
	local version="$1"
	local binary_filename="$2"
	local binary_path="$3"

	local checksum_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/checksums.txt"
	local tmp_checksums
	tmp_checksums=$(mktemp)

	echo "[*] Downloading checksums..."
	download "$checksum_url" "$tmp_checksums" || {
		echo "[!] Checksum file not available for this release — skipping verification."
		rm -f "$tmp_checksums"
		return 0
	}

	echo "[*] Verifying checksum..."
	local expected
	expected=$(grep "${binary_filename}$" "$tmp_checksums" | awk '{print $1}')
	rm -f "$tmp_checksums"

	if [ "$expected" = "" ]; then
		echo "[!] No checksum entry found for $binary_filename — skipping verification."
		return 0
	fi

	local actual
	actual=$(sha256sum "$binary_path" | awk '{print $1}')

	if [ "$actual" != "$expected" ]; then
		echo "[-] Checksum mismatch for $binary_filename"
		echo "    Expected: $expected"
		echo "    Actual:   $actual"
		rm -f "$binary_path"
		exit 1
	fi

	echo "[+] Checksum verified."
}

# =============================================================================
# Download the mathcing release asset and install into INSTALL_DIR
# =============================================================================

install_binary() {
	local arch
	arch=$(detect_arch)

	local version
	version=$(resolve_version)

	# GoReleaser default naming convention: orkowatch_linux_amd64
	local binary_filename="${BINARY_NAME}_linux_${arch}"
	local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/${binary_filename}"

	echo "[*] Downloading orkowatch $version (linux/$arch)..."

	local tmp_binary
	tmp_binary=$(mktemp)

	download "$download_url" "$tmp_binary" || {
		echo "[-] Failed to download binary."
		echo "    URL: $download_url"
		echo "    Check your internet connection or verify the release exists."
		rm -f "$tmp_binary"
		exit 1
	}

	verify_checksum "$version" "$binary_filename" "$tmp_binary"

	"$SUDO" mv "$tmp_binary" "$BINARY_PATH"
	"$SUDO" chmod +x "$BINARY_PATH"

	echo "[+] orkowatch $version installed to $BINARY_PATH"
}

# =============================================================================
# Confirm the installed binary is on PATH
# =============================================================================

verify_install() {
	echo "Verifying orkowatch installation..."
	echo ""
	if command -v "$BINARY_NAME" >/dev/null 2>&1; then
		echo ""
		echo "[+] Verification successful."
		"$BINARY_NAME" --version
		echo "    Run 'owatch --help' to see available commands."
	else
		echo "[-] Verification failed: $BINARY_NAME not found in PATH."
		echo "    The binary is at $BINARY_PATH"
		echo "    Try opening a new terminal or running: source /etc/profile"
		exit 1
	fi
}

# =============================================================================
# GoReleaser default naming convention: 'orkowatch_linux_amd64'
# =============================================================================

main() {
	echo "============================================="
	echo "  orkowatch Installer"
	echo "============================================="
	echo ""

	if [ -f "$BINARY_PATH" ]; then
		echo "[!] orkowatch is already installed at $BINARY_PATH"
		echo "    Run uninstall.sh to remove it or update.sh to check for a newer version."
		exit 0
	fi

	ensure_downloader
	install_binary
	verify_install
}

main
