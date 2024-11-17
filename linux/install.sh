#!/bin/bash

# Define installation directories
PROJECT_REPO="https://github.com/papa0four/cpscan/archive/refs/heads/main.zip"
PROJECT_ROOT="$HOME/cpscan"
INSTALL_DIR="$HOME/.local/bin"
GO_VERSION="1.23.2"
REQUIRED_PACKAGES=(
    "wget"
    "unzip"
    "git"
    "build-essential"
)

# Function to check Go version compatibility
check_go_version() {
    local current_version=""
    if command -v go >/dev/null 2>&1; then
        current_version=$(go version | awk '{print$3}' | sed 's/go//')
        echo "Detected Go version: $current_version"

        # Parse version numbers
        local required_major=$(echo $GO_VERSION | cut -d. -f1)
        local required_minor=$(echo $GO_VERSION | cut -d. -f2)
        local required_patch=$(echo $GO_VERSION | cut -d. -f3)
        
        local current_major=$(echo $current_version | cut -d. -f1)
        local current_minor=$(echo $current_version | cut -d. -f2)
        local current_patch=$(echo $current_version | cut -d. -f3)

        if [ "$current_version" != "$GO_VERSION" ]; then
            echo "Warning: Current Go version ($current_version) differs from recommended version ($GO_VERSION)"
            read -p  "Continue with installation? (y/n)" -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
}

 #Function to check and install required system packages
 install_required_packages() {
    echo "Checking required system packages..."
    for package in "${REQUIRED_PACKAGES[@]}"; do
        if ! command -v "$package" >/dev/null 2>&1; then
            echo "Installing $package..."
            sudo apt-get install -y "$package" || sudo yum install -y "$package" || {
                echo "Failed to install $package. Please install it manually."
                exit 1
            }
        fi
    done
 }

# Function to add a path to PATH persistently
add_to_path() {
    local path_entry="$1"
    local shell_rc="$HOME/.$(basename $SHELL)rc"
    local profile="$HOME/.profile"

    if [ -f "$shell_rc" ]; then
        if ! grep -q "export PATH=.*$path_entry" "$shell_rc"; then
            echo "export PATH=\$PATH:$path_entry" >> "$shell_rc"
        fi
    fi

    if [ -f "$profile" ] && ! grep -q "export PATH=.*$path_entry" "$profile"; then
        echo "export PATH=\$PATH:$path_entry" >> "$profile"
    fi
}

# Install Go if not installed
install_go() {
    if ! command -v go >/dev/null 2>&1; then
        echo "Go is not installed. Installing Go version $GO_VERSION..."
        local os_arch="linux-amd64"
        local go_url="https://go.dev/dl/go${GO_VERSION}.${os_arch}.tar.gz"

        wget "$go_url" -O "/tmp/go.tar.gz" || {
            echo "Failed to download Go. Please check your internet connection."
            exit 1
        }

        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/go.tar.gz"
        rm "/tmp/go.tar.gz"

        add_to_path "/usr/local/go/bin"
        export PATH=$PATH:/usr/local/go/bin

        echo "Go $GO_VERSION installed_successfully."
    else
        check_go_version
    fi
}

# Function to setup the project
setup_project() {
    echo "Setting up cpscan project..."

    mkdir -p "$INSTALL_DIR"

    local temp_dir=$(mktemp -d)
    wget -q -O "$temp_dir/cpscan.zip" "$PROJECT_REPO" || {
        echo "Failed to download project."
        rm -rf "$temp_dir"
        exit 1
    }

    unzip -q "$temp_dir/cpscan.zip" -d "$temp_dir" || {
        echo "Failed to extract project files."
        rm -rf "$temp_dir"
        exit 1
    }

    rm -rf "$PROJECT_ROOT"
    mv "$temp_dir/cpscan-main" "$PROJECT_ROOT"
    rm -rf "$temp_dir"

    cd "$PROJECT_ROOT" || {
        echo "Failed to enter project directory."
        exit 1
    }

    echo "Initializing Go modules..."
    go mod init github.com/papa0four/cpscan

    # Install required dependencies
    go get gopkg.in/yaml.v3
    go get github.com/spf13/cobra
    go mod tidy

    echo "Building cpscan..."
    CGO_ENABLED=0 go build -o "$INSTALL_DIR/cpscan" ./cmd/cpscan/main.go || {
        echo "Build failed. Please check the error messages above."
        exit 1
    }

    chmod +x "$INSTALL_DIR/cpscan"
    add_to_path "$INSTALL_DIR"
}

# Main installation process
main() {
    echo "Starting cpscan installation..."

    install_required_packages
    install_go
    setup_project

    if [ -n "$BASH_VERSION" ]; then
        source "$HOME/.bashrc"
    elif [ -n "$ZSH_VERSION" ]; then
        source "$HOME/.zshrc"
    else
        source "$HOME/.profile"
    fi

    if command -v cpscan >/dev/null 2>&1; then
        echo "Installation successful! Try running 'cpscan --help' for usage information."
        cpscan --version
    else
        echo "Installation seems to have failed. Please check the error message above."
        exit 1
    fi
}

# Run the installation
main