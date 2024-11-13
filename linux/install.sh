#!/bin/bash

# Define installation directories
PROJECT_REPO="https://github.com/papa0four/cpscan/archive/refs/heads/main.zip"
PROJECT_ROOT="$HOME/cpscan"
INSTALL_DIR="$HOME/.local/bin"

# Function to add a path to PATH persistently
add_to_path() {
    local path_entry="$1"
    local profile_files=("$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc")

    if ! echo "$PATH" | grep -q "$path_entry"; then
        for profile in "${profile_files[@]}"; do
            echo "export PATH=\$PATH:$path_entry" >> "$profile"
        done
    fi
}

# Install Go if not installed
if ! command -v go >/dev/null 2>&1; then
    echo "Go is not installed. Installing the latest version..."
    wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz -P "$HOME"
    sudo tar -C /usr/local -xzf "$HOME/go1.23.2.linux-amd64.tar.gz"
    rm "$HOME/go1.23.2.linux-amd64.tar.gz"
    export PATH=$PATH:/usr/local/go/bin
    add_to_path "/usr/local/go/bin"
    . "$HOME/.profile" # Source profile to make Go available in the session
else
    echo "Go is already installed."
fi

# Ensure installation directory exists
mkdir -p "$INSTALL_DIR"

# Download cpscan project from GitHub
echo "Downloading cpscan project from GitHub..."
temp_dir=$(mktemp -d)
wget -q -O "$temp_dir/cpscan.zip" "$PROJECT_REPO"

# Unzip the project and check if extraction succeeded
unzip -q "$temp_dir/cpscan.zip" -d "$temp_dir"
if [ ! -d "$temp_dir/cpscan-main" ]; then
    echo "Error: Failed to unzip project files. Exiting."
    rm -rf "$temp_dir"
    exit 1
fi

# Move project files to PROJECT_ROOT
rm -rf "$PROJECT_ROOT"  # Remove any existing project directory
mv "$temp_dir/cpscan-main" "$PROJECT_ROOT"
rm -rf "$temp_dir"

# Change to project root directory
cd "$PROJECT_ROOT" || { echo "Failed to enter project directory. Exiting."; exit 1; }

# Initialize Go modules and tidy dependencies
echo "Initializing and tidying Go modules..."
go mod init github.com/papa0four/cpscan 2>/dev/null || true
go mod tidy

# Build the cpscan executable
echo "Building the cpscan executable..."
go build -o cpscan ./cmd/main.go
if [ $? -ne 0 ]; then
    echo "Build failed. Check for errors in Go files or dependencies."
    exit 1
fi

# Move the executable to the installation directory
mv cpscan "$INSTALL_DIR"
echo "cpscan installed successfully to $INSTALL_DIR."

# Add INSTALL_DIR to PATH for all future sessions
add_to_path "$INSTALL_DIR"

# Source the correct profile for immediate session use
if [ -n "$ZSH_VERSION" ]; then
    . "$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ]; then
    . "$HOME/.bashrc"
else
    . "$HOME/.profile"
fi

echo "Installation complete. You can now run 'cpscan' from the command line."

