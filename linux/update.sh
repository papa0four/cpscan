#!/bin/bash

# Define variables
PROJECT_DIR="$HOME/cpscan"
GITHUB_URL="https://github.com/papa0four/cpscan.git"
INSTALL_DIR="$HOME/.local/bin"

# Function to check if Go is installed
check_go_installed() {
    if command -v go >/dev/null 2.&1; then
        echo "Go found in PATH."
        return 0
    elif [ -x "/usr/local/go/bin/go" ]; then
        echo "Go binary found in /usr/local/go/bin."
        export PATH=$PATH:/usr/local/go/bin
        return 0
    elif [ -d "/usr/local/bin" ]; then
        echo "Go installation directory found, but PATH is not set."
        export PATH=$PATH:/usr/local/go/bin
        return 0
    else
        echo "Go is not installed or not properly configured."
        return 1
    fi
}

# Check if Go is installed
if ! check_go_installed; then
    echo "Go is required for cpscan. Please installed Go (>=v1.23.2) before running the update script."
    exit 1
fi

# Verify Go functionality
if ! go version >/dev/null 2>&1; then
    echo "Error: Go binary is not functional. Please reinstall Golang (>=v1.23.2)."
    exit 1
fi

# Pull the latest changes from the GitHub repo
if [ -d "$PROJECT" ]; then
    echo "Updating cpscan from the GitHub repository..."
    cd "$PROJECT_DIR" || exit
    git pull origin main
else
    echo "Cloning cpscan repository..."
    git clone "$GITHUB_URL" "$PROJECT_DIR"
    cd "$PROJECT_DIR" || exit
fi

# Update dependencies
echo "Tidying Go modules..."
go mod tidy

# Build the exectuable
echo "Rebuilding the cpscan executable..."
go build -o cpscan ./cmd/main.go
if [ $? -ne 0 ]; then
    echo "Build failed. Check for errors in the code or dependencies."
    exit 1
fi

# Install the exectuable
mkdir -p "$INSTALL_DIR"
mv cpscan "$INSTALL_DIR"
echo "cpscan updated successfully and installed to $INSTALL_DIR."

# Ensure the binary path is in the PATH
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "Adding $INSTALL_DIR to PATH..."
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$HOME/.bashrc"
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$HOME/.zshrc"
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$HOME/.profile"
    source "$HOME/.bashrc" 2>/dev/null || source "$HOME/.zshrc" 2>/dev/null || source "$HOME/.profile" 2>/dev/null
fi

echo "Update complete. You can now run cpscan with the latest features."
