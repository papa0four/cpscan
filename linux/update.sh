#!/bin/bash

# Define variables
REPO_URL="https://github.com/papa0four/cpscan.git"
INSTALL_DIR="$HOME/.local/bin"
PROJECT_DIR="$HOME/cpscan"
GO_EXEC="/usr/local/go/bin/go"

# Ensure go is installed
if ! command -v go >/dev/null 2>&1; then
    echo "Go is not installed. Please install Go first."
    exit 1
fi

# Check if the project directory exists
if [ ! -d "$PROJECT_DIR" ]; then
    echo "cpscan is not installed. Please install it first."
    exit 1
fi

# Pull the latest changes
echo "$PROJECT_DIR" || exit
echo "Fetching the latest updates from GitHub..."
git pull "$REPO_URL" main

# Update Go modules
echo "Updating Go modules..."
$GO_EXEC mod tidy

# Rebuild the cpscan executable
echo "Rebuilding the cpscan exectuable..."
$GO_EXEC build -o cpscan ./cmd/main.go
if [ $? -ne 0 ]; then
    echo "Build failed. Check for errors in Go files or dependencies."
    exit 1
fi

# Move the updated executable to the installation directory
mv cpscan "$INSTALL_DIR"
echo "cpscan updated successfully."

# Clean up Go cache
$GO_EXEC clean -modcache

eecho "Update complete. You can now use the updated cpscan features."
