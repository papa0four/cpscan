#!/bin/bash

# Define directories and paths
INSTALL_DIR="$HOME/.local/bin"
PROJECT_ROOT="$HOME/cpscan"
GO_PATH="/usr/local/go"

# Helper function to remove a path from profile files
remove_from_path() {
    local path_entry="$1"
    local profile_files=("$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc")

    for profile in "${profile_files[@]}"; do
        if grep -q "export PATH=\$PATH:$path_entry" "$profile"; then
            sed -i "\|export PATH=\$PATH:$path_entry|d" "$profile"
        fi
    done
}

# Remove cpscan project directory
if [ -d "$PROJECT_ROOT" ]; then
    echo "Removing cpscan executable from $INSTALL_DIR..."
    rm "$INSTALL_DIR/cpscan"
    echo "cpscan executable removed."
else
    echo "cpscan executable not found in $INSTALL_DIR."
fi

# Remove cpscan project directory
if [ -d "$PROJECT_ROOT" ]; then
    echo "Removing cpscan project directory at $PROJECT_ROOT..."
    rm -rf "$PROJECT_ROOT"
    echo "cpscan project directory removed."
else
    echo "cpscan project directory not found."
fi

# Remove cpscan from PATH in profile files
echo "Remove cpscan from path from environment variables..."
remove_from_path "$INSTALL_DIR"
echo "Environment variable cleanup complete."

# Prompt to remove Go installation
read -p "Would you like to remove Go from your system as well? NOTE: This is not required to remove 'cpscan'. (y/N): " remove_go
if [[ "$remove_go" =~ ^[Yy]$ ]]; then
    if [ -d "$GO_PATH" ]; then
        echo "Removing Go from $GO_PATH..."
        sudo rm -rf "$GO_PATH"
        remove_from_path "$GO_PATH/bin"
        echo "Go has been removed from the system."
    else
        echo "Go not found in $GO_PATH."
    fi
else
    echo "Skipping Go removal."
fi

# Final cleanup message
echo "cpscan has been successfully removed. Restart your shell session for changes to take effect."

