#!/bin/sh

# Define the project root and installation directory
PROJECT_ROOT="$HOME/cpscan"
INSTALL_DIR="$HOME/.local/bin"

# Check if Go is installed
if ! command -v go >/dev/null 2>&1; then
    echo "Go is not installed. Installing the latest version..."
    wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    # Persist PATH change for all shells
    echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.profile"
    echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.bashrc"
    echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.zshrc"
else
    echo "Go is already installed."
fi

# Ensure PROJECT_ROOT exists and navigate there
if [ ! -d "$PROJECT_ROOT" ]; then
    echo "Error: Project root $PROJECT_ROOT does not exist. Exiting."
    exit 1
fi
cd "$PROJECT_ROOT"

# # Initialize and tidy Go modules (fetch dependencies)
# echo "Initializing and tidying Go modules..."
# go mod init 2>/dev/null || true  # Run init if no go.mod exists
# go mod tidy

# Initialize Go module if go.mod does not exist
if [ ! -f "go.mod" ]; then
    echo "Initializing Go module for cpscan..."
    go mod init github.com/papa0four/cpscan
fi

# Fetch dependencies and tidy up
echo "Tidying Go modules..."
go mod tidy

# Build the executable
echo "Building the cpscan executable..."
go build -o cpscan ./cmd/main.go
if [ $? -ne 0 ]; then
    echo "Build failed. Check for errors in Go files or dependencies."
    exit 1
fi

# Move the executable to the installation directory
mkdir -p "$INSTALL_DIR"
mv cpscan "$INSTALL_DIR"
echo "cpscan installed successfully to $INSTALL_DIR."

# Add INSTALL_DIR to PATH for all future sessions
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$HOME/.profile"
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$HOME/.bashrc"
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$HOME/.zshrc"
fi

# Source the appropriate profile file based on the current shell
if [ -n "$ZSH_VERSION" ]; then
    . "$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ]; then
    . "$HOME/.bashrc"
else
    . "$HOME/.profile"
fi

echo "Installation complete. You can now run cpscan from the command line."

