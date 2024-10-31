# #!/bin/bash
#
# # Bash script to install dependencies and create 'cpscan' executable
#
# # Function to install Go if it's not installed
# install_go() {
#     echo "Go not found. Installing the latest version of Go..."
#     GO_VERSION="go1.23.2.linux-amd64.tar.gz"
#     wget https://go.dev/dl/$GO_VERSION -O /tmp/$GO_VERSION
#
#     # Remove any previous Go installations in /usr/local
#     sudo rm -rf /usr/local/go
#
#     # Extract and install Go
#     sudo tar -C /usr/local -xzf /tmp/$GO_VERSION
#
#     # clean up
#     rm /tmp/$GO_VERSION
# }
#
# # Check if Go is installed
# if ! command -v go &> /dev/null; then
#     install_go
# else
#     echo "Go is already installed."
# fi
#
# # Update PATH for the current session
# export PATH=$PATH:/usr/local/go/bin:$HOME/.local/bin
#
# # Permanently add Go to PATH in .bashrc or .zshrc
# if [[ "$SHELL" == */zsh ]]; then
#     PROFILE_FILE="$HOME/.zshrc"
# else
#     PROFILE_FILE="$HOME/.bashrc"
# fi
#
# # Add Go and cpscan to PATH if not already in the profile
# if ! grep -q 'export PATH=$PATH:/usr/local/go/bin:$HOME/.local/bin' "$PROFILE_FILE"; then
#     echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/.local/bin' >> "$PROFILE_FILE"
# fi
#
# # Local the project root and main.go
# PROJECT_ROOT=$(find "$(pwd)" -type f -name "main.go" -path "*/cmd/*" -exec dirname {} \; | head -n 1)
#
# if [[ -z "$PROJECT_ROOT" ]]; then
#     echo "Error: Could not locate 'cmd/main.go'. Please ensure you are in the project directory or that the project structure is correct."
#     exit 1
# fi
#
# # Build the executable
# cd "$PROJECT_ROOT" || exit
# echo "Building 'cpscan executable from project root at $PROJECT_ROOT..."
# go build -o cpscan ./cmd/main.go
#
# # Move 'cpscan' to a user-local bin directory (e.g. ~/.local/bin)
# mkdir -p "$HOME/.local/bin"
# mv cpscan "$HOME/.local/bin/"
#
# # refresh PATH in the current session
# hash -r
#
# echo "cpscan installed successfully. You can now run it using the 'cpscan' command."
# #!/bin/sh

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
    . "$HOME/.profile"  # Source the profile to apply changes
else
    echo "Go is already installed."
fi

# Ensure PROJECT_ROOT exists and navigate there
if [ ! -d "$PROJECT_ROOT" ]; then
    echo "Error: Project root $PROJECT_ROOT does not exist. Exiting."
    exit 1
fi
cd "$PROJECT_ROOT"

# Initialize and tidy Go modules (fetch dependencies)
echo "Initializing and tidying Go modules..."
go mod init 2>/dev/null || true  # Run init if no go.mod exists
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

# Ensure the installation directory is in the PATH for all shells
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$HOME/.profile"
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$HOME/.bashrc"
    echo "export PATH=\$PATH:$INSTALL_DIR" >> "$HOME/.zshrc"
    . "$HOME/.profile"  # Source the profile to apply changes
fi

To ensure that the new `PATH` update takes effect immediately, even in the current shell session, you can modify the script to explicitly source the relevant shell profile after adding `cpscan` to `PATH`. Here’s the modified installation script to achieve this:

```bash
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

# Initialize and tidy Go modules (fetch dependencies)
echo "Initializing and tidying Go modules..."
go mod init 2>/dev/null || true  # Run init if no go.mod exists
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

