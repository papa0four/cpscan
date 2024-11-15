# Define variables
$GitHubRepoURL = "https://github.com/papa0four/cpscan.git"
$TempDir = "$env:TEMP\cpscan_update"
$InstallDir = "$env:ProgramFiles\cpscan"
$BackupDir = "$env:ProgramFiles\cpscan_backup"

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script as Administrator."
    exit 1
}

# Step 1: Back up current installation
if (Test-Path $InstallDir) {
    Write-Output "Backing up current cpscan installation..."
    if (Test-Path $BackupDir) {
        Remove-Item -Recurse -Force $BackupDir
    }
    Rename-Item -Path $InstallDir -NewName $BackupDir
    Write-Output "Backup completed: $BackupDir"
} else {
    Write-Output "No existing cpscan installation found. Proceeding with fresh update..."
}

# Step 2: Clone the latest version from GitHub
Write-Output "Cloning the latest version of cpscan from GitHub..."
if (Test-Path $TempDir) {
    Remove-Item -Recurse -Force $TempDir
}
git clone $GitHubRepoURL $TempDir
if (-not (Test-Path "$TempDir\cmd\main.go")) {
    Write-Error "Failed to clone cpscan repository or repository is incomplete."
    exit 1
}

# Step 3: Build the updated version
Write-Output "Building the updated cpscan application..."
Push-Location $TempDir
if (!(Test-Path "go.mod")) {
    Write-Output "Initializing Go modules..."
    go mod init github.com/papa0four/cpscan
}
Write-Output "Tidying Go modules..."
go mod tidy
Write-Output "Compiling cpscan..."
go build -o cpscan.exe ./cmd/main.go
if (-not (Test-Path ".\cpscan.exe")) {
    Write-Error "Build failed: cpscan executable not created."
    Pop-Location
    exit 1
}
Pop-Location

# Step 4: Install the updated version
Write-Output "Installing the updated cpscan application..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Move-Item -Path "$TempDir\cpscan.exe" -Destination "$InstallDir\cpscan.exe" -Force

# Step 5: Update PATH environment variable
if (!(Get-Command "cpscan" -ErrorAction SilentlyContinue)) {
    $env:Path += ";$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $env:Path, "Machine")
    Write-Output "Updated PATH environment variable to include cpscan."
}

# Step 6: Clean up temporary files
Write-Output "Cleaning up temporary files..."
Remove-Item -Recurse -Force $TempDir

# Step 7: Confirm success and allow immediate execution
Write-Output "cpscan has been successfully updated and installed."
Write-Output "You can now run the updated cpscan using the 'cpscan' command in this terminal."
& "$InstallDir\cpscan.exe" version

