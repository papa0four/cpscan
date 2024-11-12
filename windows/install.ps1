# PowerShell Script to Install Dependencies and Create 'cpscan' Executable

# Ensure the script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "Please run this script as Administrator."
    Pause
    exit
}

# Capture the initial directory
$initialDir = Get-Location

# Check if Go is installed
$goExecutable = "$env:ProgramFiles\Go\bin\go.exe"
if (Test-Path $goExecutable) {
    Write-Output "Go is already installed."
} else {
    Write-Output "Go not found. Installing the latest version of Go..."
    
    # Download and install Go
    $url = "https://go.dev/dl/go1.23.2.windows-amd64.msi"
    $installerPath = "$env:TEMP\go-installer.msi"
    
    try {
        # Download installer
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($url, $installerPath)

        # Install Go
        Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait

        # Remove Installer
        Remove-Item -Path $installerPath -ErrorAction SilentlyContinue

        # Set Go environment variables
        $env:Path += ";$env:ProgramFiles\Go\bin"
        [Environment]::SetEnvironmentVariable("Path", $env:Path, "Machine")
        Write-Output "Go installation completed. Added Go to system Path."
    } catch {
        Write-Error "An error occurred during Go installation: $_"
        Pause
        exit 1
    }
}

# Reload environment variables for the current session
if (Test-Path "$env:ProgramFiles\Go\bin\go.exe") {
    & "$env:ProgramFiles\Go\bin\go.exe" version
} else {
    Write-Output "Go executable not found in expected path."
    Pause
    exit
}

# Prepare to build cpscan executable
Write-Output "Building 'cpscan' executable from project root directory."

# Set up a temporary directory to download and extract the cpscan project
$tempDir = "$env:TEMP\cpscan"
$zipURL = "https://github.com/papa0four/cpscan/archive/refs/heads/main.zip"
$zipPath = "$tempDir\cpscan.zip"
$projectRoot = "$tempDir\cpscan-main"

if (!(Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
}

try {
    # Download and extract the latest cpscan release
    Invoke-WebRequest -Uri $zipURL -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force
} catch {
    Write-Error "Failed to download and extract the cpscan project: $_"
    Pause
    exit 1
}

# Change to the extracted project root
Push-Location $projectRoot

# Initialize go.mod if not present
if (!(Test-Path "go.mod")) {
    Write-Output "Initializing Go modules..."
    & "$env:ProgramFiles\Go\bin\go.exe" mod init cpscan
}

# Add missing dependencies explicitly
Write-Output "Fetching necessary dependencies..."
try {
    & "$env:ProgramFiles\Go\bin\go.exe" get -u github.com/shirou/gopsutil/host
    & "$env:ProgramFiles\Go\bin\go.exe" get -u github.com/spf13/cobra
} catch {
    Write-Warning "Failed to fetch dependencies: $_"
}

# Tidy Go modules to finalize dependencies
Write-Output "Tidying Go modules..."
try {
    & "$env:ProgramFiles\Go\bin\go.exe" mod tidy
} catch {
    Write-Warning "Failed to tidy Go modules: $_"
}

# Build the executable
Write-Output "Building cpscan executable..."
& "$env:ProgramFiles\Go\bin\go.exe" build -o cpscan.exe ./cmd/main.go
if (!(Test-Path ".\cpscan.exe")) {
    Write-Output "Build failed: cpscan executable not created."
    Pause
    exit
}

# Move cpscan to Program Files Directory
$destinationPath = "$env:ProgramFiles\cpscan"
if (!(Test-Path $destinationPath)) {
    New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
}
Move-Item -Path ".\cpscan.exe" -Destination "$destinationPath\cpscan.exe" -Force

# Add cpscan to Path and set it permanently
$env:Path += ";$destinationPath"
[Environment]::SetEnvironmentVariable("Path", $env:Path, "Machine")
Write-Output "cpscan installed successfully."

# return to initial directory
Pop-Location

# Refresh environment variables for current session
$refreshEnv = @"
[System.Environment]::SetEnvironmentVariable('Path', [System.Environment]::GetEnvironmentVariable('Path','Machine'), 'Process')
"@
Invoke-Expression $refreshEnv

# Confirmation and Exit
Write-Output "`nInstallation complete! You can now run 'cpscan' from any command prompt or PowerShell session."
Pause

