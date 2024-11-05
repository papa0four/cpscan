# Powershell Script to Install Dependencies and Create 'cpscan' Exectuable

# Check if the script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "Please run this script as Administrator."
    exit
}

# Check if Go is installed
$goExecutable = "$env:ProgramFiles\Go\bin\go.exe"
if (Test-Path $goExecutable) {
    Write-Output "Go is already installed."
} else {
    Write-Output "Go not found. Installing the latest version of Go..."
    # Download and install Go
    $url = "https://go.dev/dl/go1.23.2.windows-amd64.msi"
    $installerPath = "$env:TEMP\go-installer.msi"
    Invoke-WebRequest -Uri $url -OutFile $installerPath

    # Install Go
    Start-Process msiexec.exe -ArgumentsList "/i `"$installerPath`" /quiet /norestart" -Wait

    # Remove Installer
    Remove-Item -Path $installerPath

    # Set Go environment variables
    $env:Path += ";$env:ProgramFiles\Go\bin"
    [Environment]::SetEnvironmentVariable("Path", $env:Path, "Machine")
    Write-Output "Go installation completed. Added Go to system Path."
}

# Reload environment variables for current session
If (Test-Path "$env:ProgramFiles\Go\bin\go.exe") {
    & "$env:ProgramFiles\Go\bin\go.exe" version
} else {
    Write-Output "Go executable not found in expected path."
    exit
}

# Prepare to build cpscan executable
Write-Output "Building 'cpscan' executable from project root directory."

# Move to the root directory
cd "$PSScriptRoot\..\.."

# Initialize go.mod if not present
if (!(Test-Path "go.mod")) {
    Write-Output "Initializing Go modules..."
    & "$env:ProgramFiles\Go\bin\go.exe" mod init cpscan
}
& "$env:ProgramFiles\Go\bin\go.exe" mod tidy

# Build the executable
& "$env:ProgramFiles\Go\bin\go.exe" build -o cpscan.exe ./cmd/main.go
if (!(Test-Path ".\cpscan")) {
    Write-Output "Build failed: cpscan executable not created."
    exit
}

# Move cpscan to Program Files Directory
$destinationPath = "$env:ProgramFiles\cpscan"
if (!(Test-Path $destinationPath)) {
    New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
}
Move-Item -Path ".\cpscan.exe" -Desination "$destinationPath\cpscan.exe" -Force

# Add cpscan to Path and set it permanently
$env:Path += ";$destinationPath"
[Environment]::SetEnvironmentVariable("Path", $env:Path, "Machine")
Write-Output "cpscan installed successfully."

# Automatically restart the session
Write-Output "Restarting PowerShell session to apply changes

# Automatically restart the session
Write-Output "Restarting PowerShell session to apply changes

# Automatically restart the session
Write-Output "Restarting PowerShell session to apply changes..."

# Check if running in PowerShell or Command Prompt and restart accordingly
if ($Host.Name -eq "ConsoleHost") {
    # Close the current Powershell session and reopen
    Start-Process powershell.exe -ArgumentList "-NoExit", "Command", "cd $pwd; Write-Output 'Session restarted. You can now use cpscan.'"
    Stop-Process -Id $PID
} elseif ($Host.Name -eq "Windows PowerShell ISE Host") {
    # Restart for PowerShell ISE
    Start-Process powershell_ise.exe -ArgumentList "-File", $MyInvocation.MyCommand.Path
    Stop-Process -Id $PID
} else {
    # Fallback to close and open PowerShell in case of other hosts
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", "cd $pwd; Write-Output 'Session restarted. You can now use cpscan.'"
    Stop-Process -Id $PID
}
