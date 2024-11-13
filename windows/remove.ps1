# PowerShell Script to Uninstall cpscan and Associated Artifacts

# Ensure the script runs as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "Please run this script as Administrator."
    Pause
    exit
}

# Define the cpscan installation path
$cpscanPath = "$env:ProgramFiles\cpscan"

# Remove cpscan executable and directory
if (Test-Path $cpscanPath) {
    Write-Output "Removing cpscan directory and executable..."
    Remove-Item -Path $cpscanPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "cpscan directory removed."
} else {
    Write-Output "No cpscan directory found. Skipping..."
}

# Remove cpscan from the system Path
$sysPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$newPath = ($systemPath -split ';') -notmatch [regex]::Escape($cpscanPath) -join ';'
[Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
Write-Output "cpscan removed from system Path."

# Prompt to remove go installation
$goPath = "$env:ProgramFiles\Go"
$removeGo = Read-Host "Do you want to remove Go? NOTE: this is not required from cpscan removal (Y/n)"
if ($removeGo -eq 'Y' -or $removeGo -eq 'y') {
    if (Test-Path $goPath) {
        Write-Output "Removing Go installation..."
        Remove-Item -Path $goPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Go removed successfully."
    } else {
        Write-Output "No Go installation found. Skipping..."
    }
} else {
    Write-Output "Go installation retained."
}

# Refresh environment variables for the current session
$refreshEnv = @"
[System.Environment]::SetEnvironmentVariable('Path', [System.Environment]::GetEnvironmentVariable('Path', 'Machine'), 'Process')
"@
Invoke-Expression $refreshEnv

Write-Output "`ncpscan and selected components removed success. Restart your terminal or session to fully reflect changes."
Pause
