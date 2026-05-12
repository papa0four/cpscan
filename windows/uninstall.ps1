#Requires -RunAsAdministrator

# cpscan uninstall script (Windows)
# Completely removes cpscan and all associated artifacts from the target machine.
# Requires: PowerShell 5.1+, Administrator privileges

$BinaryName = "cpscan.exe"
$InstallDir = "$env:ProgramFiles\cpscan"
$BinaryPath = "$InstallDir\$BinaryName"

# Suppress progress bars
$ProgressPreference = "SilentlyContinue"

# =============================================================================

# Confirms cpscan is installed and no instance is currently running.
# A running instance locks the executable on Windows preventing deletion.
function Assert-Removable {
    if (-not (Test-Path $BinaryPath)) {
        Write-Host "[!] cpscan is not installed at $BinaryPath" -ForegroundColor Yellow
        Write-Host "    Nothing to uninstall." -ForegroundColor Yellow
        exit 0
    }

    $running = Get-Process -Name "cpscan" -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host "[-] cpscan is currently running." -ForegroundColor Red
        Write-Host "    Please close all instances of cpscan and run this script again." -ForegroundColor Yellow
        exit 1
    }
}

# Removes the binary and the install directory created by install.ps1
function Remove-Binary {
    Write-Host "[*] Removing cpscan from $InstallDir..." -ForegroundColor Cyan

    try {
        Remove-Item -Path $InstallDir -Recurse -Force
    }
    catch {
        Write-Host "[-] Failed to remove $InstallDir" -ForegroundColor Red
        Write-Host "    $_" -ForegroundColor Red
        exit 1
    }
}

# Removes only the cpscan install directory entry from the Machine PATH.
# Splits on semicolon, filters the exact entry, and rejoins.
function Remove-FromPath {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $entries     = $machinePath -split ";"
    $filtered    = $entries | Where-Object { $_ -ne $InstallDir }

    if ($filtered.Count -eq $entries.Count) {
        Write-Host "[*] cpscan was not found in system PATH — skipping PATH update." -ForegroundColor Yellow
        return
    }

    [Environment]::SetEnvironmentVariable(
        "Path",
        ($filtered -join ";"),
        "Machine"
    )

    # Refresh PATH in the current session to reflect the removal immediately
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine")

    Write-Host "[+] Removed cpscan from system PATH." -ForegroundColor Green
}

# Confirms the binary and install directory are gone and cpscan
# is no longer resolvable anywhere in PATH
function Confirm-Removal {
    if (Test-Path $BinaryPath) {
        Write-Host "[-] Uninstall failed: binary still present at $BinaryPath" -ForegroundColor Red
        exit 1
    }

    if (Test-Path $InstallDir) {
        Write-Host "[-] Uninstall failed: install directory still present at $InstallDir" -ForegroundColor Red
        exit 1
    }

    $resolved = Get-Command "cpscan" -ErrorAction SilentlyContinue
    if ($resolved) {
        Write-Host "[-] Uninstall failed: cpscan is still resolvable in PATH at:" -ForegroundColor Red
        Write-Host "    $($resolved.Source)" -ForegroundColor Red
        Write-Host "    A second installation may exist at this location." -ForegroundColor Yellow
        exit 1
    }

    Write-Host "[+] cpscan has been completely removed." -ForegroundColor Green
}

function Main {
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "  cpscan Uninstaller" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""

    try {
        Assert-Removable
        Remove-Binary
        Remove-FromPath
        Confirm-Removal
    }
    catch {
        Write-Host ""
        Write-Host "[-] Uninstall failed: $_" -ForegroundColor Red
        exit 1
    }
}

Main