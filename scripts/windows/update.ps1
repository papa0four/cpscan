#Requires -RunAsAdministrator

# cpscan update script (Windows)
# For end-users only. Checks for a newer release and updates if one exists.
# Developers and contributors should use: git pull && make install
# Requires: PowerShell 5.1+, Administrator privileges

$GitHubRepo = "papa0four/cpscan"
$BinaryName = "cpscan.exe"
$InstallDir = "$env:ProgramFiles\cpscan"
$BinaryPath = "$InstallDir\$BinaryName"
$BackupPath = "$InstallDir\$BinaryName.bak"

# Suppress progress bars
$ProgressPreference = "SilentlyContinue"

# =============================================================================

function Get-RemoteFile {
    param(
        [string]$Url,
        [string]$Destination
    )
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
    }
    catch {
        Write-Host "[-] Failed to download from: $Url" -ForegroundColor Red
        Write-Host "    $_" -ForegroundColor Red
        exit 1
    }
}

function Get-RemoteText {
    param([string]$Url)
    try {
        return Invoke-WebRequest -Uri $Url -UseBasicParsing |
            Select-Object -ExpandProperty Content
    }
    catch {
        return ""
    }
}

function Get-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        "x86" { return "386" }
        default {
            Write-Host "[-] Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" -ForegroundColor Red
            exit 1
        }
    }
}

# Returns the version string of the currently installed binary
function Get-InstalledVersion {
    $output = & $BinaryPath --version 2>&1
    return ($output -split "\s+")[-1]
}

# Resolves the latest release tag from the GitHub API
function Get-LatestVersion {
    $response = Get-RemoteText -Url "https://api.github.com/repos/$GitHubRepo/releases/latest"

    if (-not $response) {
        Write-Host "[-] Failed to reach GitHub API." -ForegroundColor Red
        Write-Host "    Check your internet connection and try again." -ForegroundColor Red
        exit 1
    }

    $version = ($response | ConvertFrom-Json).tag_name

    if (-not $version) {
        Write-Host "[-] No releases found for $GitHubRepo." -ForegroundColor Red
        Write-Host "    This project may not have a stable release yet." -ForegroundColor Red
        Write-Host "    Visit https://github.com/$GitHubRepo/releases for status." -ForegroundColor Yellow
        exit 0
    }

    return $version
}

# Backs up the current binary before attempting replacement
function Backup-Binary {
    try {
        Copy-Item -Path $BinaryPath -Destination $BackupPath -Force
    }
    catch {
        Write-Host "[-] Failed to create backup of current binary." -ForegroundColor Red
        Write-Host "    $_" -ForegroundColor Red
        exit 1
    }
}

# Restores the backed up binary — called on any failure after backup is taken
function Restore-Binary {
    if (Test-Path $BackupPath) {
        Write-Host "[!] Restoring previous version..." -ForegroundColor Yellow
        try {
            Move-Item -Path $BackupPath -Destination $BinaryPath -Force
            Write-Host "[+] Previous version restored." -ForegroundColor Green
        }
        catch {
            Write-Host "[-] Failed to restore backup. Manual recovery may be required." -ForegroundColor Red
            Write-Host "    Backup located at: $BackupPath" -ForegroundColor Yellow
        }
    }
}

# Downloads the specified release and replaces the installed binary
function Update-Binary {
    param([string]$Version)

    $arch = Get-Arch
    $BinaryFilename = "cpscan_windows_$arch.exe"
    $DownloadUrl = "https://github.com/$GitHubRepo/releases/download/$Version/$BinaryFilename"

    $TempFile = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        [System.IO.Path]::GetRandomFileName() + ".exe"
    )

    Write-Host "[*] Downloading cpscan $Version (windows/$arch)..." -ForegroundColor Cyan

    Get-RemoteFile -Url $DownloadUrl -Destination $TempFile

    try {
        Move-Item -Path $TempFile -Destination $BinaryPath -Force
    }
    catch {
        Write-Host "[-] Failed to replace binary." -ForegroundColor Red
        Write-Host "    $_" -ForegroundColor Red
        Remove-Item -Path $TempFile -ErrorAction SilentlyContinue
        Restore-Binary
        exit 1
    }
}

# Confirms the installed binary reports the expected version after update
function Confirm-Update {
    param([string]$ExpectedVersion)

    $actual = Get-InstalledVersion

    if ($actual -ne $ExpectedVersion) {
        Write-Host "[-] Update verification failed." -ForegroundColor Red
        Write-Host "    Expected: $ExpectedVersion" -ForegroundColor Red
        Write-Host "    Got:      $actual" -ForegroundColor Red
        Restore-Binary
        exit 1
    }

    # Backup no longer needed once update is confirmed
    Remove-Item -Path $BackupPath -ErrorAction SilentlyContinue

    Write-Host "[+] cpscan updated to $actual" -ForegroundColor Green
    Write-Host "    Run 'cpscan --help' to see available commands." -ForegroundColor Yellow
}

function Main {
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "  cpscan Updater" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""

    try {
        # Confirm cpscan is installed before proceeding
        if (-not (Test-Path $BinaryPath)) {
            Write-Host "[-] cpscan is not installed." -ForegroundColor Red
            Write-Host "    Run install.ps1 to install cpscan first." -ForegroundColor Yellow
            exit 1
        }

        $installedVersion = Get-InstalledVersion

        # Dev builds are not managed by this script
        if ($installedVersion -notlike "v*") {
            Write-Host "[!] cpscan $installedVersion appears to be a developer build." -ForegroundColor Yellow
            Write-Host "    This script manages release versions only." -ForegroundColor Yellow
            Write-Host "    To update a developer build: git pull && make install" -ForegroundColor Yellow
            exit 0
        }

        Write-Host "[*] Installed version: $installedVersion" -ForegroundColor White

        $latestVersion = Get-LatestVersion

        Write-Host "[*] Latest version:    $latestVersion" -ForegroundColor White

        # Already on latest
        if ($installedVersion -eq $latestVersion) {
            Write-Host "[+] cpscan is already up to date." -ForegroundColor Green
            exit 0
        }

        # Offer the update
        Write-Host ""
        Write-Host "[!] A new version is available: $latestVersion" -ForegroundColor Yellow
        $response = Read-Host "    Update cpscan from $installedVersion to $latestVersion? (y/n)"

        if ($response -notmatch "^[Yy]$") {
            Write-Host "[*] Update declined. Staying on $installedVersion." -ForegroundColor White
            exit 0
        }

        # Windows locks running executables — check before attempting replacement
        $running = Get-Process -Name "cpscan" -ErrorAction SilentlyContinue
        if ($running) {
            Write-Host "[-] cpscan is currently running." -ForegroundColor Red
            Write-Host "    Please close all instances of cpscan and run this script again." -ForegroundColor Yellow
            exit 1
        }

        Backup-Binary
        Update-Binary -Version $latestVersion
        Confirm-Update -ExpectedVersion $latestVersion
    }
    catch {
        Write-Host ""
        Write-Host "[-] Update failed: $_" -ForegroundColor Red
        Restore-Binary
        exit 1
    }
}

Main