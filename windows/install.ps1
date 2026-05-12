#Requires -RunAsAdministrator

# cpscan install script (Windows)
# Downloads the latest pre-built release binary from GitHub Releases.
# Requires: PowerShell 5.1+, Administrator privileges

$GitHubRepo = "papa0four/cpscan"
$BinaryName = "cpscan.exe"
$InstallDir = "$env:ProgramFiles\cpscan"
$BinaryPath = "$InstallDir\$BinaryName"

# Suppress Invoke-WebRequest progress bar — omitting this causes severe
# performance degradation on large downloads in PowerShell 5.1
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
        "x86"   { return "386"   }
        default {
            Write-Host "[-] Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" -ForegroundColor Red
            exit 1
        }
    }
}

function Get-LatestVersion {
    $response = Get-RemoteText -Url "https://api.github.com/repos/$GitHubRepo/releases/latest"

    if (-not $response) {
        Write-Host "[-] No releases found for $GitHubRepo." -ForegroundColor Red
        Write-Host "    This project may not have a stable release yet." -ForegroundColor Red
        Write-Host "    Visit https://github.com/$GitHubRepo/releases for status." -ForegroundColor Yellow
        exit 0
    }

    $version = ($response | ConvertFrom-Json).tag_name

    if (-not $version) {
        Write-Host "[-] Failed to resolve latest release version." -ForegroundColor Red
        Write-Host "    Check your internet connection and try again." -ForegroundColor Red
        exit 1
    }

    return $version
}

function Install-Binary {
    $arch    = Get-Arch
    $version = Get-LatestVersion

    # GoReleaser default naming convention: cpscan_windows_amd64.exe
    $BinaryFilename = "cpscan_windows_$arch.exe"
    $DownloadUrl    = "https://github.com/$GitHubRepo/releases/download/$version/$BinaryFilename"

    # Use GetRandomFileName to avoid orphaning a file the way GetTempFileName would
    $TempFile = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        [System.IO.Path]::GetRandomFileName() + ".exe"
    )

    Write-Host "[*] Downloading cpscan $version (windows/$arch)..." -ForegroundColor Cyan

    Get-RemoteFile -Url $DownloadUrl -Destination $TempFile

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    try {
        Move-Item -Path $TempFile -Destination $BinaryPath -Force
    }
    catch {
        Write-Host "[-] Failed to install binary to $BinaryPath" -ForegroundColor Red
        Write-Host "    $_" -ForegroundColor Red
        Remove-Item -Path $TempFile -ErrorAction SilentlyContinue
        exit 1
    }

    Write-Host "[+] cpscan $version installed to $BinaryPath" -ForegroundColor Green
}

function Register-Path {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $entries     = $machinePath -split ";"

    if ($InstallDir -notin $entries) {
        [Environment]::SetEnvironmentVariable(
            "Path",
            ($entries + $InstallDir) -join ";",
            "Machine"
        )
        $env:Path += ";$InstallDir"
        Write-Host "[+] Added $InstallDir to system PATH." -ForegroundColor Green
    }
}

function Confirm-Install {
    if (-not (Test-Path $BinaryPath)) {
        Write-Host "[-] Verification failed: binary not found at $BinaryPath" -ForegroundColor Red
        exit 1
    }

    $version = & $BinaryPath --version 2>&1

    Write-Host ""
    Write-Host "[+] Verification successful." -ForegroundColor Green
    Write-Host "    $version" -ForegroundColor White
    Write-Host "    Run 'cpscan --help' to see available commands." -ForegroundColor Yellow
}

function Main {
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "  cpscan Installer" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""

    # Exit cleanly if cpscan is already installed — do not attempt to overwrite
    if (Test-Path $BinaryPath) {
        Write-Host "[!] cpscan is already installed at $BinaryPath" -ForegroundColor Yellow
        Write-Host "    Run uninstall.ps1 to remove it or update.ps1 to check for a newer version." -ForegroundColor Yellow
        exit 0
    }

    try {
        Install-Binary
        Register-Path
        Confirm-Install
    }
    catch {
        Write-Host ""
        Write-Host "[-] Installation failed: $_" -ForegroundColor Red
        exit 1
    }
}

Main