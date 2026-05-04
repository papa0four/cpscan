# Define variables
$GitHubRepoURL = "https://github.com/papa0four/cpscan/archive/refs/heads/main.zip"
$TempDir = "$env:TEMP\cpscan_update"
$InstallDir = "$env:ProgramFiles\cpscan"
$BackupDir = "$env:ProgramFiles\cpscan_backup"
$ZipFile = "$TempDir\cpscan.zip"
$GoExe = "$env:ProgramFiles\Go\bin\go.exe"

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script as Administrator."
    exit 1
}

try {
    # Backup current installation
    if (Test-Path $InstallDir) {
        Write-Output "Backing up current installation..."
        if (Test-Path $BackupDir) {
            Remove-Item -Recurse -Force $BackupDir
        }
        Rename-Item -Path $InstallDir -NewName $BackupDir
    }

    # Create temp directory
    Write-Output "Creating temporary directory..."
    if (Test-Path $TempDir) {
        Remove-Item -Recurse -Force $TempDir
    }
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

    # Download and extract
    Write-Output "Downloading cpscan..."
    Invoke-WebRequest -Uri $GitHubRepoURL -OutFile $ZipFile
    
    Write-Output "Extracting..."
    Expand-Archive -Path $ZipFile -DestinationPath $TempDir -Force
    
    # Verify project structure
    Write-Output "Verifying project structure..."
    $mainDir = Get-ChildItem -Path $TempDir -Directory | Where-Object { $_.Name -eq "cpscan-main" } | Select-Object -ExpandProperty FullName
    Write-Output "Main directory: $mainDir"

    if (-not $mainDir) {
        throw "Could not find cpscan-main directory"
    }

    $mainGoPath = Join-Path -Path $mainDir -ChildPath "cmd\cpscan\main.go"
    Write-Output "Looking for main.go at: $mainGoPath"

    if (-not (Test-Path $mainGoPath)) {
        throw "Project structure not as expected. Cannot find $mainGoPath"
    }

    $ProjectRoot = $mainDir 
    
    # Build steps
    Write-Output "Building cpscan..."
    Push-Location $ProjectRoot
    if (!(Test-Path "go.mod")) {
        Start-Process -FilePath $GoExe -ArgumentList "mod", "init", "github.com/papa0four/cpscan" -Wait -NoNewWindow
    }
    Start-Process -FilePath $GoExe -ArgumentList "mod", "tidy" -Wait -NoNewWindow
    Start-Process -FilePath $GoExe -ArgumentList "build", "-o", "cpscan.exe", "./cmd/cpscan" -Wait -NoNewWindow
    
    if (-not (Test-Path ".\cpscan.exe")) {
        Write-Error "Build failed: cpscan executable not created."
        Pop-Location
        exit 1
    }
    Pop-Location
    
    # Install
    Write-Output "Installing cpscan..."
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Move-Item -Path "$ProjectRoot\cpscan.exe" -Destination "$InstallDir\cpscan.exe" -Force
    
    # Update PATH
    if (!(Get-Command "cpscan" -ErrorAction SilentlyContinue)) {
        $env:Path += ";$InstallDir"
        [Environment]::SetEnvironmentVariable("Path", $env:Path, "Machine")
        Write-Output "Updated PATH environment variable."
    }
    
    # Cleanup
    Write-Output "Cleaning up..."
    Remove-Item -Recurse -Force $TempDir
    
    Write-Output "Update complete."

} catch {
    Write-Error "Error during process: $_"
    if (Test-Path $TempDir) {
        Remove-Item -Recurse -Force $TempDir
    }
    exit 1
}
