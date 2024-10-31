# Powershell Script to install application and create custom executable

# Check if Go is installed
$goVersion = & go version 2>&1
if ($goVersion -like "*Go is not recognized*") {
    Write-Output "Go not found. Installing the latest version of Go..."

    # Download the lastest Go installer
    $url = "https://golang.org/dl/go1.21.1.windows-amd64.msi"
    $installerPath = "$env:TEMP\go-installer.msi"
    Invoke-WebRequest -Uri $url -Outfile $installerPath

    # Install Go
    Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait

    # Remove the installer
    Remove-Item -Path $installerPath
} else {
    Write-Output "Go is already installed."
}

# Temporarily add Go and cpscan paths to the current session's Path
$env:Path += ";C:\Program Files\Go\bin;$env:ProgramFiles\cpscan"

# Ensure Go and cpscan paths are added permanently for future sessions
$profilePath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("UserProfile"), "Documents", "Powershell", "Microsoft.Powershell_profile.ps1")
if (!(Test-Path -Path $profilePath)) {
    New-Item -ItemType File -Path $profilePath -Force
}

Add-Content -Path $profilePath -Value 'if (!(($env:Path -split ";") -contains "C:\Program Files\Go\bin")) { $env:Path += ";C:\Program Files\Go\bin" }'
Add-Content -Path $profilePath -Value 'if (!(($env:Path -split ";") -contains "$env:ProgramFiles\cpscan")) { $env:Path += ";$env:PrgramFiles\cpscan" }'

# Locate the project root directory (where cmd/main.go exists)
$projectRoot = Get-ChildItem -Path (Get-Location) -Recurse -Filter "main.go" | Where-Object { $_.FullName -match "\\cmd\\main\.go$" } | Select-Object -ExpandProperty DirectoryName | Select-Object -First 1

if (-not $projectRoot) {
    Write-Output "Error: Could not locate 'cmd/main.go'. Please ensure you are in the project directory or that the project structure is correct."
    exit 1
}

# Change to the project's root directory
Set-Location -Path $projectRoot
Write-Output "Building 'cpscan' executable from project root at $projectRoot..."

# Build the executable
go build -o cpspan ./cmd/main.go

# Move 'cpscan.exe' to a directory in PATH
$destinationPath = "$env:ProgramFiles\cpscan\cpscan.exe"
New-Item -ItemType Directory -Path "$env:ProgramFiles\cpscan\cpscan.exe" -Force | Out-Null
Move-Item -Path ".\cpscan.exe" -Destination $destinationPath -Force

Write-Output "cpscan installed successfully. You can now run it using the 'cpscan' command."

# Refresh the current session Path to use cpscan immediately
& $env:Path

