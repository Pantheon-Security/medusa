# PowerShell installer for clj-kondo
# Downloads and installs clj-kondo from GitHub releases

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\clj-kondo",
    [switch]$Debug
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    if ($Debug -or $Level -eq "ERROR") {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$timestamp] [$Level] $Message"
    }
}

try {
    Write-Log "Starting clj-kondo installation..." "INFO"

    # Get pinned release info from GitHub API (version from tool-versions.lock)
    $version = "v2025.10.23"
    Write-Log "Fetching release information for version $version..."
    $releaseUrl = "https://api.github.com/repos/clj-kondo/clj-kondo/releases/tags/$version"
    $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{
        "User-Agent" = "MEDUSA-Installer"
    }

    Write-Log "Installing version: $version"

    # Find Windows AMD64 asset
    $asset = $release.assets | Where-Object { $_.name -match "clj-kondo.*windows-amd64\.zip" } | Select-Object -First 1

    if (-not $asset) {
        throw "Could not find Windows AMD64 release asset"
    }

    Write-Log "Found asset: $($asset.name)"
    $downloadUrl = $asset.browser_download_url

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        Write-Log "Creating install directory: $InstallDir"
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Download zip file
    $zipPath = "$env:TEMP\clj-kondo.zip"
    Write-Log "Downloading from: $downloadUrl"
    Write-Host "Downloading clj-kondo $version..." -ForegroundColor Cyan

    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
    Write-Log "Download complete: $zipPath"

    # Extract zip
    Write-Log "Extracting to: $InstallDir"
    Write-Host "Extracting files..." -ForegroundColor Cyan

    # Remove old files if they exist
    if (Test-Path "$InstallDir\clj-kondo.exe") {
        Remove-Item "$InstallDir\clj-kondo.exe" -Force
    }

    Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force

    # Clean up zip
    Remove-Item $zipPath -Force
    Write-Log "Cleanup complete"

    # Verify installation
    $exePath = "$InstallDir\clj-kondo.exe"
    if (Test-Path $exePath) {
        Write-Host "`nSUCCESS: clj-kondo installed successfully!" -ForegroundColor Green
        Write-Host "   Location: $exePath" -ForegroundColor Gray

        # Check if in PATH
        $pathDirs = $env:Path -split ';'
        if ($pathDirs -notcontains $InstallDir) {
            Write-Host "`nNOTE: $InstallDir is not in your PATH" -ForegroundColor Yellow
            Write-Host "   Add to PATH to use 'clj-kondo' command globally" -ForegroundColor Gray
            Write-Host "`n   To add to PATH (run as administrator):" -ForegroundColor Cyan
            Write-Host "   [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$InstallDir', 'Machine')" -ForegroundColor Gray
        } else {
            Write-Host "   Already in PATH" -ForegroundColor Green
        }

        # Test execution
        Write-Host "`n   Testing installation..." -ForegroundColor Cyan
        $versionOutput = & $exePath --version 2>&1
        Write-Host "   Version: $versionOutput" -ForegroundColor Green

        exit 0
    } else {
        throw "Installation verification failed: clj-kondo.exe not found"
    }

} catch {
    Write-Log "Installation failed: $_" "ERROR"
    Write-Host "`nERROR: Installation failed: $_" -ForegroundColor Red
    Write-Host "`nPlease install manually from: https://github.com/clj-kondo/clj-kondo/releases" -ForegroundColor Yellow
    exit 1
}
