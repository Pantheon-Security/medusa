# PowerShell installer for checkmake
# Downloads and installs checkmake from GitHub releases

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\checkmake",
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
    Write-Log "Starting checkmake installation..." "INFO"

    # Get pinned release info from GitHub API (version from tools-manifest.csv)
    $version = "0.2.2"
    Write-Log "Fetching release information for version $version..."
    $releaseUrl = "https://api.github.com/repos/mrtazz/checkmake/releases/tags/$version"
    $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{
        "User-Agent" = "MEDUSA-Installer"
    }

    Write-Log "Installing version: $version"

    # Find Windows AMD64 asset
    $asset = $release.assets | Where-Object { $_.name -match "checkmake.*windows.*amd64\.exe" } | Select-Object -First 1

    if (-not $asset) {
        throw "Could not find Windows AMD64 executable in release assets"
    }

    Write-Log "Found asset: $($asset.name)"
    $downloadUrl = $asset.browser_download_url

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        Write-Log "Creating install directory: $InstallDir"
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Download executable
    $exePath = "$InstallDir\checkmake.exe"
    Write-Log "Downloading from: $downloadUrl"
    Write-Host "Downloading checkmake $version..." -ForegroundColor Cyan

    Invoke-WebRequest -Uri $downloadUrl -OutFile $exePath -UseBasicParsing
    Write-Log "Download complete: $exePath"

    # Verify installation
    if (Test-Path $exePath) {
        Write-Host "`nSUCCESS: checkmake installed successfully!" -ForegroundColor Green
        Write-Host "   Location: $exePath" -ForegroundColor Gray

        # Check if in PATH
        $pathDirs = $env:Path -split ';'
        if ($pathDirs -notcontains $InstallDir) {
            Write-Host "`nNOTE: $InstallDir is not in your PATH" -ForegroundColor Yellow
            Write-Host "   Add to PATH to use 'checkmake' command globally" -ForegroundColor Gray
            Write-Host "`n   To add to PATH (run as administrator):" -ForegroundColor Cyan
            Write-Host "   [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$InstallDir', 'Machine')" -ForegroundColor Gray
        } else {
            Write-Host "   Already in PATH" -ForegroundColor Green
        }

        # Test execution
        try {
            Write-Host "`n   Testing installation..." -ForegroundColor Cyan
            $versionOutput = & $exePath --version 2>&1 | Select-Object -First 1
            Write-Host "   Version: $versionOutput" -ForegroundColor Green
        } catch {
            Write-Log "Version check failed" "INFO"
        }

        exit 0
    } else {
        throw "Installation verification failed: checkmake.exe not found"
    }

} catch {
    Write-Log "Installation failed: $_" "ERROR"
    Write-Host "`nERROR: Installation failed: $_" -ForegroundColor Red
    Write-Host "`nPlease install manually from: https://github.com/mrtazz/checkmake/releases" -ForegroundColor Yellow
    exit 1
}
