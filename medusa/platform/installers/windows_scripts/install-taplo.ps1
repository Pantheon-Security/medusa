# PowerShell installer for taplo
# Downloads and installs taplo from GitHub releases

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\taplo",
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
    Write-Log "Starting taplo installation..." "INFO"

    # Get pinned release info from GitHub API (version from tool-versions.lock)
    $version = "0.9.3"
    Write-Log "Fetching release information for version $version..."
    $releaseUrl = "https://api.github.com/repos/tamasfe/taplo/releases/tags/$version"
    $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{
        "User-Agent" = "MEDUSA-Installer"
    }

    Write-Log "Installing version: $version"

    # Find Windows x86_64 asset (taplo-full or taplo)
    $asset = $release.assets | Where-Object { $_.name -match "taplo.*x86_64.*windows.*\.zip" } | Select-Object -First 1

    if (-not $asset) {
        # Try alternate naming pattern
        $asset = $release.assets | Where-Object { $_.name -match "taplo.*windows.*x86_64.*\.zip" } | Select-Object -First 1
    }

    if (-not $asset) {
        throw "Could not find Windows x86_64 ZIP in release assets"
    }

    Write-Log "Found asset: $($asset.name)"
    $downloadUrl = $asset.browser_download_url

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        Write-Log "Creating install directory: $InstallDir"
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Download ZIP file
    $zipPath = "$env:TEMP\taplo-$version.zip"
    Write-Log "Downloading from: $downloadUrl"
    Write-Host "Downloading taplo $version..." -ForegroundColor Cyan

    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
    Write-Log "Download complete: $zipPath"

    # Extract ZIP
    Write-Log "Extracting to: $InstallDir"
    Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force
    Write-Log "Extraction complete"

    # Clean up ZIP
    Remove-Item $zipPath -Force
    Write-Log "Cleaned up temporary ZIP file"

    # Find the taplo executable (might be taplo.exe or taplo-full.exe)
    $exePath = Get-ChildItem -Path $InstallDir -Filter "taplo*.exe" -Recurse | Select-Object -First 1 | ForEach-Object { $_.FullName }

    if (-not $exePath) {
        throw "Could not find taplo executable after extraction"
    }

    # If it's taplo-full.exe, rename to taplo.exe for consistency
    if ($exePath -match "taplo-full\.exe") {
        $newPath = Join-Path (Split-Path $exePath) "taplo.exe"
        Move-Item -Path $exePath -Destination $newPath -Force
        $exePath = $newPath
        Write-Log "Renamed taplo-full.exe to taplo.exe"
    }

    Write-Log "Found executable: $exePath"

    # Verify installation
    if (Test-Path $exePath) {
        Write-Host "`nSUCCESS: taplo installed successfully!" -ForegroundColor Green
        Write-Host "   Location: $exePath" -ForegroundColor Gray

        # Check if in PATH
        $installDirPath = Split-Path $exePath
        $pathDirs = $env:Path -split ';'
        if ($pathDirs -notcontains $installDirPath) {
            Write-Host "`nNOTE: $installDirPath is not in your PATH" -ForegroundColor Yellow
            Write-Host "   Add to PATH to use 'taplo' command globally" -ForegroundColor Gray
            Write-Host "`n   To add to PATH (run as administrator):" -ForegroundColor Cyan
            Write-Host "   [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$installDirPath', 'Machine')" -ForegroundColor Gray
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
        throw "Installation verification failed: taplo.exe not found"
    }

} catch {
    Write-Log "Installation failed: $_" "ERROR"
    Write-Host "`nERROR: Installation failed: $_" -ForegroundColor Red
    Write-Host "`nPlease install manually from: https://github.com/tamasfe/taplo/releases" -ForegroundColor Yellow
    exit 1
}
