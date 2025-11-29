# PowerShell installer for ktlint
# Downloads and installs ktlint from GitHub releases

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\ktlint",
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
    Write-Log "Starting ktlint installation..." "INFO"

    # Get pinned release info from GitHub API (version from tool-versions.lock)
    $version = "1.5.0"
    Write-Log "Fetching release information for version $version..."
    $releaseUrl = "https://api.github.com/repos/pinterest/ktlint/releases/tags/$version"
    $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{
        "User-Agent" = "MEDUSA-Installer"
    }

    Write-Log "Installing version: $version"

    # Find ktlint JAR asset (just named "ktlint")
    $asset = $release.assets | Where-Object { $_.name -eq "ktlint" } | Select-Object -First 1

    if (-not $asset) {
        throw "Could not find ktlint JAR in release assets"
    }

    Write-Log "Found asset: $($asset.name)"
    $downloadUrl = $asset.browser_download_url

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        Write-Log "Creating install directory: $InstallDir"
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Download JAR file
    $jarPath = "$InstallDir\ktlint.jar"
    Write-Log "Downloading from: $downloadUrl"
    Write-Host "Downloading ktlint $version..." -ForegroundColor Cyan

    Invoke-WebRequest -Uri $downloadUrl -OutFile $jarPath -UseBasicParsing
    Write-Log "Download complete: $jarPath"

    # Create wrapper batch file
    $batPath = "$InstallDir\ktlint.bat"
    $batContent = "@echo off`r`njava -jar `"$jarPath`" %*"
    Set-Content -Path $batPath -Value $batContent -Encoding ASCII
    Write-Log "Created wrapper script: $batPath"

    # Verify Java is available
    try {
        $javaVersion = java -version 2>&1 | Select-Object -First 1
        Write-Log "Java found: $javaVersion"
    } catch {
        Write-Host "`nWARNING: Java not found in PATH" -ForegroundColor Yellow
        Write-Host "   ktlint requires Java to run" -ForegroundColor Gray
        Write-Host "   Install Java from: https://adoptium.net/" -ForegroundColor Gray
    }

    # Verify installation
    if (Test-Path $jarPath) {
        Write-Host "`nSUCCESS: ktlint installed successfully!" -ForegroundColor Green
        Write-Host "   Location: $jarPath" -ForegroundColor Gray
        Write-Host "   Wrapper: $batPath" -ForegroundColor Gray

        # Check if in PATH
        $pathDirs = $env:Path -split ';'
        if ($pathDirs -notcontains $InstallDir) {
            Write-Host "`nNOTE: $InstallDir is not in your PATH" -ForegroundColor Yellow
            Write-Host "   Add to PATH to use 'ktlint' command globally" -ForegroundColor Gray
            Write-Host "`n   To add to PATH (run as administrator):" -ForegroundColor Cyan
            Write-Host "   [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$InstallDir', 'Machine')" -ForegroundColor Gray
        } else {
            Write-Host "   Already in PATH" -ForegroundColor Green
        }

        # Test execution (if Java available)
        try {
            Write-Host "`n   Testing installation..." -ForegroundColor Cyan
            $versionOutput = & $batPath --version 2>&1 | Select-Object -First 1
            Write-Host "   Version: $versionOutput" -ForegroundColor Green
        } catch {
            Write-Log "Version check failed (Java may not be available)" "INFO"
        }

        exit 0
    } else {
        throw "Installation verification failed: ktlint.jar not found"
    }

} catch {
    Write-Log "Installation failed: $_" "ERROR"
    Write-Host "`nERROR: Installation failed: $_" -ForegroundColor Red
    Write-Host "`nPlease install manually from: https://github.com/pinterest/ktlint/releases" -ForegroundColor Yellow
    exit 1
}
