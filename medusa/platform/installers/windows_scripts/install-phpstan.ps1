# PowerShell installer for phpstan
# Downloads and installs phpstan from GitHub releases

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\phpstan",
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
    Write-Log "Starting phpstan installation..." "INFO"

    # Get pinned release info from GitHub API (version from tool-versions.lock)
    $version = "2.0.4"
    Write-Log "Fetching release information for version $version..."
    $releaseUrl = "https://api.github.com/repos/phpstan/phpstan/releases/tags/$version"
    $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{
        "User-Agent" = "MEDUSA-Installer"
    }

    Write-Log "Installing version: $version"

    # Find phpstan.phar asset
    $asset = $release.assets | Where-Object { $_.name -eq "phpstan.phar" } | Select-Object -First 1

    if (-not $asset) {
        throw "Could not find phpstan.phar in release assets"
    }

    Write-Log "Found asset: $($asset.name)"
    $downloadUrl = $asset.browser_download_url

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        Write-Log "Creating install directory: $InstallDir"
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Download PHAR file
    $pharPath = "$InstallDir\phpstan.phar"
    Write-Log "Downloading from: $downloadUrl"
    Write-Host "Downloading phpstan $version..." -ForegroundColor Cyan

    Invoke-WebRequest -Uri $downloadUrl -OutFile $pharPath -UseBasicParsing
    Write-Log "Download complete: $pharPath"

    # Create wrapper batch file
    $batPath = "$InstallDir\phpstan.bat"
    $batContent = "@echo off`r`nphp `"$pharPath`" %*"
    Set-Content -Path $batPath -Value $batContent -Encoding ASCII
    Write-Log "Created wrapper script: $batPath"

    # Verify PHP is available
    try {
        $phpVersion = php -v 2>&1 | Select-Object -First 1
        Write-Log "PHP found: $phpVersion"
    } catch {
        Write-Host "`nWARNING: PHP not found in PATH" -ForegroundColor Yellow
        Write-Host "   phpstan requires PHP to run" -ForegroundColor Gray
        Write-Host "   Install PHP from: https://windows.php.net/download/" -ForegroundColor Gray
    }

    # Verify installation
    if (Test-Path $pharPath) {
        Write-Host "`nSUCCESS: phpstan installed successfully!" -ForegroundColor Green
        Write-Host "   Location: $pharPath" -ForegroundColor Gray
        Write-Host "   Wrapper: $batPath" -ForegroundColor Gray

        # Check if in PATH
        $pathDirs = $env:Path -split ';'
        if ($pathDirs -notcontains $InstallDir) {
            Write-Host "`nNOTE: $InstallDir is not in your PATH" -ForegroundColor Yellow
            Write-Host "   Add to PATH to use 'phpstan' command globally" -ForegroundColor Gray
            Write-Host "`n   To add to PATH (run as administrator):" -ForegroundColor Cyan
            Write-Host "   [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$InstallDir', 'Machine')" -ForegroundColor Gray
        } else {
            Write-Host "   Already in PATH" -ForegroundColor Green
        }

        # Test execution (if PHP available)
        try {
            Write-Host "`n   Testing installation..." -ForegroundColor Cyan
            $versionOutput = & $batPath --version 2>&1 | Select-Object -First 1
            Write-Host "   Version: $versionOutput" -ForegroundColor Green
        } catch {
            Write-Log "Version check failed (PHP may not be available)" "INFO"
        }

        exit 0
    } else {
        throw "Installation verification failed: phpstan.phar not found"
    }

} catch {
    Write-Log "Installation failed: $_" "ERROR"
    Write-Host "`nERROR: Installation failed: $_" -ForegroundColor Red
    Write-Host "`nPlease install manually from: https://github.com/phpstan/phpstan/releases" -ForegroundColor Yellow
    exit 1
}
