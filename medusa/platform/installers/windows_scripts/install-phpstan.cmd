@echo off
REM PHPStan Installer for Windows
REM Version: 2.0.3 (Updated: 2025-01-20)

echo Installing PHPStan...

REM Check if composer is installed
where composer >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Composer not found. Please install Composer first:
    echo https://getcomposer.org/download/
    exit /b 1
)

echo Found Composer, installing PHPStan globally...
composer global require phpstan/phpstan

if %ERRORLEVEL% EQU 0 (
    echo.
    echo PHPStan installed successfully!
    echo.
    echo Make sure Composer's global bin directory is in your PATH:
    echo   %APPDATA%\Composer\vendor\bin
    echo.
    echo Test with: phpstan --version
) else (
    echo.
    echo ERROR: PHPStan installation failed.
    exit /b 1
)

exit /b 0
