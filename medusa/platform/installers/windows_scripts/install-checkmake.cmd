@echo off
REM checkmake Installer for Windows
REM Version: 0.2.2 (Updated: 2025-01-20)

echo Installing checkmake...

REM Check if Go is installed
where go >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Go not found. Please install Go first:
    echo https://go.dev/dl/
    exit /b 1
)

echo Found Go, installing checkmake via go install...
go install github.com/mrtazz/checkmake/cmd/checkmake@latest

if %ERRORLEVEL% EQU 0 (
    echo.
    echo checkmake installed successfully!
    echo.
    echo Make sure Go's bin directory is in your PATH:
    echo   %USERPROFILE%\go\bin
    echo.
    echo Test with: checkmake --version
) else (
    echo.
    echo ERROR: checkmake installation failed.
    exit /b 1
)
