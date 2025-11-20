@echo off
REM clj-kondo Installer for Windows
REM Version: 2024.11.14 (Updated: 2025-01-20)

echo Installing clj-kondo...

REM Create install directory
set "INSTALL_DIR=%ProgramFiles%\clj-kondo"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Download clj-kondo Windows binary (using native curl.exe - less suspicious to antivirus)
echo Downloading clj-kondo 2024.11.14...
curl.exe -L -o "%TEMP%\clj-kondo.zip" "https://github.com/clj-kondo/clj-kondo/releases/download/v2024.11.14/clj-kondo-2024.11.14-windows-amd64.zip"

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to download clj-kondo
    exit /b 1
)

REM Extract the zip file (using native tar.exe - less suspicious to antivirus)
echo Extracting clj-kondo...
tar.exe -xf "%TEMP%\clj-kondo.zip" -C "%INSTALL_DIR%"

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to extract clj-kondo
    del "%TEMP%\clj-kondo.zip"
    exit /b 1
)

REM Clean up
del "%TEMP%\clj-kondo.zip"

REM Add to PATH (user level, no UAC)
echo Adding clj-kondo to PATH...
powershell -Command "& {$oldPath = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($oldPath -notlike '*%INSTALL_DIR%*') { [Environment]::SetEnvironmentVariable('Path', $oldPath + ';%INSTALL_DIR%', 'User') }}"

if %ERRORLEVEL% NEQ 0 (
    echo WARNING: Failed to update PATH. You may need to add %INSTALL_DIR% manually.
)

echo.
echo clj-kondo installed successfully!
echo.
echo You may need to restart your terminal for PATH changes to take effect.
echo Test with: clj-kondo --version

exit /b 0
