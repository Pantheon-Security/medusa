@echo off
REM ktlint Installer for Windows
REM Version: 1.5.0 (Updated: 2025-01-20)

echo Installing ktlint...

REM Check if Java is installed
where java >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Java not found. Please install Java first:
    echo https://adoptium.net/
    exit /b 1
)

REM Create install directory
set "INSTALL_DIR=%ProgramFiles%\ktlint"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Download ktlint
echo Downloading ktlint 1.5.0...
powershell -Command "& {Invoke-WebRequest -Uri 'https://github.com/pinterest/ktlint/releases/download/1.5.0/ktlint' -OutFile '%INSTALL_DIR%\ktlint.jar'}"

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to download ktlint
    exit /b 1
)

REM Create wrapper script
(
  echo @echo off
  echo java -jar "%INSTALL_DIR%\ktlint.jar" %%*
) > "%INSTALL_DIR%\ktlint.bat"

REM Add to PATH (user level, no UAC)
echo Adding ktlint to PATH...
powershell -Command "& {$oldPath = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($oldPath -notlike '*%INSTALL_DIR%*') { [Environment]::SetEnvironmentVariable('Path', $oldPath + ';%INSTALL_DIR%', 'User') }}"

if %ERRORLEVEL% NEQ 0 (
    echo WARNING: Failed to update PATH. You may need to add %INSTALL_DIR% manually.
)

echo.
echo ktlint installed successfully!
echo.
echo You may need to restart your terminal for PATH changes to take effect.
echo Test with: ktlint --version

exit /b 0
