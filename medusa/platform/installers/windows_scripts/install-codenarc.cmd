@echo off
REM CodeNarc Installer for Windows
REM Version: 3.5.0 (Updated: 2025-01-20)

echo Installing CodeNarc...

REM Check if Java is installed
where java >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Java not found. Please install Java first:
    echo https://adoptium.net/
    exit /b 1
)

REM Create install directory
set "INSTALL_DIR=%ProgramFiles%\codenarc"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Download CodeNarc
echo Downloading CodeNarc 3.5.0...
powershell -Command "& {Invoke-WebRequest -Uri 'https://github.com/CodeNarc/CodeNarc/releases/download/v3.5.0/CodeNarc-3.5.0-all.jar' -OutFile '%INSTALL_DIR%\codenarc.jar'}"

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to download CodeNarc
    exit /b 1
)

REM Create wrapper script
(
  echo @echo off
  echo java -jar "%INSTALL_DIR%\codenarc.jar" %%*
) > "%INSTALL_DIR%\codenarc.bat"

REM Add to PATH (user level, no UAC)
echo Adding CodeNarc to PATH...
powershell -Command "& {$oldPath = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($oldPath -notlike '*%INSTALL_DIR%*') { [Environment]::SetEnvironmentVariable('Path', $oldPath + ';%INSTALL_DIR%', 'User') }}"

echo.
echo CodeNarc installed successfully!
echo.
echo You may need to restart your terminal for PATH changes to take effect.
echo Test with: codenarc --version
