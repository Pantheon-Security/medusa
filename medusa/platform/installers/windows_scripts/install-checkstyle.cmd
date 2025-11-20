@echo off
REM Checkstyle Installer for Windows
REM Version: 10.21.1 (Updated: 2025-01-20)

echo Installing Checkstyle...

REM Check if Java is installed
where java >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Java not found. Please install Java first:
    echo https://adoptium.net/
    exit /b 1
)

REM Create install directory
set "INSTALL_DIR=%ProgramFiles%\checkstyle"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Download checkstyle
echo Downloading Checkstyle 10.21.1...
powershell -Command "& {Invoke-WebRequest -Uri 'https://github.com/checkstyle/checkstyle/releases/download/checkstyle-10.21.1/checkstyle-10.21.1-all.jar' -OutFile '%INSTALL_DIR%\checkstyle.jar'}"

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to download Checkstyle
    exit /b 1
)

REM Create wrapper script
(
  echo @echo off
  echo java -jar "%INSTALL_DIR%\checkstyle.jar" %%*
) > "%INSTALL_DIR%\checkstyle.bat"

REM Add to PATH (user level, no UAC)
echo Adding Checkstyle to PATH...
powershell -Command "& {$oldPath = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($oldPath -notlike '*%INSTALL_DIR%*') { [Environment]::SetEnvironmentVariable('Path', $oldPath + ';%INSTALL_DIR%', 'User') }}"

if %ERRORLEVEL% NEQ 0 (
    echo WARNING: Failed to update PATH. You may need to add %INSTALL_DIR% manually.
)

echo.
echo Checkstyle installed successfully!
echo.
echo You may need to restart your terminal for PATH changes to take effect.
echo Test with: checkstyle --version

exit /b 0
