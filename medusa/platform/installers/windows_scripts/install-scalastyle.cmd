@echo off
REM Scalastyle Installer for Windows
REM Version: 1.5.1 (Updated: 2025-01-20)

echo Installing Scalastyle...

REM Check if Java is installed
where java >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Java not found. Please install Java first:
    echo https://adoptium.net/
    exit /b 1
)

REM Create install directory
set "INSTALL_DIR=%ProgramFiles%\scalastyle"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Download scalastyle
echo Downloading Scalastyle 1.5.1...
powershell -Command "& {Invoke-WebRequest -Uri 'https://github.com/beautiful-scala/scalastyle/releases/download/v1.5.1/scalastyle_2.12-1.5.1-batch.jar' -OutFile '%INSTALL_DIR%\scalastyle.jar'}"

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to download Scalastyle
    exit /b 1
)

REM Create wrapper script
(
  echo @echo off
  echo java -jar "%INSTALL_DIR%\scalastyle.jar" %%*
) > "%INSTALL_DIR%\scalastyle.bat"

REM Add to PATH (user level, no UAC)
echo Adding Scalastyle to PATH...
powershell -Command "& {$oldPath = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($oldPath -notlike '*%INSTALL_DIR%*') { [Environment]::SetEnvironmentVariable('Path', $oldPath + ';%INSTALL_DIR%', 'User') }}"

if %ERRORLEVEL% NEQ 0 (
    echo WARNING: Failed to update PATH. You may need to add %INSTALL_DIR% manually.
)

echo.
echo Scalastyle installed successfully!
echo.
echo You may need to restart your terminal for PATH changes to take effect.
echo Test with: scalastyle --version

exit /b 0
