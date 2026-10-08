@echo off
REM ==============================================================================
REM Chameleon Honeypot — Windows Execution Launcher
REM ==============================================================================

set SCRIPT_DIR=%~dp0..
set BIN_PATH=%SCRIPT_DIR%\chameleon.exe
set CONFIG_PATH=%SCRIPT_DIR%\config\config.json

if not exist "%BIN_PATH%" (
    echo [*] Building chameleon.exe for Windows...
    cd /d "%SCRIPT_DIR%"
    go build -o "%BIN_PATH%" .\cmd\chameleon
)

echo [*] Launching Chameleon Cyber Deception Engine...
"%BIN_PATH%" -c "%CONFIG_PATH%" %*
pause
