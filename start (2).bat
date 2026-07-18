@echo off
title NiosE2E Launcher

set URL=https://raw.githubusercontent.com/sanlsan/NiosE2E/main/client.py
set FILE=client.py
set TEMP_FILE=client_new.py

echo [*] Checking for updates from GitHub...
curl -s -o %TEMP_FILE% %URL%

if not exist %TEMP_FILE% (
    echo [!] Failed to download update. Checking local internet connection...
    goto :run
)

if not exist %FILE% (
    move /Y %TEMP_FILE% %FILE% > nul
    echo [+] Client downloaded successfully.
) else (
    fc %FILE% %TEMP_FILE% > nul
    if errorlevel 1 (
        move /Y %TEMP_FILE% %FILE% > nul
        echo [+] Successfully updated to the latest version!
    ) else (
        del %TEMP_FILE%
        echo [*] You already have the latest version.
    )
)

:run
echo [*] Checking dependencies (cryptography)...
pip install cryptography > nul 2>&1

echo [*] Starting NiosE2E...
python %FILE%
pause