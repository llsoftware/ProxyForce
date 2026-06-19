@echo off
:: ProxyForce - Offline Dependency Pre-Downloader
:: Run on an INTERNET-CONNECTED machine first.
:: Downloads wheels for Python 3.11, 3.12, and 3.13 so it works
:: regardless of which Python version is on the offline build machine.

cd /d "%~dp0"

echo.
echo ==========================================
echo  ProxyForce - Offline Wheel Downloader
echo ==========================================
echo.

python --version >nul 2>&1
if errorlevel 1 goto NO_PYTHON
goto PYTHON_OK

:NO_PYTHON
echo [ERROR] Python not found in PATH.
echo         Install Python 3.11+ 64-bit on this internet machine.
pause
exit /b 1

:PYTHON_OK
for /f "tokens=2 delims= " %%v in ('python --version') do set PYVER=%%v
echo [+] Python %PYVER% on this machine.
echo.
echo [*] Downloading wheels for Python 3.11, 3.12, and 3.13 ...
echo     This covers most offline build machines.
echo.

if not exist offline_wheels mkdir offline_wheels

:: ── Python 3.11 wheels ────────────────────────────────────────────────────
echo [*] Fetching wheels for Python 3.11 ...
python -m pip download ^
    pyinstaller pyinstaller-hooks-contrib altgraph pefile ^
    --dest offline_wheels ^
    --platform win_amd64 ^
    --python-version 311 ^
    --implementation cp ^
    --only-binary=:all:

:: ── Python 3.12 wheels ────────────────────────────────────────────────────
echo.
echo [*] Fetching wheels for Python 3.12 ...
python -m pip download ^
    pyinstaller pyinstaller-hooks-contrib altgraph pefile ^
    --dest offline_wheels ^
    --platform win_amd64 ^
    --python-version 312 ^
    --implementation cp ^
    --only-binary=:all:

:: ── Python 3.13 wheels ────────────────────────────────────────────────────
echo.
echo [*] Fetching wheels for Python 3.13 ...
python -m pip download ^
    pyinstaller pyinstaller-hooks-contrib altgraph pefile ^
    --dest offline_wheels ^
    --platform win_amd64 ^
    --python-version 313 ^
    --implementation cp ^
    --only-binary=:all:

:: ── Pure-Python packages -- no version constraint ─────────────────────────
echo.
echo [*] Fetching pure-Python wheels ...
python -m pip download ^
    packaging setuptools customtkinter pystray pillow ^
    --dest offline_wheels

echo.
echo [+] Done. All wheels saved to: offline_wheels\
echo.
echo Next steps:
echo   1. Copy this whole folder to the offline build machine
echo   2. Run: STEP2_BUILD_OFFLINE.bat
echo.
pause
