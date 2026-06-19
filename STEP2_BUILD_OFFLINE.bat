@echo off
:: ProxyForce - Offline Build Script
:: Run on the AIR-GAPPED build machine.
:: Requires: Python 3.11+ 64-bit, offline_wheels\ folder from STEP1
::
:: Output: dist\ProxyForce.exe  -- single portable exe, copy to any Windows 10/11 machine

setlocal enabledelayedexpansion

echo.
echo ==========================================
echo  ProxyForce - Offline Build
echo ==========================================
echo.

:: ── Check Python ──────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 goto NO_PYTHON
goto PYTHON_OK

:NO_PYTHON
echo [ERROR] Python not found.
echo         Install Python 3.11+ 64-bit using the offline installer.
pause
exit /b 1

:PYTHON_OK
for /f "tokens=2 delims= " %%v in ('python --version') do set PYVER=%%v
echo [+] Python %PYVER%

:: ── Check offline wheels ──────────────────────────────────────────────────
if not exist offline_wheels goto NO_WHEELS
echo [+] offline_wheels\ found.
goto WHEELS_OK

:NO_WHEELS
echo [ERROR] offline_wheels\ folder not found.
echo         Run STEP1_DOWNLOAD_WHEELS.bat on an internet machine first.
pause
exit /b 1

:WHEELS_OK

:: ── Install Python packages from offline wheels ───────────────────────────
echo.
echo [*] Installing Python packages offline...

python -m pip install ^
    --no-index ^
    --find-links=offline_wheels ^
    pyinstaller customtkinter pystray pillow

if errorlevel 1 goto PIP_FAILED
echo [+] Packages installed.
goto PIP_OK

:PIP_FAILED
echo.
echo [ERROR] pip install failed.
echo         Check that offline_wheels\ has all required files.
echo         Re-run STEP1_DOWNLOAD_WHEELS.bat on an internet machine if needed.
pause
exit /b 1

:PIP_OK

:: ── Build with PyInstaller ────────────────────────────────────────────────
echo.
echo [*] Building ProxyForce.exe ...
echo     This takes 1-3 minutes, please wait.
echo.

if exist dist\ProxyForce.exe (
    echo [*] Removing previous build...
    del /f dist\ProxyForce.exe 2>nul
)

python -m PyInstaller proxyforce_onefile.spec --clean --noconfirm

if not exist dist\ProxyForce.exe goto BUILD_FAILED

echo.
echo ==========================================
echo  BUILD SUCCESSFUL
echo ==========================================
echo.
echo  Output:  dist\ProxyForce.exe
echo.
echo  Deploy:  Copy ProxyForce.exe to any Windows 10/11 machine.
echo           Double-click it (approve UAC) and configure your proxy in Settings.
echo           No install required -- runs from anywhere.
echo.

explorer dist
pause
exit /b 0

:BUILD_FAILED
echo.
echo [ERROR] Build failed. Review the output above for details.
pause
exit /b 1
