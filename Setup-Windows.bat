@echo off
setlocal
cd /d "%~dp0"
py -3.12 --version >nul 2>&1
if not errorlevel 1 (
    py -3.12 setup_device.py --engines all --launch
    goto finished
)
py -3.13 --version >nul 2>&1
if not errorlevel 1 (
    py -3.13 setup_device.py --engines all --launch
    goto finished
)
echo Install Python 3.12 from https://www.python.org/downloads/ then run this file again.
echo Include the Python launcher when installing. See START-HERE.md for details.
:finished
pause
