@echo off
cd /d "%~dp0"
py -3.12 install_model_tools.py
if errorlevel 1 echo Python 3.12 is required for full model-format coverage. You can also use Docker.
pause
