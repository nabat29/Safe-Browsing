@echo off
cd /d "%~dp0"

REM ensure the settings file exists
set dest=0.0.0.0
if not exist %dest%.txt exit /b 2

REM restore the default gateway
for /f "tokens=1,2" %%A in (%dest%.txt) do (route add %dest% mask %%A %%B >nul)
exit /b