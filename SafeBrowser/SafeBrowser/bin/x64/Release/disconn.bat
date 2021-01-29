@echo off
cd /d "%~dp0"

REM retrieve the current gateway
set dest=0.0.0.0
for /f "tokens=2,3" %%A in ('"route print %dest% | findstr /c:"%dest%" "') do (

REM save the IP and delete the gateway
echo %%A %%B>%dest%.txt
route delete %dest% >nul
)
exit /b