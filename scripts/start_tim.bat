@echo off
setlocal EnableExtensions
REM ---------------------------------------------------------------------------
REM  TIM - one-click start: backend + frontend in their own windows, then the UI
REM ---------------------------------------------------------------------------
set "ROOT=%~dp0"
start "TIM backend" cmd /k ""%ROOT%run_backend.bat""
start "TIM frontend" cmd /k ""%ROOT%run_frontend.bat""
echo Waiting for the API to come up ...
set /a TRIES=0
:wait
set /a TRIES+=1
powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/health -TimeoutSec 2) | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if %ERRORLEVEL%==0 goto ready
if %TRIES% GEQ 40 goto ready
timeout /t 1 /nobreak >nul
goto wait
:ready
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:5173"
exit /b 0
