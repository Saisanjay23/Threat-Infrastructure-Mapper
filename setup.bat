@echo off
setlocal EnableExtensions EnableDelayedExpansion
REM ---------------------------------------------------------------------------
REM  TIM - one-click setup:
REM    1. install Python + Node dependencies and Playwright Chromium
REM    2. create backend\.env with a random secret key
REM    3. verify MongoDB, create indexes, bootstrap admin, load demo data
REM    4. offer to start TIM
REM ---------------------------------------------------------------------------
set "ROOT=%~dp0"
cd /d "%ROOT%"
echo ===============================================================
echo   Threat Infrastructure Mapper (TIM) - setup
echo ===============================================================

where node >nul 2>&1 || (echo ERROR: Node.js LTS is required: https://nodejs.org/ & pause & exit /b 1)

call "%ROOT%scripts\install_requirements.bat" || (echo Setup aborted. & pause & exit /b 1)

if not exist "%ROOT%backend\.env" (
  echo.
  echo Creating backend\.env with a freshly generated secret key ...
  for /f "usebackq delims=" %%S in (`"%ROOT%backend\.venv\Scripts\python.exe" -c "import secrets;print(secrets.token_urlsafe(48))"`) do set "SECRET=%%S"
  "%ROOT%backend\.venv\Scripts\python.exe" -c "import pathlib,sys;p=pathlib.Path(r'%ROOT%backend');t=(p/'.env.example').read_text();(p/'.env').write_text(t.replace('replace-with-a-long-random-string-of-at-least-32-characters',sys.argv[1]))" "!SECRET!"
) else (
  echo backend\.env already exists - keeping it.
)

echo.
set "SEED=--seed"
set /p "ANS=Load realistic demo data (100 domains, 30 IPs, 15 certificates, 10 clusters)? [Y/n] "
if /I "!ANS!"=="n" set "SEED="
call "%ROOT%scripts\database_setup.bat" !SEED! || (echo Database setup failed - check MongoDB. & pause & exit /b 1)

echo.
echo ===============================================================
echo   Setup complete.
echo   Start TIM any time with: python run.py
echo   UI & API:  http://127.0.0.1:8000
echo   Login:     admin / ChangeMe!2026 (or check backend\.env)
echo ===============================================================
set /p "RUN=Start TIM now? [Y/n] "
if /I not "!RUN!"=="n" python "%ROOT%run.py"
exit /b 0
