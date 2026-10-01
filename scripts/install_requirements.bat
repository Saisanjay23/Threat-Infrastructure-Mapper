@echo off
setlocal EnableExtensions
REM ---------------------------------------------------------------------------
REM  TIM - install all Python and Node.js dependencies + Playwright Chromium
REM ---------------------------------------------------------------------------
set "ROOT=%~dp0"
cd /d "%ROOT%"

echo.
echo [1/4] Locating Python 3.13 ...
set "PY="
py -3.13 -c "import sys" >nul 2>&1 && set "PY=py -3.13"
if not defined PY (
  python -c "import sys; sys.exit(0 if sys.version_info[:2]>=(3,13) else 1)" >nul 2>&1 && set "PY=python"
)
if not defined PY (
  echo ERROR: Python 3.13 was not found. Install it from https://www.python.org/downloads/ and re-run.
  exit /b 1
)
%PY% --version

echo.
echo [2/4] Creating virtual environment backend\.venv and installing Python packages ...
if not exist "%ROOT%backend\.venv\Scripts\python.exe" (
  %PY% -m venv "%ROOT%backend\.venv" || (echo ERROR: venv creation failed & exit /b 1)
)
"%ROOT%backend\.venv\Scripts\python.exe" -m pip install --upgrade pip
"%ROOT%backend\.venv\Scripts\python.exe" -m pip install -r "%ROOT%backend\requirements-dev.txt" || (echo ERROR: pip install failed & exit /b 1)

echo.
echo [3/4] Installing Playwright Chromium (screenshot engine) ...
"%ROOT%backend\.venv\Scripts\python.exe" -m playwright install chromium || (echo WARNING: Playwright browser install failed - screenshots will be unavailable)

echo.
echo [4/4] Installing frontend packages (npm) ...
where npm >nul 2>&1 || (echo ERROR: Node.js / npm not found. Install Node.js LTS from https://nodejs.org/ & exit /b 1)
pushd "%ROOT%frontend"
call npm install --no-audit --no-fund || (popd & echo ERROR: npm install failed & exit /b 1)
popd

echo.
echo Dependencies installed successfully.
exit /b 0
