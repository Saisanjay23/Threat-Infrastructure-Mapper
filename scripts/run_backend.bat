@echo off
setlocal EnableExtensions
REM ---------------------------------------------------------------------------
REM  TIM - start the FastAPI backend on http://127.0.0.1:8000  (docs: /docs)
REM  Pass --reload for auto-reload during development.
REM ---------------------------------------------------------------------------
set "ROOT=%~dp0"
set "PYEXE=%ROOT%backend\.venv\Scripts\python.exe"
if not exist "%PYEXE%" (
  echo ERROR: backend virtual environment missing. Run setup.bat first.
  pause
  exit /b 1
)
if not exist "%ROOT%backend\.env" (
  echo ERROR: backend\.env missing. Run setup.bat first.
  pause
  exit /b 1
)
title TIM backend
cd /d "%ROOT%backend"
"%PYEXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 %*
