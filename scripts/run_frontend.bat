@echo off
setlocal EnableExtensions
REM ---------------------------------------------------------------------------
REM  TIM - start the React UI on http://127.0.0.1:5173 (proxies /api to :8000)
REM ---------------------------------------------------------------------------
set "ROOT=%~dp0"
if not exist "%ROOT%frontend\node_modules" (
  echo ERROR: frontend dependencies missing. Run setup.bat first.
  pause
  exit /b 1
)
title TIM frontend
cd /d "%ROOT%frontend"
call npm run dev
