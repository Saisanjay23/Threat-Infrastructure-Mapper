@echo off
setlocal EnableExtensions
REM ---------------------------------------------------------------------------
REM  TIM - verify MongoDB, create indexes, bootstrap admin + providers
REM  Usage:  database_setup.bat            (setup only)
REM          database_setup.bat --seed     (setup + load demo data)
REM          database_setup.bat --reseed   (wipe demo data and reload it)
REM ---------------------------------------------------------------------------
set "ROOT=%~dp0"
set "PYEXE=%ROOT%backend\.venv\Scripts\python.exe"
if not exist "%PYEXE%" (
  echo ERROR: backend virtual environment missing. Run install_requirements.bat first.
  exit /b 1
)

sc query MongoDB >nul 2>&1
if %ERRORLEVEL%==0 (
  sc query MongoDB | find "RUNNING" >nul || (
    echo Starting MongoDB Windows service ...
    net start MongoDB >nul 2>&1 || echo WARNING: could not start the MongoDB service - start it as Administrator.
  )
) else (
  echo NOTE: no "MongoDB" Windows service found - make sure mongod is running on the URI in backend\.env
)

pushd "%ROOT%backend"
"%PYEXE%" -m app.cli db-setup || (popd & exit /b 1)
if /I "%~1"=="--seed" "%PYEXE%" -m app.cli seed
if /I "%~1"=="--reseed" "%PYEXE%" -m app.cli seed --reset
popd
exit /b 0
