@echo off
setlocal EnableExtensions
title TIM - Public Custom Tunnel (Auto-Reconnect)
set "ROOT=%~dp0"
cd /d "%ROOT%"

echo ===============================================================
echo   Threat Infrastructure Mapper (TIM) - Public Custom Link
echo ===============================================================
echo.
echo URL: https://threat-infrastructure-mapper.loca.lt
echo.
echo Auto-reconnect is ENABLED. If the connection blips, it will
echo automatically reconnect within 2 seconds.
echo Keep this window open while sharing TIM.
echo ===============================================================
echo.

:tunnel_loop
npx --yes localtunnel --port 5173 --subdomain threat-infrastructure-mapper
echo.
echo [!] Tunnel connection dropped. Reconnecting automatically in 2 seconds...
timeout /t 2 /nobreak >nul
goto tunnel_loop
