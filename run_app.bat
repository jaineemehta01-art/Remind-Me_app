@echo off
setlocal
title 🔔 Remind Me Launcher

REM Launch the aesthetic PowerShell console interface
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0launch.ps1"
if %ERRORLEVEL% EQU 0 goto :EOF

REM Fallback if PowerShell execution is restricted
echo Starting Remind Me App...
start "" "%~dp0index.html"
