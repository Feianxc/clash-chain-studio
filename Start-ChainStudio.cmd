@echo off
setlocal
set "ROOT=%~dp0"
where pwsh >nul 2>nul
if %errorlevel%==0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\Start-ChainStudio.ps1"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\Start-ChainStudio.ps1"
)
endlocal
