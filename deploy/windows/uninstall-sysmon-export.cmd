@echo off
REM Removes the near-live Sysmon export: the scheduled task, the script and the exports (they contain private data).
REM Run in an administrator terminal. Also clear monitor.sysmon.folder in AegisLens (Settings > Start-up options).
setlocal
set "ROOT=%ProgramData%\AegisLens"
net session >nul 2>nul || (
  echo Please run this in an administrator terminal.
  exit /b 2
)
schtasks /Delete /TN "AegisLens Sysmon export" /F
if exist "%ROOT%\sysmon" rmdir /s /q "%ROOT%\sysmon"
if exist "%ROOT%\sysmon-export.ps1" del /q "%ROOT%\sysmon-export.ps1"
if exist "%ROOT%\last-export.txt" del /q "%ROOT%\last-export.txt"
rmdir "%ROOT%" 2>nul
echo Removed.
