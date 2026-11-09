@echo off
REM Near-live Sysmon for AegisLens: exports new Sysmon events every minute into C:\ProgramData\AegisLens\sysmon.
REM Run ONCE in an administrator terminal:  deploy\windows\install-sysmon-export.cmd [windows-user-who-runs-AegisLens]
REM The task runs as SYSTEM, so the script is copied to a folder only administrators can change, and only that user
REM (plus SYSTEM and administrators) can read the exports. Then set monitor.sysmon.folder=C:\ProgramData\AegisLens\sysmon.
REM Remove everything again with uninstall-sysmon-export.cmd.
setlocal
set "ROOT=%ProgramData%\AegisLens"
set "READER=%~1"
if "%READER%"=="" set "READER=%USERDOMAIN%\%USERNAME%"

net session >nul 2>nul || (
  echo Please run this in an administrator terminal ^(right-click Terminal, Run as administrator^).
  exit /b 2
)
wevtutil gl Microsoft-Windows-Sysmon/Operational >nul 2>nul || (
  echo Sysmon is not installed: its event log Microsoft-Windows-Sysmon/Operational does not exist.
  exit /b 2
)
if not exist "%~dp0sysmon-export.ps1" (
  echo Cannot find sysmon-export.ps1 next to this script.
  exit /b 2
)

if not exist "%ROOT%\sysmon" mkdir "%ROOT%\sysmon" || exit /b 1
REM Only SYSTEM and administrators may change anything here; the reader may only read.
icacls "%ROOT%" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "%READER%:(OI)(CI)RX" >nul || exit /b 1
copy /y "%~dp0sysmon-export.ps1" "%ROOT%\sysmon-export.ps1" >nul || exit /b 1

schtasks /Create /TN "AegisLens Sysmon export" /SC MINUTE /MO 1 /RU SYSTEM /RL HIGHEST /F ^
  /TR "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%ROOT%\sysmon-export.ps1\"" || exit /b 1
schtasks /Run /TN "AegisLens Sysmon export" >nul

echo.
echo Installed. Every minute the newest Sysmon events land in %ROOT%\sysmon (readable by %READER%).
echo Last run status: %ROOT%\last-export.txt
echo Now point AegisLens at that folder: Settings ^> Start-up options ^> monitor.sysmon.folder = %ROOT%\sysmon ^> Restart now
