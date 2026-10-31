@echo off
REM Runs AegisLens headless at logon for the current user with Windows Task Scheduler (no admin rights needed).
REM Usage: install-task.cmd "C:\path\to\aegislens-1.0.0.jar"
REM Remove it again with uninstall-task.cmd. Logs and data: %USERPROFILE%\.aegislens
if "%~1"=="" (
  echo Usage: %~nx0 "C:\path\to\aegislens-1.0.0.jar"
  exit /b 2
)
if not exist "%~1" (
  echo Cannot find %~1
  exit /b 2
)
where javaw >nul 2>nul || (
  echo javaw.exe is not on PATH. Install JDK 26 and add its bin folder to PATH.
  exit /b 2
)
schtasks /Create /TN "AegisLens" /TR "javaw -jar \"%~f1\" --headless" /SC ONLOGON /RL LIMITED /F
if errorlevel 1 exit /b 1
echo Installed. It starts at your next logon; start it now with:  schtasks /Run /TN "AegisLens"
