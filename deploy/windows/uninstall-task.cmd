@echo off
REM Stops and removes the AegisLens logon task created by install-task.cmd. The data folder is kept.
schtasks /End /TN "AegisLens" >nul 2>nul
schtasks /Delete /TN "AegisLens" /F
