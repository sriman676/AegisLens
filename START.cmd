@echo off
REM Double-click to start AegisLens. Builds the JAR first if it is missing or older than the code (tests skipped;
REM run "mvn clean verify" for the full check). Extra arguments are passed on, for example: START.cmd --headless
setlocal EnableDelayedExpansion
cd /d "%~dp0"
set "JAR=target\aegislens-1.0.0.jar"

where java >nul 2>nul || (
  echo Java was not found. Install JDK 26 or newer and add its bin folder to PATH.
  goto :fail
)
set "JMAJOR="
for /f "tokens=3" %%v in ('java -version 2^>^&1 ^| findstr /i "version"') do set "JVER=%%~v"
for /f "delims=." %%m in ("!JVER!") do set "JMAJOR=%%m"
if not defined JMAJOR (
  echo Could not read the Java version. AegisLens needs Java 26 or newer.
  goto :fail
)
if !JMAJOR! LSS 26 (
  echo AegisLens needs Java 26 or newer, but "java" on PATH is version !JVER!.
  goto :fail
)

REM Exit code 0 = the JAR exists and is newer than every file in src and pom.xml.
powershell -NoProfile -NonInteractive -Command "$j = Get-Item '%JAR%' -ErrorAction SilentlyContinue; if (-not $j) { exit 1 }; $n = Get-ChildItem src, pom.xml -Recurse -File | Where-Object { $_.LastWriteTime -gt $j.LastWriteTime } | Select-Object -First 1; if ($n) { exit 1 } else { exit 0 }"
if errorlevel 1 call :build || goto :fail

if /i "%~1"=="--headless" goto :console
if /i "%~1"=="--check-config" goto :console
if /i "%~1"=="--siem-test" goto :console
if /i "%~1"=="--version" goto :console
where javaw >nul 2>nul && (
  start "AegisLens" javaw -jar "%JAR%" %*
  exit /b 0
)
:console
java -jar "%JAR%" %*
exit /b %errorlevel%

:build
set "MVN="
where mvn >nul 2>nul && set "MVN=mvn"
if not defined MVN for /d %%d in ("%USERPROFILE%\tools\apache-maven-*") do if exist "%%d\bin\mvn.cmd" set "MVN=%%d\bin\mvn.cmd"
if not defined MVN (
  echo The app needs to be built first, but Maven was not found. Install Maven 3.9 or newer and add it to PATH.
  exit /b 1
)
echo Building AegisLens (first start or the code changed; about a minute)...
call "%MVN%" -q -DskipTests package
if errorlevel 1 (
  echo The build failed; see the messages above.
  exit /b 1
)
exit /b 0

:fail
echo.
pause
exit /b 1
