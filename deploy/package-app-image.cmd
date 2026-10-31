@echo off
REM Windows version of package-app-image.sh: builds target\dist\AegisLens\AegisLens.exe with its own Java runtime.
REM Run from the project folder after "mvn package". No WiX or other installer tools are needed for an app-image.
set VERSION=1.0.0
if exist target\jpackage-input rmdir /s /q target\jpackage-input
if exist target\dist rmdir /s /q target\dist
mkdir target\jpackage-input
copy target\aegislens-%VERSION%.jar target\jpackage-input\ >nul || exit /b 1
jpackage --type app-image --name AegisLens --app-version %VERSION% --input target\jpackage-input --main-jar aegislens-%VERSION%.jar --main-class com.aegislens.ui.Launcher --jlink-options "--strip-debug --no-man-pages --no-header-files" --vendor "AegisLens team" --description "Defensive security workbench" --dest target\dist || exit /b 1
echo Done: target\dist\AegisLens\AegisLens.exe
