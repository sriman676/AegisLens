#!/bin/sh
# Builds a self-contained AegisLens folder with its own Java runtime (jpackage "app-image": no installer tools needed).
# Run from the project folder after "mvn package". Output: target/dist/AegisLens (Windows: AegisLens.exe inside).
# jpackage builds for the OS it runs on, so run it once on each OS you want to ship.
set -e
VERSION=1.0.0
rm -rf target/jpackage-input target/dist
mkdir -p target/jpackage-input
cp "target/aegislens-$VERSION.jar" target/jpackage-input/
jpackage --type app-image --name AegisLens --app-version "$VERSION" \
  --input target/jpackage-input --main-jar "aegislens-$VERSION.jar" --main-class com.aegislens.ui.Launcher \
  --jlink-options "--strip-debug --no-man-pages --no-header-files" --vendor "AegisLens team" --description "Defensive security workbench" --dest target/dist
echo "Done: target/dist/AegisLens"
