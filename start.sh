#!/usr/bin/env sh
# Starts AegisLens on Linux or macOS. Builds the JAR first if it is missing or older than the code (tests skipped;
# run "mvn clean verify" for the full check). Extra arguments are passed on, for example: ./start.sh --headless
set -eu
cd "$(dirname "$0")"
JAR=target/aegislens-1.0.0.jar

if ! command -v java >/dev/null 2>&1; then
  echo "Java was not found. Install JDK 26 or newer and put it on PATH." >&2
  exit 1
fi
version=$(java -version 2>&1 | sed -n 's/.*version "\([0-9][0-9]*\).*/\1/p' | head -n 1)
if [ -z "$version" ] || [ "$version" -lt 26 ]; then
  echo "AegisLens needs Java 26 or newer (found: ${version:-unknown})." >&2
  exit 1
fi

if [ ! -f "$JAR" ] || [ -n "$(find src pom.xml -type f -newer "$JAR" 2>/dev/null | head -n 1)" ]; then
  MVN=""
  if command -v mvn >/dev/null 2>&1; then
    MVN=mvn
  else
    for d in "$HOME"/tools/apache-maven-*/bin/mvn; do
      [ -x "$d" ] && MVN="$d"
    done
  fi
  if [ -z "$MVN" ]; then
    echo "The app needs to be built first, but Maven was not found. Install Maven 3.9 or newer." >&2
    exit 1
  fi
  echo "Building AegisLens (first start or the code changed; about a minute)..."
  "$MVN" -q -DskipTests package
fi

exec java -jar "$JAR" "$@"
