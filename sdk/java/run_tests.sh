#!/bin/sh
# Builds the Java SDK and runs its tests (no build tool, JDK ≥ 17). The live test needs the fixture:
# cargo build -p bridge-tests --bin sdk-fixture (or BRIDGE_FIXTURE=<path>).
set -e
cd "$(dirname "$0")"
rm -rf build && mkdir -p build
javac -Xlint:all -Werror -d build $(find src -name '*.java')
java -cp build net.bridge4.VectorsTest ../vectors/vectors.json
FIXTURE=${BRIDGE_FIXTURE:-../../target/debug/sdk-fixture}
if [ -x "$FIXTURE" ]; then java -cp build net.bridge4.LiveTest "$FIXTURE"; else echo "live: skipped (no sdk-fixture)"; fi
