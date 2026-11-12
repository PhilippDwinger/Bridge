#!/bin/bash
# Runs the Luau SDK tests with Lune 0.8.9: RFC crypto vectors, Bridge vectors, live test against the Rust fixture
# (cargo build -p bridge-tests --bin sdk-fixture, or BRIDGE_FIXTURE=<path>).
set -e
cd "$(dirname "$0")/.."
lune run tests/crypto.luau
lune run tests/vectors.luau
FIXTURE=${BRIDGE_FIXTURE:-../../target/debug/sdk-fixture}
if [ ! -x "$FIXTURE" ]; then echo "live: skipped (no sdk-fixture)"; exit 0; fi
DIR=$(mktemp -d)
mkfifo "$DIR/in"
"$FIXTURE" < "$DIR/in" > "$DIR/info" &
exec 4>"$DIR/in"
for _ in $(seq 1 100); do [ -s "$DIR/info" ] && break; sleep 0.1; done
BRIDGE_FIXTURE_INFO=$(head -n 1 "$DIR/info") lune run tests/live.luau
exec 4>&-
wait
rm -rf "$DIR"
