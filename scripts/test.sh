#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_CLASSES_DIR="$ROOT_DIR/build/test-classes"

"$ROOT_DIR/scripts/build.sh"
rm -rf "$TEST_CLASSES_DIR"
mkdir -p "$TEST_CLASSES_DIR"
find "$ROOT_DIR/src/test/java" -name '*.java' -print | sort > "$ROOT_DIR/build/test-sources.txt"

javac --release 11 \
    -encoding UTF-8 \
    -cp "$ROOT_DIR/build/classes" \
    -d "$TEST_CLASSES_DIR" \
    @"$ROOT_DIR/build/test-sources.txt"

java -cp "$ROOT_DIR/build/classes:$TEST_CLASSES_DIR" \
    com.encryptedchat.crypto.CryptoSelfTest

