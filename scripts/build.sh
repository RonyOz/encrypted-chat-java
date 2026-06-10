#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
CLASSES_DIR="$BUILD_DIR/classes"

rm -rf "$CLASSES_DIR"
mkdir -p "$CLASSES_DIR"
find "$ROOT_DIR/src/main/java" -name '*.java' -print | sort > "$BUILD_DIR/main-sources.txt"

javac --release 11 -encoding UTF-8 -d "$CLASSES_DIR" @"$BUILD_DIR/main-sources.txt"

jar --create \
    --file "$BUILD_DIR/encrypted-chat.jar" \
    --main-class com.encryptedchat.ChatApplication \
    -C "$CLASSES_DIR" .

jar --create \
    --file "$BUILD_DIR/observer.jar" \
    --main-class com.encryptedchat.observer.SessionObserverApp \
    -C "$CLASSES_DIR" .

echo "Creado: $BUILD_DIR/encrypted-chat.jar"
echo "Creado: $BUILD_DIR/observer.jar"

