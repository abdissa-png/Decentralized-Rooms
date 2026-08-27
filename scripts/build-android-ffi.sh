#!/usr/bin/env bash
# Build rooms-ffi cdylib for Android ABIs and optionally generate Kotlin bindings.
# Usage:
#   ./scripts/build-android-ffi.sh              # build jniLibs + Kotlin
#   ./scripts/build-android-ffi.sh --bindings   # host .so + Kotlin only
#   ./scripts/build-android-ffi.sh --so-only    # Android .so only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FFI="$ROOT/ffi"
ANDROID_JNI="$ROOT/android/app/src/main/jniLibs"
KOTLIN_OUT="$ROOT/android/app/src/main/java"
MODE="${1:---all}"

export ANDROID_HOME="${ANDROID_HOME:-${HOME}/Android/Sdk}"
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  if [[ -d "$ANDROID_HOME/ndk" ]]; then
    # Prefer newest side-by-side NDK.
    ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME/ndk"/* 2>/dev/null | sort -V | tail -1 || true)"
  fi
fi
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: missing required command: $1" >&2
    exit 1
  }
}

need_cmd rustc
need_cmd cargo

generate_kotlin() {
  echo "==> Building host librooms_ffi for UniFFI bindgen"
  (
    cd "$FFI"
    cargo build
  )
  local lib
  if [[ -f "$FFI/target/debug/librooms_ffi.so" ]]; then
    lib="$FFI/target/debug/librooms_ffi.so"
  elif [[ -f "$FFI/target/debug/librooms_ffi.dylib" ]]; then
    lib="$FFI/target/debug/librooms_ffi.dylib"
  else
    echo "error: host librooms_ffi not found after cargo build" >&2
    exit 1
  fi

  echo "==> Generating Kotlin bindings → $KOTLIN_OUT"
  mkdir -p "$KOTLIN_OUT"
  (
    cd "$FFI"
    if cargo run --quiet --bin uniffi-bindgen -- generate \
      --library "$lib" \
      --language kotlin \
      --out-dir "$KOTLIN_OUT" 2>/dev/null; then
      :
    elif command -v uniffi-bindgen >/dev/null 2>&1; then
      uniffi-bindgen generate --library "$lib" --language kotlin --out-dir "$KOTLIN_OUT"
    else
      echo "error: uniffi-bindgen unavailable. Ensure ffi has bin/uniffi-bindgen.rs" >&2
      exit 1
    fi
  )
  echo "OK: Kotlin bindings generated under $KOTLIN_OUT/uniffi/"
}

build_android_so() {
  if [[ -z "$ANDROID_NDK_HOME" || ! -d "$ANDROID_NDK_HOME" ]]; then
    echo "error: ANDROID_NDK_HOME not set or missing." >&2
    echo "  Install: sdkmanager \"ndk;26.1.10909125\"" >&2
    echo "  Or: export ANDROID_NDK_HOME=/path/to/ndk" >&2
    exit 2
  fi
  export ANDROID_NDK_HOME
  echo "Using NDK: $ANDROID_NDK_HOME"

  need_cmd rustup
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android >/dev/null

  if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "==> Installing cargo-ndk"
    cargo install cargo-ndk --locked
  fi

  echo "==> Cross-compiling librooms_ffi.so (arm64-v8a, armeabi-v7a, x86_64)"
  mkdir -p "$ANDROID_JNI"
  (
    cd "$FFI"
    cargo ndk \
      -t arm64-v8a \
      -t armeabi-v7a \
      -t x86_64 \
      -o "$ANDROID_JNI" \
      build --release
  )
  echo "OK: jniLibs:"
  find "$ANDROID_JNI" -name 'librooms_ffi.so' -print
}

case "$MODE" in
  --bindings)
    generate_kotlin
    ;;
  --so-only)
    build_android_so
    ;;
  --all|"")
    generate_kotlin
    build_android_so
    ;;
  *)
    echo "usage: $0 [--all|--bindings|--so-only]" >&2
    exit 1
    ;;
esac

echo "Done. Next: cd android && ./gradlew :app:assembleSecureDebug"
