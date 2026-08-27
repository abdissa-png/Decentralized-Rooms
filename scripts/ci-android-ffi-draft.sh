#!/usr/bin/env bash
# Draft CI job fragment for Android FFI (not wired into host rust CI by default).
# Copy into .github/workflows/ when a runner with Android SDK+NDK is available.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "This script documents the Android FFI CI shape."
echo "Required secrets/env: ANDROID_HOME, ANDROID_NDK_HOME (or sdkmanager install)."
echo
cat <<'YAML'
# .github/workflows/android-ffi.yml (draft)
name: Android FFI
on:
  workflow_dispatch:
  push:
    paths: ["ffi/**", "android/**", "scripts/build-android-ffi.sh", "core/**"]
jobs:
  ffi-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: aarch64-linux-android,armv7-linux-androideabi,x86_64-linux-android
      - uses: android-actions/setup-android@v3
      - run: sdkmanager "ndk;26.1.10909125" "platforms;android-34" "build-tools;34.0.0"
      - run: cargo install cargo-ndk --locked
      - run: ./scripts/build-android-ffi.sh --all
      - run: |
          cd android
          ./gradlew :app:assembleSecureDebug :app:testSecureDebugUnitTest
      - uses: actions/upload-artifact@v4
        with:
          name: librooms-ffi-jni
          path: android/app/src/main/jniLibs/**/librooms_ffi.so
YAML

if [[ "${1:-}" == "--local" ]]; then
  exec "$ROOT/scripts/build-android-ffi.sh" --all
fi
