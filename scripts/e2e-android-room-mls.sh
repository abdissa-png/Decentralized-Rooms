#!/usr/bin/env bash
# Host-side MLS path smoke + instructions for device lab.
# Full 2-device Compose automation is manual (see docs/mls-on-device.md).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/core"
cargo test -p rooms-mls --lib
cd "$ROOT/ffi"
cargo test mls_ffi -- --nocapture
echo "OK: host MLS + FFI session tests green."
echo "Device demo: rebuild FFI (./scripts/build-android-ffi.sh --all), then follow docs/mls-on-device.md"
