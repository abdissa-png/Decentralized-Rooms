# ffi — UniFFI Android bindings

Rust crate `rooms-ffi` exposes identity, local room sessions, OpenMLS groups, and the SyncLab TCP node to Kotlin.

This crate lives **outside** `core/` so `cd core && cargo test --workspace` does not require UniFFI.

## Build (no Android SDK required)

```bash
cd ffi
cargo build
cargo test --lib
```

Produces `target/debug/librooms_ffi.so` (Linux) or `.dylib` (macOS).

## UDL surface (`src/rooms.udl`)

| Area | Examples |
|---|---|
| Identity | `create_identity_bundle`, `identity_id_hex_from_secret_blob` |
| Events | `create_signed_text_event` (opaque ciphertext) |
| Rooms | `LocalRoomSession` — invite, accept, membership, `sign_text_event`, state blob |
| MLS | `MlsGroupSession` — create, welcome, commit, seal/open |
| Sync | `SyncLabNode` — listen, push, pull, relay, remember peer VK |

## Generate Kotlin bindings

```bash
cd ffi
cargo build
cargo run --bin uniffi-bindgen -- generate \
  --library target/debug/librooms_ffi.so \
  --language kotlin \
  --out-dir ../android/app/src/main/java
```

One-shot (SDK + NDK):

```bash
./scripts/build-android-ffi.sh --all
```

See [`../android/README.md`](../android/README.md) for the app module.
