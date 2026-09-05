# Decentralized Encrypted Rooms

Invite-only, end-to-end encrypted messaging with a **Rust** protocol core, **UniFFI** bindings, and an **Android** client. Identity is key-based (not phone numbers). Group membership is a signed CRDT; group media crypto is **OpenMLS**; 1:1 chat uses **Signal Protocol**. LAN sync uses a framed TCP lab transport; a small TCP relay helps when peers are not on the same Wi‑Fi.

Secrets stay on device (Android Keystore wrap). There is no phone-number account system and no third-party analytics in the secure APK flavor.

## What works today

- **Identity** — master identity ≠ device key; create on first launch; wrap the secret blob with Keystore.
- **1:1 chat** — libsignal seal/open, compact QR / `derooms://invite/v1/` pairing, LAN advertise, optional BLE and Wi‑Fi Direct, optional NAT relay fallback.
- **Rooms** — founding, invite QR, Accept gossip over LAN, membership CRDT, opaque signed events, OpenMLS seal when the FFI is built with MLS.
- **Sync** — process-scoped TCP listen on port `44002`, Offer/Want/Have/Ack, inbox that stays up after leaving a room screen.
- **Relay** — self-hosted `rooms-relay` (TCP DRRL splice, default `:44099`), Docker and Fly recipes included.

## Repository layout

```
.
├── core/                 # Rust workspace (protocol & crypto glue)
│   ├── proto/            # canonical encodings / CIDs (BLAKE3)
│   ├── identity/         # IdentityId, device keys
│   ├── room/             # founding event, membership CRDT
│   ├── mls/              # OpenMLS glue (create / welcome / epoch)
│   ├── sync/             # version vectors, CID diff, mesh sketches
│   ├── storage/          # sled-backed local store
│   ├── discovery/        # invite / DHT stubs
│   ├── transport/        # QUIC stack + TCP relay binary
│   ├── signal/           # 1:1 Signal crate surface
│   ├── rooms-core/       # facade re-exports
│   └── spikes/           # learning spikes (Noise, DAG, OpenMLS, …)
├── ffi/                  # UniFFI crate (identity, rooms, MLS, SyncLab)
├── android/              # Kotlin / Jetpack Compose client
├── scripts/              # FFI build, relay, device e2e helpers
├── seeds/                # seed / bootstrap notes
├── Dockerfile            # rooms-relay image
└── fly.toml              # optional Fly TCP service for the relay
```

## Stack

| Concern | Choice |
|---|---|
| Core | Rust 2021 (`rustc` ≥ 1.75) |
| Mobile | Kotlin, Jetpack Compose, minSdk 26 |
| P2P / LAN | libp2p (QUIC) in core; SyncLab TCP on Android |
| Groups | OpenMLS |
| 1:1 | libsignal-client (JNI) |
| Hash / CID | BLAKE3 |
| Local DB | sled (RocksDB remains the longer-term store) |

## Build & test

### Rust core

```bash
cd core
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

CI (GitHub Actions) runs the same checks — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

### UniFFI

```bash
cd ffi
cargo test --lib
```

Cross-compile `librooms_ffi.so` for Android (needs NDK + `cargo-ndk`):

```bash
./scripts/build-android-ffi.sh --all
```

### Android

```bash
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
cd android
./gradlew :app:assembleSecureDebug :app:testSecureDebugUnitTest
```

APK: `android/app/build/outputs/apk/secure/debug/app-secure-debug.apk`

Do not commit `android/local.properties`. Rebuild native libs with the FFI script rather than checking in cargo-ndk `libif_watch-*` leftovers.

### Rooms relay

```bash
./scripts/run-relay.sh
# or
docker build -t rooms-relay .
docker run --rm -p 44099:44099 rooms-relay
```

In the app, paste `HOST:44099` as the NAT relay fallback for 1:1 when peers are not on the same LAN.

## App flow (short)

1. Create identity (once).
2. **1:1** — start listening, share/scan invite QR, send after Signal is ready.
3. **Rooms** — founder: create room, scan the joiner’s **identity QR** (Rooms list → Show my identity QR). Joiner: scan the invite QR. Exchange **sync QRs** on the same Wi‑Fi so messages and Accept receipts move over LAN.

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).
