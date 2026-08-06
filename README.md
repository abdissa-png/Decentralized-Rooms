# Decentralized Encrypted Rooms

Invite-only, end-to-end encrypted messaging with a **Rust** protocol core.
Identity is key-based. Group membership is a signed CRDT; group crypto is
OpenMLS; 1:1 is Signal Protocol. Transports prefer QUIC via libp2p.

## Layout

```
core/     Rust workspace (proto, identity, room, mls, sync, transport, …)
ffi/      UniFFI (next)
android/  Kotlin client (next)
```

## Build

```bash
cd core
cargo test --workspace
```

## License

Dual-licensed under MIT OR Apache-2.0.
