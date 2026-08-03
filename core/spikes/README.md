# Phase 0 spikes

Learning spikes from `project-plan-timeline.md` §5 (WBS 2.2–2.7). Implement here
before promoting into production crates. **Compose libraries — do not invent crypto.**

| Done | WBS | Spike | Module | Notes |
|:---:|---|---|---|---|
| [x] | 2.2 | Noise XX handshake (`snow`) | `noise` | In-memory XX + one AEAD message |
| [x] | 2.3 | Toy hash-chained / DAG log + signatures | `dag_log` | BLAKE3 ids, ed25519, multi-parent merge |
| [x] | 2.4 | CRDT counter → OR-Set → concurrent merge | `crdt` | G/PN-Counter + add-wins OR-Set |
| [x] | 2.5 | Minimal Kademlia lookup | `kademlia` | Deterministic in-process FIND_NODE (no UDP in CI) |
| [x] | 2.6 | OpenMLS 2–3 member group + membership change | `openmls` | OpenMLS 0.6 + rust crypto provider |
| [x] | 2.7 | libsignal 1:1 hello (bindings survey) | `libsignal` | Survey + stub API (see §2.7) |

**Specs promoted from spikes (WBS 2.8–2.11):** see [`docs/protocol/`](../../docs/protocol/).  
**Gate 0:** **PASSED** (2026-08-05) — [`docs/gate-0-review.md`](../../docs/gate-0-review.md); spike limitations below are **accepted** as learning-spike scope.  
**Phase 1 status:** [`docs/phase-1-status.md`](../../docs/phase-1-status.md).

Run from `core/`:

```bash
cargo test -p rooms-spikes
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

## Limitations

### 2.2 Noise XX
- Uses `snow` 0.10 with `Noise_XX_25519_ChaChaPoly_SHA256`.
- In-memory only; production sessions come from **libp2p Noise**.

### 2.3 DAG log
- Toy canonical bytes (`rooms-spike/dag-event/v0`) — superseded for product by
  `docs/protocol/event-encoding.md` (`rooms/MessageEvent/v1`).
- No gossip, compaction, or partial-order sync protocol (see sync-frames draft).

### 2.4 CRDT
- Educational OR-Set (dot union / add-wins). Not wired to room membership ACL.
- No delta-CRDT wire codec yet (feeds WBS 2.11 sync sketch).

### 2.5 Kademlia
- **No UDP in CI.** Iterative FIND_NODE over a `HashMap` of simulated nodes with
  XOR distance and k-buckets (`K=3`, `α=2`).
- No FIND_VALUE, republish, or S/Kademlia hardening — production uses **libp2p Kademlia**.

### 2.6 OpenMLS
- Pinned to **openmls 0.6** + `openmls_rust_crypto` 0.3 + `openmls_basic_credential` 0.3
  (stable line; 0.9 is still RC and needs rustc ≥ 1.91).
- Creates Alice group → adds Bob → adds Charlie → app message → removes Bob;
  asserts epoch advances. In-memory provider only.

### 2.7 libsignal — ADR-style note

| Option | Verdict |
|---|---|
| crates.io `libsignal-protocol` 0.1 | **Reject** — abandoned C FFI wrapper |
| `libsignal-protocol-syft` / community forks | Heavy + often **AGPL**; license review needed |
| Official [signalapp/libsignal](https://github.com/signalapp/libsignal) | **Recommended** — Java/Swift/Rust; Android via JNI/AAR |

**Phase 1 approach:** Keep a `SignalSession` trait/API in a future `signal-glue`
crate (stubbed here). For the Android hello app, call **libsignal-client** from
Kotlin/JNI for 1:1 crypto first; UniFFI the Rust core for identity/DAG/sync.
Optionally vendor Signal’s Rust `protocol` crate via git dependency after build
and license review. **Do not invent X3DH / Double Ratchet.**

The `libsignal` module’s `seal_stub` / `open_stub` are compile-checked placeholders
only (XOR pad) — not cryptography.
