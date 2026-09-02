# seeds

Optional community seed-node / bootstrap helpers.

## Relay (NAT / no shared LAN)

A TCP circuit-relay binary ships from the core workspace (not libp2p circuit v2):

```bash
./scripts/run-relay.sh
# or: cd core && cargo run -p rooms-transport --bin rooms-relay -- 0.0.0.0:44099
```

On Android, paste `HOST:44099` under 1:1 → Connect → NAT relay fallback. The relay sees ciphertext and connection metadata, not message plaintext.

Encrypted shard storage as a durability seed is not in this tree yet.
