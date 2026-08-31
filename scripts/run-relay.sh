#!/usr/bin/env bash
# Run the TCP rooms-relay helper for NAT / no-shared-LAN labs.
# Usage:
#   ./scripts/run-relay.sh              # 0.0.0.0:44099
#   ./scripts/run-relay.sh 0.0.0.0:44100
#
# LAN gateway: bind 0.0.0.0, open the TCP port on the host firewall, then paste
# HOST:port into Android Direct message → Manage → Public / NAT relay.
# Invite relay= auto-applies on the peer. Docs: docs/relay-nat.md
# This is self-host. There is no public DeRooms DRRL fleet; do not treat
# bore.pub / this laptop as the product default.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIND="${1:-0.0.0.0:44099}"
cd "$ROOT/core"
echo "==> rooms-relay listening on $BIND"
echo "    Android: Direct message → Manage → Public / NAT relay → Save"
echo "    Invite:  relay=HOST:PORT line auto-applies on peer paste"
echo "    Docs:    docs/relay-nat.md (self-host; no public DeRooms fleet)"
# Print a best-effort LAN hint for physical phones.
if command -v hostname >/dev/null 2>&1; then
  HINT="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  if [[ -n "${HINT:-}" ]]; then
    PORT="${BIND##*:}"
    echo "    Hint:    ${HINT}:${PORT}  (first hostname -I address)"
  fi
fi
exec cargo run -p rooms-transport --bin rooms-relay -- "$BIND"
