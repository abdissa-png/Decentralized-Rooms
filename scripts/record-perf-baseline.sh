#!/usr/bin/env bash
# Record a lightweight host PERF baseline stamp for Gate 2 prep.
# Runs quiet lib tests for MLS crypto nameplates + typed sync objects,
# then writes a stamp under docs/e2e-artifacts/perf/ (creates the dir).
#
# Usage:
#   ./scripts/record-perf-baseline.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/docs/e2e-artifacts/perf"
mkdir -p "$OUT_DIR"

STAMP="$OUT_DIR/baseline-$(date -u +%Y%m%dT%H%M%SZ).txt"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

{
  echo "perf-baseline"
  echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$(hostname 2>/dev/null || echo unknown)"
  echo "cwd=$ROOT"
  echo ""
} >"$STAMP"

cd "$ROOT/core"

echo "==> cargo test -p rooms-mls --lib crypto_ --quiet"
START=$(date +%s)
if cargo test -p rooms-mls --lib crypto_ --quiet >"$TMP" 2>&1; then
  MLS_STATUS=pass
else
  MLS_STATUS=fail
fi
END=$(date +%s)
MLS_SECS=$((END - START))
{
  echo "rooms-mls crypto_ status=$MLS_STATUS elapsed_secs=$MLS_SECS"
  echo "--- rooms-mls output ---"
  cat "$TMP"
  echo ""
} >>"$STAMP"
if [[ "$MLS_STATUS" != pass ]]; then
  echo "rooms-mls crypto_ failed; stamp at $STAMP" >&2
  exit 1
fi

echo "==> cargo test -p rooms-sync --lib typed_ --quiet"
START=$(date +%s)
if cargo test -p rooms-sync --lib typed_ --quiet >"$TMP" 2>&1; then
  SYNC_STATUS=pass
else
  SYNC_STATUS=fail
fi
END=$(date +%s)
SYNC_SECS=$((END - START))
{
  echo "rooms-sync typed_ status=$SYNC_STATUS elapsed_secs=$SYNC_SECS"
  echo "--- rooms-sync output ---"
  cat "$TMP"
  echo ""
  echo "verdict=ok"
} >>"$STAMP"
if [[ "$SYNC_STATUS" != pass ]]; then
  echo "rooms-sync typed_ failed; stamp at $STAMP" >&2
  exit 1
fi

ln -sfn "$(basename "$STAMP")" "$OUT_DIR/latest.txt"
echo "Wrote $STAMP"
echo "Also $OUT_DIR/latest.txt -> $(basename "$STAMP")"
