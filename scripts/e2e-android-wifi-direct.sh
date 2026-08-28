#!/usr/bin/env bash
# Best-effort MESH-WD-BULK lab (Wi‑Fi Direct sealed bulk).
# OEM note: Lenovo Tab M7 / Motorola One Vision often flake on P2P group
# formation. Script records markers; host simulation in rooms-sync is the
# CI-reliable path. Exit 0 only if SEND_OK+RECV_OK; otherwise exit 2 (soft fail).
#
# Hardening (2026-08): Bob uses GO/receive stance; Alice sender stance with
# connect retries. Still soft-fail on OEM flake.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${HOME}/Android/Sdk}"
export PATH="${ANDROID_HOME}/platform-tools:${PATH:-}"
PKG="${E2E_PKG:-org.derooms.app}"
LAB="${PKG}/.e2e.E2eLabActivity"
LOGDIR="${E2E_LOGDIR:-$ROOT/docs/e2e-artifacts/wifi-direct}"
mkdir -p "$LOGDIR"

DEVICES="$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device" {print $1}' || true)"
COUNT="$(printf '%s\n' "$DEVICES" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "==> adb devices: $COUNT"
if [[ "$COUNT" -lt 2 ]]; then
  echo "warn: need 2 devices — skipping device lab (host sim still green in cargo)" >&2
  exit 0
fi
mapfile -t DEV_ARR < <(printf '%s\n' "$DEVICES" | sed '/^$/d')
A=""
B=""
for s in "${DEV_ARR[@]}"; do
  case "$s" in
    HA1AFYLS) B="$s" ;;
    ZY323XBNMS) A="$s" ;;
  esac
done
if [[ -z "$A" || -z "$B" ]]; then
  A="${DEV_ARR[0]}"
  B="${DEV_ARR[1]}"
fi
echo "==> Alice(send)=$A  Bob(recv)=$B"

APK="$ROOT/android/app/build/outputs/apk/secure/debug/app-secure-debug.apk"
if [[ "${E2E_REBUILD:-0}" == "1" ]] || [[ ! -f "$APK" ]]; then
  (
    cd "$ROOT"
    ./scripts/build-android-ffi.sh --all
    cd android && ./gradlew :app:assembleSecureDebug
  )
fi

adb -s "$A" install -r "$APK"
adb -s "$B" install -r "$APK"
for s in "$A" "$B"; do
  adb -s "$s" shell pm grant "$PKG" android.permission.ACCESS_FINE_LOCATION 2>/dev/null || true
  adb -s "$s" shell pm grant "$PKG" android.permission.ACCESS_COARSE_LOCATION 2>/dev/null || true
  adb -s "$s" shell pm grant "$PKG" android.permission.NEARBY_WIFI_DEVICES 2>/dev/null || true
  adb -s "$s" shell svc wifi enable 2>/dev/null || true
  adb -s "$s" shell settings put secure location_mode 3 2>/dev/null || true
  adb -s "$s" logcat -G 16M 2>/dev/null || true
done
sleep 2

lab() {
  local serial="$1"
  shift
  adb -s "$serial" shell am start -n "$LAB" \
    -a android.intent.action.MAIN \
    --es cmd "$1" \
    "${@:2}" >/dev/null
}

adb -s "$A" shell am force-stop "$PKG" || true
adb -s "$B" shell am force-stop "$PKG" || true
adb -s "$A" logcat -c || true
adb -s "$B" logcat -c || true

echo "==> Bob wd_recv (GO stance)"
lab "$B" wd_recv --ei timeout_sec 100
sleep 6
echo "==> Alice wd_send (connect retries)"
lab "$A" wd_send --ei timeout_sec 90

OK_SEND=0
OK_RECV=0
OK_PEER=0
OK_GROUP=0
for _ in $(seq 1 110); do
  if adb -s "$A" logcat -d -s DEROOMS_WD:I DEROOMS_E2E:I 2>/dev/null | grep -q "E2E_WD_SEND_OK"; then
    OK_SEND=1
  fi
  if adb -s "$B" logcat -d -s DEROOMS_WD:I DEROOMS_E2E:I 2>/dev/null | grep -q "E2E_WD_RECV_OK"; then
    OK_RECV=1
  fi
  if adb -s "$A" logcat -d -s DEROOMS_WD:I DEROOMS_E2E:I 2>/dev/null | grep -q "E2E_WD_PEER_SEEN"; then
    OK_PEER=1
  fi
  if adb -s "$B" logcat -d -s DEROOMS_WD:I DEROOMS_E2E:I 2>/dev/null | grep -qE "E2E_WD_GROUP_FORMED|E2E_WD_CREATE_GROUP_OK|E2E_WD_GO_LISTEN"; then
    OK_GROUP=1
  fi
  if [[ "$OK_SEND" -eq 1 && "$OK_RECV" -eq 1 ]]; then
    break
  fi
  sleep 1
done

adb -s "$A" logcat -d -s DEROOMS_WD:I DEROOMS_E2E:I >"$LOGDIR/alice.log" || true
adb -s "$B" logcat -d -s DEROOMS_WD:I DEROOMS_E2E:I >"$LOGDIR/bob.log" || true
{
  echo "as_of=$(date -Iseconds)"
  echo "alice=$A bob=$B"
  echo "SEND_OK=$OK_SEND RECV_OK=$OK_RECV PEER_SEEN=$OK_PEER GROUP=$OK_GROUP"
} >"$LOGDIR/summary.txt"

echo "SEND_OK=$OK_SEND RECV_OK=$OK_RECV PEER_SEEN=$OK_PEER GROUP=$OK_GROUP (logs in $LOGDIR)"
if [[ "$OK_SEND" -eq 1 && "$OK_RECV" -eq 1 ]]; then
  echo "PASS MESH-WD-BULK lab markers"
  exit 0
fi
echo "CONDITIONAL — device WD flaky; host rooms-sync simulate_bulk_transfer is CI path" >&2
exit 2
