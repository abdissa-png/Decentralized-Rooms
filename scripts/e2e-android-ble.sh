#!/usr/bin/env bash
# Two-device BLE GATT sealed-frame lab (MESH-BLE-TEXT path).
# Requires: Bluetooth ON on both phones; preferably nearby; Wi‑Fi may be off.
# OEM note: some devices disable BLE in airplane mode even when BT appears on.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${HOME}/Android/Sdk}"
export PATH="${ANDROID_HOME}/platform-tools:${PATH:-}"
PKG="${E2E_PKG:-org.derooms.app}"
LAB="${PKG}/.e2e.E2eLabActivity"
LOGDIR="${E2E_LOGDIR:-$ROOT/docs/e2e-artifacts/ble}"
mkdir -p "$LOGDIR"

DEVICES="$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device" {print $1}' || true)"
COUNT="$(printf '%s\n' "$DEVICES" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "==> adb devices: $COUNT"
if [[ "$COUNT" -lt 2 ]]; then
  echo "error: need 2 devices with Bluetooth on" >&2
  exit 3
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
# BLE permissions (API 31+ runtime; location for API ≤30)
for s in "$A" "$B"; do
  adb -s "$s" shell pm grant "$PKG" android.permission.BLUETOOTH_ADVERTISE 2>/dev/null || true
  adb -s "$s" shell pm grant "$PKG" android.permission.BLUETOOTH_SCAN 2>/dev/null || true
  adb -s "$s" shell pm grant "$PKG" android.permission.BLUETOOTH_CONNECT 2>/dev/null || true
  adb -s "$s" shell pm grant "$PKG" android.permission.ACCESS_FINE_LOCATION 2>/dev/null || true
  adb -s "$s" shell svc bluetooth enable 2>/dev/null || true
  adb -s "$s" shell cmd bluetooth_manager enable 2>/dev/null || true
  # BLE scan on API ≤30 typically needs location services on.
  adb -s "$s" shell settings put secure location_mode 3 2>/dev/null || true
  adb -s "$s" logcat -G 16M 2>/dev/null || true
done
sleep 2
for s in "$A" "$B"; do
  state="$(adb -s "$s" shell settings get global bluetooth_on | tr -d '\r')"
  loc="$(adb -s "$s" shell settings get secure location_mode | tr -d '\r')"
  echo "==> $s bluetooth_on=$state location_mode=$loc"
done
adb -s "$A" shell am force-stop "$PKG" || true
adb -s "$B" shell am force-stop "$PKG" || true
adb -s "$A" logcat -c || true
adb -s "$B" logcat -c || true

lab() {
  local serial="$1"
  shift
  adb -s "$serial" shell am start -n "$LAB" \
    -a android.intent.action.MAIN \
    --es cmd "$1" \
    "${@:2}" >/dev/null
}

echo "==> Bob ble_recv (needs location_mode=3 on API≤30)"
lab "$B" ble_recv --ei timeout_sec 90
sleep 3
echo "==> Alice ble_send"
lab "$A" ble_send --ei timeout_sec 75

echo "==> waiting for log markers…"
OK_SEND=0
OK_RECV=0
OK_PEER=0
for _ in $(seq 1 100); do
  if adb -s "$A" logcat -d -s DEROOMS_BLE:I DEROOMS_E2E:I 2>/dev/null | grep -q "E2E_BLE_SEND_OK"; then
    OK_SEND=1
  fi
  if adb -s "$B" logcat -d -s DEROOMS_BLE:I DEROOMS_E2E:I 2>/dev/null | grep -q "E2E_BLE_RECV_OK"; then
    OK_RECV=1
  fi
  if adb -s "$A" logcat -d -s DEROOMS_BLE:I DEROOMS_E2E:I 2>/dev/null | grep -q "E2E_BLE_PEER_SEEN"; then
    OK_PEER=1
  fi
  if [[ "$OK_SEND" -eq 1 && "$OK_RECV" -eq 1 ]]; then
    break
  fi
  sleep 1
done

adb -s "$A" logcat -d -s DEROOMS_BLE:I DEROOMS_E2E:I >"$LOGDIR/alice.log" || true
adb -s "$B" logcat -d -s DEROOMS_BLE:I DEROOMS_E2E:I >"$LOGDIR/bob.log" || true

echo "SEND_OK=$OK_SEND RECV_OK=$OK_RECV PEER_SEEN=$OK_PEER (logs in $LOGDIR)"
if [[ "$OK_SEND" -eq 1 && "$OK_RECV" -eq 1 ]]; then
  echo "PASS MESH-BLE-TEXT lab markers"
  exit 0
fi
echo "FAIL — need location on, phones nearby; RF/OEM flake residual; see $LOGDIR" >&2
exit 1
