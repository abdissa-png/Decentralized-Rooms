#!/usr/bin/env bash
# Cross-device Gate 1 E2E: invite → Signal establish → seal → sync frames → decrypt.
# Requires 2 adb devices on the same LAN.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${HOME}/Android/Sdk}"
export PATH="${ANDROID_HOME}/platform-tools:${ANDROID_HOME}/emulator:${PATH:-}"
PKG="${E2E_PKG:-org.derooms.app}"
LAB="${PKG}/.e2e.E2eLabActivity"
LOGDIR="${E2E_LOGDIR:-$ROOT/docs/e2e-artifacts}"
EXCHANGE_HOST="$LOGDIR/exchange"
mkdir -p "$LOGDIR" "$EXCHANGE_HOST"

echo "==> Host companion"
(
  cd "$ROOT/core"
  cargo test -p rooms-transport --lib two_node_identity_sign_sync_e2e -- --nocapture
  cargo test -p rooms-transport --lib two_node_sync_over_libp2p_streams -- --nocapture
)
(
  cd "$ROOT/ffi"
  cargo test --lib
)

DEVICES="$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device" {print $1}' || true)"
COUNT="$(printf '%s\n' "$DEVICES" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "==> adb devices: $COUNT"
printf '%s\n' "$DEVICES"
if [[ "$COUNT" -lt 2 ]]; then
  echo "error: need 2 devices" >&2
  exit 3
fi
mapfile -t DEV_ARR < <(printf '%s\n' "$DEVICES" | sed '/^$/d')
# Prefer known lab serials when present: Lenovo=consumer(Bob), moto=provider(Alice)
A=""
B=""
for s in "${DEV_ARR[@]}"; do
  case "$s" in
    HA1AFYLS) B="$s" ;; # Bob / consumer (armeabi-v7a tablet)
    ZY323XBNMS) A="$s" ;; # Alice / provider
  esac
done
# Fallback: first=Alice provider, second=Bob consumer
if [[ -z "$A" || -z "$B" ]]; then
  A="${DEV_ARR[0]}"
  B="${DEV_ARR[1]}"
fi
echo "==> Alice(provider)=$A  Bob(consumer)=$B"

APK="$ROOT/android/app/build/outputs/apk/secure/debug/app-secure-debug.apk"
if [[ "${E2E_REBUILD:-1}" == "1" ]] || [[ ! -f "$APK" ]]; then
  echo "==> Building FFI + APK"
  (
    cd "$ROOT"
    ./scripts/build-android-ffi.sh --all
    cd android && ./gradlew :app:assembleSecureDebug
  )
fi

device_ip() {
  local s="$1"
  # Prefer wlan gateway route src
  local ip
  ip="$(adb -s "$s" shell ip route 2>/dev/null | awk '/wlan|wlan0|rmnet_data|eth0/ && /src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' | tr -d '\r')"
  if [[ -z "$ip" ]]; then
    ip="$(adb -s "$s" shell ip -f inet addr show wlan0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | tr -d '\r' | head -1)"
  fi
  if [[ -z "$ip" ]]; then
    ip="$(adb -s "$s" shell ifconfig wlan0 2>/dev/null | awk '/inet addr/{print $2}' | cut -d: -f2 | tr -d '\r')"
  fi
  echo "$ip"
}

echo "==> LAN IPs"
IP_A="$(device_ip "$A")"
IP_B="$(device_ip "$B")"
echo "Alice IP=$IP_A  Bob IP=$IP_B"
if [[ -z "$IP_B" ]]; then
  echo "error: could not discover Bob LAN IP (same Wi-Fi required)" >&2
  exit 4
fi

echo "==> Install + clear"
adb -s "$A" install -r "$APK"
adb -s "$B" install -r "$APK"
adb -s "$A" shell pm clear "$PKG" >/dev/null
adb -s "$B" shell pm clear "$PKG" >/dev/null
adb -s "$A" logcat -c || true
adb -s "$B" logcat -c || true

# App-private exchange: files/derooms-e2e (debuggable → run-as)
EXREL="files/derooms-e2e"

runas_cat() {
  local serial="$1"
  local rel="$2"
  local out="$3"
  adb -s "$serial" shell run-as "$PKG" cat "$rel" | tr -d '\r' >"$out"
}

runas_write() {
  local serial="$1"
  local rel="$2"
  local src="$3"
  local base
  base="$(basename "$rel")"
  adb -s "$serial" push "$src" "/data/local/tmp/derooms-$base" >/dev/null
  adb -s "$serial" shell run-as "$PKG" cp "/data/local/tmp/derooms-$base" "$rel"
  adb -s "$serial" shell rm -f "/data/local/tmp/derooms-$base" >/dev/null || true
}

wait_log() {
  local serial="$1"
  local needle="$2"
  local seconds="${3:-90}"
  local i
  for ((i = 0; i < seconds; i++)); do
    if adb -s "$serial" logcat -d 2>/dev/null | grep -F "DEROOMS_E2E" | grep -F "$needle" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

echo "==> Start Bob consumer (listen on $IP_B)"
adb -s "$B" shell am start -n "$LAB" \
  --es cmd consumer \
  --es advertise_ip "$IP_B" \
  --ei port 44001

if ! wait_log "$B" "E2E_CONSUMER_READY" 90; then
  echo "error: Bob did not become ready" >&2
  adb -s "$B" logcat -d 2>/dev/null | grep -E 'DEROOMS_E2E|AndroidRuntime|FATAL' | tee "$LOGDIR/logcat-bob-fail.txt" | tail -60
  exit 5
fi

echo "==> Pull Bob prekey + listen addr"
runas_cat "$B" "$EXREL/prekey.b64" "$EXCHANGE_HOST/bob_prekey.b64"
runas_cat "$B" "$EXREL/listen_addr.txt" "$EXCHANGE_HOST/bob_listen_addr.txt"
BOB_ADDR="$(tr -d '\r\n' <"$EXCHANGE_HOST/bob_listen_addr.txt")"
echo "Bob dial addr: $BOB_ADDR"

echo "==> Start Alice provider"
adb -s "$A" shell am start -n "$LAB" \
  --es cmd provider

if ! wait_log "$A" "E2E_PROVIDER_READY" 90; then
  echo "error: Alice did not become ready" >&2
  adb -s "$A" logcat -d 2>/dev/null | grep -E 'DEROOMS_E2E|AndroidRuntime|FATAL' | tee "$LOGDIR/logcat-alice-fail.txt" | tail -60
  exit 5
fi

echo "==> Exchange materials"
runas_cat "$A" "$EXREL/device_pubkey.hex" "$EXCHANGE_HOST/alice_device_pubkey.hex"
runas_write "$B" "$EXREL/peer_device_pubkey.hex" "$EXCHANGE_HOST/alice_device_pubkey.hex"
runas_write "$A" "$EXREL/peer_prekey.b64" "$EXCHANGE_HOST/bob_prekey.b64"
runas_write "$A" "$EXREL/peer_listen_addr.txt" "$EXCHANGE_HOST/bob_listen_addr.txt"

echo "==> Waiting for sync + decrypt markers"
SEND_OK=0
DECRYPT_OK=0
if wait_log "$A" "E2E_SYNC_SEND_OK" 90; then
  SEND_OK=1
  echo "Alice: E2E_SYNC_SEND_OK"
fi
if wait_log "$B" "E2E_DECRYPT_OK" 90; then
  DECRYPT_OK=1
  echo "Bob: E2E_DECRYPT_OK"
fi

adb -s "$A" logcat -d 2>/dev/null | grep 'DEROOMS_E2E' | tee "$LOGDIR/logcat-cross-A-${A}.txt" | tail -40
adb -s "$B" logcat -d 2>/dev/null | grep 'DEROOMS_E2E' | tee "$LOGDIR/logcat-cross-B-${B}.txt" | tail -40

grep -E 'E2E_' "$LOGDIR/logcat-cross-A-${A}.txt" >"$LOGDIR/markers-A.txt" || true
grep -E 'E2E_' "$LOGDIR/logcat-cross-B-${B}.txt" >"$LOGDIR/markers-B.txt" || true

if [[ "$SEND_OK" -eq 1 && "$DECRYPT_OK" -eq 1 ]]; then
  echo "==> CROSS-DEVICE E2E PASS"
  echo "PASS" >"$LOGDIR/cross-device-verdict.txt"
  exit 0
fi

echo "==> CROSS-DEVICE E2E FAIL send=$SEND_OK decrypt=$DECRYPT_OK" >&2
echo "FAIL send=$SEND_OK decrypt=$DECRYPT_OK" >"$LOGDIR/cross-device-verdict.txt"
echo "Alice IP=$IP_A Bob IP=$IP_B — ensure same Wi-Fi; check device firewalls." >&2
exit 6
