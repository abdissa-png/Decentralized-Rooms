#!/usr/bin/env bash
# Product-path peer chat smoke via PeerChatController (same mechanisms as Compose UI).
# Lab cmds: peer_recv / peer_send on E2eLabActivity. Does not click Compose widgets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${HOME}/Android/Sdk}"
export PATH="${ANDROID_HOME}/platform-tools:${PATH:-}"
PKG="${E2E_PKG:-org.derooms.app}"
LAB="${PKG}/.e2e.E2eLabActivity"
LOGDIR="${E2E_LOGDIR:-$ROOT/docs/e2e-artifacts}"
EXCHANGE_HOST="$LOGDIR/exchange-peer-ui"
mkdir -p "$LOGDIR" "$EXCHANGE_HOST"

DEVICES="$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device" {print $1}' || true)"
COUNT="$(printf '%s\n' "$DEVICES" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "==> adb devices: $COUNT"
if [[ "$COUNT" -lt 2 ]]; then
  echo "error: need 2 devices" >&2
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

device_ip() {
  local s="$1"
  local ip
  ip="$(adb -s "$s" shell ip route 2>/dev/null | awk '/wlan|wlan0|rmnet_data|eth0/ && /src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' | tr -d '\r')"
  if [[ -z "$ip" ]]; then
    ip="$(adb -s "$s" shell ip -f inet addr show wlan0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | tr -d '\r' | head -1)"
  fi
  echo "$ip"
}

IP_B="$(device_ip "$B")"
echo "Bob IP=$IP_B"
if [[ -z "$IP_B" ]]; then
  echo "error: Bob LAN IP missing" >&2
  exit 4
fi

adb -s "$A" install -r "$APK"
adb -s "$B" install -r "$APK"
adb -s "$A" shell pm clear "$PKG" >/dev/null
adb -s "$B" shell pm clear "$PKG" >/dev/null
adb -s "$A" logcat -c || true
adb -s "$B" logcat -c || true

EXREL="files/derooms-e2e"

runas_cat() {
  adb -s "$1" shell run-as "$PKG" cat "$2" | tr -d '\r' >"$3"
}

runas_write() {
  local serial="$1" rel="$2" src="$3" base
  base="$(basename "$rel")"
  adb -s "$serial" push "$src" "/data/local/tmp/derooms-$base" >/dev/null
  adb -s "$serial" shell run-as "$PKG" cp "/data/local/tmp/derooms-$base" "$rel"
  adb -s "$serial" shell rm -f "/data/local/tmp/derooms-$base" >/dev/null || true
}

wait_log() {
  local serial="$1" needle="$2" seconds="${3:-90}" i
  for ((i = 0; i < seconds; i++)); do
    if adb -s "$serial" logcat -d 2>/dev/null | grep -F "DEROOMS_E2E" | grep -F "$needle" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

echo "==> Bob peer_recv"
adb -s "$B" shell am start -n "$LAB" \
  --es cmd peer_recv \
  --es advertise_ip "$IP_B" \
  --ei port 44001

if ! wait_log "$B" "E2E_PEER_UI_RECV_READY" 60; then
  echo "error: peer_recv not ready" >&2
  adb -s "$B" logcat -d 2>/dev/null | grep -E 'DEROOMS_E2E|AndroidRuntime' | tail -40
  exit 5
fi

runas_cat "$B" "$EXREL/peer_invite.txt" "$EXCHANGE_HOST/peer_invite.txt"

echo "==> Alice peer_send"
adb -s "$A" shell am start -n "$LAB" --es cmd peer_send

if ! wait_log "$A" "E2E_PEER_UI_SEND_READY" 60; then
  echo "error: peer_send not ready" >&2
  exit 5
fi

# Push invite to Alice; Alice writes sender card; pull card to Bob.
for ((i = 0; i < 90; i++)); do
  if adb -s "$A" shell run-as "$PKG" test -d files/derooms-e2e 2>/dev/null; then
    break
  fi
  sleep 1
done
runas_write "$A" "$EXREL/peer_invite.txt" "$EXCHANGE_HOST/peer_invite.txt"

# Wait for Alice sender card, copy to Bob, then signal Alice to send.
CARD_OK=0
for ((i = 0; i < 60; i++)); do
  if adb -s "$A" shell run-as "$PKG" cat "$EXREL/peer_sender_card.txt" 2>/dev/null | tr -d '\r' | grep -q DEROOMS_SENDER; then
    runas_cat "$A" "$EXREL/peer_sender_card.txt" "$EXCHANGE_HOST/peer_sender_card.txt"
    runas_write "$B" "$EXREL/peer_sender_card.txt" "$EXCHANGE_HOST/peer_sender_card.txt"
    echo "go" >"$EXCHANGE_HOST/peer_go_send.txt"
    runas_write "$A" "$EXREL/peer_go_send.txt" "$EXCHANGE_HOST/peer_go_send.txt"
    CARD_OK=1
    break
  fi
  sleep 1
done
if [[ "$CARD_OK" -ne 1 ]]; then
  echo "error: Alice did not write sender card" >&2
  exit 5
fi

# Give Bob a moment to pasteSenderCard + start pull before Alice sends.
sleep 3

SEND_OK=0
DECRYPT_OK=0
if wait_log "$A" "E2E_PEER_UI_SEND_OK" 90; then SEND_OK=1; fi
if wait_log "$B" "E2E_PEER_UI_DECRYPT_OK" 90; then DECRYPT_OK=1; fi

adb -s "$A" logcat -d 2>/dev/null | grep 'DEROOMS_E2E' | tee "$LOGDIR/logcat-peer-ui-A.txt" | tail -30
adb -s "$B" logcat -d 2>/dev/null | grep 'DEROOMS_E2E' | tee "$LOGDIR/logcat-peer-ui-B.txt" | tail -30

if [[ "$SEND_OK" -eq 1 && "$DECRYPT_OK" -eq 1 ]]; then
  echo "==> PEER UI PATH E2E PASS"
  echo "PASS" >"$LOGDIR/peer-ui-verdict.txt"
  exit 0
fi
echo "==> PEER UI PATH E2E FAIL send=$SEND_OK decrypt=$DECRYPT_OK" >&2
echo "FAIL send=$SEND_OK decrypt=$DECRYPT_OK" >"$LOGDIR/peer-ui-verdict.txt"
exit 6
