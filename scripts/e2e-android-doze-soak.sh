#!/usr/bin/env bash
# MESH-DOZE / opportunistic sync soak helper (best-effort, 1+ devices).
# Does not claim Gate 2 MESH-DOZE green — records FGS/WM/Sync-now markers + stamps.
#
# Usage:
#   ./scripts/e2e-android-doze-soak.sh              # ~2 min smoke (default)
#   SOAK_MINUTES=15 ./scripts/e2e-android-doze-soak.sh
#   SOAK_MINUTES=120 ALL_DEVICES=1 ./scripts/e2e-android-doze-soak.sh
#   START_FGS=0 ./scripts/e2e-android-doze-soak.sh  # skip lab fgs_start
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${HOME}/Android/Sdk}"
export PATH="${ANDROID_HOME}/platform-tools:${PATH:-}"
PKG="${E2E_PKG:-org.derooms.app}"
LAB="${PKG}/.e2e.E2eLabActivity"
LOGDIR="${E2E_LOGDIR:-$ROOT/docs/e2e-artifacts/doze-soak}"
SOAK_MINUTES="${SOAK_MINUTES:-2}"
START_FGS="${START_FGS:-1}"
ALL_DEVICES="${ALL_DEVICES:-1}"
SCREEN_OFF="${SCREEN_OFF:-1}"
NUDGE_SEC="${NUDGE_SEC:-60}"
SKIP_INSTALL="${SKIP_INSTALL:-0}"
INSTALL_TIMEOUT_SEC="${INSTALL_TIMEOUT_SEC:-90}"
mkdir -p "$LOGDIR"

mapfile -t DEV_ARR < <(adb devices 2>/dev/null | awk 'NR>1 && $2=="device" {print $1}')
COUNT="${#DEV_ARR[@]}"
echo "==> adb devices: $COUNT"
if [[ "$COUNT" -lt 1 ]]; then
  echo "warn: no devices — skipping Doze soak" >&2
  exit 0
fi

if [[ "$ALL_DEVICES" == "1" ]]; then
  SERIALS=("${DEV_ARR[@]}")
else
  SERIALS=("${DEV_ARR[0]}")
fi
echo "==> soak devices=${SERIALS[*]} minutes=$SOAK_MINUTES start_fgs=$START_FGS skip_install=$SKIP_INSTALL"

APK="$ROOT/android/app/build/outputs/apk/secure/debug/app-secure-debug.apk"
if [[ "$SKIP_INSTALL" != "1" && ! -f "$APK" ]]; then
  echo "warn: APK missing at $APK — build assembleSecureDebug first (or SKIP_INSTALL=1)" >&2
  exit 0
fi

lab_cmd() {
  local serial="$1" cmd="$2"
  adb -s "$serial" shell am start -n "$LAB" \
    -a android.intent.action.MAIN \
    --es cmd "$cmd" >/dev/null 2>&1 || true
}

pull_stamps() {
  local serial="$1" outdir="$2"
  mkdir -p "$outdir"
  for f in sync_fgs.stamp sync_opportunistic.stamp sync_now.stamp; do
    adb -s "$serial" shell "run-as $PKG cat files/$f 2>/dev/null" \
      >"$outdir/$f" 2>/dev/null || echo "(missing)" >"$outdir/$f"
  done
}

for SERIAL in "${SERIALS[@]}"; do
  echo "==> preparing $SERIAL"
  if [[ "$SKIP_INSTALL" != "1" ]]; then
    if ! timeout "$INSTALL_TIMEOUT_SEC" adb -s "$SERIAL" install -r "$APK" >/dev/null; then
      echo "warn: install timed out/failed on $SERIAL — continuing with existing APK" >&2
    fi
  else
    echo "  (SKIP_INSTALL=1 — using installed APK)"
  fi
  adb -s "$SERIAL" shell am force-stop "$PKG" || true
  adb -s "$SERIAL" logcat -c || true
  adb -s "$SERIAL" shell dumpsys batterystats --reset >/dev/null 2>&1 || true

  if [[ "$START_FGS" == "1" ]]; then
    lab_cmd "$SERIAL" fgs_start
    sleep 2
  fi
  lab_cmd "$SERIAL" sync_now
  sleep 2
  lab_cmd "$SERIAL" sync_status

  if [[ "$SCREEN_OFF" == "1" ]]; then
    adb -s "$SERIAL" shell input keyevent KEYCODE_SLEEP >/dev/null 2>&1 || \
      adb -s "$SERIAL" shell input keyevent 26 >/dev/null 2>&1 || true
  fi
done

echo "==> soaking ${SOAK_MINUTES}m (screen may sleep; FGS/WM OS-dependent)"
SECS=$((SOAK_MINUTES * 60))
# For multi-hour soaks, nudge less often to reduce wake noise.
if [[ "$SOAK_MINUTES" -ge 30 && "$NUDGE_SEC" -eq 60 ]]; then
  NUDGE_SEC=300
fi
ELAPSED=0
while [[ "$ELAPSED" -lt "$SECS" ]]; do
  for SERIAL in "${SERIALS[@]}"; do
    lab_cmd "$SERIAL" sync_now
    # Heartbeat poll without forcing UI wake every cycle.
    if (( ELAPSED % 300 == 0 )); then
      lab_cmd "$SERIAL" sync_status
    fi
  done
  sleep "$NUDGE_SEC"
  ELAPSED=$((ELAPSED + NUDGE_SEC))
  echo "  … ${ELAPSED}s / ${SECS}s"
done

PASS_ANY=0
SUMMARY_LINES=()
for SERIAL in "${SERIALS[@]}"; do
  DEVDIR="$LOGDIR/$SERIAL"
  mkdir -p "$DEVDIR"
  adb -s "$SERIAL" logcat -d -s DEROOMS_SYNC:I DEROOMS_E2E:I >"$DEVDIR/logcat.txt" || true
  # Also keep legacy flat path for first device.
  cp "$DEVDIR/logcat.txt" "$LOGDIR/${SERIAL}.log" 2>/dev/null || true

  FGS=0
  FGS_BEAT=0
  WM_NOW=0
  SYNC_NOW=0
  OPP=0
  grep -q "E2E_SYNC_FGS_START" "$DEVDIR/logcat.txt" && FGS=1 || true
  grep -q "E2E_SYNC_FGS_HEARTBEAT" "$DEVDIR/logcat.txt" && FGS_BEAT=1 || true
  grep -q "E2E_SYNC_WM_NOW" "$DEVDIR/logcat.txt" && WM_NOW=1 || true
  grep -q "E2E_SYNC_NOW" "$DEVDIR/logcat.txt" && SYNC_NOW=1 || true
  grep -q "E2E_SYNC_OPPORTUNISTIC" "$DEVDIR/logcat.txt" && OPP=1 || true

  pull_stamps "$SERIAL" "$DEVDIR/stamps"
  # Stamp files survive logcat rotation — count as opportunistic evidence.
  if grep -q '^ts=[1-9]' "$DEVDIR/stamps/sync_opportunistic.stamp" 2>/dev/null; then
    OPP=1
  fi
  if grep -q '^ts=[1-9]' "$DEVDIR/stamps/sync_fgs.stamp" 2>/dev/null; then
    FGS=1
  fi
  if grep -q 'heartbeat=1' "$DEVDIR/stamps/sync_fgs.stamp" 2>/dev/null; then
    FGS_BEAT=1
  fi
  adb -s "$SERIAL" shell dumpsys batterystats 2>/dev/null | head -n 80 \
    >"$DEVDIR/batterystats-head.txt" || true
  adb -s "$SERIAL" shell dumpsys activity services "$PKG" 2>/dev/null | head -n 50 \
    >"$DEVDIR/services.txt" || true
  # Best-effort uid power summary line.
  adb -s "$SERIAL" shell dumpsys batterystats 2>/dev/null | \
    grep -E "UID u0a|Estimated power|Foreground services|Wake lock" | head -n 40 \
    >"$DEVDIR/batterystats-grep.txt" || true

  MODEL="$(adb -s "$SERIAL" shell getprop ro.product.model 2>/dev/null | tr -d '\r' || echo unknown)"
  SDK="$(adb -s "$SERIAL" shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r' || echo '?')"
  {
    echo "serial=$SERIAL model=$MODEL sdk=$SDK"
    echo "FGS_START=$FGS FGS_HEARTBEAT=$FGS_BEAT WM_NOW=$WM_NOW SYNC_NOW=$SYNC_NOW OPPORTUNISTIC=$OPP"
  } >"$DEVDIR/summary.txt"

  LINE="serial=$SERIAL model=$MODEL FGS_START=$FGS FGS_HEARTBEAT=$FGS_BEAT WM_NOW=$WM_NOW SYNC_NOW=$SYNC_NOW OPPORTUNISTIC=$OPP"
  SUMMARY_LINES+=("$LINE")
  echo "$LINE"
  if [[ "$SYNC_NOW" -eq 1 || "$WM_NOW" -eq 1 ]]; then
    PASS_ANY=1
  fi
done

{
  echo "as_of=$(date -Iseconds)"
  echo "soak_minutes=$SOAK_MINUTES start_fgs=$START_FGS nudge_sec=$NUDGE_SEC screen_off=$SCREEN_OFF"
  echo "devices=${#SERIALS[@]}"
  for L in "${SUMMARY_LINES[@]}"; do
    echo "$L"
  done
  echo "note=MESH-DOZE Gate 2 not claimed; multi-hour soak numbers are evidence only"
} >"$LOGDIR/summary.txt"

# Keep a convenient batterystats head at the top level (first device).
FIRST="${SERIALS[0]}"
cp "$LOGDIR/$FIRST/batterystats-head.txt" "$LOGDIR/batterystats-head.txt" 2>/dev/null || true
cp "$LOGDIR/$FIRST/services.txt" "$LOGDIR/services.txt" 2>/dev/null || true

echo "Artifacts: $LOGDIR"
if [[ "$PASS_ANY" -eq 1 ]]; then
  echo "PASS doze-soak markers (not full MESH-DOZE Gate 2)"
  exit 0
fi
echo "CONDITIONAL — no sync markers; check OEM / permissions" >&2
exit 2
