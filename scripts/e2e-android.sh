#!/usr/bin/env bash
# Gate 1 Android / device E2E harness.
# Fails clearly when adb devices are missing; runs host companion otherwise.
# With 2+ devices: install secure-debug APK, launch, best-effort UI smoke,
# and capture logcat (identity / libsignal / UniFFI / sync errors).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${HOME}/Android/Sdk}"
export PATH="${ANDROID_HOME}/platform-tools:${ANDROID_HOME}/emulator:${PATH:-}"
PKG="${E2E_PKG:-org.derooms.app}"
ACTIVITY="${E2E_ACTIVITY:-org.derooms.app/.MainActivity}"
LOGDIR="${E2E_LOGDIR:-$ROOT/docs/e2e-artifacts}"
mkdir -p "$LOGDIR"

echo "==> Environment"
echo "ANDROID_HOME=${ANDROID_HOME}"
echo "ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-<unset>}"
command -v adb >/dev/null && adb version | head -1 || echo "adb: missing"
command -v rustc >/dev/null && rustc --version || echo "rustc: missing"

echo "==> Host companion (identity → sign → libp2p sync)"
(
  cd "$ROOT/core"
  cargo test -p rooms-transport --lib two_node_identity_sign_sync_e2e -- --nocapture
  cargo test -p rooms-transport --lib two_node_sync_over_libp2p_streams -- --nocapture
)

echo "==> FFI"
(
  cd "$ROOT/ffi"
  cargo test
)

DEVICES="$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device" {print $1}' || true)"
COUNT="$(printf '%s\n' "$DEVICES" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "==> adb devices (ready): $COUNT"
printf '%s\n' "$DEVICES"

if [[ "$COUNT" -lt 2 ]]; then
  cat <<'EOF' >&2

error: need 2 Android devices/emulators for product E2E-1TO1.
  - Start two AVDs or plug in two API 26+ devices
  - adb devices should list two lines with state "device"
  - Then re-run: ./scripts/e2e-android.sh
  - Manual steps: docs/e2e-1to1-runbook.md

Host companion tests above already passed (interim Gate 1 evidence).
EOF
  exit 3
fi

mapfile -t DEV_ARR < <(printf '%s\n' "$DEVICES" | sed '/^$/d')
A="${DEV_ARR[0]}"
B="${DEV_ARR[1]}"
APK="$ROOT/android/app/build/outputs/apk/secure/debug/app-secure-debug.apk"

if [[ ! -f "$APK" ]]; then
  echo "==> Building secure debug APK"
  (
    cd "$ROOT"
    ./scripts/build-android-ffi.sh --all || {
      echo "warn: native FFI build failed; assembling APK with stub/UniFFI as available" >&2
    }
    cd "$ROOT/android"
    ./gradlew :app:assembleSecureDebug
  )
fi

device_meta() {
  local s="$1"
  echo "serial=$s model=$(adb -s "$s" shell getprop ro.product.model | tr -d '\r') android=$(adb -s "$s" shell getprop ro.build.version.release | tr -d '\r') sdk=$(adb -s "$s" shell getprop ro.build.version.sdk | tr -d '\r') abi=$(adb -s "$s" shell getprop ro.product.cpu.abi | tr -d '\r')"
}

echo "==> Device A: $(device_meta "$A")"
echo "==> Device B: $(device_meta "$B")"

echo "==> Installing on $A and $B"
adb -s "$A" install -r "$APK"
adb -s "$B" install -r "$APK"

# Fresh onboarding for smoke (app data only; no factory reset).
echo "==> Clearing app data on both (clean onboarding smoke)"
adb -s "$A" shell pm clear "$PKG" >/dev/null
adb -s "$B" shell pm clear "$PKG" >/dev/null

echo "==> Clearing logcat buffers"
adb -s "$A" logcat -c || true
adb -s "$B" logcat -c || true

echo "==> Launching $ACTIVITY"
adb -s "$A" shell am start -n "$ACTIVITY" || true
adb -s "$B" shell am start -n "$ACTIVITY" || true
sleep 3

# Best-effort Compose UI automation via uiautomator text bounds.
tap_text() {
  local serial="$1"
  local needle="$2"
  local dump="/tmp/derooms-ui-${serial}.xml"
  adb -s "$serial" shell uiautomator dump /sdcard/derooms-ui.xml >/dev/null 2>&1 || return 1
  adb -s "$serial" pull /sdcard/derooms-ui.xml "$dump" >/dev/null 2>&1 || return 1
  local bounds
  bounds="$(python3 - "$dump" "$needle" <<'PY' || true
import re, sys
path, needle = sys.argv[1], sys.argv[2]
try:
    xml = open(path, encoding="utf-8", errors="ignore").read()
except OSError:
    sys.exit(1)
# Prefer text=, then content-desc=; Compose often exposes button labels as text.
for attr in ("text", "content-desc"):
    for m in re.finditer(
        rf'{attr}="([^"]*)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
        xml,
        re.I,
    ):
        label = m.group(1) or ""
        if needle.lower() not in label.lower():
            continue
        x1, y1, x2, y2 = map(int, m.group(2, 3, 4, 5))
        print((x1 + x2) // 2, (y1 + y2) // 2)
        sys.exit(0)
    # bounds may appear before the attribute
    for m in re.finditer(
        rf'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"[^>]*{attr}="([^"]*)"',
        xml,
        re.I,
    ):
        label = m.group(5) or ""
        if needle.lower() not in label.lower():
            continue
        x1, y1, x2, y2 = map(int, m.group(1, 2, 3, 4))
        print((x1 + x2) // 2, (y1 + y2) // 2)
        sys.exit(0)
sys.exit(1)
PY
)"
  if [[ -z "${bounds:-}" ]]; then
    return 1
  fi
  # shellcheck disable=SC2086
  adb -s "$serial" shell input tap $bounds
  return 0
}

ui_dump_texts() {
  local serial="$1"
  local out="$2"
  local dump="/tmp/derooms-ui-${serial}.xml"
  adb -s "$serial" shell uiautomator dump /sdcard/derooms-ui.xml >/dev/null 2>&1 || {
    echo "(uiautomator dump failed)" >"$out"
    return 1
  }
  adb -s "$serial" pull /sdcard/derooms-ui.xml "$dump" >/dev/null 2>&1 || return 1
  python3 - "$dump" "$out" <<'PY'
import re, sys
xml = open(sys.argv[1], encoding="utf-8", errors="ignore").read()
texts = re.findall(r'text="([^"]+)"', xml)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    for t in texts:
        if t.strip():
            f.write(t + "\n")
print("\n".join(t for t in texts if t.strip())[:2000])
PY
}

smoke_device() {
  local serial="$1"
  local label="$2"
  echo "==> UI smoke on $label ($serial)"
  # Onboarding → Create identity → Disclosure → Continue → Chat status line
  tap_text "$serial" "Create identity" && sleep 2 || echo "warn: could not tap Create identity on $serial"
  # Long disclosure copy may push the accept button below the fold on short screens.
  adb -s "$serial" shell input swipe 400 1200 400 400 300 >/dev/null 2>&1 || true
  sleep 0.5
  if ! tap_text "$serial" "I understand"; then
    adb -s "$serial" shell input swipe 300 900 300 200 300 >/dev/null 2>&1 || true
    sleep 0.5
    tap_text "$serial" "I understand" || echo "warn: could not tap disclosure accept on $serial"
  fi
  sleep 2
  local ui_out="$LOGDIR/ui-${label}-${serial}.txt"
  ui_dump_texts "$serial" "$ui_out" || true
  echo "--- UI texts ($label) ---"
  cat "$ui_out" 2>/dev/null || true
}

smoke_device "$A" "A"
smoke_device "$B" "B"

echo "==> Process check"
for s in "$A" "$B"; do
  echo -n "$s pid: "
  adb -s "$s" shell pidof "$PKG" 2>/dev/null | tr -d '\r' || echo "(not running)"
done

echo "==> Capturing logcat snippets (no secrets expected in filter)"
filter_log() {
  local serial="$1"
  local out="$2"
  # Broad-ish filter; strip lines that look like hex blobs > 40 chars to reduce secret risk.
  adb -s "$serial" logcat -d -v time 2>/dev/null | \
    grep -Ei 'derooms|rooms_ffi|libsignal|UnsatisfiedLink|UniFFI|AndroidRuntime|FATAL|Signal|sync|identity|JNA|dlopen' | \
    grep -Ev '[0-9a-fA-F]{48,}' | \
    tail -n 80 >"$out" || true
  echo "--- logcat $serial (tail) ---"
  cat "$out" || true
}

filter_log "$A" "$LOGDIR/logcat-A-${A}.txt"
filter_log "$B" "$LOGDIR/logcat-B-${B}.txt"

# Summarize automated smoke from UI dumps
summarize() {
  local label="$1"
  local serial="$2"
  local f="$LOGDIR/ui-${label}-${serial}.txt"
  local uniffi="UNKNOWN" libsig="UNKNOWN" identity="UNKNOWN" chat="UNKNOWN"
  if [[ -f "$f" ]]; then
    grep -qi 'UniFFI ok' "$f" && uniffi="ok" || true
    grep -qi 'UniFFI stub' "$f" && uniffi="stub" || true
    grep -qi 'libsignal ok' "$f" && libsig="ok" || true
    grep -qi 'libsignal pending' "$f" && libsig="pending" || true
    grep -qi 'Identity created' "$f" && identity="created" || true
    grep -qi 'Create your identity' "$f" && identity="still_onboarding" || true
    grep -qi '1:1 chat' "$f" && chat="reached" || true
  fi
  echo "SMOKE_$label serial=$serial uniffi=$uniffi libsignal=$libsig identity=$identity chat=$chat"
}

echo "==> Automated smoke summary"
summarize A "$A"
summarize B "$B"

cat <<EOF

==> Automated device smoke complete
Installed + launched on two devices; best-effort onboarding taps + UI/logcat capture.
Artifacts: $LOGDIR

For cross-device invite → establish → seal → sync → decrypt, run:
  ./scripts/e2e-android-cross.sh
Devices: $A , $B
EOF
