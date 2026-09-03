# android — Compose client

Kotlin / Jetpack Compose app (`org.derooms.app`). Talks to `rooms-ffi` via UniFFI when `librooms_ffi.so` is on the JNI path, and seals 1:1 payloads with **libsignal-client**.

**minSdk = 26.** The **secure** product flavor ships without third-party analytics.

## Layout

```
android/
├── settings.gradle.kts
├── build.gradle.kts
├── gradle.properties
├── gradlew
└── app/
    ├── build.gradle.kts
    └── src/main/
        ├── jniLibs/*/librooms_ffi.so   # from ../../scripts/build-android-ffi.sh
        ├── java/org/derooms/app/
        │   ├── MainActivity.kt
        │   ├── core/RoomsCore.kt
        │   ├── crypto/IdentityKeystore.kt
        │   ├── signal/SignalSession.kt
        │   ├── peer/                   # 1:1 controller, invites, store
        │   ├── room/                   # room store, URIs, LAN hub
        │   ├── ble/  wifi/  sync/
        │   └── ui/
        ├── java/uniffi/rooms/rooms.kt  # generated
        └── res/
```

## Build

```bash
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)}"

# From repo root:
./scripts/build-android-ffi.sh --all
cd android && ./gradlew :app:assembleSecureDebug :app:testSecureDebugUnitTest
```

APK: `app/build/outputs/apk/secure/debug/app-secure-debug.apk`

## Features

- Onboarding + Keystore-wrapped identity
- Security-limitations disclosure before chat
- 1:1 Signal session, QR invites, LAN / BLE / Wi‑Fi Direct / relay
- Rooms: create, invite, Accept sync, LAN message inbox on a stable listen port
- Secure flavor: no analytics SDKs
