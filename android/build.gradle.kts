// Top-level Android build — Gate 1 Compose shell + UniFFI (WBS 2.13 / 3.6).
// Kotlin 2.1 required by libsignal-client 0.86.5 metadata.
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "2.1.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.0" apply false
}
