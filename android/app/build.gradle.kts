plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.derooms.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.derooms.app"
        // Locked by ADR-0002 (docs/decisions/ADR-0002-android-min-sdk.md).
        minSdk = 26
        targetSdk = 34
        versionCode = 3
        versionName = "0.1.1-gate1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    flavorDimensions += "distribution"
    productFlavors {
        // FR-UX-004: no third-party analytics SDKs in this flavor (or any current flavor).
        create("secure") {
            dimension = "distribution"
            isDefault = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
        debug {
            isDebuggable = true
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
        // libsignal-client ships desktop natives; strip from Android APK.
        resources {
            excludes += setOf(
                "libsignal_jni*.dylib",
                "libsignal_jni_testing*",
                "signal_jni*.dll",
                "META-INF/proguard/libsignal.pro",
            )
        }
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    // Secure / Gate 1: first-party + AndroidX + crypto (libsignal) — no analytics.
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.0.4")

    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    // UniFFI Kotlin bindings require JNA (Android AAR).
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    // Official Signal Protocol (AGPL). See docs/libsignal-android-plan.md / ADR-0003.
    // Maven Central publishes both artifacts for 0.86.5; Android natives live in
    // libsignal-android.
    implementation("org.signal:libsignal-client:0.86.5")
    implementation("org.signal:libsignal-android:0.86.5")

    // QR show/scan for derooms://invite/v1/ (ZXing — no custom crypto).
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("androidx.appcompat:appcompat:1.6.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.signal:libsignal-client:0.86.5")
}
