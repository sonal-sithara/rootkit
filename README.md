# RootKit

[![](https://jitpack.io/v/com.github.ssithara/rootkit.svg)](https://jitpack.io/#com.github.ssithara/rootkit)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)

Android security detection library for root, runtime tampering, and environment threats.

## Features

- **Root Detection** — Root binaries, SU commands, Magisk framework, MagiskHide/DenyList
- **Runtime Tampering** — Frida, Xposed/LSPosed, memory tampering, native hooks (inline, GOT, PLT)
- **Environment Detection** — Emulator identification, debugger detection
- **Periodic Monitoring** — Lifecycle-aware periodic checks with sequential, parallel, or staggered execution
- **Result Encryption** — AES-256-GCM encrypted results with per-instance session keys
- **Native Detection** — C/C++ implementations via JNI for low-level checks

## Installation

Add JitPack to your `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

Add the dependency in your app's `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.github.ssithara:rootkit:1.0.0")
}
```

## Quick Start

```kotlin
RootKit(context).use { rootKit ->
    rootKit.initialize()
    
    // Run all detections at once
    val report = rootKit.runAllDetections()
    
    if (report.anyThreatFound(rootKit)) {
        // Security threat detected — take action
    }
    
    // Or check individual detections
    val rootResult = rootKit.decryptResult(rootKit.isRootedDevice())
    if (rootResult == Result.FOUND) {
        // Device is rooted
    }
}
// Automatically disposed via Closeable
```

## Usage

### One-Shot Detection

For apps that check security at startup:

```kotlin
val rootKit = RootKit(context)
rootKit.initialize()

// Individual checks (return encrypted strings)
val isRooted = rootKit.decryptResult(rootKit.isRootedDevice())
val isMagisk = rootKit.decryptResult(rootKit.isMagiskDetected())
val isFrida = rootKit.decryptResult(rootKit.isFridaDetected())
val isEmulator = rootKit.decryptResult(rootKit.isEmulatorDevice())
val isDebugger = rootKit.decryptResult(rootKit.isDebuggerDetected())

rootKit.dispose()
```

### Full Security Report

```kotlin
RootKit(context).use { rootKit ->
    rootKit.initialize()
    val report = rootKit.runAllDetections()
    
    // Decrypted status
    val rootStatus = report.rootStatus(rootKit)     // Result.FOUND / NOT_FOUND / ERROR
    val emulatorStatus = report.emulatorStatus(rootKit)
    
    // All results as a map
    val allResults = report.toDecodedMap(rootKit)
}
```

### Periodic Monitoring

```kotlin
val config = PeriodicCheckConfig.Builder()
    .setInterval(30_000L)           // Check every 30 seconds
    .monitorAllDetections()         // Monitor all detection types
    .setCallback(object : PeriodicCheckConfig.SecurityCallback {
        override fun onDetectionResult(
            type: PeriodicCheckConfig.DetectionType,
            result: PeriodicCheckConfig.DetectionResult
        ) {
            // Handle individual detection result
        }
        
        override fun onCheckCycleComplete(summary: PeriodicCheckConfig.SecuritySummary) {
            // Handle complete check cycle
            if (summary.anyThreatDetected) {
                // Threat found — take action
            }
        }
        
        override fun onError(
            type: PeriodicCheckConfig.DetectionType,
            error: Throwable
        ) {
            // Handle detection error
        }
    })
    .build()

val controller = rootKit.initialize(config)
controller.start()
```

### Lifecycle-Aware Monitoring

Automatically pauses/resumes with Activity lifecycle:

```kotlin
val lifecycleCheck = rootKit.initialize(config)
    .bindToLifecycle(lifecycle)

// Checks auto-pause on onStop, resume on onStart
// Controller auto-disposed on onDestroy
```

### App Visibility-Aware Monitoring

Pauses checks when app goes to background:

```kotlin
val controller = rootKit.initialize(config)
val visibilityCheck = controller.withAppVisibilityAwareness()
controller.start()

// Or continue at reduced frequency in background
val visibilityCheck = controller.withAppVisibilityAwareness(
    AppVisibilityAwareCheck.VisibilityConfig.CONTINUE_REDUCED
)
```

### DSL Builder

```kotlin
val controller = rootKit.initialize {
    setInterval(60_000L)
    addDetections(
        PeriodicCheckConfig.DetectionType.ROOT,
        PeriodicCheckConfig.DetectionType.FRIDA
    )
    setCallback(myCallback)
    setExecutionMode(PeriodicCheckConfig.ExecutionMode.PARALLEL)
}
controller.start()
```

## API Reference

| Method | Returns | Description |
|--------|---------|-------------|
| `initialize()` | `Unit` | Load native library for detection |
| `initialize(config)` | `PeriodicCheckController` | Start periodic monitoring |
| `initialize { }` | `PeriodicCheckController` | DSL-style periodic config |
| `isRootedDevice()` | `String` | Combined root/Magisk/MagiskHide check |
| `isRootDetected()` | `String` | Root binaries and SU commands |
| `isMagiskDetected()` | `String` | Magisk framework detection |
| `isMagiskHideDetected()` | `String` | MagiskHide/DenyList stub detection |
| `isRuntimeTamperingDetected()` | `String` | Combined Frida/Xposed/hooks/memory |
| `isFridaDetected()` | `String` | Frida instrumentation detection |
| `isXposedDetected()` | `String` | Xposed/LSPosed detection |
| `isMemoryTamperingDetected()` | `String` | Memory integrity detection |
| `isNativeHookDetected()` | `String` | Native hook detection |
| `isEmulatorDevice()` | `String` | Emulator detection |
| `isDebuggerDetected()` | `String` | Debugger detection |
| `runAllDetections()` | `SecurityReport` | Run all checks, get typed report |
| `decryptResult(encrypted)` | `Result` | Decrypt encrypted result to enum |
| `getEncryptionKey()` | `String` | Get Base64 AES-256-GCM session key |
| `getRuntimeTamperingDetails()` | `Map<String, Map<String, Any?>>` | Per-vector breakdown |
| `getRuntimeTamperingSummary()` | `RuntimeDetectionSummary?` | Runtime tampering summary |
| `getEmulatorDetails()` | `Map<String, Boolean>` | Emulator check breakdown |
| `getDebuggerDetails()` | `Map<String, Boolean>` | Debugger check breakdown |
| `dispose()` | `Unit` | Release resources |
| `close()` | `Unit` | Closeable — delegates to dispose() |

### Detection Types (PeriodicCheckConfig.DetectionType)

| Type | Description |
|------|-------------|
| `ROOT` | Root binaries and SU commands |
| `MAGISK` | Magisk framework |
| `MAGISK_HIDE` | MagiskHide/DenyList |
| `FRIDA` | Frida instrumentation |
| `XPOSED` | Xposed/LSPosed |
| `MEMORY_TAMPERING` | Memory integrity |
| `NATIVE_HOOK` | Inline/GOT/PLT hooks |
| `RUNTIME_TAMPERING` | All runtime checks combined |
| `DEBUGGER` | Debugger detection |
| `EMULATOR` | Emulator detection |

## Permissions

### QUERY_ALL_PACKAGES

The library requires the `QUERY_ALL_PACKAGES` permission for Magisk stub detection on Android 11+ (API 30+). This permission is declared in the library's `AndroidManifest.xml` and will be merged into your app automatically.

**Google Play Policy**: This permission is classified as a sensitive permission. If you distribute your app on Google Play, you must provide a justification for its use in the Play Console. Acceptable justifications include security-related functionality. See [Google Play's policy](https://support.google.com/googleplay/android-developer/answer/10158779) for details.

If your app does not target Google Play, or does not need Magisk stub detection, the permission can be removed by adding to your app's `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" tools:node="remove" />
```

## ProGuard / R8

The library includes consumer ProGuard rules (`consumer-rules.pro`) that are automatically applied to your app. These rules preserve:
- JNI method names for native detection
- Public API types (`RootKit`, `Result`, periodic check types)
- Kotlin metadata for reflection

No additional ProGuard configuration is required.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `UnsatisfiedLinkError` | Ensure `RootKit.initialize()` is called before any detection. Check that `librootkit.so` is built for your target architecture (arm64-v8a, armeabi-v7a). |
| `IllegalStateException: RootKit is not initialized` | Call `initialize()` before detection methods. |
| `IllegalStateException: RootKit is already initialized` | Create a new `RootKit` instance or call `dispose()` first. |
| Encrypted results can't be decrypted | Use the same `RootKit` instance for both detection and decryption. Each instance has a unique session key. |
| Magisk stub detection fails on Android 11+ | Ensure `QUERY_ALL_PACKAGES` permission is granted. |
| Native logs | Check logcat with tag `DetectMagiskNative`. |
| Periodic checks not running | Ensure `controller.start()` is called. For lifecycle-aware checks, ensure the lifecycle is at least STARTED. |

## Architecture

```
:app → :rootkit → native (librootkit.so)
                  └── xposeddetector (prefab)
                  └── rootbeer-lib
```

### Detection Flow

```
RootKit facade → encrypted results → decryptResult() → Result enum
             ↓
PeriodicCheckController → SecurityCallback → SecuritySummary
```

## License

```
Copyright 2024 Sonal Sithara

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
