# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project Structure

Android security library with two modules:

- `:rootkit` - Library module (published as `com.ssithara:rootkit:1.0.0`)
- `:app` - Demo app consuming the library

### Package Organization

The rootkit library is organized into the following packages:

```
com.ssithara.rootkit/
├── RootKit.kt                    # Public facade (stays at root)
├── core/                         # Core infrastructure
│   ├── DetectorResult.kt         # Abstract base class for detectors
│   ├── Result.kt                 # Result enum (FOUND/NOT_FOUND)
│   ├── EncryptionService.kt      # Encryption utility (internal)
│   └── AppZygote.kt              # Zygote preload support
├── detection/                    # All detection implementations
│   ├── root/                     # Root-related detections
│   │   ├── RootDetection.kt
│   │   ├── MagiskDetection.kt
│   │   └── MagiskHideDetection.kt
│   ├── runtime/                  # Runtime tampering detections
│   │   ├── RuntimeTamperingDetection.kt
│   │   ├── FridaDetection.kt
│   │   ├── XposedDetection.kt
│   │   ├── NativeHookDetection.kt
│   │   └── MemoryTamperingDetection.kt
│   └── environment/              # Environment detections
│       ├── EmulatorDetection.kt
│       └── DebuggerDetection.kt
└── internal/                     # Internal utilities (not part of public API)
    ├── util/
    │   ├── ShellEx.kt
    │   └── ConstData.kt
    └── dto/
        └── MagiskStubInfoDto.kt
```

#### Package Descriptions

- **`core/`** - Core infrastructure classes including the abstract detector base class, result enum, and encryption service
- **`detection/root/`** - Root and Magisk detection implementations
- **`detection/runtime/`** - Runtime tampering detections (Frida, Xposed, native hooks, memory tampering)
- **`detection/environment/`** - Environment checks (emulator, debugger)
- **`internal/`** - Internal utilities and DTOs (not part of public API)

## Build Commands

```bash
./gradlew build                    # Build all modules
./gradlew :app:assembleDebug       # Build debug APK
./gradlew :rootkit:assembleRelease # Build library AAR
./gradlew test                     # Run unit tests (host machine)
./gradlew connectedAndroidTest     # Run instrumented tests (device required)
```

## Critical Patterns

### Native Library Initialization

[`RootKit.initialize()`](rootkit/src/main/java/com/ssithara/rootkit/RootKit.kt) MUST be called before using detection methods - it loads the native `librootkit.so` via JNI.

### Detector Pattern

All detection classes extend [`DetectorResult`](rootkit/src/main/java/com/ssithara/rootkit/core/DetectorResult.kt) and implement `run(): Result` returning `Result.FOUND` or `Result.NOT_FOUND`.

### Result Encryption

All detection results are encrypted with AES-GCM via [`EncryptionService.encryptWithBase64Key()`](rootkit/src/main/java/com/ssithara/rootkit/core/EncryptionService.kt) before returning. App module decrypts for display.

## NDK Configuration

- NDK version: `27.0.12077973` (specified in rootkit/build.gradle.kts)
- Build system: ndk-build (Android.mk), NOT CMake
- Prefab enabled for `xposeddetector` dependency

## Key Dependencies

- `com.scottyab:rootbeer-lib` - Root detection library
- `io.github.vvb2060.ndk:xposeddetector` - Xposed framework detection (via prefab)
