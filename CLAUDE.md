# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Android security detection library with two modules:

- `:rootkit` - Security library published as `com.ssithara:rootkit:1.0.0`
- `:app` - Demo app consuming the library with Jetpack Compose UI

## Build Commands

```bash
./gradlew build                    # Build all modules
./gradlew :app:assembleDebug       # Build debug APK
./gradlew :rootkit:assembleRelease # Build library AAR
./gradlew test                     # Run unit tests (host machine)
./gradlew connectedAndroidTest     # Run instrumented tests (device required)
./gradlew clean                    # Clean build artifacts
```

## Architecture

### Module Dependency Graph

```
:app → :rootkit → native (librootkit.so)
                  └── xposeddetector (prefab)
                  └── rootbeer-lib
```

### Library Package Structure

```
com.ssithara.rootkit/
├── RootKit.kt                    # Public facade - single entry point
├── core/                         # Core infrastructure
│   ├── DetectorResult.kt         # Abstract base class for detectors
│   ├── Result.kt                 # Result enum (FOUND/NOT_FOUND)
│   ├── EncryptionService.kt      # AES-GCM encryption (internal)
│   └── AppZygote.kt              # Zygote preload support
├── detection/                    # All detection implementations
│   ├── root/                     # Root, Magisk, MagiskHide
│   ├── runtime/                  # Frida, Xposed, native hooks, memory tampering
│   └── environment/              # Emulator, debugger
└── internal/                     # Utilities and DTOs (not public API)
```

### App Architecture

MVVM with unidirectional data flow:
- `MainActivity.kt` - Single Activity entry point
- `SecurityViewModel.kt` - State management with StateFlow
- `SecurityRepository.kt` - Bridges RootKit library to UI
- Compose screens in `ui/screens/`

## Critical Patterns

### Native Library Initialization

`RootKit.initialize()` MUST be called before using any detection method. It loads `librootkit.so` via JNI.

### Detector Implementation Pattern

All detection classes:
1. Extend `DetectorResult` with `context: Context` constructor parameter
2. Implement `run(): Result` returning `Result.FOUND` or `Result.NOT_FOUND`
3. Register in `RootKit` class using `by lazy` initialization

### Result Encryption

All public detection results are encrypted with AES-GCM via `EncryptionService.encryptWithBase64Key()` before returning. The app module decrypts for display.

### Native Code Integration

- JNI naming pattern: `Java_com_ssithara_rootkit_<Class>_<method>`
- Register new native methods in `rootkit.cpp`
- Update `Android.mk` when adding new source files

## NDK Configuration

- NDK version: `27.0.12077973`
- Build system: **ndk-build** (Android.mk), NOT CMake
- Prefab enabled for `xposeddetector` dependency

## Detection Capabilities

| Detection     | Layer  | Description                              |
|---------------|--------|------------------------------------------|
| Root          | Kotlin | RootBeer lib + custom checks             |
| Magisk        | Native | JNI detection of Magisk framework        |
| MagiskHide    | Kotlin | Stub package analysis                    |
| Frida         | Native | Native detection of Frida instrumentation|
| Xposed        | Native | xposeddetector via prefab                |
| Native Hooks  | Native | PLT/GOT hook detection                   |
| Memory Tamper | Native | Memory integrity checks                  |
| Emulator      | Kotlin | System property analysis                 |
| Debugger      | Kotlin | Debugger attachment detection            |

## Troubleshooting

- **UnsatisfiedLinkError**: Verify NDK version, ensure `RootKit.initialize()` called first
- **Magisk stub detection fails**: Requires `QUERY_ALL_PACKAGES` permission on Android 11+
- **Native logs**: Tagged `DetectMagiskNative` in logcat

## Key Dependencies

- `com.scottyab:rootbeer-lib:0.1.1` - Root detection
- `io.github.vvb2060.ndk:xposeddetector:2.2` - Xposed detection (prefab)
- Jetpack Compose BOM 2024.09.00 (app module)
