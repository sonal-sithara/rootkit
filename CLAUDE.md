# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Android security detection library with two modules:

- `:rootkit` - Security library published as `com.ssithara:rootkit:1.0.0`
- `:app` - Demo app consuming the library with Jetpack Compose UI

Project root name is `RootDetection` (set in `settings.gradle.kts`).

## Build Commands

```bash
# Build
./gradlew build                    # Build all modules
./gradlew :app:assembleDebug       # Build debug APK
./gradlew :rootkit:assembleRelease # Build library AAR

# Test
./gradlew test                     # Run all unit tests (host machine)
./gradlew connectedAndroidTest     # Run instrumented tests (device required)

# Single test
./gradlew :app:testDebugUnitTest --tests "com.ssithara.rootdetection.ExampleUnitTest"
./gradlew :app:testDebugUnitTest --tests "com.ssithara.rootdetection.ExampleUnitTest.testMethodName"

# Lint
./gradlew lint                     # Run lint on all modules
./gradlew :rootkit:lint            # Lint only rootkit module

# Clean
./gradlew clean
```

## Architecture

### Module Dependency Graph

```
:app → :rootkit → native (librootkit.so)
                  └── xposeddetector (prefab)
                  └── rootbeer-lib
```

### Library Package Structure (`com.ssithara.rootkit/`)

```
├── RootKit.kt                    # Public facade - single entry point
├── core/                         # Core infrastructure
│   ├── DetectorResult.kt         # Abstract base class for detectors
│   ├── Result.kt                 # Result enum (FOUND/NOT_FOUND/ERROR)
│   ├── EncryptionService.kt      # AES-256-GCM encryption (internal)
│   ├── AppZygote.kt              # Zygote preload support
│   └── periodic/                 # Periodic check infrastructure
├── detection/                    # All detection implementations
│   ├── root/                     # Root, Magisk, MagiskHide
│   ├── runtime/                  # Frida, Xposed, native hooks, memory tampering, runtime tampering (coordinator)
│   └── environment/              # Emulator, debugger
└── internal/                     # Utilities and DTOs (not public API)
```

### App Architecture

MVVM with unidirectional data flow:
- `MainActivity.kt` - Single Activity entry point
- `SecurityViewModel.kt` - State management with StateFlow
- `SecurityRepository.kt` - Bridges RootKit library to UI, handles decryption
- Compose screens in `ui/screens/` (Dashboard, RootDetection, RuntimeDetection, EnvironmentDetection)

Data flow: `RootKit` facade -> encrypted results -> `SecurityRepository` decrypts -> `SecurityViewModel` updates StateFlow -> Compose UI recomposes

### Native Code Structure (`rootkit/src/main/cpp/`)

- `Android.mk` - ndk-build config, auto-discovers all `.c`/`.cpp` in `src/`
- `Application.mk` - arm64-v8a + armeabi-v7a, C++20, c++_shared STL
- `src/rootkit.cpp` - Magisk native detection (su paths, mount paths)
- `src/frida_detection.cpp` - 6 Frida detection methods (ports, memory maps, threads, libraries, fd, env vars)
- `src/xposed_detection.cpp` - 6 Xposed detection methods (memory maps, libraries, zygote, riru, zygisk, hook memory)
- `src/native_hook_detection.cpp` - 5 hook detection methods (inline, GOT, PLT, frameworks, function pointers) with arch-specific code (ARM64/ARM32/x86)
- `src/memory_tampering_detection.cpp` - 6 memory integrity methods

## Critical Patterns

### Native Library Initialization

`RootKit.initialize()` MUST be called before using any detection method. It loads `librootkit.so` via JNI. Three init variants: simple, with `PeriodicCheckConfig`, or with DSL builder.

### Detector Implementation Pattern

All detection classes:
1. Extend `DetectorResult` with `context: Context` constructor parameter
2. Implement `run(): Result` returning `Result.FOUND`, `Result.NOT_FOUND`, or `Result.ERROR`
3. Use `runSafely()` from base class for exception handling
4. Register in `RootKit` class using `by lazy` initialization

When adding a new detector:
- Create class extending `DetectorResult` in the appropriate `detection/` subpackage
- Add `external fun` declarations for any native JNI methods
- JNI naming pattern: `Java_com_ssithara_rootkit_detection_<subcategory>_<Class>_<method>`
- Add new `.cpp` files to `cpp/src/` (auto-discovered by Android.mk)
- Encrypt all public results: `EncryptionService.encryptWithBase64Key(result.name)`

### Result Encryption

All public detection results are encrypted with AES-256-GCM via `EncryptionService.encryptWithBase64Key()` before returning. Per-instance session key generated at runtime. The app module decrypts for display using its own `EncryptionService`.

### Periodic Check System

`core/periodic/` provides lifecycle-aware periodic security checks:
- `PeriodicCheckConfig.Builder` for configuration (interval, detections, callback, execution mode)
- Three execution modes: sequential, parallel, staggered
- `LifecycleAwarePeriodicCheck` binds to Activity/Fragment lifecycle
- `AppVisibilityAwareCheck` pauses checks when app backgrounds
- `CheckExecutionGuard` provides mutex-based overlap protection

### Coordinator Pattern

`RuntimeTamperingDetection` coordinates Frida, Xposed, NativeHook, and MemoryTampering sub-detectors with a 5-second cache and anti-timing-attack jitter.

## NDK Configuration

- NDK version: `27.0.12077973`
- Build system: **ndk-build** (Android.mk), NOT CMake
- Prefab enabled for `xposeddetector` dependency
- Release flags: `-Oz -flto`, hidden visibility, stripped symbols

## Key Versions

- AGP: 8.11.2, Kotlin: 2.2.21, Gradle: 8.13
- compileSdk: 36 (rootkit), 35 (app) / minSdk: 24
- JVM target: Java 11, JitPack: openjdk21

## Code Style

- Official Kotlin code style (set in `gradle.properties`)
- 4-space indentation, same-line opening braces
- Use `by lazy` for expensive initialization
- Use `applicationContext` to prevent Activity/Fragment leaks
- Use `AtomicBoolean`/`AtomicReference` for thread-safe primitives
- Use `WeakReference` for callback storage
- Use `Dispatchers.Default` for computation, `Dispatchers.Main` for UI callbacks
- Return `Result.ERROR` when detection fails rather than throwing

## Key Dependencies

- `com.scottyab:rootbeer-lib:0.1.1` - Root detection
- `io.github.vvb2060.ndk:xposeddetector:2.2` - Xposed detection (prefab)
- `org.jetbrains.kotlinx:kotlinx-coroutines-android` - Coroutines
- Jetpack Compose BOM 2024.09.00 (app module)

## Troubleshooting

- **UnsatisfiedLinkError**: Verify NDK version, ensure `RootKit.initialize()` called first, check `librootkit.so` is built for target architecture
- **Magisk stub detection fails**: Requires `QUERY_ALL_PACKAGES` permission on Android 11+
- **Native logs**: Tagged `DetectMagiskNative` in logcat
- **Encrypted results**: Use `EncryptionService.decryptWithBase64Key()` to view actual values during debugging
