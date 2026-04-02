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
│   ├── AppZygote.kt              # Zygote preload support
│   └── periodic/                 # Periodic check infrastructure
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

- **`core/`** - Core infrastructure classes including the abstract detector base class, result enum, encryption service, and periodic check infrastructure
- **`detection/root/`** - Root and Magisk detection implementations
- **`detection/runtime/`** - Runtime tampering detections (Frida, Xposed, native hooks, memory tampering)
- **`detection/environment/`** - Environment checks (emulator, debugger)
- **`internal/`** - Internal utilities and DTOs (not part of public API)

---

## Build Commands

```bash
# Build all modules
./gradlew build

# Build specific modules
./gradlew :app:assembleDebug       # Build debug APK
./gradlew :rootkit:assembleRelease # Build library AAR

# Run tests
./gradlew test                     # Run all unit tests (host machine)
./gradlew connectedAndroidTest     # Run instrumented tests (device required)

# Run a single test class
./gradlew :app:testDebugUnitTest --tests "com.ssithara.rootdetection.ExampleUnitTest"
./gradlew :rootkit:testDebugUnitTest --tests "com.ssithara.rootkit.ExampleUnitTest"

# Run a single test method
./gradlew :app:testDebugUnitTest --tests "com.ssithara.rootdetection.ExampleUnitTest.testMethodName"

# Lint
./gradlew lint                     # Run lint on all modules
./gradlew :rootkit:lint           # Lint only rootkit module
./gradlew :app:lint               # Lint only app module

# Clean and rebuild
./gradlew clean
./gradlew assembleDebug
```

---

## Critical Patterns

### Native Library Initialization

[`RootKit.initialize()`](rootkit/src/main/java/com/ssithara/rootkit/RootKit.kt) MUST be called before using detection methods - it loads the native `librootkit.so` via JNI.

### Detector Pattern

All detection classes extend [`DetectorResult`](rootkit/src/main/java/com/ssithara/rootkit/core/DetectorResult.kt) and implement `run(): Result` returning `Result.FOUND`, `Result.NOT_FOUND`, or `Result.ERROR`.

### Result Encryption

All detection results are encrypted with AES-GCM via [`EncryptionService.encryptWithBase64Key()`](rootkit/src/main/java/com/ssithara/rootkit/core/EncryptionService.kt) before returning. App module decrypts for display.

---

## NDK Configuration

- NDK version: `27.0.12077973` (specified in rootkit/build.gradle.kts)
- Build system: ndk-build (Android.mk), NOT CMake
- Prefab enabled for `xposeddetector` dependency

---

## Key Dependencies

- `com.scottyab:rootbeer-lib` - Root detection library
- `io.github.vvb2060.ndk:xposeddetector` - Xposed framework detection (via prefab)

---

## Code Style Guidelines

### General Principles

- **Kotlin code style**: Official (set in `gradle.properties`: `kotlin.code.style=official`)
- **JVM target**: Java 11
- **Min SDK**: 24
- **Compile SDK**: 36 (rootkit), 35 (app)

### Naming Conventions

- **Classes**: PascalCase (e.g., `RootDetection`, `EncryptionService`)
- **Functions/Properties**: camelCase (e.g., `isRootedDevice()`, `sessionKey`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `TAG`, `CHECK_TIMEOUT_MS`)
- **Packages**: lowercase with no underscores (e.g., `com.ssithara.rootkit.core`)
- **Private backing fields**: `_fieldName` pattern when paired with public property

### Import Organization

Standard Kotlin import order (no blank lines between groups):
1. Kotlin standard library (`kotlin.*`)
2. Android imports (`android.*`)
3. Java standard library (`java.*`, `javax.*`)
4. Third-party libraries
5. Project imports (grouped by package depth)

### Code Formatting

- **Line length**: Target under 120 characters
- **Indentation**: 4 spaces (no tabs)
- **Braces**: Same-line opening brace for functions/classes
- **Property declarations**: Single line for simple properties, multiline for complex ones
- **Use `by lazy`** for expensive initialization that may not be used

### Type Usage

- Use Kotlin nullable types (`?`) appropriately
- Prefer `val` over `var` - use `var` only when mutation is necessary
- Use explicit types for public API, type inference is acceptable for private/internal code
- Use `AtomicBoolean`, `AtomicReference` for thread-safe primitives
- Use `WeakReference` for callback storage to prevent memory leaks

### Error Handling

- Detection classes should use `runSafely()` from base class for exception handling
- Use `runCatching` for recoverable errors (especially native method calls)
- Return `Result.ERROR` when detection fails rather than throwing
- Log errors with appropriate tag using `android.util.Log`
- Use meaningful error messages in exceptions

### Threading and Coroutines

- Use `CoroutineScope` with `SupervisorJob` for fault isolation
- Use `Dispatchers.Default` for computation, `Dispatchers.Main` for UI callbacks
- Use `withContext` to switch dispatchers
- Use `withTimeout` for operations that should not block indefinitely
- Set thread priority to `THREAD_PRIORITY_BACKGROUND` for detection operations

### Context Usage

- Always use `applicationContext` to prevent Activity/Fragment leaks
- Pass `Context` as constructor parameter, never hold Activity references

### Documentation

- Use KDoc for public API classes and functions
- Include `@throws` annotations for methods that can throw
- Document native method requirements with `@Throws(UnsatisfiedLinkError::class)`
- Use concise, descriptive comments for complex logic

### Testing

- Unit tests go in `src/test/java/`
- Instrumented tests go in `src/androidTest/java/`
- Test class naming: `<ClassName>Test` (e.g., `RootDetectionTest`)
- Test method naming: `test<Description>()` or `<description>_test()`
- Use `@Test` annotation for test methods
- Mock Android context using Mockito or similar for unit tests
