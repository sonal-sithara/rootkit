# Architect Mode Rules

## Module Dependency Graph

```
:app → :rootkit → native (librootkit.so)
                  └── xposeddetector (prefab)
                  └── rootbeer-lib
```

## Detection Layer Architecture

```
RootKit (facade)
    ├── MagiskHideDetection (stub package analysis)
    ├── MagiskDetection (native JNI)
    ├── RootDetection (RootBeer + custom checks)
    ├── EmulatorDetection (system properties)
    └── DebuggerDetection (debugger checks)
```

## Native Layer

- [`rootkit.cpp`](rootkit/src/main/cpp/src/rootkit.cpp) - JNI bindings for Magisk/su path detection
- Uses ndk-build (not CMake) - see [`Android.mk`](rootkit/src/main/cpp/Android.mk)
- xposeddetector integrated via prefab system

## Encryption Flow

All detection results flow through `EncryptionService.encryptWithBase64Key()` using AES-GCM with hardcoded key. App module has matching decryption logic.
