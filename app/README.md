# Demo App

Reference application demonstrating how to integrate the RootKit security detection library.

## Architecture

MVVM with unidirectional data flow:

```
MainActivity → SecurityViewModel → SecurityRepository → RootKit library
```

- `SecurityViewModel` — StateFlow-based state management
- `SecurityRepository` — Bridges RootKit library to UI, handles result decryption
- Compose screens for each detection category

## Running

```bash
./gradlew :app:assembleDebug
```

Install on device:

```bash
./gradlew :app:installDebug
```

## Screens

| Screen | Detection Category |
|--------|-------------------|
| Dashboard | Overview of all detections |
| Root Detection | Root, Magisk, MagiskHide |
| Runtime Detection | Frida, Xposed, Memory Tampering, Native Hooks |
| Environment Detection | Emulator, Debugger |
