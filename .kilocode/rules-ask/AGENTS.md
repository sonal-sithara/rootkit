# Ask Mode Rules

## Module Architecture

- `:rootkit` - Security detection library (root, emulator, debugger, Magisk, overlay)
- `:app` - Demo application showing library usage with Jetpack Compose UI

## Key Detection Capabilities

| Detection     | Class                                                                                         | Method                     |
| ------------- | --------------------------------------------------------------------------------------------- | -------------------------- |
| Root          | [`RootDetection`](rootkit/src/main/java/com/ssithara/rootkit/RootDetection.kt:16)             | `isRootedDevice()`         |
| Magisk Hide   | [`MagiskHideDetection`](rootkit/src/main/java/com/ssithara/rootkit/MagiskHideDetection.kt:12) | Part of `isRootedDevice()` |
| Magisk Native | [`MagiskDetection`](rootkit/src/main/java/com/ssithara/rootkit/MagiskDetection.kt)            | Part of `isRootedDevice()` |
| Emulator      | [`EmulatorDetection`](rootkit/src/main/java/com/ssithara/rootkit/EmulatorDetection.kt)        | `isEmulatorDevice()`       |
| Debugger      | [`DebuggerDetection`](rootkit/src/main/java/com/ssithara/rootkit/DebuggerDetection.kt)        | `isDebuggerDetected()`     |
| Overlay       | [`OverlayDetection`](rootkit/src/main/java/com/ssithara/rootkit/OverlayDetection.kt)          | `detectOverlay()`          |

## Library Publication

Published as `com.ssithara:rootkit:1.0.0` via JitPack (configured in jitpack.yml)
