# RootKit SDK — Integration Guide

**RootKit** is a standalone Android security detection library published as `com.ssithara:rootkit`.

## Gradle Dependency

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        mavenCentral()  // or your private registry
    }
}

dependencies {
    implementation("com.ssithara:rootkit:1.1.0")
}
```

## Permissions

### `QUERY_ALL_PACKAGES` (required for full Magisk detection on Android 11+)

This permission is **not declared by the library** — you must add it to your app's manifest yourself if you need Magisk stub detection on Android 11+.

**Android 10 and below:** Automatically granted — no action needed.

**Android 11 and above:** Add to your `AndroidManifest.xml`:

```xml
<uses-permission
    android:name="android.permission.QUERY_ALL_PACKAGES"
    android:maxSdkVersion="32" />
```

You will need to justify this permission to Google Play in your store listing. Without it, Magisk stub detection returns `ERROR` on Android 11+.

### App Zygote Preloading (optional, for faster native init)

The library supports preloading `librootkit.so` in the zygote process for faster initialization. To enable it, add to your app's manifest:

```xml
<application
    android:zygotePreloadName="com.ssithara.rootkit.core.AppZygote">
</application>
```

This is optional — detection works without it, just slightly slower on first call.

## Initialization

Call `RootKit.initialize()` once at app startup, before any detection method:

```kotlin
class MyApp : Application() {
    override fun onCreate() {
        super.onCreate()

        // Simple init — loads native library only
        RootKit(context).use { rootKit ->
            rootKit.initialize()
        }
    }
}
```

### With Periodic Monitoring

```kotlin
val controller = RootKit(context).initialize {
    setInterval(30_000L)                          // Check every 30 seconds
    monitorAllDetections()                       // Monitor all detection categories
    setCallback(object : PeriodicCheckConfig.SecurityCallback {
        override fun onCheckCycleComplete(summary: SecuritySummary) {
            if (summary.anyThreatFound()) {
                // Handle threat detected
            }
        }
        override fun onDetectionResult(type: DetectionType, result: DetectionResult) { }
        override fun onError(type: DetectionType, error: Throwable) { }
    })
}
controller.start()
```

### Lifecycle-Aware (recommended for Activities/Fragments)

```kotlin
class MainActivity : AppCompatActivity() {

    private val rootKit by lazy { RootKit(this) }
    private var lifecycleCheck: LifecycleAwarePeriodicCheck? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val config = PeriodicCheckConfig.Builder()
            .setInterval(30_000L)
            .monitorAllDetections()
            .setCallback(securityCallback)
            .build()

        lifecycleCheck = rootKit.initialize(config).bindToLifecycle(lifecycle)
        lifecycleCheck?.controller?.start()
    }

    override fun onDestroy() {
        lifecycleCheck?.controller?.stop()
        rootKit.close()
        super.onDestroy()
    }
}
```

## Running Detections

### All detections at once

```kotlin
RootKit(context).use { rootKit ->
    rootKit.initialize()
    val report = rootKit.runAllDetections()

    if (report.anyThreatFound()) {
        // Handle threat
    }
}
```

### Individual categories

```kotlin
RootKit(context).use { rootKit ->
    rootKit.initialize()

    val rootEncrypted = rootKit.isRootDetected()
    val rootResult = rootKit.decryptResult(rootEncrypted)  // Result.FOUND / NOT_FOUND / ERROR

    val runtimeEncrypted = rootKit.isRuntimeTamperingDetected()
    val runtimeResult = rootKit.decryptResult(runtimeEncrypted)

    val envEncrypted = rootKit.isEnvironmentThreatDetected()
    val envResult = rootKit.decryptResult(envEncrypted)
}
```

### Runtime tampering detail (Frida, Xposed, Memory, Native Hooks)

```kotlin
RootKit(context).use { rootKit ->
    rootKit.initialize()

    val runtimeEncrypted = rootKit.isRuntimeTamperingDetected()
    if (rootKit.decryptResult(runtimeEncrypted) == Result.FOUND) {
        // Runtime tampering detected — drill down
        rootKit.getRuntimeTamperingSummary()?.let { summary ->
            when {
                summary.fridaDetected -> println("Frida detected")
                summary.xposedDetected -> println("Xposed detected")
                summary.memoryTamperingDetected -> println("Memory tampering detected")
                summary.nativeHookDetected -> println("Native hook detected")
            }
        }
    }
}
```

## Result Decryption

All detection results are encrypted with AES-256-GCM. Use `RootKit.decryptResult()` to decode:

```kotlin
val encrypted: String = rootKit.isRootDetected()
val result: Result = rootKit.decryptResult(encrypted)
// Result.FOUND    — threat detected
// Result.NOT_FOUND — no threat
// Result.ERROR    — detection failed (e.g., permission missing)
```

## Kotlin Coroutines

The library includes `kotlinx-coroutines-android` as an **API dependency** (transitive). This is required for the periodic monitoring feature. If your app does not use coroutines, R8 will strip unused classes.

## Transitive Dependencies

These are automatically pulled in:

| Dependency | Version | Purpose |
|-----------|---------|---------|
| `org.jetbrains.kotlinx:kotlinx-coroutines-android` | 1.7.3 | Coroutine support for periodic checks |
| `androidx.lifecycle:lifecycle-process` | 2.8.7 | Lifecycle-aware periodic checks |

## ProGuard / R8

The library ships `consumer-rules.pro` which is automatically applied to your app's R8 configuration. It ensures:
- JNI native method names are not renamed
- Public API classes are kept
- Kotlin metadata is preserved

No additional keep rules are needed.

## Troubleshooting

### `UnsatisfiedLinkError: dlopen failed: library "librootkit.so" not found`
Ensure `RootKit.initialize()` is called before any detection method. If using a ABI-split APK, verify the AAR includes the native library for your target architectures.

### Magisk stub detection returns `ERROR` on Android 11+
Declare `QUERY_ALL_PACKAGES` in your app manifest. Without this permission, the library cannot query installed packages to detect Magisk stubs.

### AppZygote crashes on Android Q+ devices
The library preloads `librootkit.so` in the zygote process for faster native library loading. If this fails, it fails fast. The detection library will still work via lazy JNI loading — but initialization will be slower on first detection call.

## Public API Reference

| Type | Location |
|------|----------|
| `RootKit` | `com.ssithara.rootkit.RootKit` |
| `Result` enum | `com.ssithara.rootkit.core.Result` |
| `DetectionResult` | `com.ssithara.rootkit.DetectionResult` (typealias) |
| `SecurityReport` | `com.ssithara.rootkit.SecurityReport` |
| `PeriodicCheckConfig` | `com.ssithara.rootkit.core.periodic.PeriodicCheckConfig` |
| `PeriodicCheckController` | `com.ssithara.rootkit.core.periodic.PeriodicCheckController` |
| `LifecycleAwarePeriodicCheck` | `com.ssithara.rootkit.core.periodic.LifecycleAwarePeriodicCheck` |

All detection implementation classes (e.g., `FridaDetection`, `MagiskDetection`) are **internal** and should not be accessed directly.
