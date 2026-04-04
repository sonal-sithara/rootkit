# Implementation Plan: RootKit Code Issues

## Files to Modify

- `rootkit/src/main/java/com/ssithara/rootkit/internal/util/ShellEx.kt`
- `rootkit/src/main/java/com/ssithara/rootkit/RootKit.kt`
- `rootkit/src/main/java/com/ssithara/rootkit/core/periodic/PeriodicCheckControllerImpl.kt`
- `rootkit/src/main/java/com/ssithara/rootkit/detection/root/RootDetection.kt`
- `rootkit/src/main/java/com/ssithara/rootkit/core/AppZygote.kt`

---

## Issue 1: ShellEx.kt:36-37 - NPE Risk with Non-Nullable Assertion

**File:** `rootkit/src/main/java/com/ssithara/rootkit/internal/util/ShellEx.kt`

**Problem:** The pattern `while (`in`.readLine().also { line = it } != null)` combined with `fullResponse.add(line!!)` is:
1. Confusing and non-idiomatic
2. The `line!!` assertion is technically unnecessary but creates a subtle hazard

**Current Code (lines 34-38):**
```kotlin
var line: String?
while (`in`.readLine().also { line = it } != null) {
    fullResponse.add(line!!)
}
```

**Fix:** Use a more idiomatic pattern that eliminates the assertion:
```kotlin
var line: String? = `in`.readLine()
while (line != null) {
    fullResponse.add(line)
    line = `in`.readLine()
}
```

**Alternative Fix (more concise):**
```kotlin
`in`.forEachLine { line ->
    fullResponse.add(line)
}
```

---

## Issue 2: ShellEx.kt:76-85 - Race Condition on `exitCode`

**File:** `rootkit/src/main/java/com/ssithara/rootkit/internal/util/ShellEx.kt`

**Problem:** `exitCode` is a plain `Int` modified by a waiter thread and read by the main thread without synchronization. This is a data race per JMM.

**Current Code (lines 75-94):**
```kotlin
var exitCode = -1
val waiter = Thread {
    try {
        exitCode = process.waitFor()
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
    }
}.also {
    it.isDaemon = true
    it.start()
}

waiter.join(TIMEOUT_MS)

when {
    waiter.isAlive -> true
    else -> exitCode == 0
}
```

**Fix:** Use `AtomicInteger` for proper visibility guarantees:
```kotlin
import java.util.concurrent.atomic.AtomicInteger

// In the class, change the method:
fun executeCommandSU(shellCmd: SHELL_CMD): Boolean {
    val process = try {
        Runtime.getRuntime().exec(shellCmd.command)
    } catch (e: Exception) {
        return false
    }

    return try {
        process.outputStream.close()

        val exitCode = AtomicInteger(-1)
        val waiter = Thread {
            try {
                exitCode.set(process.waitFor())
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        waiter.join(TIMEOUT_MS)

        when {
            waiter.isAlive -> true
            else -> exitCode.get() == 0
        }
    } catch (e: Exception) {
        false
    } finally {
        process.destroy()
    }
}
```

---

## Issue 3: RootKit.kt:295-310 - Inconsistent FOUND/ERROR Priority

**File:** `rootkit/src/main/java/com/ssithara/rootkit/RootKit.kt`

**Problem:** The logic checks `FOUND in detections` then `ERROR in detections`, but the intent is to prioritize FOUND over ERROR. The current logic is actually correct but confusingly written.

**Current Code (lines 303-308):**
```kotlin
val isRooted = if (Result.FOUND in detections)
    Result.FOUND
else if (Result.ERROR in detections)
    Result.ERROR
else
    Result.NOT_FOUND
```

**Fix:** Simplify for clarity using when expression:
```kotlin
val isRooted = when {
    detections.any { it == Result.FOUND } -> Result.FOUND
    detections.any { it == Result.ERROR } -> Result.ERROR
    else -> Result.NOT_FOUND
}
```

---

## Issue 4: PeriodicCheckControllerImpl.kt:253 - Parallel Execution Swallows Exceptions

**File:** `rootkit/src/main/java/com/ssithara/rootkit/core/periodic/PeriodicCheckControllerImpl.kt`

**Problem:** `async { }` can throw if the block throws before suspending (e.g., during `executeDetectionSafely` which uses `withTimeout`). Unlike sequential execution where exceptions are caught by `executeDetectionSafely`, parallel execution can propagate exceptions via `awaitAll()`.

**Current Code (lines 253-261):**
```kotlin
private suspend fun executeParallel(): List<PeriodicCheckConfig.DetectionResult> = coroutineScope {
    config.detections.map { detectionType ->
        async {
            val result = executeDetectionSafely(detectionType)
            notifyDetectionResult(detectionType, result)
            result
        }
    }.awaitAll()
}
```

**Fix:** Wrap each async in try-catch to ensure consistent error handling:
```kotlin
private suspend fun executeParallel(): List<PeriodicCheckConfig.DetectionResult> = coroutineScope {
    config.detections.map { detectionType ->
        async {
            try {
                val result = executeDetectionSafely(detectionType)
                notifyDetectionResult(detectionType, result)
                result
            } catch (e: CancellationException) {
                throw e  // Don't catch cancellation
            } catch (e: Throwable) {
                // This shouldn't happen since executeDetectionSafely catches exceptions,
                // but Defensive catch in case of unexpected errors
                val errorResult = PeriodicCheckConfig.DetectionResult(
                    detectionType = detectionType,
                    result = Result.ERROR,
                    timestamp = System.currentTimeMillis()
                )
                notifyDetectionResult(detectionType, errorResult)
                errorResult
            }
        }
    }.awaitAll()
}
```

---

## Issue 5: PeriodicCheckControllerImpl.kt:91-95 - isPaused Returns True After Disposal

**File:** `rootkit/src/main/java/com/ssithara/rootkit/core/periodic/PeriodicCheckControllerImpl.kt`

**Problem:** After `dispose()` sets `disposed=true`, `isPaused` returns `false` while `isRunning` also returns `false`. This creates an inconsistent state.

**Current Code (lines 91-95):**
```kotlin
override val isRunning: Boolean
    get() = _isRunning.get() && !disposed.get()

override val isPaused: Boolean
    get() = _isPaused.get() && !disposed.get()
```

**Fix:** Ensure consistent behavior - after disposal, both should return false:
```kotlin
override val isRunning: Boolean
    get() = !disposed.get() && _isRunning.get()

override val isPaused: Boolean
    get() = !disposed.get() && _isPaused.get()
```

This ensures that once `disposed=true`, both properties immediately return `false` regardless of internal state.

---

## Issue 6: RootDetection.kt:28-38 - Brand-Specific Root Checks Inconsistency

**File:** `rootkit/src/main/java/com/ssithara/rootkit/detection/root/RootDetection.kt`

**Problem:** Devices matching specific brands (ONEPLUS, MOTO, XIAOMI) use `rootBeer.isRooted()` while other devices use `rootBeer.isRootedWithBusyBoxCheck()`. This creates inconsistent detection behavior.

**Current Code (lines 27-39):**
```kotlin
val brandLowercase = Build.BRAND.lowercase(Locale.ROOT)
if (brandLowercase.contains(ONEPLUS) || brandLowercase.contains(MOTO) || brandLowercase.contains(
        XIAOMI
    )
) {
    if (rootBeer.isRooted()) {
        detected = Result.FOUND
    }
} else {
    if (rootBeer.isRootedWithBusyBoxCheck()) {
        detected = Result.FOUND
    }
}
```

**Fix:** Apply both checks to all brands for consistent detection:
```kotlin
val brandLowercase = Build.BRAND.lowercase(Locale.ROOT)
if (brandLowercase.contains(ONEPLUS) || brandLowercase.contains(MOTO) || brandLowercase.contains(
        XIAOMI
    )
) {
    // These brands may hide root from standard checks, but busybox reveals it
    if (rootBeer.isRooted() || rootBeer.isRootedWithBusyBoxCheck()) {
        detected = Result.FOUND
    }
} else {
    // Standard root check for other brands
    if (rootBeer.isRooted()) {
        detected = Result.FOUND
    }
}
```

---

## Issue 7: RootKit.kt:381-388 - Double Exception Catching in Individual Detection Methods

**File:** `rootkit/src/main/java/com/ssithara/rootkit/RootKit.kt`

**Problem:** Individual methods like `isFridaDetected()` catch exceptions and return `Result.ERROR`, but the underlying `runtimeTamperingDetection.isFridaDetected()` may already return a cached result that was computed via `runSafely()` which catches exceptions internally. The double catching is redundant and obscures error flow.

**Current Code (lines 380-388):**
```kotlin
fun isFridaDetected(): String {
    checkInitialized()
    val result = try {
        if (runtimeTamperingDetection.isFridaDetected()) Result.FOUND else Result.NOT_FOUND
    } catch (e: Throwable) {
        Log.e(TAG, "Frida detection failed: ${e.message}", e)
        Result.ERROR
    }
    return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
}
```

**Fix:** Remove redundant try-catch since `RuntimeTamperingDetection` methods don't throw - they use cached results from `getOrComputeSummary()` which internally calls `runSafely()` and returns booleans:
```kotlin
fun isFridaDetected(): String {
    checkInitialized()
    val result = if (runtimeTamperingDetection.isFridaDetected()) Result.FOUND else Result.NOT_FOUND
    return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
}
```

**Apply same fix to:**
- `isXposedDetected()` (lines 394-402)
- `isMemoryTamperingDetected()` (lines 408-416)
- `isNativeHookDetected()` (lines 422-430)

---

## Issue 8: MagiskDetection.kt:40 - Non-Idiomatic readLine Pattern

**File:** `rootkit/src/main/java/com/ssithara/rootkit/detection/root/MagiskDetection.kt`

**Problem:** Same pattern as ShellEx.kt - uses `also` with nullable assertion.

**Current Code (lines 40-48):**
```kotlin
var str: String?
while (reader.readLine().also { str = it } != null) {
    for (path in blackListedMountPaths) {
        if (str?.contains(path) == true) {
            isMagiskPresent = Result.FOUND
            break
        }
    }
    if (isMagiskPresent == Result.FOUND) break
}
```

**Fix:** Use simpler null-safe access or forEachLine:
```kotlin
var line: String?
while (reader.readLine().also { line = it } != null) {
    for (path in blackListedMountPaths) {
        if (line!!.contains(path)) {
            isMagiskPresent = Result.FOUND
            break
        }
    }
    if (isMagiskPresent == Result.FOUND) break
}
```

Or cleaner:
```kotlin
reader.lineSequence().forEach { line ->
    for (path in blackListedMountPaths) {
        if (line.contains(path)) {
            isMagiskPresent = Result.FOUND
            return@forEach
        }
    }
}
```

---

## Issue 9: RootKit.kt:168 - Redundant Synchronization

**File:** `rootkit/src/main/java/com/ssithara/rootkit/RootKit.kt`

**Problem:** Double-checked locking with AtomicBoolean is redundant since AtomicBoolean already provides lock-free thread-safety.

**Current Code (lines 164-175):**
```kotlin
private fun loadLibraryOnce() {
    if (isLibraryLoaded.get()) {
        return
    }
    synchronized(isLibraryLoaded) {
        if (isLibraryLoaded.get()) {
            return
        }
        System.loadLibrary("rootkit")
        isLibraryLoaded.set(true)
    }
}
```

**Fix:** Use compareAndSet for simpler, lock-free implementation:
```kotlin
private fun loadLibraryOnce() {
    if (isLibraryLoaded.compareAndSet(false, true)) {
        System.loadLibrary("rootkit")
    }
}
```

---

## Issue 10: AppZygote.kt:17 - Swallows UnsatisfiedLinkError Silently

**File:** `rootkit/src/main/java/com/ssithara/rootkit/core/AppZygote.kt`

**Problem:** The zygote preload catches `UnsatisfiedLinkError` but only logs it, allowing the app to continue without the native library. This can cause crashes later when native methods are called.

**Current Code (lines 17-24):**
```kotlin
override fun doPreload(p0: ApplicationInfo) {
    try {
        System.loadLibrary("rootkit")
    } catch (e: UnsatisfiedLinkError) {
        Log.e(TAG, "Failed to load rootkit library during zygote preload: ${e.message}", e)
    } catch (e: Exception) {
        Log.e(TAG, "Unexpected error loading rootkit library during zygote preload: ${e.message}", e)
    }
}
```

**Fix:** Re-throw the error to fail fast rather than continue with a broken library:
```kotlin
override fun doPreload(p0: ApplicationInfo) {
    try {
        System.loadLibrary("rootkit")
    } catch (e: UnsatisfiedLinkError) {
        Log.e(TAG, "Failed to load rootkit library during zygote preload: ${e.message}", e)
        throw e  // Fail fast - do not continue with broken library
    } catch (e: Exception) {
        Log.e(TAG, "Unexpected error loading rootkit library during zygote preload: ${e.message}", e)
        throw e  // Fail fast on unexpected errors too
    }
}
```

---

## Summary of Changes

| Issue | File | Priority | Fix Type |
|-------|------|----------|----------|
| 1 | ShellEx.kt:36-37 | Critical | Refactor loop pattern |
| 2 | ShellEx.kt:76-85 | Critical | Use AtomicInteger |
| 3 | RootKit.kt:295-310 | Critical | Clarify with when expression |
| 4 | PeriodicCheckControllerImpl.kt:253 | Moderate | Add exception handling |
| 5 | PeriodicCheckControllerImpl.kt:91-95 | Moderate | Reorder conditions |
| 6 | RootDetection.kt:28-38 | Moderate | Consistent detection |
| 7 | RootKit.kt:381-388 | Minor | Remove redundant catch |
| 8 | MagiskDetection.kt:40 | Minor | Simplify loop |
| 9 | RootKit.kt:168 | Minor | Lock-free approach |
| 10 | AppZygote.kt:17 | Minor | Fail fast |

---

## Execution Order

1. **ShellEx.kt** - Issues 1 & 2 (related to same file)
2. **RootKit.kt** - Issues 3, 7, & 9 (related to same file)
3. **PeriodicCheckControllerImpl.kt** - Issues 4 & 5 (related to same file)
4. **RootDetection.kt** - Issue 6
5. **MagiskDetection.kt** - Issue 8
6. **AppZygote.kt** - Issue 10
