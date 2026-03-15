# Periodic Security Checks Architecture

## Overview

This document outlines the architecture for adding periodic security checks to the RootKit SDK. The enhancement enables continuous monitoring of device security state with configurable intervals and callback-based notifications.

## Current Architecture Analysis

### Existing Components

```
RootKit (facade)
├── initialize() - Loads native library
├── Detection Methods (on-demand)
│   ├── isRootedDevice()
│   ├── isDebuggerDetected()
│   ├── isEmulatorDevice()
│   ├── isRuntimeTamperingDetected()
│   └── Individual detection methods
└── Detail Methods
    ├── getRuntimeTamperingDetails()
    ├── getEmulatorDetails()
    └── getDebuggerDetails()
```

### Key Patterns

- **Lazy Initialization**: Detection classes use `by lazy` for deferred instantiation
- **DetectorResult Abstract Class**: All detectors extend [`DetectorResult`](rootkit/src/main/java/com/ssithara/rootkit/core/DetectorResult.kt) and implement `run(): Result`
- **Encryption**: All results flow through [`EncryptionService.encryptWithBase64Key()`](rootkit/src/main/java/com/ssithara/rootkit/core/EncryptionService.kt)
- **Result Enum**: Simple `FOUND`/`NOT_FOUND` enum in [`Result.kt`](rootkit/src/main/java/com/ssithara/rootkit/core/Result.kt)

---

## 1. API Design

### 1.1 Configuration Class

```kotlin
// rootkit/src/main/java/com/ssithara/rootkit/core/PeriodicCheckConfig.kt

/**
 * Configuration for periodic security checks
 */
class PeriodicCheckConfig private constructor(
    val intervalMs: Long,
    val initialDelayMs: Long,
    val detections: Set<DetectionType>,
    val callback: SecurityCallback?,
    val errorHandler: ErrorHandler?,
    val executionMode: ExecutionMode
) {
    /**
     * Types of security detections that can be monitored
     */
    enum class DetectionType {
        ROOT,
        MAGISK,
        MAGISK_HIDE,
        DEBUGGER,
        EMULATOR,
        FRIDA,
        XPOSED,
        MEMORY_TAMPERING,
        NATIVE_HOOK,
        RUNTIME_TAMPERING  // Composite of Frida, Xposed, Memory, NativeHook
    }

    /**
     * Execution mode for periodic checks
     */
    enum class ExecutionMode {
        SEQUENTIAL,     // Run detections one after another
        PARALLEL,       // Run all detections concurrently
        STAGGERED       // Run with small delays between detections
    }

    /**
     * Callback interface for security detection results
     */
    interface SecurityCallback {
        fun onDetectionResult(detectionType: DetectionType, result: DetectionResult)
        fun onCheckCycleComplete(summary: SecuritySummary)
        fun onError(detectionType: DetectionType, error: Throwable)
    }

    /**
     * Result of a single detection check
     */
    data class DetectionResult(
        val detectionType: DetectionType,
        val result: Result,
        val timestamp: Long = System.currentTimeMillis(),
        val encryptedValue: String? = null,
        val details: Map<String, Any>? = null
    )

    /**
     * Summary of a complete check cycle
     */
    data class SecuritySummary(
        val results: Map<DetectionType, DetectionResult>,
        val anyThreatDetected: Boolean,
        val threatCount: Int,
        val checkDurationMs: Long,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Error handler for detection failures
     */
    interface ErrorHandler {
        fun handleError(detectionType: DetectionType, error: Throwable): Boolean
    }

    /**
     * Builder for creating PeriodicCheckConfig
     */
    class Builder {
        private var intervalMs: Long = DEFAULT_INTERVAL_MS
        private var initialDelayMs: Long = DEFAULT_INITIAL_DELAY_MS
        private val detections: MutableSet<DetectionType> = mutableSetOf()
        private var callback: SecurityCallback? = null
        private var errorHandler: ErrorHandler? = null
        private var executionMode: ExecutionMode = ExecutionMode.SEQUENTIAL

        /**
         * Set the interval between periodic checks
         * @param intervalMs Interval in milliseconds (minimum: 1000ms)
         */
        fun setInterval(intervalMs: Long) = apply {
            require(intervalMs >= MIN_INTERVAL_MS) {
                "Interval must be at least $MIN_INTERVAL_MS ms"
            }
            this.intervalMs = intervalMs
        }

        /**
         * Set initial delay before first check
         * @param delayMs Delay in milliseconds
         */
        fun setInitialDelay(delayMs: Long) = apply {
            this.initialDelayMs = delayMs
        }

        /**
         * Add a detection type to monitor
         */
        fun addDetection(detectionType: DetectionType) = apply {
            detections.add(detectionType)
        }

        /**
         * Add multiple detection types to monitor
         */
        fun addDetections(vararg types: DetectionType) = apply {
            detections.addAll(types)
        }

        /**
         * Monitor all available detection types
         */
        fun monitorAllDetections() = apply {
            detections.addAll(DetectionType.values())
        }

        /**
         * Set the callback for receiving results
         */
        fun setCallback(callback: SecurityCallback) = apply {
            this.callback = callback
        }

        /**
         * Set error handler for detection failures
         */
        fun setErrorHandler(handler: ErrorHandler) = apply {
            this.errorHandler = handler
        }

        /**
         * Set execution mode for checks
         */
        fun setExecutionMode(mode: ExecutionMode) = apply {
            this.executionMode = mode
        }

        fun build(): PeriodicCheckConfig {
            require(detections.isNotEmpty()) {
                "At least one detection type must be specified"
            }
            return PeriodicCheckConfig(
                intervalMs = intervalMs,
                initialDelayMs = initialDelayMs,
                detections = detections.toSet(),
                callback = callback,
                errorHandler = errorHandler,
                executionMode = executionMode
            )
        }

        companion object {
            const val DEFAULT_INTERVAL_MS = 30_000L       // 30 seconds
            const val DEFAULT_INITIAL_DELAY_MS = 1_000L   // 1 second
            const val MIN_INTERVAL_MS = 1_000L            // 1 second minimum
        }
    }
}
```

### 1.2 Updated RootKit API

```kotlin
// rootkit/src/main/java/com/ssithara/rootkit/RootKit.kt

class RootKit(private val context: Context) {

    // Existing on-demand methods remain unchanged for backward compatibility

    /**
     * Initialize the SDK with native library loading only.
     * Backward compatible with existing usage.
     */
    fun initialize() {
        System.loadLibrary("rootkit")
    }

    /**
     * Initialize the SDK with periodic security monitoring.
     *
     * @param config Configuration for periodic checks
     * @return PeriodicCheckController to control the monitoring lifecycle
     * @throws IllegalStateException if already initialized with periodic checks
     */
    fun initialize(config: PeriodicCheckConfig): PeriodicCheckController {
        System.loadLibrary("rootkit")
        return PeriodicCheckControllerImpl(context, config)
    }

    /**
     * Initialize with a simplified configuration using DSL-style builder.
     *
     * @param block Configuration builder lambda
     * @return PeriodicCheckController to control the monitoring lifecycle
     */
    fun initialize(block: PeriodicCheckConfig.Builder.() -> Unit): PeriodicCheckController {
        val config = PeriodicCheckConfig.Builder().apply(block).build()
        return initialize(config)
    }

    // ... existing detection methods ...
}
```

### 1.3 Controller Interface

```kotlin
// rootkit/src/main/java/com/ssithara/rootkit/core/PeriodicCheckController.kt

/**
 * Controller for managing periodic security check lifecycle
 */
interface PeriodicCheckController {

    /**
     * Whether periodic checks are currently running
     */
    val isRunning: Boolean

    /**
     * Whether checks are currently paused
     */
    val isPaused: Boolean

    /**
     * Start periodic security checks.
     * No-op if already running.
     */
    fun start()

    /**
     * Stop periodic security checks.
     * Releases all resources and cancels pending checks.
     */
    fun stop()

    /**
     * Pause periodic checks without releasing resources.
     * Can be resumed with resume().
     */
    fun pause()

    /**
     * Resume paused periodic checks.
     */
    fun resume()

    /**
     * Trigger an immediate security check.
     * Does not affect the periodic schedule.
     */
    fun checkNow()

    /**
     * Update the check interval at runtime.
     * Takes effect on the next scheduled check.
     */
    fun updateInterval(newIntervalMs: Long)

    /**
     * Reset interval to the original configured value.
     */
    fun resetInterval()

    /**
     * Get the current check interval in milliseconds.
     */
    fun getInterval(): Long

    /**
     * Get the last known security summary.
     * Returns null if no check has been completed yet.
     */
    fun getLastSummary(): PeriodicCheckConfig.SecuritySummary?

    /**
     * Release all resources and cleanup.
     * Controller cannot be used after calling this.
     */
    fun dispose()
}
```

---

## 2. Execution Strategy

### 2.1 Scheduler Selection

**Recommendation: CoroutineScope with SupervisorJob**

```
┌─────────────────────────────────────────────────────────────┐
│                    PeriodicCheckController                   │
├─────────────────────────────────────────────────────────────┤
│  CoroutineScope (SupervisorJob + Dispatchers.Default)       │
│      │                                                       │
│      ├── Periodic Job (fixedRateTimer alternative)          │
│      │       │                                               │
│      │       └──> [Check Cycle]                              │
│      │               │                                       │
│      │               ├── Sequential Mode:                    │
│      │               │   Detection1 → Detection2 → ...      │
│      │               │                                       │
│      │               ├── Parallel Mode:                      │
│      │               │   Detection1 ┐                        │
│      │               │   Detection2 ├─→ awaitAll            │
│      │               │   Detection3 ┘                        │
│      │               │                                       │
│      │               └── Staggered Mode:                     │
│      │                   Detection1 → (100ms) → Detection2  │
│      │                                                       │
│      └── Immediate Check Job (checkNow)                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Rationale for Coroutines over Alternatives:**

| Option                       | Pros                                                                  | Cons                                        | Verdict                  |
| ---------------------------- | --------------------------------------------------------------------- | ------------------------------------------- | ------------------------ |
| **CoroutineScope**           | Lightweight, structured concurrency, easy cancellation, no extra deps | Requires careful lifecycle management       | ✅ Recommended           |
| **WorkManager**              | Persistent, battery-optimized, guaranteed execution                   | Overkill for in-memory checks, high latency | ❌ Not suitable          |
| **Handler/Runnable**         | Simple, no dependencies                                               | Manual cleanup, no structured concurrency   | ❌ Legacy approach       |
| **ScheduledExecutorService** | JVM standard                                                          | No lifecycle awareness, manual cleanup      | ❌ Not Android-optimized |
| **Timer**                    | Simple API                                                            | No exception handling, not lifecycle-aware  | ❌ Deprecated pattern    |

### 2.2 Threading Model

```kotlin
// Threading strategy
internal class PeriodicCheckScheduler(
    private val config: PeriodicCheckConfig
) {
    // Main scope with SupervisorJob for fault tolerance
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // Dedicated scope for check execution (can be customized)
    private val checkDispatcher: CoroutineDispatcher = when (config.executionMode) {
        ExecutionMode.PARALLEL -> Dispatchers.Default.limitedParallelism(
            runtime = maxOf(2, config.detections.size.coerceAtMost(4))
        )
        else -> Dispatchers.Default
    }

    // ... implementation
}
```

**Thread Allocation:**

```
Main Thread (UI)
    │
    └──> Callbacks dispatched here (via Dispatchers.Main)

Dispatchers.Default (Background)
    │
    ├──> Periodic scheduling
    │
    └──> Detection execution
         │
         ├── Sequential: Single thread processes all
         │
         └── Parallel: Limited parallelism (max 4 threads)
             to prevent resource exhaustion
```

### 2.3 Overlapping Check Handling

```kotlin
internal class CheckExecutionGuard {
    private val checkMutex = Mutex()
    private var isCheckInProgress = AtomicBoolean(false)

    /**
     * Execute a check cycle with overlap protection.
     * Returns immediately if a check is already in progress.
     */
    suspend fun executeWithGuard(block: suspend () -> Unit): Boolean {
        if (!isCheckInProgress.compareAndSet(false, true)) {
            // Previous check still running, skip this cycle
            return false
        }

        return try {
            checkMutex.withLock {
                block()
            }
            true
        } finally {
            isCheckInProgress.set(false)
        }
    }
}
```

**Overlap Strategies:**

| Strategy            | Behavior                             | Use Case                            |
| ------------------- | ------------------------------------ | ----------------------------------- |
| **SKIP**            | Skip new check if previous running   | Default - prevents resource buildup |
| **CANCEL_PREVIOUS** | Cancel previous and start new        | Time-sensitive applications         |
| **QUEUE**           | Queue new check for after completion | Must not miss any checks            |

**Recommendation: SKIP strategy** with optional configuration for other modes.

---

## 3. Memory Management

### 3.1 Lifecycle Awareness

```
┌─────────────────────────────────────────────────────────────┐
│                    Memory Management Flow                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Application                                                 │
│      │                                                       │
│      ├── RootKit.initialize(config)                          │
│      │       │                                               │
│      │       └── PeriodicCheckController (WeakReference)     │
│      │               │                                       │
│      │               ├── CoroutineScope (controlled)         │
│      │               │                                       │
│      │               └── Detection References                │
│      │                       │                               │
│      │                       └── Weak or Soft references     │
│      │                                                       │
│      └── LifecycleObserver (optional)                        │
│              │                                               │
│              ├── ON_STOP → pause()                           │
│              └── ON_START → resume()                         │
│                                                              │
│  Cleanup Trigger:                                            │
│      ├── Explicit: controller.dispose()                      │
│      ├── Implicit: WeakReference cleared                     │
│      └── Process Death: Scope cancelled automatically        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Cleanup Mechanism

```kotlin
internal class PeriodicCheckControllerImpl(
    context: Context,
    private val config: PeriodicCheckConfig
) : PeriodicCheckController, Disposable {

    // Use application context to prevent activity leaks
    private val appContext: Context = context.applicationContext

    // Weak reference for callback to allow GC if consumer is collected
    private val callbackRef = WeakReference(config.callback)

    // Supervised scope for fault isolation
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // Active periodic job reference
    private var periodicJob: Job? = null

    // Track disposed state
    private val disposed = AtomicBoolean(false)

    override fun dispose() {
        if (disposed.compareAndSet(false, true)) {
            stop()
            scope.cancel()  // Cancels all children
            callbackRef.clear()
            lastSummaryRef.set(null)
        }
    }

    // Cleanup on finalize as safety net
    protected fun finalize() {
        if (!disposed.get()) {
            scope.cancel()
        }
    }
}
```

### 3.3 Memory Leak Prevention Checklist

| Concern                     | Mitigation                                      |
| --------------------------- | ----------------------------------------------- |
| **Activity Context Leak**   | Always use `context.applicationContext`         |
| **Callback Leak**           | Use `WeakReference` for callback storage        |
| **Coroutine Leak**          | Use `SupervisorJob` with explicit `cancel()`    |
| **Detection Instance Leak** | Reuse lazy instances from RootKit facade        |
| **Stream/Channel Leak**     | Use `try-finally` or `use{}` blocks             |
| **Listener Accumulation**   | Single callback reference, no list accumulation |

### 3.4 Lifecycle-Aware Integration (Optional)

```kotlin
// Optional: Lifecycle-aware extension for Activity/Fragment
class LifecycleAwarePeriodicCheck(
    private val controller: PeriodicCheckController,
    lifecycle: Lifecycle
) : DefaultLifecycleObserver {

    init {
        lifecycle.addObserver(this)
    }

    override fun onStart(owner: LifecycleOwner) {
        controller.resume()
    }

    override fun onStop(owner: LifecycleOwner) {
        controller.pause()
    }

    override fun onDestroy(owner: LifecycleOwner) {
        controller.dispose()
    }
}

// Usage extension
fun PeriodicCheckController.bindToLifecycle(lifecycle: Lifecycle): PeriodicCheckController {
    LifecycleAwarePeriodicCheck(this, lifecycle)
    return this
}
```

### 3.5 App Visibility Awareness (Recommended)

App visibility awareness pauses security checks when the entire app goes to background, saving battery and CPU resources. This uses `ProcessLifecycleOwner` to track app-level visibility.

```kotlin
// rootkit/src/main/java/com/ssithara/rootkit/core/periodic/AppVisibilityAwareCheck.kt

/**
 * Monitors app-level visibility and automatically pauses/resumes periodic checks.
 * Uses ProcessLifecycleOwner to detect when app goes to background.
 *
 * Benefits:
 * - Saves battery when app is not visible to user
 * - Reduces CPU usage during background operation
 * - Automatically resumes checks when app returns to foreground
 *
 * Note: Security checks are paused in background. If continuous background
 * monitoring is required, use ForegroundService instead.
 */
class AppVisibilityAwareCheck(
    private val controller: PeriodicCheckController,
    private val config: VisibilityConfig = VisibilityConfig.DEFAULT
) : DefaultLifecycleObserver {

    data class VisibilityConfig(
        val pauseInBackground: Boolean = true,
        val resumeOnForeground: Boolean = true,
        val backgroundCheckIntervalMultiplier: Long = 0,  // 0 = pause completely
        val minBackgroundIntervalMs: Long = 60_000L  // If multiplier > 0, minimum 60s in background
    ) {
        companion object {
            val DEFAULT = VisibilityConfig()
            val CONTINUE_REDUCED = VisibilityConfig(
                pauseInBackground = false,
                backgroundCheckIntervalMultiplier = 4  // 4x slower in background
            )
        }
    }

    init {
        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
    }

    override fun onStart(owner: LifecycleOwner) {
        // App came to foreground
        if (config.resumeOnForeground) {
            controller.resume()
            // Reset to original interval if it was changed
            if (config.backgroundCheckIntervalMultiplier > 0) {
                controller.resetInterval()
            }
        }
    }

    override fun onStop(owner: LifecycleOwner) {
        // App went to background
        if (config.pauseInBackground) {
            controller.pause()
        } else if (config.backgroundCheckIntervalMultiplier > 0) {
            // Reduce frequency instead of pausing completely
            val currentInterval = controller.getInterval()
            val newInterval = (currentInterval * config.backgroundCheckIntervalMultiplier)
                .coerceAtLeast(config.minBackgroundIntervalMs)
            controller.updateInterval(newInterval)
        }
    }

    /**
     * Detach from lifecycle and cleanup.
     * Call this when you want to stop visibility-aware behavior.
     */
    fun detach() {
        ProcessLifecycleOwner.get().lifecycle.removeObserver(this)
    }
}

// Extension function for easy setup
fun PeriodicCheckController.withAppVisibilityAwareness(
    config: AppVisibilityAwareCheck.VisibilityConfig = AppVisibilityAwareCheck.VisibilityConfig.DEFAULT
): PeriodicCheckController {
    AppVisibilityAwareCheck(this, config)
    return this
}
```

**Usage Examples:**

```kotlin
// Example 1: Pause checks completely when app goes to background (default)
val controller = rootKit.initialize {
    monitorAllDetections()
    setCallback(securityCallback)
}.withAppVisibilityAwareness()

controller.start()
// Checks will automatically pause when app goes to background
// and resume when app returns to foreground

// Example 2: Continue checks in background but at reduced frequency
val controller = rootKit.initialize {
    setInterval(15_000L)  // 15 seconds in foreground
    monitorAllDetections()
    setCallback(securityCallback)
}.withAppVisibilityAwareness(
    AppVisibilityAwareCheck.VisibilityConfig.CONTINUE_REDUCED
    // In background: 15s * 4 = 60 second intervals
)

// Example 3: Combined with Activity lifecycle for fine-grained control
val controller = rootKit.initialize {
    monitorAllDetections()
    setCallback(securityCallback)
}.withAppVisibilityAwareness()  // App-level visibility
 .bindToLifecycle(lifecycle)    // Activity-level lifecycle (optional)
```

**Architecture Diagram:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    App Visibility Flow                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ProcessLifecycleOwner                                           │
│      │                                                           │
│      ├── ON_START (App visible)                                  │
│      │       │                                                   │
│      │       └── AppVisibilityAwareCheck                         │
│      │               │                                           │
│      │               └── controller.resume()                     │
│      │                   └── Checks running at normal interval   │
│      │                                                           │
│      └── ON_STOP (App in background)                             │
│              │                                                   │
│              └── AppVisibilityAwareCheck                         │
│                      │                                           │
│                      ├── Config.pauseInBackground = true         │
│                      │       └── controller.pause()             │
│                      │           └── Checks stopped             │
│                      │                                           │
│                      └── Config.pauseInBackground = false        │
│                              └── controller.updateInterval()    │
│                                  └── Checks at reduced frequency │
│                                                                  │
│  Memory Safety:                                                  │
│      - Uses ProcessLifecycleOwner.get() (singleton)              │
│      - Observer removed in detach()                              │
│      - No activity references held                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Configuration Options:**

| Option                              | Default | Description                                         |
| ----------------------------------- | ------- | --------------------------------------------------- |
| `pauseInBackground`                 | `true`  | Pause checks when app goes to background            |
| `resumeOnForeground`                | `true`  | Resume checks when app returns to foreground        |
| `backgroundCheckIntervalMultiplier` | `0`     | Multiply interval by this in background (0 = pause) |
| `minBackgroundIntervalMs`           | `60000` | Minimum interval in background when multiplier > 0  |

**Dependency Requirement:**

```kotlin
// build.gradle.kts - Already included in most Android projects
implementation("androidx.lifecycle:lifecycle-process:2.7.0")
```

---

## 4. Performance Optimizations

### 4.1 Execution Modes Comparison

```
Sequential Mode:
Time:  0ms    50ms   100ms  150ms  200ms
       ├──────┼──────┼──────┼──────┤
       [Root] [Magisk][Debug][Emul] [Done]

       Total: ~200ms
       CPU: Single core utilized
       Memory: Minimal


Parallel Mode:
Time:  0ms    50ms   100ms
       ├──────┼──────┤
       [Root] ┐
       [Magisk]├─→ awaitAll
       [Debug]│
       [Emul] ┘

       Total: ~50-100ms (depends on slowest)
       CPU: Multi-core utilized
       Memory: Higher (concurrent instances)


Staggered Mode:
Time:  0ms    50ms   100ms  150ms  180ms
       ├──────┼──────┼──────┼──────┤
       [Root]
              [Magisk]
                     [Debug]
                            [Emul]

       Total: ~180ms
       CPU: Spread across time
       Memory: Controlled, one at a time with gaps
```

### 4.2 Staggered Execution Implementation

```kotlin
private suspend fun executeStaggered(
    detections: Set<DetectionType>,
    staggerDelayMs: Long = 50L
): List<DetectionResult> {
    return detections.mapIndexed { index, detectionType ->
        // Stagger start times
        delay(index * staggerDelayMs)

        withTimeout(CHECK_TIMEOUT_MS) {
            executeDetection(detectionType)
        }
    }.awaitAll()

    companion object {
        private const val CHECK_TIMEOUT_MS = 5_000L
    }
}
```

### 4.3 Background Priority

```kotlin
// Use background priority for detection threads
private val backgroundDispatcher = Dispatchers.Default + ThreadPriorityTransformer()

private class ThreadPriorityTransformer : CoroutineContext.Element {
    companion object Key : CoroutineContext.Key<ThreadPriorityTransformer>

    override val key: CoroutineContext.Key<*>
        get() = Key

    fun adjustThreadPriority() {
        // Lower priority to avoid impacting UI
        android.os.Process.setThreadPriority(
            android.os.Process.THREAD_PRIORITY_BACKGROUND
        )
    }
}
```

### 4.4 Caching Strategy

```kotlin
internal class DetectionResultCache {
    private val cache = ConcurrentHashMap<DetectionType, CachedResult>()
    private val cacheTtlMs: Long = 5_000L  // 5 second cache

    data class CachedResult(
        val result: DetectionResult,
        val timestamp: Long
    ) {
        fun isExpired(ttlMs: Long): Boolean {
            return System.currentTimeMillis() - timestamp > ttlMs
        }
    }

    fun get(type: DetectionType): DetectionResult? {
        return cache[type]?.takeIf { !it.isExpired(cacheTtlMs) }?.result
    }

    fun put(result: DetectionResult) {
        cache[result.detectionType] = CachedResult(result, System.currentTimeMillis())
    }

    fun clear() = cache.clear()
}
```

### 4.5 Performance Metrics

| Metric                   | Target               | Measurement                      |
| ------------------------ | -------------------- | -------------------------------- |
| **Check Cycle Duration** | < 500ms (sequential) | System.currentTimeMillis() delta |
| **Memory Overhead**      | < 1MB additional     | Debug.MemoryStats                |
| **CPU Impact**           | < 5% when idle       | Systrace profiling               |
| **Battery Impact**       | Negligible           | Battery Historian analysis       |
| **Callback Latency**     | < 16ms (one frame)   | Main thread dispatch timing      |

---

## 5. Developer Experience

### 5.1 Quick Start Examples

**Minimal Setup:**

```kotlin
// Simplest possible setup - all detections, default interval
val controller = rootKit.initialize {
    setCallback(object : PeriodicCheckConfig.SecurityCallback {
        override fun onDetectionResult(type: DetectionType, result: DetectionResult) {
            if (result.result == Result.FOUND) {
                // Handle security threat
            }
        }
        override fun onCheckCycleComplete(summary: SecuritySummary) {}
        override fun onError(type: DetectionType, error: Throwable) {}
    })
}
controller.start()
```

**Customized Setup:**

```kotlin
// Custom configuration
val controller = rootKit.initialize {
    setInterval(60_000L)  // 1 minute
    setInitialDelay(5_000L)  // 5 second initial delay
    addDetections(
        DetectionType.ROOT,
        DetectionType.MAGISK,
        DetectionType.FRIDA,
        DetectionType.DEBUGGER
    )
    setExecutionMode(ExecutionMode.STAGGERED)
    setCallback(myCallback)
    setErrorHandler { type, error ->
        Log.w("Security", "Detection $type failed", error)
        true  // Continue monitoring
    }
}
controller.start()
```

**Lifecycle-Aware Setup:**

```kotlin
class MainActivity : AppCompatActivity() {
    private lateinit var securityController: PeriodicCheckController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val rootKit = RootKit(this)
        securityController = rootKit.initialize {
            monitorAllDetections()
            setCallback(securityCallback)
        }.bindToLifecycle(lifecycle)

        securityController.start()
    }
}
```

### 5.2 Default Values

| Configuration      | Default         | Rationale                                  |
| ------------------ | --------------- | ------------------------------------------ |
| **Interval**       | 30 seconds      | Balance between responsiveness and battery |
| **Initial Delay**  | 1 second        | Allow app startup to complete              |
| **Detections**     | None (required) | Explicit opt-in for security               |
| **Execution Mode** | Sequential      | Predictable performance                    |
| **Callback**       | Null (required) | Must handle results                        |
| **Error Handler**  | Null            | Fail-fast by default                       |

### 5.3 Error Handling

```kotlin
// Error handling hierarchy
sealed class DetectionError : Exception() {
    class NativeLibraryNotLoaded : DetectionError()
    class DetectionTimeout(val detectionType: DetectionType) : DetectionError()
    class ContextNotAvailable : DetectionError()
    class ControllerDisposed : DetectionError()
    class CheckAlreadyInProgress : DetectionError()
}

// Graceful degradation
internal suspend fun executeDetectionSafely(
    type: DetectionType
): DetectionResult {
    return try {
        executeDetection(type)
    } catch (e: CancellationException) {
        throw e  // Don't catch cancellation
    } catch (e: Exception) {
        val handled = config.errorHandler?.handleError(type, e) ?: false
        if (!handled) {
            callbackRef.get()?.onError(type, e)
        }
        DetectionResult(
            detectionType = type,
            result = Result.NOT_FOUND,  // Fail safe
            timestamp = System.currentTimeMillis()
        )
    }
}
```

### 5.4 Documentation Points

Key areas requiring documentation:

1. **Threading Guarantees**: Callbacks execute on main thread
2. **Lifecycle Requirements**: Must call `dispose()` or bind to lifecycle
3. **Interval Constraints**: Minimum 1 second, no maximum
4. **Error Recovery**: Automatic retry on next interval
5. **Native Library**: Must call `initialize()` before any detection
6. **Memory**: Automatic cleanup on process death

---

## 6. Suggestions and Improvements

### 6.1 Recommended Enhancements

**1. Detection Result History**

```kotlin
// Track historical results for trend analysis
interface SecurityHistory {
    fun getRecentResults(count: Int): List<SecuritySummary>
    fun getThreatTimeline(): Flow<ThreatEvent>
    fun clearHistory()
}
```

**2. Adaptive Interval**

```kotlin
// Adjust interval based on threat level
class AdaptiveIntervalConfig(
    val baseIntervalMs: Long,
    val threatIntervalMs: Long,  // Faster when threats detected
    val safeIntervalMs: Long     // Slower when all clear
) {
    fun calculateInterval(threatDetected: Boolean): Long {
        return if (threatDetected) threatIntervalMs else safeIntervalMs
    }
}
```

**3. Batched Callbacks**

```kotlin
// Reduce callback frequency for high-frequency checks
interface BatchedSecurityCallback : SecurityCallback {
    fun onBatchResults(results: List<DetectionResult>)

    // Configure batching
    val batchSize: Int get() = 5
    val batchTimeoutMs: Long get() = 100L
}
```

**4. Threat Severity Levels**

```kotlin
enum class ThreatSeverity {
    LOW,       // Emulator detection
    MEDIUM,    // Debugger attached
    HIGH,      // Root detected
    CRITICAL   // Runtime tampering (Frida/Xposed)
}

fun DetectionType.toSeverity(): ThreatSeverity = when (this) {
    DetectionType.EMULATOR -> ThreatSeverity.LOW
    DetectionType.DEBUGGER -> ThreatSeverity.MEDIUM
    DetectionType.ROOT, DetectionType.MAGISK -> ThreatSeverity.HIGH
    DetectionType.FRIDA, DetectionType.XPOSED -> ThreatSeverity.CRITICAL
    else -> ThreatSeverity.MEDIUM
}
```

### 6.2 Alternative Patterns to Consider

**1. Flow-Based API (Kotlin Idiomatic)**

```kotlin
// Alternative: Expose as Flow instead of callback
fun RootKit.securityFlow(config: PeriodicCheckConfig): Flow<SecuritySummary> {
    return flow {
        while (true) {
            emit(performCheck(config))
            delay(config.intervalMs)
        }
    }
        .flowOn(Dispatchers.Default)
        .distinctUntilChanged()
}

// Usage
rootKit.securityFlow(config)
    .collect { summary ->
        // Handle in real-time
    }
```

**2. Event Bus Pattern**

```kotlin
// Decouple detection from handling
object SecurityEventBus {
    private val _events = MutableSharedFlow<SecurityEvent>()
    val events: SharedFlow<SecurityEvent> = _events.asSharedFlow()

    internal suspend fun emit(event: SecurityEvent) {
        _events.emit(event)
    }
}

// Multiple consumers can observe
SecurityEventBus.events
    .filter { it.severity >= ThreatSeverity.HIGH }
    .collect { event ->
        // React to high-severity threats
    }
```

**3. Sealed Class State Machine**

```kotlin
sealed class SecurityState {
    object Idle : SecurityState()
    object Checking : SecurityState()
    data class Secure(val lastCheck: Long) : SecurityState()
    data class ThreatDetected(
        val threats: Set<DetectionType>,
        val lastCheck: Long
    ) : SecurityState()
    data class Error(val error: Throwable) : SecurityState()
}

// State transitions are explicit and testable
```

### 6.3 Best Practices from Similar SDKs

| SDK                      | Pattern                        | Applicability                            |
| ------------------------ | ------------------------------ | ---------------------------------------- |
| **WorkManager**          | Constraints-based execution    | Consider for battery-aware scheduling    |
| **Firebase Performance** | Trace-based monitoring         | Apply for detection timing metrics       |
| **OkHttp**               | Interceptor chain              | Consider for detection pipeline          |
| **Retrofit**             | Callback/Call dual API         | Provide both callback and coroutine APIs |
| **Room**                 | Flow/LiveData/Callback options | Support multiple observation patterns    |

### 6.4 Testing Considerations

```kotlin
// Test infrastructure recommendations
interface TestablePeriodicCheck {
    // For unit testing - inject mock detectors
    fun injectDetector(type: DetectionType, detector: DetectorResult)

    // For integration testing - control time
    fun setTimeProvider(provider: () -> Long)

    // For UI testing - trigger checks manually
    fun triggerCheck(): CompletableFuture<SecuritySummary>
}
```

---

## 7. Implementation Checklist

### Phase 1: Core Infrastructure

- [ ] Create `PeriodicCheckConfig` with builder pattern
- [ ] Create `PeriodicCheckController` interface
- [ ] Implement `PeriodicCheckControllerImpl` with coroutine scheduling
- [ ] Add `DetectionResult` and `SecuritySummary` data classes

### Phase 2: Execution Engine

- [ ] Implement sequential execution mode
- [ ] Implement parallel execution mode
- [ ] Implement staggered execution mode
- [ ] Add overlap protection with `CheckExecutionGuard`
- [ ] Add timeout handling for individual detections

### Phase 3: Memory Management

- [ ] Implement weak reference callback storage
- [ ] Add proper scope cancellation in `dispose()`
- [ ] Create lifecycle-aware extension (Activity/Fragment)
- [ ] Create app visibility-aware extension (App-level)
- [ ] Add memory leak detection in debug builds

### Phase 4: Integration

- [ ] Update `RootKit.initialize()` with overload
- [ ] Maintain backward compatibility
- [ ] Add result caching layer
- [ ] Implement error handling pipeline
- [ ] Add lifecycle-process dependency for app visibility

### Phase 5: Testing & Documentation

- [ ] Unit tests for all execution modes
- [ ] Integration tests with actual detectors
- [ ] Memory leak tests
- [ ] App visibility behavior tests
- [ ] API documentation
- [ ] Migration guide for existing users

---

## 8. File Structure

```
rootkit/src/main/java/com/ssithara/rootkit/
├── RootKit.kt                          # Updated with new initialize() overloads
├── core/
│   ├── DetectorResult.kt               # Existing - unchanged
│   ├── Result.kt                       # Existing - unchanged
│   ├── EncryptionService.kt            # Existing - unchanged
│   ├── periodic/                       # NEW PACKAGE
│   │   ├── PeriodicCheckConfig.kt      # Configuration class
│   │   ├── PeriodicCheckController.kt  # Controller interface
│   │   ├── PeriodicCheckControllerImpl.kt  # Implementation
│   │   ├── CheckExecutionGuard.kt      # Overlap protection
│   │   ├── DetectionResultCache.kt     # Optional caching
│   │   ├── LifecycleAwarePeriodicCheck.kt  # Activity/Fragment lifecycle
│   │   └── AppVisibilityAwareCheck.kt  # App-level visibility awareness
│   └── ...
├── detection/                          # Existing - unchanged
└── internal/                           # Existing - unchanged
```

---

## 9. Summary

This architecture provides a robust, performant, and developer-friendly solution for periodic security checks in the RootKit SDK:

| Aspect            | Solution                                         |
| ----------------- | ------------------------------------------------ |
| **API**           | Builder pattern config + callback interface      |
| **Scheduling**    | CoroutineScope with SupervisorJob                |
| **Threading**     | Dispatchers.Default with main-thread callbacks   |
| **Overlap**       | Skip strategy with atomic guard                  |
| **Memory**        | Weak references + explicit dispose               |
| **Performance**   | Three execution modes + optional caching         |
| **Battery**       | App visibility awareness - pause in background   |
| **DX**            | Minimal setup + lifecycle integration            |
| **Compatibility** | Backward compatible with existing `initialize()` |

The design prioritizes:

1. **Safety**: Memory leaks prevented through weak references and structured concurrency
2. **Flexibility**: Multiple execution modes and configuration options
3. **Simplicity**: Quick start with sensible defaults
4. **Performance**: Efficient resource usage with staggered execution option
5. **Battery Optimization**: Automatic pause when app goes to background
