package com.ssithara.rootkit.core.periodic

import android.content.Context
import android.os.Process
import com.ssithara.rootkit.core.EncryptionService
import com.ssithara.rootkit.core.Result
import com.ssithara.rootkit.detection.environment.DebuggerDetection
import com.ssithara.rootkit.detection.environment.EmulatorDetection
import com.ssithara.rootkit.detection.root.MagiskDetection
import com.ssithara.rootkit.detection.root.MagiskHideDetection
import com.ssithara.rootkit.detection.root.RootDetection
import com.ssithara.rootkit.detection.runtime.RuntimeTamperingDetection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Implementation of [PeriodicCheckController] that manages periodic security checks.
 *
 * This class handles:
 * - Coroutine-based scheduling with SupervisorJob for fault tolerance
 * - Three execution modes: Sequential, Parallel, Staggered
 * - Overlap protection to prevent resource buildup
 * - Memory safety with weak references
 * - Main thread callbacks for safe UI updates
 *
 * @property appContext Application context (uses applicationContext to prevent leaks)
 * @property config Configuration for periodic checks
 */
internal class PeriodicCheckControllerImpl(
    context: Context,
    private val config: PeriodicCheckConfig,
    private val encryptionKey: String
) : PeriodicCheckController {

    // Use application context to prevent activity leaks
    private val appContext: Context = context.applicationContext

    // Weak reference for callback to allow GC if consumer is collected
    private val callbackRef = WeakReference(config.callback)

    // Supervised scope for fault isolation
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // Main thread dispatcher for callbacks
    private val mainDispatcher: CoroutineDispatcher = Dispatchers.Main

    // Active periodic job reference
    private var periodicJob: AtomicReference<Job?> = AtomicReference(null)

    // Guard to prevent overlapping checks
    private val executionGuard = CheckExecutionGuard()

    // Track running/paused state
    private val _isRunning = AtomicBoolean(false)
    private val _isPaused = AtomicBoolean(false)

    // Track disposed state
    private val disposed = AtomicBoolean(false)

    // Current interval (can be updated at runtime)
    private val currentIntervalMs = AtomicLong(config.intervalMs)

    // Last completed summary
    private val lastSummaryRef = AtomicReference<PeriodicCheckConfig.SecuritySummary?>(null)

    // Lazy detection instances (reused from existing pattern)
    private val magiskHideDetection by lazy { MagiskHideDetection(appContext) }
    private val magiskDetection by lazy { MagiskDetection(appContext) }
    private val rootDetection by lazy { RootDetection(appContext) }
    private val debuggerDetection by lazy { DebuggerDetection(appContext) }
    private val emulatorDetection by lazy { EmulatorDetection(appContext) }
    private val runtimeTamperingDetection by lazy { RuntimeTamperingDetection(appContext) }

    override val isRunning: Boolean
        get() = _isRunning.get() && !disposed.get()

    override val isPaused: Boolean
        get() = _isPaused.get() && !disposed.get()

    override fun start() {
        if (disposed.get()) {
            throw IllegalStateException("Controller has been disposed")
        }

        if (_isRunning.compareAndSet(false, true)) {
            _isPaused.set(false)
            startPeriodicChecks()
        }
    }

    override fun stop() {
        _isRunning.set(false)
        _isPaused.set(false)
        cancelPeriodicJob()
    }

    override fun pause() {
        if (_isRunning.get()) {
            _isPaused.set(true)
        }
    }

    override fun resume() {
        if (_isRunning.get() && _isPaused.compareAndSet(true, false)) {
            // Resume by triggering the next check cycle
            // The periodic job will continue from where it was
        }
    }

    override fun checkNow() {
        if (disposed.get()) {
            throw IllegalStateException("Controller has been disposed")
        }

        scope.launch {
            // Wrap with execution guard to prevent concurrent execution with periodic checks
            executionGuard.executeWithGuard {
                executeDetections()
            }.fold(
                onExecuted = { results ->
                    val startTime = System.currentTimeMillis()
                    val duration = System.currentTimeMillis() - startTime
                    val summary = createSummary(results, duration)

                    // Store last summary
                    lastSummaryRef.set(summary)

                    // Notify callback on main thread
                    notifyCycleComplete(summary)
                },
                onSkipped = {
                    // Check was skipped due to overlap with periodic check
                    // This is expected behavior - the periodic check will handle notifications
                }
            )
        }
    }

    override fun updateInterval(newIntervalMs: Long) {
        require(newIntervalMs >= PeriodicCheckConfig.Builder.MIN_INTERVAL_MS) {
            "Interval must be at least ${PeriodicCheckConfig.Builder.MIN_INTERVAL_MS} ms"
        }
        currentIntervalMs.set(newIntervalMs)
    }

    override fun resetInterval() {
        currentIntervalMs.set(config.intervalMs)
    }

    override fun getInterval(): Long = currentIntervalMs.get()

    override fun getLastSummary(): PeriodicCheckConfig.SecuritySummary? = lastSummaryRef.get()

    override fun dispose() {
        if (disposed.compareAndSet(false, true)) {
            stop()
            scope.coroutineContext[Job]?.cancel()
            callbackRef.clear()
            lastSummaryRef.set(null)
        }
    }

    // Cleanup on finalize as safety net
    @Throws(Throwable::class)
    protected fun finalize() {
        if (!disposed.get()) {
            scope.coroutineContext[Job]?.cancel()
        }
    }

    private fun startPeriodicChecks() {
        val job = scope.launch {
            // Initial delay
            delay(config.initialDelayMs)

            while (scope.isActive && _isRunning.get()) {
                // Skip if paused
                if (!_isPaused.get()) {
                    executeCheckCycle()
                }

                // Wait for next interval
                delay(currentIntervalMs.get())
            }
        }

        periodicJob.set(job)
    }

    private fun cancelPeriodicJob() {
        periodicJob.getAndSet(null)?.cancel()
    }

    private suspend fun executeCheckCycle() {
        executionGuard.executeWithGuard {
            executeDetections()
        }.fold(
            onExecuted = { results ->
                val startTime = System.currentTimeMillis()
                val duration = System.currentTimeMillis() - startTime
                val summary = createSummary(results, duration)

                // Store last summary
                lastSummaryRef.set(summary)

                // Notify callback on main thread
                notifyCycleComplete(summary)
            },
            onSkipped = {
                // Check was skipped due to overlap - this is expected behavior
            }
        )
    }

    /**
     * Internal function that executes all detections based on the configured execution mode.
     * This function is called within the execution guard by both periodic checks and checkNow().
     */
    private suspend fun executeDetections(): List<PeriodicCheckConfig.DetectionResult> {
        return when (config.executionMode) {
            PeriodicCheckConfig.ExecutionMode.SEQUENTIAL -> executeSequential()
            PeriodicCheckConfig.ExecutionMode.PARALLEL -> executeParallel()
            PeriodicCheckConfig.ExecutionMode.STAGGERED -> executeStaggered()
        }
    }

    private suspend fun executeSequential(): List<PeriodicCheckConfig.DetectionResult> {
        val results = mutableListOf<PeriodicCheckConfig.DetectionResult>()

        for (detectionType in config.detections) {
            // Check for cancellation
            if (!scope.isActive) break

            val result = executeDetectionSafely(detectionType)
            results.add(result)

            // Notify individual result on main thread
            notifyDetectionResult(detectionType, result)
        }

        return results
    }

    private suspend fun executeParallel(): List<PeriodicCheckConfig.DetectionResult> = coroutineScope {
        config.detections.map { detectionType ->
            async {
                val result = executeDetectionSafely(detectionType)
                notifyDetectionResult(detectionType, result)
                result
            }
        }.awaitAll()
    }

    private suspend fun executeStaggered(
        staggerDelayMs: Long = DEFAULT_STAGGER_DELAY_MS
    ): List<PeriodicCheckConfig.DetectionResult> {
        val results = mutableListOf<PeriodicCheckConfig.DetectionResult>()
        var isFirst = true

        for (detectionType in config.detections) {
            // Check for cancellation
            if (!scope.isActive) break

            // Stagger start times (skip delay for first item)
            if (!isFirst) {
                delay(staggerDelayMs)
            }
            isFirst = false

            val result = executeDetectionSafely(detectionType)
            results.add(result)

            // Notify individual result on main thread
            notifyDetectionResult(detectionType, result)
        }

        return results
    }

    private suspend fun executeDetectionSafely(
        type: PeriodicCheckConfig.DetectionType
    ): PeriodicCheckConfig.DetectionResult {
        return try {
            withTimeout(CHECK_TIMEOUT_MS) {
                executeDetection(type)
            }
        } catch (e: CancellationException) {
            throw e  // Don't catch cancellation
        } catch (e: Exception) {
            // Notify error callback on main thread (like other callbacks)
            notifyError(type, e)

            // Let error handler decide what to do - dispatch to main thread for consistency
            withContext(mainDispatcher) {
                try {
                    config.errorHandler?.handleError(type, e)
                } catch (handlerEx: Exception) {
                    Log.e(TAG, "Error handler threw exception", handlerEx)
                }
            }

            // Return safe result (fail safe - assume no threat on error)
            PeriodicCheckConfig.DetectionResult(
                detectionType = type,
                result = Result.NOT_FOUND,
                timestamp = System.currentTimeMillis()
            )
        }
    }

    private suspend fun executeDetection(
        type: PeriodicCheckConfig.DetectionType
    ): PeriodicCheckConfig.DetectionResult {
        // Set background thread priority for detection execution
        setThreadPriorityBackground()

        val result = when (type) {
            PeriodicCheckConfig.DetectionType.ROOT -> rootDetection.run()
            PeriodicCheckConfig.DetectionType.MAGISK -> magiskDetection.run()
            PeriodicCheckConfig.DetectionType.MAGISK_HIDE -> magiskHideDetection.run()
            PeriodicCheckConfig.DetectionType.DEBUGGER -> debuggerDetection.run()
            PeriodicCheckConfig.DetectionType.EMULATOR -> emulatorDetection.run()
            PeriodicCheckConfig.DetectionType.FRIDA -> {
                if (runtimeTamperingDetection.isFridaDetected()) Result.FOUND else Result.NOT_FOUND
            }

            PeriodicCheckConfig.DetectionType.XPOSED -> {
                if (runtimeTamperingDetection.isXposedDetected()) Result.FOUND else Result.NOT_FOUND
            }

            PeriodicCheckConfig.DetectionType.MEMORY_TAMPERING -> {
                if (runtimeTamperingDetection.isMemoryTamperingDetected()) Result.FOUND else Result.NOT_FOUND
            }

            PeriodicCheckConfig.DetectionType.NATIVE_HOOK -> {
                if (runtimeTamperingDetection.isNativeHookDetected()) Result.FOUND else Result.NOT_FOUND
            }

            PeriodicCheckConfig.DetectionType.RUNTIME_TAMPERING -> runtimeTamperingDetection.run()
        }

        val encryptedValue = EncryptionService.encryptWithBase64Key(result.name, encryptionKey)

        return PeriodicCheckConfig.DetectionResult(
            detectionType = type,
            result = result,
            timestamp = System.currentTimeMillis(),
            encryptedValue = encryptedValue
        )
    }

    private fun setThreadPriorityBackground() {
        try {
            Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)
        } catch (_: Exception) {
            // Ignore priority setting failures
        }
    }

    private fun createSummary(
        results: List<PeriodicCheckConfig.DetectionResult>,
        durationMs: Long
    ): PeriodicCheckConfig.SecuritySummary {
        val resultMap = results.associateBy { it.detectionType }
        val threatResults = results.filter { it.result == Result.FOUND }

        return PeriodicCheckConfig.SecuritySummary(
            results = resultMap,
            anyThreatDetected = threatResults.isNotEmpty(),
            threatCount = threatResults.size,
            checkDurationMs = durationMs,
            timestamp = System.currentTimeMillis()
        )
    }

    // Callback notification helpers - dispatch to main thread
    private suspend fun notifyDetectionResult(
        type: PeriodicCheckConfig.DetectionType,
        result: PeriodicCheckConfig.DetectionResult
    ) {
        withContext(mainDispatcher) {
            callbackRef.get()?.onDetectionResult(type, result)
        }
    }

    private suspend fun notifyCycleComplete(summary: PeriodicCheckConfig.SecuritySummary) {
        withContext(mainDispatcher) {
            callbackRef.get()?.onCheckCycleComplete(summary)
        }
    }

    private suspend fun notifyError(
        type: PeriodicCheckConfig.DetectionType,
        error: Throwable
    ) {
        withContext(mainDispatcher) {
            callbackRef.get()?.onError(type, error)
        }
    }

    companion object {
        private const val CHECK_TIMEOUT_MS = 5_000L
        private const val DEFAULT_STAGGER_DELAY_MS = 50L
    }
}
