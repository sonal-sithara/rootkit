package com.ssithara.rootkit.core.periodic

import com.ssithara.rootkit.core.Result

/**
 * Configuration for periodic security checks
 *
 * Use the Builder to create a configuration:
 * ```kotlin
 * val config = PeriodicCheckConfig.Builder()
 *     .setInterval(30_000L)
 *     .monitorAllDetections()
 *     .setCallback(myCallback)
 *     .build()
 * ```
 */
class PeriodicCheckConfig private constructor(
    val intervalMs: Long,
    val initialDelayMs: Long,
    val detections: Set<DetectionType>,
    val callback: SecurityCallback?,
    val errorHandler: ErrorHandler?,
    val executionMode: ExecutionMode
) {
    init {
        // Validate interval is positive
        require(intervalMs > 0) {
            "Interval must be positive, got: $intervalMs"
        }
        // Validate initial delay is non-negative
        require(initialDelayMs >= 0) {
            "Initial delay must be non-negative, got: $initialDelayMs"
        }
        // Validate detections is not empty
        require(detections.isNotEmpty()) {
            "At least one detection type must be specified"
        }
    }
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
        RUNTIME_TAMPERING
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
        /**
         * Called when a single detection completes
         */
        fun onDetectionResult(detectionType: DetectionType, result: DetectionResult)

        /**
         * Called when all detections in a cycle complete
         */
        fun onCheckCycleComplete(summary: SecuritySummary)

        /**
         * Called when a detection encounters an error
         */
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
        /**
         * Handle an error from a detection
         * @return true to continue monitoring, false to stop
         */
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
            detections.addAll(DetectionType.entries)
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
