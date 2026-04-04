package com.ssithara.rootkit.core.periodic

import androidx.annotation.Keep

/**
 * Controller for managing periodic security check lifecycle
 *
 * Example usage:
 * ```kotlin
 * val controller = rootKit.initialize(config)
 * controller.start()
 *
 * // Later...
 * controller.pause()  // Pause checks
 * controller.resume() // Resume checks
 *
 * // When done
 * controller.dispose()
 * ```
 */
@Keep
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
     * Can be restarted with start().
     */
    fun stop()

    /**
     * Pause periodic checks without releasing resources.
     * Can be resumed with resume().
     */
    fun pause()

    /**
     * Resume paused periodic checks.
     * No-op if not paused.
     */
    fun resume()

    /**
     * Trigger an immediate security check.
     * Does not affect the periodic schedule.
     * Results are delivered via the configured callback.
     */
    fun checkNow()

    /**
     * Update the check interval at runtime.
     * Takes effect on the next scheduled check.
     * @param newIntervalMs New interval in milliseconds
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
