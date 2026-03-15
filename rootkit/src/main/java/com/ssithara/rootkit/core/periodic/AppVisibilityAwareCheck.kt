package com.ssithara.rootkit.core.periodic

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner

/**
 * Monitors app-level visibility and automatically pauses/resumes periodic checks.
 *
 * Uses [ProcessLifecycleOwner] to detect when the app goes to background,
 * saving battery and CPU resources when the user isn't interacting with the app.
 *
 * **Benefits:**
 * - Saves battery when app is not visible to user
 * - Reduces CPU usage during background operation
 * - Automatically resumes checks when app returns to foreground
 *
 * **Note:** Security checks are paused in background by default. If continuous
 * background monitoring is required, use [VisibilityConfig.CONTINUE_REDUCED]
 * to continue at a reduced frequency.
 *
 * Usage:
 * ```kotlin
 * // Pause checks completely when app goes to background (default)
 * val controller = rootKit.initialize(config)
 *     .withAppVisibilityAwareness()
 *
 * // Continue checks in background but at reduced frequency
 * val controller = rootKit.initialize(config)
 *     .withAppVisibilityAwareness(VisibilityConfig.CONTINUE_REDUCED)
 * ```
 */
class AppVisibilityAwareCheck(
    private val controller: PeriodicCheckController,
    private val config: VisibilityConfig = VisibilityConfig.DEFAULT
) : DefaultLifecycleObserver {

    /**
     * Configuration for app visibility behavior
     *
     * @property pauseInBackground Whether to pause checks when app goes to background
     * @property resumeOnForeground Whether to resume checks when app returns to foreground
     * @property backgroundCheckIntervalMultiplier Multiply interval by this in background (0 = pause)
     * @property minBackgroundIntervalMs Minimum interval in background when multiplier > 0
     */
    data class VisibilityConfig(
        val pauseInBackground: Boolean = true,
        val resumeOnForeground: Boolean = true,
        val backgroundCheckIntervalMultiplier: Long = 0,
        val minBackgroundIntervalMs: Long = 60_000L
    ) {
        companion object {
            /**
             * Default configuration: Pause checks completely when app goes to background
             */
            val DEFAULT = VisibilityConfig()

            /**
             * Continue checks in background but at reduced frequency (4x slower)
             */
            val CONTINUE_REDUCED = VisibilityConfig(
                pauseInBackground = false,
                backgroundCheckIntervalMultiplier = 4
            )

            /**
             * Create a custom configuration
             */
            fun custom(
                pauseInBackground: Boolean = true,
                intervalMultiplier: Long = 0,
                minIntervalMs: Long = 60_000L
            ): VisibilityConfig = VisibilityConfig(
                pauseInBackground = pauseInBackground,
                backgroundCheckIntervalMultiplier = intervalMultiplier,
                minBackgroundIntervalMs = minIntervalMs
            )
        }
    }

    // Store original interval for reset
    private var originalIntervalMs: Long = 0L
    private var isAttached = false

    init {
        attach()
    }

    private fun attach() {
        if (!isAttached) {
            originalIntervalMs = controller.getInterval()
            ProcessLifecycleOwner.get().lifecycle.addObserver(this)
            isAttached = true
        }
    }

    /**
     * Detach from lifecycle and cleanup.
     * Call this when you want to stop visibility-aware behavior.
     */
    fun detach() {
        if (isAttached) {
            ProcessLifecycleOwner.get().lifecycle.removeObserver(this)
            isAttached = false
        }
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

    companion object {
        /**
         * Create an app visibility-aware check with default configuration
         */
        fun create(controller: PeriodicCheckController): AppVisibilityAwareCheck {
            return AppVisibilityAwareCheck(controller, VisibilityConfig.DEFAULT)
        }

        /**
         * Create an app visibility-aware check with custom configuration
         */
        fun create(
            controller: PeriodicCheckController,
            config: VisibilityConfig
        ): AppVisibilityAwareCheck {
            return AppVisibilityAwareCheck(controller, config)
        }
    }
}

/**
 * Extension function to add app visibility awareness to a controller
 */
fun PeriodicCheckController.withAppVisibilityAwareness(
    config: AppVisibilityAwareCheck.VisibilityConfig = AppVisibilityAwareCheck.VisibilityConfig.DEFAULT
): PeriodicCheckController {
    AppVisibilityAwareCheck(this, config)
    return this
}
