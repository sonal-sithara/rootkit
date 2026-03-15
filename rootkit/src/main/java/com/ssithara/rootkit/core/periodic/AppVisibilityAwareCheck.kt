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
 * ## Construction
 *
 * Use the [create] factory methods or the [withAppVisibilityAwareness] extension
 * rather than constructing this class directly.  Both take care of calling
 * [attach] after the instance is fully initialised, which avoids the classic
 * `this`-escape anti-pattern of registering a lifecycle observer inside an
 * `init` block before the object is ready.
 *
 * ```kotlin
 * // Pause checks completely when app goes to background (default)
 * val visibilityCheck = rootKit.initialize(config)
 *     .withAppVisibilityAwareness()
 *
 * // Continue checks in background but at reduced frequency
 * val visibilityCheck = rootKit.initialize(config)
 *     .withAppVisibilityAwareness(AppVisibilityAwareCheck.VisibilityConfig.CONTINUE_REDUCED)
 *
 * // Stop visibility-aware behaviour later
 * visibilityCheck.detach()
 * ```
 */
class AppVisibilityAwareCheck(
    private val controller: PeriodicCheckController?,
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
             * Default configuration: Pause checks completely when app goes to background.
             */
            val DEFAULT = VisibilityConfig()

            /**
             * Continue checks in background but at reduced frequency (4x slower).
             */
            val CONTINUE_REDUCED = VisibilityConfig(
                pauseInBackground = false,
                backgroundCheckIntervalMultiplier = 4
            )

            /**
             * Create a custom configuration.
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

    // Stored so attach/detach can be called multiple times safely.
    private var isAttached = false

    // Captured at attach() time so resetInterval() can restore the original value.
    private var originalIntervalMs: Long = 0L

    // NO init block — addObserver(this) is intentionally NOT called here.
    // Registering `this` as an observer inside a constructor is the classic
    // "this-escape" anti-pattern: the partially-constructed object is handed to
    // external code (the Lifecycle) before all fields are initialised.  The
    // factory methods and extension function below call attach() explicitly once
    // construction is complete, which is the safe approach.

    /**
     * Registers this instance as a [ProcessLifecycleOwner] observer and starts
     * responding to foreground/background transitions.
     *
     * This method is idempotent — calling it more than once has no effect.
     * It is called automatically by [create] and [withAppVisibilityAwareness];
     * you only need to call it manually if you constructed this class directly.
     */
    fun attach() {
        if (!isAttached && controller != null) {
            originalIntervalMs = controller.getInterval()
            ProcessLifecycleOwner.get().lifecycle.addObserver(this)
            isAttached = true
        }
    }

    /**
     * Unregisters this instance from the [ProcessLifecycleOwner] lifecycle.
     *
     * After detaching, foreground/background transitions no longer affect the
     * controller. The original interval is restored before detaching.
     * Call [attach] to re-enable visibility-aware behaviour.
     */
    fun detach() {
        if (isAttached) {
            // Restore original interval before detaching
            if (originalIntervalMs > 0) {
                controller?.updateInterval(originalIntervalMs)
            }
            ProcessLifecycleOwner.get().lifecycle.removeObserver(this)
            isAttached = false
        }
    }

    override fun onStart(owner: LifecycleOwner) {
        // App came to foreground.
        if (config.resumeOnForeground) {
            controller?.resume()

            // Restore original interval if it was slowed down in the background.
            if (config.backgroundCheckIntervalMultiplier > 0) {
                controller?.resetInterval()
            }
        }
    }

    override fun onStop(owner: LifecycleOwner) {
        // App went to background.
        if (config.pauseInBackground) {
            controller?.pause()
        } else if (config.backgroundCheckIntervalMultiplier > 0) {
            // Reduce frequency instead of pausing completely.
            val currentInterval = controller?.getInterval() ?: return
            val newInterval = (currentInterval * config.backgroundCheckIntervalMultiplier)
                .coerceAtLeast(config.minBackgroundIntervalMs)
            controller?.updateInterval(newInterval)
        }
    }

    companion object {
        /**
         * Creates an [AppVisibilityAwareCheck] with the [VisibilityConfig.DEFAULT]
         * configuration and immediately attaches it to the process lifecycle.
         *
         * Prefer this factory over the constructor to avoid the `this`-escape
         * anti-pattern.
         */
        fun create(controller: PeriodicCheckController): AppVisibilityAwareCheck {
            return AppVisibilityAwareCheck(controller, VisibilityConfig.DEFAULT)
                .also { it.attach() }
        }

        /**
         * Creates an [AppVisibilityAwareCheck] with a custom [config] and
         * immediately attaches it to the process lifecycle.
         *
         * Prefer this factory over the constructor to avoid the `this`-escape
         * anti-pattern.
         */
        fun create(
            controller: PeriodicCheckController,
            config: VisibilityConfig
        ): AppVisibilityAwareCheck {
            return AppVisibilityAwareCheck(controller, config)
                .also { it.attach() }
        }
    }
}

/**
 * Attaches app-visibility awareness to this [PeriodicCheckController] and
 * returns the [AppVisibilityAwareCheck] wrapper so the caller can [AppVisibilityAwareCheck.detach]
 * it later if needed.
 *
 * The returned wrapper is registered with [ProcessLifecycleOwner], which holds a
 * strong reference to it for the lifetime of the process lifecycle.  The caller
 * does **not** need to retain the return value merely to keep it alive, but
 * should store it if they want the ability to call [AppVisibilityAwareCheck.detach].
 *
 * ```kotlin
 * val visibilityCheck = rootKit.initialize(config)
 *     .withAppVisibilityAwareness()
 * visibilityCheck.controller.start()
 *
 * // Later, to stop visibility-aware behaviour:
 * visibilityCheck.detach()
 * ```
 */
fun PeriodicCheckController.withAppVisibilityAwareness(
    config: AppVisibilityAwareCheck.VisibilityConfig = AppVisibilityAwareCheck.VisibilityConfig.DEFAULT
): AppVisibilityAwareCheck {
    return AppVisibilityAwareCheck.create(this, config)
}
