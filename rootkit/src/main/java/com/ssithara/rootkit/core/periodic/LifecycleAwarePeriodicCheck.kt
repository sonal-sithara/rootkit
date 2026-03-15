package com.ssithara.rootkit.core.periodic

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner

/**
 * Lifecycle-aware extension for periodic security checks.
 *
 * Automatically pauses checks when the lifecycle owner (Activity/Fragment) stops,
 * and resumes when it starts. Disposes the controller when the lifecycle is destroyed.
 *
 * Usage:
 * ```kotlin
 * val controller = rootKit.initialize(config)
 *     .bindToLifecycle(lifecycle)
 *
 * controller.start()
 * // Checks will automatically pause/resume based on lifecycle
 * // Controller will be disposed when lifecycle is destroyed
 * ```
 */
class LifecycleAwarePeriodicCheck(
    private val controller: PeriodicCheckController,
    lifecycle: Lifecycle
) : DefaultLifecycleObserver {

    init {
        lifecycle.addObserver(this)
    }

    override fun onStart(owner: LifecycleOwner) {
        // Activity/Fragment became visible
        controller.resume()
    }

    override fun onStop(owner: LifecycleOwner) {
        // Activity/Fragment went to background
        controller.pause()
    }

    override fun onDestroy(owner: LifecycleOwner) {
        // Activity/Fragment is being destroyed
        controller.dispose()
    }

    companion object {
        /**
         * Bind a controller to a lifecycle
         */
        fun bind(
            controller: PeriodicCheckController,
            lifecycle: Lifecycle
        ): PeriodicCheckController {
            LifecycleAwarePeriodicCheck(controller, lifecycle)
            return controller
        }
    }
}

/**
 * Extension function to bind a controller to a lifecycle
 */
fun PeriodicCheckController.bindToLifecycle(lifecycle: Lifecycle): PeriodicCheckController {
    LifecycleAwarePeriodicCheck(this, lifecycle)
    return this
}
