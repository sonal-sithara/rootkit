package com.ssithara.rootkit.core.periodic

import androidx.annotation.Keep
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner

/**
 * Lifecycle-aware extension for periodic security checks.
 *
 * Automatically pauses checks when the lifecycle owner (Activity/Fragment) stops,
 * and resumes when it starts. Disposes the controller when the lifecycle is destroyed.
 *
 * **Lifecycle State Requirements:**
 * - [attach] must be called to start observing lifecycle events
 * - [controller.start] should be called after attaching to begin periodic checks
 * - [controller.dispose] will only be called if the controller was started (via [controller.start])
 * - If the controller was never started, dispose() should be called manually by the caller
 *
 * ## Construction
 *
 * Use the [bind] factory method or the [bindToLifecycle] extension rather than
 * constructing this class directly.  Both call [attach] after the instance is
 * fully initialised, avoiding the classic `this`-escape anti-pattern of
 * registering a lifecycle observer inside an `init` block before the object
 * is ready.
 *
 * ```kotlin
 * val lifecycleCheck = rootKit.initialize(config)
 *     .bindToLifecycle(lifecycle)
 *
 * lifecycleCheck.controller.start()
 * // Checks will automatically pause/resume based on lifecycle.
 * // Controller will be disposed when the lifecycle owner is destroyed.
 * ```
 */
@Keep
class LifecycleAwarePeriodicCheck(
    val controller: PeriodicCheckController,
    private val lifecycle: Lifecycle,
) : DefaultLifecycleObserver {

    // Track whether the controller has been started
    // This ensures dispose() is only called if start() was called
    @Volatile
    private var hasStarted = false

    // NO init block — addObserver(this) is intentionally NOT called here.
    // Registering `this` as an observer inside a constructor is the classic
    // "this-escape" anti-pattern: the partially-constructed object is handed to
    // external code (the Lifecycle) before all fields are initialised.  The
    // factory method and extension function below call attach() explicitly once
    // construction is complete, which is the safe approach.

    /**
     * Registers this instance as a [Lifecycle] observer and starts responding
     * to lifecycle events.
     *
     * This method is idempotent — the [Lifecycle] implementation ignores
     * duplicate registrations of the same observer.  It is called automatically
     * by [bind] and [bindToLifecycle]; you only need to call it manually if you
     * constructed this class directly.
     */
    fun attach(): LifecycleAwarePeriodicCheck {
        lifecycle.addObserver(this)
        return this
    }

    override fun onStart(owner: LifecycleOwner) {
        // Activity/Fragment became visible — resume checks.
        controller.resume()
    }

    override fun onStop(owner: LifecycleOwner) {
        // Activity/Fragment went to background — pause checks.
        controller.pause()
    }

    override fun onDestroy(owner: LifecycleOwner) {
        // Activity/Fragment is being destroyed — release all resources.
        // Only dispose if the controller was started; otherwise, let the caller
        // handle disposal since they may be reusing the controller.
        if (hasStarted) {
            controller.dispose()
        }
    }

    /**
     * Marks the controller as started. This should be called after
     * [controller.start] to ensure proper cleanup on lifecycle destruction.
     *
     * This is automatically called by the [bind] and [bindToLifecycle] factory methods
     * after starting the controller.
     */
    fun markStarted() {
        hasStarted = true
    }

    companion object {
        /**
         * Creates a [LifecycleAwarePeriodicCheck], attaches it to [lifecycle],
         * starts the controller, and returns the wrapper so the caller retains
         * a reference to it.
         *
         * Prefer this factory over the constructor to avoid the `this`-escape
         * anti-pattern.
         *
         * @param controller The [PeriodicCheckController] to bind.
         * @param lifecycle  The [Lifecycle] to observe.
         * @return           The attached [LifecycleAwarePeriodicCheck] wrapper.
         */
        @JvmStatic
        @Keep
        fun bind(
            controller: PeriodicCheckController,
            lifecycle: Lifecycle,
        ): LifecycleAwarePeriodicCheck {
            val wrapper = LifecycleAwarePeriodicCheck(controller, lifecycle).attach()
            wrapper.controller.start()
            wrapper.markStarted()
            return wrapper
        }
    }
}

/**
 * Binds this [PeriodicCheckController] to [lifecycle] and returns the
 * [LifecycleAwarePeriodicCheck] wrapper so the caller can retain a reference
 * to it.
 *
 * The returned wrapper is registered as an observer on [lifecycle], which holds
 * a strong reference to it for the duration of that lifecycle.  The caller does
 * **not** need to retain the return value merely to keep it alive, but should
 * store it if they need access to the [LifecycleAwarePeriodicCheck.controller]
 * property after binding.
 *
 * ```kotlin
 * val lifecycleCheck = rootKit.initialize(config)
 *     .bindToLifecycle(lifecycle)
 *
 * lifecycleCheck.controller.start()
 * // Checks automatically pause on onStop and resume on onStart.
 * // controller.dispose() is called automatically on onDestroy.
 * ```
 *
 * @receiver The controller to bind.
 * @param lifecycle The lifecycle to observe.
 * @return The [LifecycleAwarePeriodicCheck] wrapper (already attached).
 */
fun PeriodicCheckController.bindToLifecycle(lifecycle: Lifecycle): LifecycleAwarePeriodicCheck {
    return LifecycleAwarePeriodicCheck.bind(this, lifecycle)
}
