package com.ssithara.rootkit.detection.runtime

import android.content.Context
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import kotlin.random.Random

/**
 * Runtime Tampering Detection Coordinator
 *
 * Aggregates all runtime tampering detection modules:
 * - Frida Detection
 * - Xposed/LSPosed Detection
 * - Memory Tampering Detection
 * - Native Hook Detection
 *
 * Provides a unified interface for comprehensive runtime tampering checks.
 *
 * ## Result Caching
 *
 * Each full detection cycle is expensive because it invokes multiple native
 * routines (port scans, /proc/self/maps reads, ELF walks, etc.). To prevent
 * the same work being repeated within a single logical "check" — for example
 * when a caller invokes [run] followed immediately by [isFridaDetected] — all
 * boolean helpers share a short-lived cache backed by [getOrComputeSummary].
 *
 * The cache is stored in an [AtomicReference] for lock-free reads and guarded
 * by a [java.util.concurrent.locks.ReentrantLock] for the compute path. When
 * the cache expires, only the first thread to acquire the lock performs the
 * expensive native detection work; concurrent threads wait and then reuse the
 * freshly computed result via double-checked locking.
 *
 * ## Security Considerations
 *
 * - Cache TTL includes random jitter to prevent timing attacks
 * - Detection failures are tracked separately from "not detected" results
 * - Uses [Result.ERROR] when sub-detectors fail internally
 */
class RuntimeTamperingDetection(context: Context) : DetectorResult(context) {

    // -------------------------------------------------------------------------
    // Sub-detectors (lazy so native library is not required until first use)
    // -------------------------------------------------------------------------

    private val fridaDetection by lazy { FridaDetection(context) }
    private val xposedDetection by lazy { XposedDetection(context) }
    private val memoryTamperingDetection by lazy { MemoryTamperingDetection(context) }
    private val nativeHookDetection by lazy { NativeHookDetection(context) }

    // -------------------------------------------------------------------------
    // Cache
    // -------------------------------------------------------------------------

    /**
     * Snapshot of one full detection cycle together with the wall-clock time at
     * which it was computed.
     */
    private data class CachedSummary(
        val summary: DetectionSummary,
        val timestamp: Long,
    )

    private val cachedSummary = AtomicReference<CachedSummary?>(null)

    /**
     * Lock that serializes concurrent cache computations so that only one
     * thread performs the expensive native detection work at a time while
     * other threads wait and then reuse the freshly computed result.
     */
    private val cacheLock = ReentrantLock()

    // -------------------------------------------------------------------------
    // Core
    // -------------------------------------------------------------------------

    /**
     * Returns a [DetectionSummary] that was computed no earlier than
     * the effective cache TTL milliseconds ago.
     *
     * Uses a [ReentrantLock] so that concurrent calls properly serialize
     * around the cache computation. Only one thread will perform the
     * expensive native detection work; others will wait and reuse the
     * freshly computed result.
     *
     * The effective TTL includes random jitter to prevent timing attacks
     * that could infer detection results by measuring cache hit/miss timing.
     */
    private fun getOrComputeSummary(): DetectionSummary {
        val now = System.currentTimeMillis()

        // Fast path: check cache without acquiring lock
        cachedSummary.get()?.let { cached ->
            if (now - cached.timestamp < getEffectiveTtl()) {
                return cached.summary
            }
        }

        // Slow path: acquire lock and double-check cache
        cacheLock.lock()
        try {
            // Double-check after acquiring lock — another thread may have
            // already computed a fresh summary while we were waiting.
            val nowAfterLock = System.currentTimeMillis()
            cachedSummary.get()?.let { cached ->
                if (nowAfterLock - cached.timestamp < getEffectiveTtl()) {
                    return cached.summary
                }
            }

            val fridaResult = fridaDetection.runSafely()
            val xposedResult = xposedDetection.runSafely()
            val memoryResult = memoryTamperingDetection.runSafely()
            val nativeHookResult = nativeHookDetection.runSafely()

            val summary = DetectionSummary(
                fridaDetected = fridaResult == Result.FOUND,
                fridaFailed = fridaResult == Result.ERROR,
                xposedDetected = xposedResult == Result.FOUND,
                xposedFailed = xposedResult == Result.ERROR,
                memoryTamperingDetected = memoryResult == Result.FOUND,
                memoryTamperingFailed = memoryResult == Result.ERROR,
                nativeHookDetected = nativeHookResult == Result.FOUND,
                nativeHookFailed = nativeHookResult == Result.ERROR,
            )

            cachedSummary.set(CachedSummary(summary, System.currentTimeMillis()))
            return summary
        } finally {
            cacheLock.unlock()
        }
    }

    /**
     * Computes the effective cache TTL with random jitter to prevent timing attacks.
     *
     * The jitter is a random value between 0 and [MAX_JITTER_MS] milliseconds,
     * added to the base TTL. This makes it harder for attackers to infer
     * detection results by measuring cache timing differences.
     */
    private fun getEffectiveTtl(): Long {
        return CACHE_TTL_MS + Random.nextLong(0, MAX_JITTER_MS)
    }

    /** Runs all sub-detectors and returns [Result.FOUND] if any threat is detected.
     * Returns [Result.ERROR] if any sub-detector failed internally.
     */
    override fun run(): Result {
        val summary = getOrComputeSummary()
        
        // If any detection failed, return ERROR to indicate incomplete results
        if (summary.anyFailed) {
            return Result.ERROR
        }
        
        return if (summary.anyDetected) Result.FOUND else Result.NOT_FOUND
    }

    // -------------------------------------------------------------------------
    // Granular boolean helpers (all backed by the shared cache)
    // -------------------------------------------------------------------------

    /** Returns `true` if Frida instrumentation is detected. */
    fun isFridaDetected(): Boolean = getOrComputeSummary().fridaDetected

    /** Returns `true` if Xposed / LSPosed is detected. */
    fun isXposedDetected(): Boolean = getOrComputeSummary().xposedDetected

    /** Returns `true` if memory tampering is detected. */
    fun isMemoryTamperingDetected(): Boolean = getOrComputeSummary().memoryTamperingDetected

    /** Returns `true` if native (PLT/GOT/inline) hooks are detected. */
    fun isNativeHookDetected(): Boolean = getOrComputeSummary().nativeHookDetected

    // -------------------------------------------------------------------------
    // Module accessors
    // -------------------------------------------------------------------------

    /** Direct access to the [FridaDetection] module for granular sub-checks. */
    fun fridaDetectionModule(): FridaDetection = fridaDetection

    /** Direct access to the [XposedDetection] module for granular sub-checks. */
    fun xposedDetectionModule(): XposedDetection = xposedDetection

    /** Direct access to the [MemoryTamperingDetection] module for granular sub-checks. */
    fun memoryTamperingDetectionModule(): MemoryTamperingDetection = memoryTamperingDetection

    /** Direct access to the [NativeHookDetection] module for granular sub-checks. */
    fun nativeHookDetectionModule(): NativeHookDetection = nativeHookDetection

    // -------------------------------------------------------------------------
    // Detailed results
    // -------------------------------------------------------------------------

    /**
     * Returns the cached [DetectionSummary] from the most recent check cycle,
     * recomputing only if the cache has expired.
     */
    fun getDetectionSummary(): DetectionSummary = getOrComputeSummary()

    /**
     * Returns per-vector breakdown maps from all four sub-detectors.
     *
     * Each sub-detector's [getDetectionDetails] re-runs its own individual
     * checks to produce a granular breakdown — this is intentional because the
     * per-vector detail methods are more expensive than the summary and are only
     * called when the caller explicitly needs them.
     * 
     * Note: Native hook detection details may contain null values indicating
     * detection failures.
     */
    fun getComprehensiveDetectionDetails(): Map<String, Map<String, Any?>> {
        return mapOf(
            "frida" to fridaDetection.getDetectionDetails(),
            "xposed" to xposedDetection.getDetectionDetails(),
            "memory_tampering" to memoryTamperingDetection.getDetectionDetails(),
            "native_hooks" to nativeHookDetection.getDetectionDetails(),
        )
    }

    // -------------------------------------------------------------------------
    // Summary data class
    // -------------------------------------------------------------------------

    /**
     * Immutable snapshot of a single detection cycle.
     *
     * Includes both detection results and failure flags to distinguish between
     * "not detected" and "detection failed" states.
     */
    data class DetectionSummary(
        val fridaDetected: Boolean,
        val fridaFailed: Boolean = false,
        val xposedDetected: Boolean,
        val xposedFailed: Boolean = false,
        val memoryTamperingDetected: Boolean,
        val memoryTamperingFailed: Boolean = false,
        val nativeHookDetected: Boolean,
        val nativeHookFailed: Boolean = false,
    ) {
        /** `true` if at least one threat was detected. */
        val anyDetected: Boolean
            get() = fridaDetected || xposedDetected || memoryTamperingDetected || nativeHookDetected

        /** `true` if every sub-detector fired simultaneously. */
        val allDetected: Boolean
            get() = fridaDetected && xposedDetected && memoryTamperingDetected && nativeHookDetected

        /** Number of sub-detectors that returned a positive result. */
        val detectionCount: Int
            get() = listOf(fridaDetected, xposedDetected, memoryTamperingDetected, nativeHookDetected)
                .count { it }

        /** `true` if any sub-detector failed to complete its check. */
        val anyFailed: Boolean
            get() = fridaFailed || xposedFailed || memoryTamperingFailed || nativeHookFailed

        /** Number of sub-detectors that failed. */
        val failureCount: Int
            get() = listOf(fridaFailed, xposedFailed, memoryTamperingFailed, nativeHookFailed)
                .count { it }
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    companion object {
        /**
         * Base cache TTL in milliseconds.
         *
         * Five seconds is a reasonable balance between:
         * - Avoiding redundant native calls within a single logical check operation.
         * - Ensuring results remain current for the periodic monitoring use-case.
         */
        private const val CACHE_TTL_MS = 5_000L

        /**
         * Maximum random jitter added to cache TTL to prevent timing attacks.
         *
         * Adding random jitter makes it harder for attackers to infer detection
         * results by measuring the time difference between cache hits and misses.
         */
        private const val MAX_JITTER_MS = 1_500L
    }
}
