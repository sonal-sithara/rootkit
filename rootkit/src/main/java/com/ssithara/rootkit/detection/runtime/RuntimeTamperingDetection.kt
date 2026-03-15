package com.ssithara.rootkit.detection.runtime

import android.content.Context
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result
import java.util.concurrent.atomic.AtomicReference

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
 * boolean helpers share a short-lived [CACHE_TTL_MS]-millisecond cache backed
 * by [getOrComputeSummary].
 *
 * The cache is stored in an [AtomicReference] so it is safe to read/write from
 * multiple threads without synchronization. In the unlikely event that two
 * threads both observe a stale entry at exactly the same moment, both will
 * compute a fresh summary independently and the last write wins — this is
 * acceptable because both computations produce the same logical result.
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

    // -------------------------------------------------------------------------
    // Core
    // -------------------------------------------------------------------------

    /**
     * Returns a [DetectionSummary] that was computed no earlier than
     * [CACHE_TTL_MS] milliseconds ago.
     *
     * If the cached entry is still fresh it is returned immediately without
     * touching any native code.  Otherwise all four sub-detectors are run,
     * the result is cached, and then returned.
     */
    private fun getOrComputeSummary(): DetectionSummary {
        val now = System.currentTimeMillis()

        cachedSummary.get()?.let { cached ->
            if (now - cached.timestamp < CACHE_TTL_MS) {
                return cached.summary
            }
        }

        val fridaResult = fridaDetection.run()
        val xposedResult = xposedDetection.run()
        val memoryResult = memoryTamperingDetection.run()
        val nativeHookResult = nativeHookDetection.run()

        val summary = DetectionSummary(
            fridaDetected = fridaResult == Result.FOUND,
            xposedDetected = xposedResult == Result.FOUND,
            memoryTamperingDetected = memoryResult == Result.FOUND,
            nativeHookDetected = nativeHookResult == Result.FOUND,
        )

        cachedSummary.set(CachedSummary(summary, System.currentTimeMillis()))
        return summary
    }

    /** Runs all sub-detectors and returns [Result.FOUND] if any threat is detected. */
    override fun run(): Result {
        val summary = getOrComputeSummary()
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
     */
    fun getComprehensiveDetectionDetails(): Map<String, Map<String, Boolean>> {
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
     */
    data class DetectionSummary(
        val fridaDetected: Boolean,
        val xposedDetected: Boolean,
        val memoryTamperingDetected: Boolean,
        val nativeHookDetected: Boolean,
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
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    companion object {
        /**
         * How long (in milliseconds) a computed [DetectionSummary] is considered
         * fresh before the sub-detectors are run again.
         *
         * Five seconds is a reasonable balance between:
         * - Avoiding redundant native calls within a single logical check operation.
         * - Ensuring results remain current for the periodic monitoring use-case.
         */
        private const val CACHE_TTL_MS = 5_000L
    }
}
