package com.ssithara.rootkit.detection.runtime

import android.content.Context
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result

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
 */
class RuntimeTamperingDetection(context: Context) : DetectorResult(context) {

    private val fridaDetection by lazy { FridaDetection(context) }
    private val xposedDetection by lazy { XposedDetection(context) }
    private val memoryTamperingDetection by lazy { MemoryTamperingDetection(context) }
    private val nativeHookDetection by lazy { NativeHookDetection(context) }

    override fun run(): Result {
        val detections = listOf(
            fridaDetection.run(),
            xposedDetection.run(),
            memoryTamperingDetection.run(),
            nativeHookDetection.run()
        )

        return if (Result.FOUND in detections) Result.FOUND else Result.NOT_FOUND
    }

    /**
     * Get individual detection modules for granular access
     */
    fun fridaDetectionModule(): FridaDetection = fridaDetection

    fun xposedDetectionModule(): XposedDetection = xposedDetection

    fun memoryTamperingDetectionModule(): MemoryTamperingDetection = memoryTamperingDetection

    fun nativeHookDetectionModule(): NativeHookDetection = nativeHookDetection

    /**
     * Check if Frida is detected
     */
    fun isFridaDetected(): Boolean = fridaDetection.run() == Result.FOUND

    /**
     * Check if Xposed/LSPosed is detected
     */
    fun isXposedDetected(): Boolean = xposedDetection.run() == Result.FOUND

    /**
     * Check if memory tampering is detected
     */
    fun isMemoryTamperingDetected(): Boolean = memoryTamperingDetection.run() == Result.FOUND

    /**
     * Check if native hooks are detected
     */
    fun isNativeHookDetected(): Boolean = nativeHookDetection.run() == Result.FOUND

    /**
     * Get comprehensive detection details from all modules
     */
    fun getComprehensiveDetectionDetails(): Map<String, Map<String, Boolean>> {
        return mapOf(
            "frida" to fridaDetection.getDetectionDetails(),
            "xposed" to xposedDetection.getDetectionDetails(),
            "memory_tampering" to memoryTamperingDetection.getDetectionDetails(),
            "native_hooks" to nativeHookDetection.getDetectionDetails()
        )
    }

    /**
     * Get a summary of all detections
     * 
     * Note: This method runs each detection once and reuses the results
     * to avoid redundant native calls that would occur if calling
     * isFridaDetected(), isXposedDetected(), etc. individually.
     */
    fun getDetectionSummary(): DetectionSummary {
        // Run each detection once and reuse results to avoid double execution
        val fridaResult = fridaDetection.run()
        val xposedResult = xposedDetection.run()
        val memoryResult = memoryTamperingDetection.run()
        val nativeHookResult = nativeHookDetection.run()
        
        return DetectionSummary(
            fridaDetected = fridaResult == Result.FOUND,
            xposedDetected = xposedResult == Result.FOUND,
            memoryTamperingDetected = memoryResult == Result.FOUND,
            nativeHookDetected = nativeHookResult == Result.FOUND
        )
    }

    /**
     * Data class to hold detection summary
     */
    data class DetectionSummary(
        val fridaDetected: Boolean,
        val xposedDetected: Boolean,
        val memoryTamperingDetected: Boolean,
        val nativeHookDetected: Boolean
    ) {
        val anyDetected: Boolean
            get() = fridaDetected || xposedDetected || memoryTamperingDetected || nativeHookDetected

        val allDetected: Boolean
            get() = fridaDetected && xposedDetected && memoryTamperingDetected && nativeHookDetected

        val detectionCount: Int
            get() = listOf(fridaDetected, xposedDetected, memoryTamperingDetected, nativeHookDetected)
                .count { it }
    }
}
