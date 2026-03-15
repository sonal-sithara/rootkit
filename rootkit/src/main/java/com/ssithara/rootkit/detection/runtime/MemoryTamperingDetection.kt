package com.ssithara.rootkit.detection.runtime

import android.content.Context
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result

/**
 * Memory Tampering Detection Module
 * 
 * Detects memory tampering through multiple vectors:
 * - Suspicious memory regions detection
 * - Anonymous executable memory detection
 * - Code integrity checks
 * - Unusual permission detection
 * - Code cave detection (large memory gaps)
 * - Modified base address detection (ASLR bypass)
 *
 * ## Limitations
 *
 * Memory tampering detection has inherent limitations:
 * - Code cave detection uses heuristics that may produce false positives on
 *   certain devices or Android versions due to legitimate memory allocations.
 * - The threshold for large memory gaps can be adjusted via detection parameters
 *   to reduce false positives in production.
 * - Some detection methods may not work on all Android versions or architectures.
 *
 * ## Error Handling
 *
 * Detection failures are tracked separately from "not detected" results.
 * Native method failures return [Result.ERROR] instead of treating them
 * as "no tampering detected".
 */
class MemoryTamperingDetection(context: Context) : DetectorResult(context) {

    companion object {
        @JvmStatic
        private external fun detectSuspiciousRegions(): Boolean

        @JvmStatic
        private external fun detectAnonymousExecMemory(): Boolean

        @JvmStatic
        private external fun checkCodeIntegrity(): Boolean

        @JvmStatic
        private external fun detectUnusualPermissions(): Boolean

        @JvmStatic
        private external fun detectCodeCaves(): Boolean

        @JvmStatic
        private external fun detectModifiedBaseAddress(): Boolean
    }

    /**
     * Runs all detection methods and returns the aggregated result.
     *
     * Returns [Result.FOUND] if any detection method finds tampering.
     * Returns [Result.ERROR] if any native method fails.
     * Returns [Result.NOT_FOUND] only if all checks pass without finding tampering.
     */
    override fun run(): Result {
        val detections = mutableListOf<Boolean>()
        val failures = mutableListOf<Boolean>()

        // Run all detection methods, tracking both results and failures
        runCatching { detections.add(detectSuspiciousRegions()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectAnonymousExecMemory()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(checkCodeIntegrity()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectUnusualPermissions()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectCodeCaves()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectModifiedBaseAddress()) }
            .onFailure { failures.add(true) }

        // If any native method failed, return ERROR
        if (failures.isNotEmpty()) {
            return Result.ERROR
        }

        // If any detection found tampering, return FOUND
        return if (detections.any { it }) Result.FOUND else Result.NOT_FOUND
    }

    /**
     * Run individual detection methods for granular checking.
     * Returns false if the native method fails.
     */
    fun isDetectedBySuspiciousRegions(): Boolean = 
        runCatching { detectSuspiciousRegions() }.getOrDefault(false)

    fun isDetectedByAnonymousExecMemory(): Boolean = 
        runCatching { detectAnonymousExecMemory() }.getOrDefault(false)

    fun isDetectedByCodeIntegrity(): Boolean = 
        runCatching { checkCodeIntegrity() }.getOrDefault(false)

    fun isDetectedByUnusualPermissions(): Boolean = 
        runCatching { detectUnusualPermissions() }.getOrDefault(false)

    /**
     * Check for code caves (large gaps in memory mappings).
     * 
     * Note: This detection method may produce false positives on certain
     * devices. Consider adjusting the threshold or disabling this check
     * if you experience excessive false positives.
     */
    fun isDetectedByCodeCaves(): Boolean = 
        runCatching { detectCodeCaves() }.getOrDefault(false)

    fun isDetectedByModifiedBaseAddress(): Boolean = 
        runCatching { detectModifiedBaseAddress() }.getOrDefault(false)

    /**
     * Get detailed detection results.
     * Note: Failures are not explicitly tracked in the returned map;
     * callers should use [run] to check for detection failures.
     */
    fun getDetectionDetails(): Map<String, Boolean> {
        return mapOf(
            "suspicious_regions_detection" to isDetectedBySuspiciousRegions(),
            "anonymous_exec_memory_detection" to isDetectedByAnonymousExecMemory(),
            "code_integrity_detection" to isDetectedByCodeIntegrity(),
            "unusual_permissions_detection" to isDetectedByUnusualPermissions(),
            "code_caves_detection" to isDetectedByCodeCaves(),
            "modified_base_address_detection" to isDetectedByModifiedBaseAddress()
        )
    }
}
