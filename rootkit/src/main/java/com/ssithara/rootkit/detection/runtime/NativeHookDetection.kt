package com.ssithara.rootkit.detection.runtime

import android.content.Context
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result

/**
 * Native Hook Detection Module
 * 
 * Detects native code hooks through multiple vectors:
 * - Inline hook detection (checks function prologues for JMP instructions)
 * - GOT hook detection (verifies GOT entries point to valid locations)
 * - PLT hook detection (checks PLT entries for modifications)
 * - Hook framework detection (checks for known hooking libraries)
 * - Modified function pointer detection
 *
 * ## Security Considerations
 *
 * When native library loading fails (e.g., dlopen returns null), this is
 * treated as a suspicious condition that may indicate tampering or an
 * attempt to hide hooks.
 *
 * ## Error Handling
 *
 * Detection failures are tracked separately from "not detected" results.
 * Native method failures return [Result.ERROR] instead of treating them
 * as "no hook detected".
 */
class NativeHookDetection(context: Context) : DetectorResult(context) {

    companion object {
        @JvmStatic
        private external fun detectInlineHooks(): Boolean

        @JvmStatic
        private external fun detectGOTHooks(): Boolean

        @JvmStatic
        private external fun detectPLTHooks(): Boolean

        @JvmStatic
        private external fun detectHookFrameworks(): Boolean

        /**
         * Detects modified function pointers.
         * Returns -1 if native library loading failed (dlopen returned null).
         * This is treated as a suspicious condition.
         */
        @JvmStatic
        private external fun detectModifiedFunctionPointers(): Int
    }

    /**
     * Runs all detection methods and returns the aggregated result.
     *
     * Returns [Result.FOUND] if any detection method finds hooks.
     * Returns [Result.ERROR] if any native method fails.
     * Returns [Result.NOT_FOUND] only if all checks pass without finding hooks.
     */
    override fun run(): Result {
        val detections = mutableListOf<Boolean>()
        val failures = mutableListOf<Boolean>()

        // Run all detection methods, tracking both results and failures
        runCatching { detections.add(detectInlineHooks()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectGOTHooks()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectPLTHooks()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectHookFrameworks()) }
            .onFailure { failures.add(true) }
        
        // detectModifiedFunctionPointers returns -1 if dlopen failed (suspicious)
        runCatching { 
            val result = detectModifiedFunctionPointers()
            if (result < 0) {
                // -1 indicates dlopen failure - treat as error/suspicious
                failures.add(true)
                detections.add(false)
            } else {
                detections.add(result > 0)
            }
        }.onFailure { failures.add(true) }

        // If any native method failed, return ERROR
        if (failures.isNotEmpty()) {
            return Result.ERROR
        }

        // If any detection found hooks, return FOUND
        return if (detections.any { it }) Result.FOUND else Result.NOT_FOUND
    }

    /**
     * Run individual detection methods for granular checking.
     * Returns false if the native method fails.
     * 
     * Note: [isDetectedByModifiedFunctionPointers] may return null when
     * native library loading fails (dlopen returns null).
     */
    fun isDetectedByInlineHooks(): Boolean = 
        runCatching { detectInlineHooks() }.getOrDefault(false)

    fun isDetectedByGOTHooks(): Boolean = 
        runCatching { detectGOTHooks() }.getOrDefault(false)

    fun isDetectedByPLTHooks(): Boolean = 
        runCatching { detectPLTHooks() }.getOrDefault(false)

    fun isDetectedByHookFrameworks(): Boolean = 
        runCatching { detectHookFrameworks() }.getOrDefault(false)

    /**
     * Check for modified function pointers.
     * Returns null if native library loading failed (dlopen returned null),
     * which is treated as suspicious.
     */
    fun isDetectedByModifiedFunctionPointers(): Boolean? {
        return runCatching {
            val result = detectModifiedFunctionPointers()
            if (result < 0) {
                // -1 indicates dlopen failure - return null to indicate error
                null
            } else {
                result > 0
            }
        }.getOrNull()
    }

    /**
     * Get detailed detection results.
     * Note: Failures are not explicitly tracked in the returned map;
     * callers should use [run] to check for detection failures.
     * The modified_function_pointer_detection may be null if native
     * library loading failed.
     */
    fun getDetectionDetails(): Map<String, Boolean?> {
        return mapOf(
            "inline_hook_detection" to isDetectedByInlineHooks(),
            "got_hook_detection" to isDetectedByGOTHooks(),
            "plt_hook_detection" to isDetectedByPLTHooks(),
            "hook_framework_detection" to isDetectedByHookFrameworks(),
            "modified_function_pointer_detection" to isDetectedByModifiedFunctionPointers()
        )
    }
}
