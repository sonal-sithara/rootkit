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

        @JvmStatic
        private external fun detectModifiedFunctionPointers(): Boolean
    }

    override fun run(): Result {
        val detections = mutableListOf<Boolean>()

        // Run all detection methods
        runCatching { detections.add(detectInlineHooks()) }
        runCatching { detections.add(detectGOTHooks()) }
        runCatching { detections.add(detectPLTHooks()) }
        runCatching { detections.add(detectHookFrameworks()) }
        runCatching { detections.add(detectModifiedFunctionPointers()) }

        // If any detection found hooks, return FOUND
        return if (detections.any { it }) Result.FOUND else Result.NOT_FOUND
    }

    /**
     * Run individual detection methods for granular checking
     */
    fun isDetectedByInlineHooks(): Boolean = 
        runCatching { detectInlineHooks() }.getOrDefault(false)

    fun isDetectedByGOTHooks(): Boolean = 
        runCatching { detectGOTHooks() }.getOrDefault(false)

    fun isDetectedByPLTHooks(): Boolean = 
        runCatching { detectPLTHooks() }.getOrDefault(false)

    fun isDetectedByHookFrameworks(): Boolean = 
        runCatching { detectHookFrameworks() }.getOrDefault(false)

    fun isDetectedByModifiedFunctionPointers(): Boolean = 
        runCatching { detectModifiedFunctionPointers() }.getOrDefault(false)

    /**
     * Get detailed detection results
     */
    fun getDetectionDetails(): Map<String, Boolean> {
        return mapOf(
            "inline_hook_detection" to isDetectedByInlineHooks(),
            "got_hook_detection" to isDetectedByGOTHooks(),
            "plt_hook_detection" to isDetectedByPLTHooks(),
            "hook_framework_detection" to isDetectedByHookFrameworks(),
            "modified_function_pointer_detection" to isDetectedByModifiedFunctionPointers()
        )
    }
}
