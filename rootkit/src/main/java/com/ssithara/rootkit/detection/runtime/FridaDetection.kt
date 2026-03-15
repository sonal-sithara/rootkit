package com.ssithara.rootkit.detection.runtime

import android.content.Context
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result

/**
 * Frida Detection Module
 *
 * Detects Frida instrumentation framework through multiple vectors:
 * - Port detection (checks common Frida server ports)
 * - Memory maps detection (looks for Frida signatures in /proc/self/maps)
 * - Thread detection (checks for Frida-related thread names)
 * - Library detection (checks for Frida libraries in memory)
 * - File descriptor detection (checks for Frida-related file descriptors)
 *
 * ## Error Handling
 *
 * Detection failures are tracked separately from "not detected" results.
 * Native method failures return [Result.ERROR] instead of treating them
 * as "no detection".
 */
class FridaDetection(context: Context) : DetectorResult(context) {

    companion object {
        @JvmStatic
        @Throws(UnsatisfiedLinkError::class)
        private external fun detectByPorts(): Boolean

        @JvmStatic
        @Throws(UnsatisfiedLinkError::class)
        private external fun detectByMemoryMaps(): Boolean

        @JvmStatic
        @Throws(UnsatisfiedLinkError::class)
        private external fun detectByThreads(): Boolean

        @JvmStatic
        @Throws(UnsatisfiedLinkError::class)
        private external fun detectByLibraries(): Boolean

        @JvmStatic
        @Throws(UnsatisfiedLinkError::class)
        private external fun detectByFileDescriptors(): Boolean

        @JvmStatic
        @Throws(UnsatisfiedLinkError::class)
        private external fun detectByEnvVars(): Boolean
    }

    /**
     * Runs all detection methods and returns the aggregated result.
     *
     * Returns [Result.FOUND] if any detection method finds Frida.
     * Returns [Result.ERROR] if any native method fails.
     * Returns [Result.NOT_FOUND] only if all checks pass without finding Frida.
     */
    override fun run(): Result {
        val detections = mutableListOf<Boolean>()
        val failures = mutableListOf<Boolean>()

        // Run all detection methods, tracking both results and failures
        runCatching { detections.add(detectByPorts()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectByMemoryMaps()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectByThreads()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectByLibraries()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectByFileDescriptors()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectByEnvVars()) }
            .onFailure { failures.add(true) }

        // If any native method failed, return ERROR
        if (failures.isNotEmpty()) {
            return Result.ERROR
        }

        // If any detection found Frida, return FOUND
        return if (detections.any { it }) Result.FOUND else Result.NOT_FOUND
    }

    /**
     * Run individual detection methods for granular checking.
     * Returns false if the native method fails.
     */
    fun isDetectedByPorts(): Boolean = runCatching { detectByPorts() }.getOrDefault(false)

    fun isDetectedByMemoryMaps(): Boolean = runCatching { detectByMemoryMaps() }.getOrDefault(false)

    fun isDetectedByThreads(): Boolean = runCatching { detectByThreads() }.getOrDefault(false)

    fun isDetectedByLibraries(): Boolean = runCatching { detectByLibraries() }.getOrDefault(false)

    fun isDetectedByFileDescriptors(): Boolean =
        runCatching { detectByFileDescriptors() }.getOrDefault(false)

    fun isDetectedByEnvVars(): Boolean = runCatching { detectByEnvVars() }.getOrDefault(false)

    /**
     * Get detailed detection results.
     * Note: Failures are not explicitly tracked in the returned map;
     * callers should use [run] to check for detection failures.
     */
    fun getDetectionDetails(): Map<String, Boolean> {
        return mapOf(
            "port_detection" to isDetectedByPorts(),
            "memory_maps_detection" to isDetectedByMemoryMaps(),
            "thread_detection" to isDetectedByThreads(),
            "library_detection" to isDetectedByLibraries(),
            "file_descriptor_detection" to isDetectedByFileDescriptors(),
            "env_var_detection" to isDetectedByEnvVars()
        )
    }
}
