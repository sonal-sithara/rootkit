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
 */
class FridaDetection(context: Context) : DetectorResult(context) {

    companion object {
        @JvmStatic
        private external fun detectByPorts(): Boolean

        @JvmStatic
        private external fun detectByMemoryMaps(): Boolean

        @JvmStatic
        private external fun detectByThreads(): Boolean

        @JvmStatic
        private external fun detectByLibraries(): Boolean

        @JvmStatic
        private external fun detectByFileDescriptors(): Boolean

        @JvmStatic
        private external fun detectByEnvVars(): Boolean
    }

    override fun run(): Result {
        val detections = mutableListOf<Boolean>()

        // Run all detection methods
        runCatching { detections.add(detectByPorts()) }
        runCatching { detections.add(detectByMemoryMaps()) }
        runCatching { detections.add(detectByThreads()) }
        runCatching { detections.add(detectByLibraries()) }
        runCatching { detections.add(detectByFileDescriptors()) }
        runCatching { detections.add(detectByEnvVars()) }

        // If any detection found Frida, return FOUND
        return if (detections.any { it }) Result.FOUND else Result.NOT_FOUND
    }

    /**
     * Run individual detection methods for granular checking
     */
    fun isDetectedByPorts(): Boolean = runCatching { detectByPorts() }.getOrDefault(false)

    fun isDetectedByMemoryMaps(): Boolean = runCatching { detectByMemoryMaps() }.getOrDefault(false)

    fun isDetectedByThreads(): Boolean = runCatching { detectByThreads() }.getOrDefault(false)

    fun isDetectedByLibraries(): Boolean = runCatching { detectByLibraries() }.getOrDefault(false)

    fun isDetectedByFileDescriptors(): Boolean =
        runCatching { detectByFileDescriptors() }.getOrDefault(false)

    fun isDetectedByEnvVars(): Boolean = runCatching { detectByEnvVars() }.getOrDefault(false)

    /**
     * Get detailed detection results
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
