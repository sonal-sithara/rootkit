package com.ssithara.rootkit.detection.runtime

import android.content.Context
import android.content.pm.PackageManager
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result

/**
 * Xposed/LSPosed Detection Module
 * 
 * Detects Xposed hooking frameworks through multiple vectors:
 * - Stack trace analysis (checks for Xposed frames in exceptions)
 * - Package detection (checks for installed Xposed packages)
 * - Memory maps detection (looks for Xposed signatures in /proc/self/maps)
 * - Library detection (checks for Xposed libraries in memory)
 * - Zygote detection (checks for Zygote modifications)
 * - Riru detection (checks for Riru framework)
 * - Zygisk detection (checks for Zygisk injection)
 */
class XposedDetection(context: Context) : DetectorResult(context) {

    companion object {
        // Known Xposed-related packages
        private val XPOSED_PACKAGES = listOf(
            "de.robv.android.xposed.installer",
            "io.github.lsposed.manager",
            "org.lsposed.manager",
            "com.sollyu.xposed.hook.model",
            "com.elderdrivers.riru.edxposed",
            "com.android.xposed"
        )

        // Known Xposed class signatures
        private val XPOSED_CLASS_SIGNATURES = listOf(
            "de.robv.android.xposed",
            "io.github.lsposed",
            "EdXposed",
            "XposedBridge",
            "lsposed"
        )

        @JvmStatic
        private external fun detectByMemoryMaps(): Boolean

        @JvmStatic
        private external fun detectByLibraries(): Boolean

        @JvmStatic
        private external fun detectByZygote(): Boolean

        @JvmStatic
        private external fun detectRiru(): Boolean

        @JvmStatic
        private external fun detectZygisk(): Boolean

        @JvmStatic
        private external fun detectHookMemory(): Boolean
    }

    override fun run(): Result {
        // Check stack trace (Kotlin-based detection)
        if (checkStackTrace()) return Result.FOUND

        // Check installed packages (Kotlin-based detection)
        if (checkInstalledPackages()) return Result.FOUND

        // Check for loaded classes (Kotlin-based detection)
        if (checkLoadedClasses()) return Result.FOUND

        // Native-based detections
        val nativeDetections = mutableListOf<Boolean>()
        runCatching { nativeDetections.add(detectByMemoryMaps()) }
        runCatching { nativeDetections.add(detectByLibraries()) }
        runCatching { nativeDetections.add(detectByZygote()) }
        runCatching { nativeDetections.add(detectRiru()) }
        runCatching { nativeDetections.add(detectZygisk()) }
        runCatching { nativeDetections.add(detectHookMemory()) }

        return if (nativeDetections.any { it }) Result.FOUND else Result.NOT_FOUND
    }

    /**
     * Check stack trace for Xposed frames
     */
    private fun checkStackTrace(): Boolean {
        return try {
            throw Exception("Xposed detection")
        } catch (e: Exception) {
            e.stackTrace.any { frame ->
                XPOSED_CLASS_SIGNATURES.any { signature ->
                    frame.className.contains(signature, ignoreCase = true)
                }
            }
        }
    }

    /**
     * Check for installed Xposed-related packages
     */
    private fun checkInstalledPackages(): Boolean {
        val pm = context.packageManager
        return XPOSED_PACKAGES.any { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    }

    /**
     * Check for Xposed-related classes loaded in the classloader
     */
    private fun checkLoadedClasses(): Boolean {
        return try {
            val classLoader = context.classLoader
            val xposedClasses = listOf(
                "de.robv.android.xposed.XposedBridge",
                "io.github.lsposed.lspd.core.Startup",
                "com.android.xposed.XposedInit"
            )

            xposedClasses.any { className ->
                try {
                    Class.forName(className, false, classLoader)
                    true
                } catch (e: ClassNotFoundException) {
                    false
                }
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Run individual detection methods for granular checking
     */
    fun isDetectedByStackTrace(): Boolean = checkStackTrace()

    fun isDetectedByPackages(): Boolean = checkInstalledPackages()

    fun isDetectedByLoadedClasses(): Boolean = checkLoadedClasses()

    fun isDetectedByMemoryMaps(): Boolean = runCatching { detectByMemoryMaps() }.getOrDefault(false)

    fun isDetectedByLibraries(): Boolean = runCatching { detectByLibraries() }.getOrDefault(false)

    fun isDetectedByZygote(): Boolean = runCatching { detectByZygote() }.getOrDefault(false)

    fun isDetectedByRiru(): Boolean = runCatching { detectRiru() }.getOrDefault(false)

    fun isDetectedByZygisk(): Boolean = runCatching { detectZygisk() }.getOrDefault(false)

    fun isDetectedByHookMemory(): Boolean = runCatching { detectHookMemory() }.getOrDefault(false)

    /**
     * Get detailed detection results
     */
    fun getDetectionDetails(): Map<String, Boolean> {
        return mapOf(
            "stack_trace_detection" to isDetectedByStackTrace(),
            "package_detection" to isDetectedByPackages(),
            "loaded_classes_detection" to isDetectedByLoadedClasses(),
            "memory_maps_detection" to isDetectedByMemoryMaps(),
            "library_detection" to isDetectedByLibraries(),
            "zygote_detection" to isDetectedByZygote(),
            "riru_detection" to isDetectedByRiru(),
            "zygisk_detection" to isDetectedByZygisk(),
            "hook_memory_detection" to isDetectedByHookMemory()
        )
    }
}
