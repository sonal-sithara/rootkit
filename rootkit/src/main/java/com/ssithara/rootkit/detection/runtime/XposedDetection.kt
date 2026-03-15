package com.ssithara.rootkit.detection.runtime

import android.content.Context
import android.content.pm.PackageManager
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result

/**
 * Xposed/LSPosed Detection Module
 * 
 * Detects Xposed hooking frameworks through multiple vectors:
 * - Package detection (checks for installed Xposed packages)
 * - Memory maps detection (looks for Xposed signatures in /proc/self/maps)
 * - Library detection (checks for Xposed libraries in memory)
 * - Zygote detection (checks for Zygote modifications)
 * - Riru detection (checks for Riru framework)
 * - Zygisk detection (checks for Zygisk injection)
 * - Hook memory detection (checks for hook-related memory patterns)
 *
 * ## Security Considerations
 *
 * The stack trace check was removed because modern hooking frameworks can
 * suppress exception stack traces, making this detection unreliable.
 *
 * ## Error Handling
 *
 * Detection failures are tracked separately from "not detected" results.
 * Native method failures return [Result.ERROR] instead of treating them
 * as "no detection".
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

    /**
     * Runs all detection methods and returns the aggregated result.
     *
     * Returns [Result.FOUND] if any detection method finds Xposed.
     * Returns [Result.ERROR] if any native method fails.
     * Returns [Result.NOT_FOUND] only if all checks pass without finding Xposed.
     */
    override fun run(): Result {
        // Check installed packages (Kotlin-based detection)
        if (checkInstalledPackages()) return Result.FOUND

        // Check for loaded classes (Kotlin-based detection)
        if (checkLoadedClasses()) return Result.FOUND

        // Native-based detections with error tracking
        val detections = mutableListOf<Boolean>()
        val failures = mutableListOf<Boolean>()

        runCatching { detections.add(detectByMemoryMaps()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectByLibraries()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectByZygote()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectRiru()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectZygisk()) }
            .onFailure { failures.add(true) }
        runCatching { detections.add(detectHookMemory()) }
            .onFailure { failures.add(true) }

        // If any native method failed, return ERROR
        if (failures.isNotEmpty()) {
            return Result.ERROR
        }

        return if (detections.any { it }) Result.FOUND else Result.NOT_FOUND
    }

    /**
     * Check for installed Xposed-related packages.
     * 
     * Note: This check may produce false positives on development devices
     * that have Xposed Manager installed but are not actively hooking.
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
     * Check for Xposed-related classes loaded in the classloader.
     * 
     * This is often more reliable than package detection since Xposed
     * modules may not have the manager installed.
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
     * Run individual detection methods for granular checking.
     * Returns false if the native method fails.
     */
    fun isDetectedByPackages(): Boolean = checkInstalledPackages()

    fun isDetectedByLoadedClasses(): Boolean = checkLoadedClasses()

    fun isDetectedByMemoryMaps(): Boolean = runCatching { detectByMemoryMaps() }.getOrDefault(false)

    fun isDetectedByLibraries(): Boolean = runCatching { detectByLibraries() }.getOrDefault(false)

    fun isDetectedByZygote(): Boolean = runCatching { detectByZygote() }.getOrDefault(false)

    fun isDetectedByRiru(): Boolean = runCatching { detectRiru() }.getOrDefault(false)

    fun isDetectedByZygisk(): Boolean = runCatching { detectZygisk() }.getOrDefault(false)

    fun isDetectedByHookMemory(): Boolean = runCatching { detectHookMemory() }.getOrDefault(false)

    /**
     * Get detailed detection results.
     * Note: Failures are not explicitly tracked in the returned map;
     * callers should use [run] to check for detection failures.
     */
    fun getDetectionDetails(): Map<String, Boolean> {
        return mapOf(
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
