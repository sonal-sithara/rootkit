package com.ssithara.rootkit.detection.environment

import android.content.Context
import android.os.Debug
import android.provider.Settings
import android.util.Log
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result
import com.ssithara.rootkit.detection.runtime.FridaDetection

/**
 * Debugger and Frida Detection
 *
 * Detects if the application is being debugged or if Frida instrumentation
 * framework is present.
 *
 * Note: If you're using RuntimeTamperingDetection, consider using it instead
 * of this class directly to avoid duplicate Frida detection overhead.
 * RuntimeTamperingDetection provides comprehensive tampering detection
 * including Frida, Xposed, memory tampering, and native hooks.
 */
class DebuggerDetection(
    context: Context,
    /**
     * Whether to include Frida detection in this detector.
     * Set to false if you're using RuntimeTamperingDetection separately
     * to avoid duplicate detection overhead.
     */
    private val includeFridaDetection: Boolean = true,
    /**
     * Whether to treat ADB being enabled as a debugger detection.
     * Defaults to false since ADB is commonly enabled during development
     * and on many consumer devices. Set to true for stricter detection.
     */
    private val treatAdbAsDebugger: Boolean = false
) : DetectorResult(context) {

    companion object {
        private const val TAG = "DebuggerDetection"
    }

    private val fridaDetection by lazy { FridaDetection(context) }

    override fun run(): Result {
        // Check if a debugger is actively attached to the process
        val isDebuggerConnected = Debug.isDebuggerConnected()

        // Check if ADB debugging is enabled on the device (broader security signal)
        // Only checked when treatAdbAsDebugger is true, since ADB is commonly
        // enabled during development and on many consumer devices.
        val isAdbEnabled = if (treatAdbAsDebugger) {
            try {
                Settings.Secure.getInt(
                    context.contentResolver,
                    Settings.Secure.ADB_ENABLED,
                    0
                ) == 1
            } catch (e: Exception) {
                false
            }
        } else {
            false
        }

        val isFridaDetected = if (includeFridaDetection) {
            try {
                fridaDetection.run() == Result.FOUND
            } catch (e: Exception) {
                Log.e(TAG, "Frida detection failed", e)
                false
            }
        } else {
            false
        }

        return if (isDebuggerConnected || isAdbEnabled || isFridaDetected) {
            Result.FOUND
        } else {
            Result.NOT_FOUND
        }
    }

    /**
     * Get detailed detection results for individual debugger checks
     * @return Map of check names to boolean results (true = issue detected)
     */
    fun getDetectionDetails(): Map<String, Boolean> {
        val isDebuggerConnected = try {
            Debug.isDebuggerConnected()
        } catch (e: Exception) {
            false
        }

        val isAdbEnabled = if (treatAdbAsDebugger) {
            try {
                Settings.Secure.getInt(
                    context.contentResolver,
                    Settings.Secure.ADB_ENABLED,
                    0
                ) == 1
            } catch (e: Exception) {
                false
            }
        } else {
            false
        }

        val isFridaDetected = if (includeFridaDetection) {
            try {
                fridaDetection.run() == Result.FOUND
            } catch (e: Exception) {
                Log.e(TAG, "Frida detection failed", e)
                false
            }
        } else {
            false
        }

        return mapOf(
            "debugger_connected_check" to isDebuggerConnected,
            "adb_enabled_check" to isAdbEnabled,
            "frida_detection_check" to isFridaDetected
        )
    }
}
