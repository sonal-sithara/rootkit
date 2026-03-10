package com.ssithara.rootkit

import android.app.Activity
import android.content.Context
import android.util.Log
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.EncryptionService
import com.ssithara.rootkit.core.Result
import com.ssithara.rootkit.detection.environment.DebuggerDetection
import com.ssithara.rootkit.detection.environment.EmulatorDetection
import com.ssithara.rootkit.detection.environment.OverlayDetection
import com.ssithara.rootkit.detection.root.MagiskDetection
import com.ssithara.rootkit.detection.root.MagiskHideDetection
import com.ssithara.rootkit.detection.root.RootDetection
import com.ssithara.rootkit.detection.runtime.RuntimeTamperingDetection

class RootKit(private val context: Context) {
    private var activity: Activity? = null
    private val overlayDetection by lazy { OverlayDetection() }
    private val magiskHideDetection by lazy { MagiskHideDetection(context) }
    private val magiskDetection by lazy { MagiskDetection(context) }
    private val rootDetection by lazy { RootDetection(context) }
    private val debuggerDetection by lazy { DebuggerDetection(context) }
    private val emulatorDetection by lazy { EmulatorDetection(context) }
    private val runtimeTamperingDetection by lazy { RuntimeTamperingDetection(context) }

    fun initialize() {
        System.loadLibrary("rootkit")
    }

    fun setSecureFlags() {
        (activity ?: context as? Activity)?.let {
            overlayDetection.setSecureFlags(it)
        } ?: Log.e("RootKit", "Activity is null. Ensure RootKit has a valid Activity.")
    }

    fun detectOverlay() {
        (activity ?: context as? Activity)?.let {
            overlayDetection.initOverlayDetection(it)
        } ?: Log.e("RootKit", "Activity is null. Ensure RootKit has a valid Activity.")
    }

    fun updateActivity(activity: Activity?) {
        this.activity = activity
    }

    fun isRootedDevice(): String {
        val detections = listOf(
            magiskHideDetection.run(),
            magiskDetection.run(),
            rootDetection.run()
        )

        val isRooted = if (Result.FOUND in detections)
            Result.FOUND
        else
            Result.NOT_FOUND

        return EncryptionService.encryptWithBase64Key(isRooted.name)
    }


    fun isDebuggerDetected(): String {
        val result = debuggerDetection.run()
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    fun isEmulatorDevice(): String {
        val result = emulatorDetection.run()
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Comprehensive runtime tampering detection
     * Checks for Frida, Xposed, memory tampering, and native hooks
     */
    fun isRuntimeTamperingDetected(): String {
        val result = runtimeTamperingDetection.run()
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Frida-specific detection
     */
    fun isFridaDetected(): String {
        val result = if (runtimeTamperingDetection.isFridaDetected())
            Result.FOUND
        else
            Result.NOT_FOUND
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Xposed/LSPosed-specific detection
     */
    fun isXposedDetected(): String {
        val result = if (runtimeTamperingDetection.isXposedDetected())
            Result.FOUND
        else
            Result.NOT_FOUND
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Memory tampering-specific detection
     */
    fun isMemoryTamperingDetected(): String {
        val result = if (runtimeTamperingDetection.isMemoryTamperingDetected())
            Result.FOUND
        else
            Result.NOT_FOUND
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Native hook-specific detection
     */
    fun isNativeHookDetected(): String {
        val result = if (runtimeTamperingDetection.isNativeHookDetected())
            Result.FOUND
        else
            Result.NOT_FOUND
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Get detailed detection results for all runtime tampering checks
     */
    fun getRuntimeTamperingDetails(): Map<String, Map<String, Boolean>> {
        return runtimeTamperingDetection.getComprehensiveDetectionDetails()
    }

    /**
     * Get a summary of runtime tampering detections
     */
    fun getRuntimeTamperingSummary(): RuntimeTamperingDetection.DetectionSummary {
        return runtimeTamperingDetection.getDetectionSummary()
    }
}
