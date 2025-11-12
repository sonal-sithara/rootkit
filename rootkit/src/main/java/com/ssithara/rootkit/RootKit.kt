package com.ssithara.rootkit

import android.app.Activity
import android.content.Context
import android.util.Log

class RootKit(private val context: Context) {
    private var activity: Activity? = null
    private val overlayDetection by lazy { OverlayDetection() }
    private val magiskHideDetection by lazy { MagiskHideDetection(context) }
    private val magiskDetection by lazy { MagiskDetection(context) }
    private val rootDetection by lazy { RootDetection(context) }
    private val debuggerDetection by lazy { DebuggerDetection(context) }
    private val emulatorDetection by lazy { EmulatorDetection(context) }


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

        val isRooted = if (DetectorResult.Result.FOUND in detections)
            DetectorResult.Result.FOUND
        else
            DetectorResult.Result.NOT_FOUND

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

    fun encryptData(data: String): String {
        return EncryptionService.encryptWithBase64Key(data)
    }
}