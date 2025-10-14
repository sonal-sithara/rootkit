package com.ssithara.rootkit

import android.app.Activity
import android.content.Context
import android.util.Log

class RootKit(private val context: Context) {
    private var activity: Activity? = null
    private val overlayDetection by lazy { OverlayDetection() }
    private val magiskDetection by lazy { MagiskDetection(context) }


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

    fun isRootedDevice(): DetectorResult.Result {
        return magiskDetection.run();
    }
}