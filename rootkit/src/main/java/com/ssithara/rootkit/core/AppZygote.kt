package com.ssithara.rootkit.core

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.Q)
@Suppress("NewApi")
class AppZygote : ZygotePreload {

    companion object {
        private const val TAG = "AppZygote"
    }

    override fun doPreload(p0: ApplicationInfo) {
        try {
            System.loadLibrary("rootkit")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load rootkit library during zygote preload: ${e.message}", e)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error loading rootkit library during zygote preload: ${e.message}", e)
        }
    }
}
