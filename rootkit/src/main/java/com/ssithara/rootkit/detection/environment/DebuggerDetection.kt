package com.ssithara.rootkit.detection.environment

import android.content.Context
import android.provider.Settings
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
class DebuggerDetection(context: Context) : DetectorResult(context) {
    
    private val fridaDetection by lazy { FridaDetection(context) }
    
    override fun run(): Result {

        val isDebuggerDetected = Settings.Secure.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED,
            0
        ) == 1

        val isFridaDetected = fridaDetection.run() == Result.FOUND

        return if (isDebuggerDetected || isFridaDetected) {
            Result.FOUND
        } else {
            Result.NOT_FOUND
        }


    }
}
