package com.ssithara.rootkit

import android.content.Context
import android.provider.Settings

class DebuggerDetection(context: Context) : DetectorResult(context) {
    override fun run(): Result {

        val isDebuggerDetected = Settings.Secure.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED,
            0
        ) == 1

        val isFridaDetected = HookDetection.isFridaDetected()

        return if (isDebuggerDetected || isFridaDetected) {
            Result.FOUND
        } else {
            Result.NOT_FOUND
        }


    }
}