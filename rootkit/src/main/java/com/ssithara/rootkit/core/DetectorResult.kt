package com.ssithara.rootkit.core

import android.content.Context
import android.util.Log

abstract class DetectorResult(protected val context: Context) {

    companion object {
        private const val TAG = "DetectorResult"
    }

    abstract fun run(): Result

    /**
     * Executes the detection safely, catching any exceptions that may occur.
     * Returns [Result.ERROR] if an exception is caught, otherwise returns the result from [run].
     *
     * @return The detection result, or [Result.ERROR] if an exception occurred.
     */
    fun runSafely(): Result {
        return try {
            run()
        } catch (e: Throwable) {
            Log.e(TAG, "Detection failed: ${e.javaClass.simpleName}: ${e.message}", e)
            Result.ERROR
        }
    }
}
