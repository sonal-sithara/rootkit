package com.ssithara.rootkit.detection.root

import android.content.Context
import android.util.Log
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.io.IOException

class MagiskDetection(context: Context) : DetectorResult(context) {
    private external fun isMagiskPresentNative(): Boolean

    override fun run(): Result {
        var isMagiskPresent = Result.NOT_FOUND

        // Kotlin: scan /proc/self/mounts for blacklisted paths
        try {
            val blackListedMountPaths = arrayOf(
                "magisk", "core/mirror", "core/img",
                "/su/bin/",
                "/system/bin/failsafe/",
                "/system/usr/we-need-root/",
                "/su",
                // Additional Magisk mount paths
                "/sbin/.magisk",
                "/data/adb/magisk",
                "/data/adb/modules",
                "/data/adb/post-fs-data.d",
                "/data/adb/magisk.img",
                "/sbin/magisk"
            )

            val file = File("/proc/self/mounts")
            FileInputStream(file).use { fis ->
                BufferedReader(InputStreamReader(fis)).use { reader ->
                    var str: String?
                    while (reader.readLine().also { str = it } != null) {
                        for (path in blackListedMountPaths) {
                            if (str?.contains(path) == true) {
                                isMagiskPresent = Result.FOUND
                                break
                            }
                        }
                        if (isMagiskPresent == Result.FOUND) break
                    }
                }
            }
        } catch (e: IOException) {
            Log.e(TAG, "Error reading /proc/self/mounts", e)
            // /proc/self/mounts unreadable — continue to native check
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error in Magisk detection", e)
        }

        // Native: run independently regardless of the Kotlin result above.
        // Magisk may hide itself from /proc/self/mounts, so these two checks
        // must be orthogonal.
        try {
            if (isMagiskPresentNative()) {
                isMagiskPresent = Result.FOUND
            }
        } catch (e: Exception) {
            Log.e(TAG, "Native Magisk check failed", e)
        }

        return isMagiskPresent
    }

    companion object {
        private const val TAG = "MagiskDetection"
    }
}
