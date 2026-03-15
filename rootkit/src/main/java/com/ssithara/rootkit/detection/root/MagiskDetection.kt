package com.ssithara.rootkit.detection.root

import android.content.Context
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
            )

            val file = File("/proc/self/mounts")
            FileInputStream(file).use { fis ->
                BufferedReader(InputStreamReader(fis)).use { reader ->
                    var str: String?
                    while (reader.readLine().also { str = it } != null) {
                        for (path in blackListedMountPaths) {
                            if (str!!.contains(path)) {
                                isMagiskPresent = Result.FOUND
                                break
                            }
                        }
                        if (isMagiskPresent == Result.FOUND) break
                    }
                }
            }
        } catch (e: IOException) {
            // /proc/self/mounts unreadable — continue to native check
        } catch (e: Exception) {
            // ignore
        }

        // Native: run independently regardless of the Kotlin result above.
        // Magisk may hide itself from /proc/self/mounts, so these two checks
        // must be orthogonal.
        try {
            if (isMagiskPresentNative()) {
                isMagiskPresent = Result.FOUND
            }
        } catch (e: Exception) {
            // ignore — native library may not be loaded yet
        }

        return isMagiskPresent
    }
}
