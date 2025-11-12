package com.ssithara.rootkit

import android.content.Context
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader

class MagiskDetection(context: Context) : DetectorResult(context) {
    private external fun isMagiskPresentNative(): Boolean

    override fun run(): Result {
        var isMagiskPresent = Result.NOT_FOUND

        try {
            val blackListedMountPaths = arrayOf<String?>(
                "magisk", "core/mirror", "core/img",
                "/su/bin/",
                "/system/bin/failsafe/",
                "/system/usr/we-need-root/",
                "/su",
            )

            val file = File("/proc/self/mounts")
            val fis = FileInputStream(file)
            val reader = BufferedReader(InputStreamReader(fis))
            var str: String?
            var count = 0
            while ((reader.readLine().also { str = it }) != null && (count == 0)) {
                for (path in blackListedMountPaths) {
                    if (str!!.contains(path!!)) {
                        count++
                        break
                    }
                }
            }
            reader.close()
            fis.close()

            if (count > 0) {
                isMagiskPresent = Result.FOUND
            }
            if (count > 0) {
                val isMasiskPresentNative = isMagiskPresentNative()
                if (isMasiskPresentNative) {
                    isMagiskPresent = Result.FOUND
                }

            }
        } catch (e: Exception) {
        }
        return isMagiskPresent
    }
}