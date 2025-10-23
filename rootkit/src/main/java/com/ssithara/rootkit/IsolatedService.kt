package com.ssithara.rootkit

import android.app.Service
import android.content.Intent
import android.os.IBinder
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStreamReader
import java.lang.annotation.Native

class IsolatedService : Service() {


    private val blackListedMountPaths = arrayOf("magisk", "core/mirror", "core/img")

    override fun onBind(intent: Intent): IBinder {
        return mBinder
    }

    private val mBinder = object : Isolated.Stub() {
        fun isMagiskPresent(): Boolean {
            var isMagiskPresent = false
            val file = File("/proc/self/mounts")

            try {
                FileInputStream(file).use { fis ->
                    BufferedReader(InputStreamReader(fis)).use { reader ->
                        var count = 0
                        var str: String?
                        while (reader.readLine().also { str = it } != null && count == 0) {
                            for (path in blackListedMountPaths) {
                                if (str!!.contains(path)) {
                                    count++
                                    break
                                }
                            }
                        }
                        if (count > 0) {
                            isMagiskPresent = true
                        } else {
                            isMagiskPresent = Native.isMagiskPresentNative()
                        }
                    }
                }
            } catch (e: IOException) {
                e.printStackTrace()
            }
            return isMagiskPresent
        }
    }
}