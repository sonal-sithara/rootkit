package com.ssithara.rootkit

import android.content.Context
import android.os.Build
import java.io.File
import java.util.Locale

class EmulatorDetection(context: Context) : DetectorResult(context) {

    private val paths: ArrayList<String?> = ArrayList<String?>(
        mutableListOf<String?>(
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd",
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "ueventd.android_x86.rc",
            "x86.prop",
            "ueventd.ttVM_x86.rc",
            "init.ttVM_x86.rc",
            "fstab.ttVM_x86",
            "fstab.vbox86",
            "init.vbox86.rc",
            "ueventd.vbox86.rc",
            "fstab.andy",
            "ueventd.andy.rc",
            "fstab.nox",
            "init.nox.rc",
            "ueventd.nox.rc"
        )
    )


    private fun isEmulator(): Boolean {
        /*        Log.e("*********",Build.MANUFACTURER);
                Log.e("*********",Build.MODEL);
                Log.e("*********",Build.HARDWARE);
                Log.e("*********",Build.PRODUCT);
                Log.e("*********",Build.BOARD);*/

        return Build.MANUFACTURER.contains("Genymotion")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("sdk_gphone64_x86_64")
                || Build.MODEL.lowercase(Locale.getDefault()).contains("droid4x")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.HARDWARE.lowercase(Locale.getDefault()).contains("goldfish")
                || Build.HARDWARE === "goldfish_x86_64" || Build.HARDWARE === "goldfish" || Build.HARDWARE === "vbox86" || Build.HARDWARE.lowercase(
            Locale.getDefault()
        ).contains("nox")
                || Build.FINGERPRINT.startsWith("generic")
                || Build.PRODUCT === "sdk" || Build.PRODUCT === "google_sdk" || Build.PRODUCT === "sdk_x86" || Build.PRODUCT === "vbox86p" || Build.PRODUCT.lowercase(
            Locale.getDefault()
        ).contains("nox")
                || Build.BOARD.lowercase(Locale.getDefault()).contains("nox")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
    }

    private fun isEmulator2(): Boolean {
        try {
            for (i in paths.indices) {
                val file = File(paths.get(i) ?: "")
                if (file.exists()) {
                    return true
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }

    override fun run(): Result {
        var isEmulator = Result.NOT_FOUND
        if (isEmulator() || isEmulator2()) {
            isEmulator = Result.FOUND
        }
        return isEmulator
    }
}