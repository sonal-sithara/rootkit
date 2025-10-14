package com.ssithara.rootkit

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.ssithara.rootkit.dto.MagiskStubInfoDto
import java.io.File

class MagiskDetection(context: Context) : DetectorResult(context) {


    private val flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_PROVIDERS or PackageManager.GET_RECEIVERS

    private val magiskStubs = listOf(
        MagiskStubInfoDto("Magisk v28.1", 2, 2, 1, 1, "i.r"),
        MagiskStubInfoDto("Magisk (47cc532d) (28101)", 2, 2, 1, 1, "n.v"),
        MagiskStubInfoDto("Magisk (895b5f6c) (28003)", 2, 2, 1, 1, "x.ML2"),
        MagiskStubInfoDto("Magisk (a34c04f9) (28002)", 2, 2, 1, 1, "i.BeB"),
        MagiskStubInfoDto("Magisk v28.0", 2, 2, 1, 1, "v.S"),
        MagiskStubInfoDto("Magisk (070719db) (28001)", 2, 2, 1, 1, "iV.E"),
        MagiskStubInfoDto("Magisk (4f18a66d) (27008)", 2, 2, 1, 1, "z.p"),
        MagiskStubInfoDto("Magisk (8e82113b) (27007)", 2, 2, 1, 1, "mEK.mEK"),
        MagiskStubInfoDto("Magisk (0495468d) (27006)", 2, 2, 1, 1, "gbu.SY"),
        MagiskStubInfoDto("Magisk (7b81e2d2) (27005)", 2, 2, 1, 1, "d2w.DFE"),
        MagiskStubInfoDto("Magisk v27.0", 2, 2, 1, 1, "sg.KB"),
        MagiskStubInfoDto("Magisk v26.4", 2, 2, 1, 1, "pDJ.Q"),
        MagiskStubInfoDto("Magisk v26.3", 2, 2, 1, 1, "zgY.fb"),
        MagiskStubInfoDto("Magisk v26.2", 2, 2, 1, 1, "rk.FKk"),
        MagiskStubInfoDto("Magisk v26.1", 2, 2, 1, 1, "h.dS"),
        MagiskStubInfoDto("Magisk v26.0", 2, 2, 1, 1, "b.j"),
        MagiskStubInfoDto("Magisk v25.2", 2, 2, 1, 1, "m.Kdo"),
        MagiskStubInfoDto("Magisk v25.1", 2, 2, 1, 1, "f1.oh"),
        MagiskStubInfoDto("Magisk v25.0", 2, 2, 1, 1, "iE7.e"),
        MagiskStubInfoDto("Magisk v24.3", 2, 2, 1, 1, "o.h"),
        MagiskStubInfoDto("Magisk v24.2", 2, 2, 1, 1, "iuf.vF"),
        MagiskStubInfoDto("Magisk v24.1", 2, 2, 1, 1, "d.g"),
        MagiskStubInfoDto("Magisk v24.0", 2, 2, 1, 1, "S.T"),
        MagiskStubInfoDto("v26.4-kitsune-2", 2, 2, 1, 1, "f.B1")
    )

    @SuppressLint("QueryPermissionsNeeded")
    override fun run(): Result {
        var result = Result.NOT_FOUND
        val pm = context.packageManager
        val intent = Intent(Intent.ACTION_MAIN)

        val activities = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.queryIntentActivities(
                intent, PackageManager.ResolveInfoFlags.of(
                    PackageManager.MATCH_DIRECT_BOOT_UNAWARE.toLong()
                )
            )
        } else {
            pm.queryIntentActivities(
                intent, PackageManager.MATCH_DIRECT_BOOT_UNAWARE
            )
        }

        for (pkg in activities) {
            runCatching {
                val pInfo = pm.getPackageInfo(pkg.activityInfo.packageName, flags)
                val aInfo = pInfo.applicationInfo
                if (aInfo == null) return@runCatching
                val apkFile = File(aInfo.sourceDir)
                val apkSize = apkFile.length() / 1024
                if (apkSize !in 20..40 && apkSize !in 9 * 1024..20 * 1024) return@runCatching
                if (aInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0) return@runCatching

                for (stub in magiskStubs) {
                    if ((pInfo.activities?.size == stub.activities) &&
                        (pInfo.services?.size == stub.services) &&
                        (pInfo.receivers?.size == stub.broadcast_receivers) &&
                        (pInfo.providers?.size == stub.content_providers) &&
                        (pInfo.applicationInfo?.className?.lowercase() == stub.class_name.lowercase())
                    ) {
                        result = Result.FOUND
                        return@runCatching
                    }
                }
            }
        }
        return result
    }
}