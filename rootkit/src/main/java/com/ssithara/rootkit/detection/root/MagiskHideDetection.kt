package com.ssithara.rootkit.detection.root

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result
import com.ssithara.rootkit.internal.dto.MagiskStubInfoDto
import java.io.File

class MagiskHideDetection(context: Context) : DetectorResult(context) {


    private val flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_PROVIDERS or PackageManager.GET_RECEIVERS

    private val magiskStubs = listOf(
        MagiskStubInfo("Magisk v30.6", 2, 2, 1, 1, "vxy.O"),
        MagiskStubInfo("Magisk v30.5", 2, 2, 1, 1, "pRe.K"),
        MagiskStubInfo("Magisk v30.4", 2, 2, 1, 1, "pW.ECr"),
        MagiskStubInfo("Magisk v30.3", 2, 2, 1, 1, "b.xj"),
        MagiskStubInfo("Magisk v30.2", 2, 2, 1, 1, "v.g"),
        MagiskStubInfo("Magisk v30.1", 2, 2, 1, 1, "t.Xi"),
        MagiskStubInfo("Magisk v30.0", 2, 2, 1, 1, "zy.sz"),
        MagiskStubInfo("Magisk v29.0", 2, 2, 1, 1, "u.H"),
        MagiskStubInfo("Magisk (b1dc47a0) (29001)", 2, 2, 1, 1, "zrx.KW"),
        MagiskStubInfo("Magisk (427a1ca4) (28104)", 2, 2, 1, 1, "g.fF"),
        MagiskStubInfo("Magisk (1e3edb88) (28103)", 2, 2, 1, 1, "igA.VV"),
        MagiskStubInfo("Magisk (b62835cb) (28102)", 2, 2, 1, 1, "c.t"),
        MagiskStubInfo("Magisk v28.1", 2, 2, 1, 1, "i.r"),
        MagiskStubInfo("Magisk (47cc532d) (28101)", 2, 2, 1, 1, "n.v"),
        MagiskStubInfo("Magisk (895b5f6c) (28003)", 2, 2, 1, 1, "x.ML2"),
        MagiskStubInfo("Magisk (a34c04f9) (28002)", 2, 2, 1, 1, "i.BeB"),
        MagiskStubInfo("Magisk v28.0", 2, 2, 1, 1, "v.S"),
        MagiskStubInfo("Magisk (070719db) (28001)", 2, 2, 1, 1, "iV.E"),
        MagiskStubInfo("Magisk (4f18a66d) (27008)", 2, 2, 1, 1, "z.p"),
        MagiskStubInfo("Magisk (8e82113b) (27007)", 2, 2, 1, 1, "mEK.mEK"),
        MagiskStubInfo("Magisk (0495468d) (27006)", 2, 2, 1, 1, "gbu.SY"),
        MagiskStubInfo("Magisk (7b81e2d2) (27005)", 2, 2, 1, 1, "d2w.DFE"),
        MagiskStubInfo("Magisk v27.0", 2, 2, 1, 1, "sg.KB"),
        MagiskStubInfo("Magisk v26.4", 2, 2, 1, 1, "pDJ.Q"),
        MagiskStubInfo("Magisk v26.3", 2, 2, 1, 1, "zgY.fb"),
        MagiskStubInfo("Magisk v26.2", 2, 2, 1, 1, "rk.FKk"),
        MagiskStubInfo("Magisk v26.1", 2, 2, 1, 1, "h.dS"),
        MagiskStubInfo("Magisk v26.0", 2, 2, 1, 1, "b.j"),
        MagiskStubInfo("Magisk v25.2", 2, 2, 1, 1, "m.Kdo"),
        MagiskStubInfo("Magisk v25.1", 2, 2, 1, 1, "f1.oh"),
        MagiskStubInfo("Magisk v25.0", 2, 2, 1, 1, "iE7.e"),
        MagiskStubInfo("Magisk v24.3", 2, 2, 1, 1, "o.h"),
        MagiskStubInfo("Magisk v24.2", 2, 2, 1, 1, "iuf.vF"),
        MagiskStubInfo("Magisk v24.1", 2, 2, 1, 1, "d.g"),
        MagiskStubInfo("Magisk v24.0", 2, 2, 1, 1, "S.T"),
        MagiskStubInfo("v26.4-kitsune-2", 2, 2, 1, 1, "f.B1"),
        MagiskStubInfo("v26.4-kitsune-2", 2, 2, 1, 1, "com.topjohnwu.magisk.core.App")
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
                        (pInfo.providers?.size == stub.content_providers)
//                        &&
//                        (pInfo.applicationInfo?.className?.lowercase() == stub.class_name.lowercase())
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
