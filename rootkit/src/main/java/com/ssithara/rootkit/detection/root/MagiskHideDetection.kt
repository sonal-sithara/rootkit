package com.ssithara.rootkit.detection.root

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import com.ssithara.rootkit.core.DetectorResult
import com.ssithara.rootkit.core.Result
import com.ssithara.rootkit.internal.dto.MagiskStubInfo
import java.io.File

internal class MagiskHideDetection(context: Context) : DetectorResult(context) {


    private val flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_PROVIDERS or PackageManager.GET_RECEIVERS

    private fun getPackageInfoFlags(): Long = flags.toLong()

    // Magisk stub signatures for detecting Magisk Hide
    // These stubs are used by Magisk to hide its presence from app listings
    private val magiskStubs = listOf(
        // Magisk v30.x series
        MagiskStubInfo("Magisk v30.6", 2, 2, 1, 1, "vxy.O"),
        MagiskStubInfo("Magisk v30.5", 2, 2, 1, 1, "pRe.K"),
        MagiskStubInfo("Magisk v30.4", 2, 2, 1, 1, "pW.ECr"),
        MagiskStubInfo("Magisk v30.3", 2, 2, 1, 1, "b.xj"),
        MagiskStubInfo("Magisk v30.2", 2, 2, 1, 1, "v.g"),
        MagiskStubInfo("Magisk v30.1", 2, 2, 1, 1, "t.Xi"),
        MagiskStubInfo("Magisk v30.0", 2, 2, 1, 1, "zy.sz"),
        // Magisk v29.x series
        MagiskStubInfo("Magisk v29.0", 2, 2, 1, 1, "u.H"),
        // Magisk v28.x series (including beta builds)
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
        // Magisk v27.x series
        MagiskStubInfo("Magisk (4f18a66d) (27008)", 2, 2, 1, 1, "z.p"),
        MagiskStubInfo("Magisk (8e82113b) (27007)", 2, 2, 1, 1, "mEK.mEK"),
        MagiskStubInfo("Magisk (0495468d) (27006)", 2, 2, 1, 1, "gbu.SY"),
        MagiskStubInfo("Magisk (7b81e2d2) (27005)", 2, 2, 1, 1, "d2w.DFE"),
        MagiskStubInfo("Magisk v27.0", 2, 2, 1, 1, "sg.KB"),
        // Magisk v26.x series
        MagiskStubInfo("Magisk v26.4", 2, 2, 1, 1, "pDJ.Q"),
        MagiskStubInfo("Magisk v26.3", 2, 2, 1, 1, "zgY.fb"),
        MagiskStubInfo("Magisk v26.2", 2, 2, 1, 1, "rk.FKk"),
        MagiskStubInfo("Magisk v26.1", 2, 2, 1, 1, "h.dS"),
        MagiskStubInfo("Magisk v26.0", 2, 2, 1, 1, "b.j"),
        // Magisk v25.x series
        MagiskStubInfo("Magisk v25.2", 2, 2, 1, 1, "m.Kdo"),
        MagiskStubInfo("Magisk v25.1", 2, 2, 1, 1, "f1.oh"),
        MagiskStubInfo("Magisk v25.0", 2, 2, 1, 1, "iE7.e"),
        // Magisk v24.x series
        MagiskStubInfo("Magisk v24.3", 2, 2, 1, 1, "o.h"),
        MagiskStubInfo("Magisk v24.2", 2, 2, 1, 1, "iuf.vF"),
        MagiskStubInfo("Magisk v24.1", 2, 2, 1, 1, "d.g"),
        MagiskStubInfo("Magisk v24.0", 2, 2, 1, 1, "S.T"),
        // Alternative class names for kitsune/MagiskHide
        MagiskStubInfo("v26.4-kitsune-2", 2, 2, 1, 1, "f.B1"),
        MagiskStubInfo("v26.4-kitsune-2", 2, 2, 1, 1, "com.topjohnwu.magisk.core.App")
    )

    // Package name patterns for dynamic Magisk detection
    // These patterns can detect Magisk even when stub signatures change
    private val magiskPackagePatterns = listOf(
        "com.topjohnwu.magisk",
        "io.microndecor",
        "me.weishu.kernelsu",
        "com.topjohnwu.magisk.delta",
        "com.topjohnwu.magisk.canary"
    )

    @SuppressLint("QueryPermissionsNeeded")
    override fun run(): Result {
        var result = Result.NOT_FOUND
        val pm = context.packageManager
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)

        val activities = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
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
        } catch (e: SecurityException) {
            Log.e(TAG, "Permission denied querying intent activities", e)
            return result
        }

        for (pkg in activities) {
            val packageName = pkg.activityInfo.packageName
            
            // Quick check: first verify package name patterns
            if (isMagiskPackageName(packageName)) {
                Log.d(TAG, "Found potential Magisk package: $packageName")
                result = Result.FOUND
                return result
            }
            
            // Detailed stub signature check
            runCatching {
                @Suppress("DEPRECATION")
                val pInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(getPackageInfoFlags()))
                } else {
                    pm.getPackageInfo(packageName, flags)
                }
                val aInfo = pInfo.applicationInfo
                if (aInfo == null) return@runCatching
                
                val apkFile = File(aInfo.sourceDir)
                val apkSize = apkFile.length() / 1024
                
                // Size check: Magisk stubs are typically small (20-40KB) or large (9-20MB)
                // Note: This can be bypassed by modifying the APK size
                if (apkSize !in 20..40 && apkSize !in 9 * 1024..20 * 1024) {
                    return@runCatching
                }
                
                // System app flag check
                // Note: This can be bypassed with Magisk Hide enabled
                if (aInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0) {
                    return@runCatching
                }

                for (stub in magiskStubs) {
                    // Application class name is always set by Magisk stubs; if the
                    // package has no custom Application class it cannot be this stub.
                    val packageClassName = pInfo.applicationInfo?.className
                    val classNameMatches = packageClassName != null &&
                            packageClassName.equals(stub.class_name, ignoreCase = true)

                    // Also check for direct class name match for newer versions
                    val directClassMatch = stub.class_name == "com.topjohnwu.magisk" && 
                            packageClassName != null &&
                            packageClassName.contains("topjohnwu", ignoreCase = true)

                    if ((pInfo.activities?.size == stub.activities) &&
                        (pInfo.services?.size == stub.services) &&
                        (pInfo.receivers?.size == stub.broadcast_receivers) &&
                        (pInfo.providers?.size == stub.content_providers) &&
                        (classNameMatches || directClassMatch)
                    ) {
                        Log.d(TAG, "Matched Magisk stub: ${stub.version} for package: $packageName")
                        result = Result.FOUND
                        return result // Early return to avoid unnecessary iterations
                    }
                }
            }.onFailure { e ->
                Log.e(TAG, "Error checking package: $packageName", e)
            }
        }
        return result
    }
    
    /**
     * Check if the package name matches known Magisk-related package patterns
     */
    private fun isMagiskPackageName(packageName: String): Boolean {
        val packageLower = packageName.lowercase()
        return magiskPackagePatterns.any { pattern ->
            packageLower == pattern.lowercase() || 
            packageLower.contains(pattern.lowercase())
        }
    }

    companion object {
        private const val TAG = "MagiskHideDetection"
    }
}
