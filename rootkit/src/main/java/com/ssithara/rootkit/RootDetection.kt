package com.ssithara.rootkit

import android.content.Context
import android.os.Build
import com.scottyab.rootbeer.RootBeer
import com.ssithara.rootkit.ConstData.Companion.dangerousListApps
import com.ssithara.rootkit.ConstData.Companion.notWritablePath
import com.ssithara.rootkit.ConstData.Companion.rootCloakingApps
import com.ssithara.rootkit.ConstData.Companion.rootsAppPackage
import com.ssithara.rootkit.ConstData.Companion.superUserPath
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.Scanner

class RootDetection(context: Context) : DetectorResult(context) {

    private val ONEPLUS = "oneplus"
    private val MOTO = "moto"
    private val XIAOMI = "Xiaomi"


    override fun run(): Result {
        var detected: Result = Result.NOT_FOUND

        val rootBeer = RootBeer(context)

        if (Build.BRAND.contains(ONEPLUS) || Build.BRAND.contains(MOTO) || Build.BRAND.contains(
                XIAOMI
            )
        ) {
            if (rootBeer.isRooted()) {
                detected = Result.FOUND
            }
        } else {
            if (rootBeer.isRootedWithBusyBoxCheck()) {
                detected = Result.FOUND
            }
        }

        try {
            if (isPathExist("su")
                || isSUExist()
                || isTestBuildKey()
                || isHaveRootHideApps()
                || isHaveDangerousApps()
                || isHaveRootManagementApps()
                || isHaveDangerousProperties()
                || isHaveReadWritePermission()
            ) {
                detected = Result.FOUND
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }


        try {
            if (checkRootMethod8() || checkRootMethod9()) {
                detected = Result.FOUND
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }


        return detected

    }

    private fun isPathExist(ext: String): Boolean {
        for (path in superUserPath) {
            val file: File = File(path, ext)
            if (file.exists()) {
                return true
            }
        }
        return false
    }

    private fun isSUExist(): Boolean {
        var process: Process? = null
        try {
            process = Runtime.getRuntime().exec(arrayOf<String>("/system/xbin/which", "su"))
            val `in` = BufferedReader(InputStreamReader(process.getInputStream()))
            if (`in`.readLine() != null) {
                return true
            }
            return false
        } catch (e: java.lang.Exception) {
            return false
        } finally {
            if (process != null) {
                process.destroy()
            }
        }
    }

    private fun isTestBuildKey(): Boolean {
        val buildTags = Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) {
            return true
        }
        return false
    }

    private fun isHaveDangerousApps(): Boolean {
        val packages = ArrayList<String>()
        packages.addAll(dangerousListApps.filterNotNull())
        return isAnyPackageFromListInstalled(packages)
    }

    private fun isHaveRootManagementApps(): Boolean {
        val packages = ArrayList<String>()
        packages.addAll(rootsAppPackage.filterNotNull())
        return isAnyPackageFromListInstalled(packages)
    }

    private fun isHaveRootHideApps(): Boolean {
        val packages = ArrayList<String>()
        packages.addAll(rootCloakingApps.filterNotNull())
        return isAnyPackageFromListInstalled(packages)
    }


    //check dangerous properties
    private fun isHaveDangerousProperties(): Boolean {
        val dangerousProps: MutableMap<String, String?> = HashMap<String, String?>()
        dangerousProps.put("ro.debuggable", "1")
        dangerousProps.put("ro.secure", "0")

        var result = false
        val lines: Array<String>? = commander("getprop")
        if (lines == null) {
            return false
        }
        for (line in lines) {
            for (key in dangerousProps.keys) {
                if (line.contains(key)) {
                    var badValue = dangerousProps.get(key)
                    badValue = "[$badValue]"
                    if (line.contains(badValue)) {
                        result = true
                    }
                }
            }
        }
        return result
    }


    private fun isHaveReadWritePermission(): Boolean {
        var result = false
        val lines: Array<String>? = commander("mount")

        for (line in lines!!) {
            val args = line.split(" ".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
            if (args.size < 4) {
                continue
            }
            val mountPoint = args[1]
            val mountOptions = args[3]

            for (path in notWritablePath) {
                if (mountPoint.equals(path, ignoreCase = true)) {
                    for (opt in mountOptions.split(",".toRegex()).dropLastWhile { it.isEmpty() }
                        .toTypedArray()) {
                        if (opt.equals("rw", ignoreCase = true)) {
                            result = true
                            break
                        }
                    }
                }
            }
        }

        return result
    }

    fun checkRootMethod8(): Boolean {
        val result: Boolean = ShellEx().executeCommandSU(ShellEx.Companion.SHELL_CMD.run_su)
        return result
    }

    fun checkRootMethod9(): Boolean {
        val result: List<String>? =
            ShellEx().executeCommand(ShellEx.Companion.SHELL_CMD.check_su)
        if (result != null) {
            for (tempString in result) {
                if (tempString.endsWith("su")) return true
            }
        }
        return false
    }

    private fun isAnyPackageFromListInstalled(pkg: java.util.ArrayList<String>): Boolean {
        var result = false
        val pm = context.packageManager
        for (packageName in pkg) {
            try {
                pm.getPackageInfo(packageName, 0)
                result = true
            } catch (e: java.lang.Exception) {
            }
        }
        return result
    }

    private fun commander(command: String?): Array<String>? {
        try {
            val inputStream = Runtime.getRuntime().exec(command).inputStream
            if (inputStream == null) {
                return null
            }
            val propVal = Scanner(inputStream).useDelimiter("\\A").next()
            return propVal.split("\n".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        } catch (e: java.lang.Exception) {
            e.printStackTrace()
            return null
        }
    }
}