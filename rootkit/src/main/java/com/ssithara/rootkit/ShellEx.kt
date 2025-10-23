package com.ssithara.rootkit

import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter

class ShellEx {

    companion object {
        enum class SHELL_CMD(val command: Array<String>) {
            check_su_binary(arrayOf("/system/xbin/which", "su")),
            check_daemon_su(arrayOf("ps", "daemonsu")),
            run_su(arrayOf("su")),
            check_su(arrayOf("ps", "|", "grep", "su"))
        }
    }


    fun executeCommand(shellCmd: SHELL_CMD): List<String>? {
        val fullResponse = mutableListOf<String>()
        val localProcess = try {
            Runtime.getRuntime().exec(shellCmd.command)
        } catch (e: Exception) {
            return null
        }

        BufferedWriter(OutputStreamWriter(localProcess.outputStream)).use { out ->
            BufferedReader(InputStreamReader(localProcess.inputStream)).use { `in` ->
                try {
                    var line: String?
                    while (`in`.readLine().also { line = it } != null) {
                        fullResponse.add(line!!)
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        }
        android.util.Log.d("RootInspector", "--> Full response was: $fullResponse")
        return fullResponse
    }

    fun executeCommandSU(shellCmd: SHELL_CMD): Boolean {
        return try {
            Runtime.getRuntime().exec(shellCmd.command)
            true
        } catch (e: Exception) {
            false
        }
    }
}