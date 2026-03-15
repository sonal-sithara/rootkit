package com.ssithara.rootkit.internal.util

import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter

internal class ShellEx {

    companion object {
        enum class SHELL_CMD(val command: Array<String>) {
            check_su_binary(arrayOf("/system/xbin/which", "su")),
            check_daemon_su(arrayOf("ps", "daemonsu")),
            run_su(arrayOf("su")),
            check_su(arrayOf("ps", "|", "grep", "su"))
        }

        private const val TIMEOUT_MS = 1_000L
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
        return fullResponse
    }

    /**
     * Executes the given shell command and returns whether it exited successfully (exit code 0).
     *
     * Previously this method always returned `true` as long as [Runtime.exec] did not throw,
     * regardless of whether the command actually succeeded. Now it:
     *  1. Closes stdin immediately so interactive commands (e.g. `su`) do not block forever.
     *  2. Waits up to [TIMEOUT_MS] milliseconds for the process to finish.
     *  3. Returns `true` if the process timed out (still running → binary is present and
     *     interactive, e.g. `su` waiting for root-shell input) or exited with code 0.
     *  4. Returns `false` if the process exited with a non-zero code (binary rejected the call)
     *     or if [Runtime.exec] threw (binary not found).
     *  5. Always destroys the [Process] in a finally block to prevent resource leaks.
     */
    fun executeCommandSU(shellCmd: SHELL_CMD): Boolean {
        val process = try {
            Runtime.getRuntime().exec(shellCmd.command)
        } catch (e: Exception) {
            // Binary not found or could not be executed
            return false
        }

        return try {
            // Close stdin so interactive commands do not block waiting for input
            process.outputStream.close()

            var exitCode = -1
            val waiter = Thread {
                try {
                    exitCode = process.waitFor()
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }.also {
                it.isDaemon = true
                it.start()
            }

            waiter.join(TIMEOUT_MS)

            when {
                // Process still running after timeout → su is present and accepting input
                waiter.isAlive -> true
                // Process finished cleanly
                else -> exitCode == 0
            }
        } catch (e: Exception) {
            false
        } finally {
            process.destroy()
        }
    }
}
