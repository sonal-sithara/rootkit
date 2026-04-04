package com.ssithara.rootkit

import androidx.annotation.Keep
import com.ssithara.rootkit.core.Result

/**
 * Typed snapshot of all security detection results from a single check cycle.
 *
 * Use [RootKit.runAllDetections] to obtain an instance. Each field contains the
 * encrypted result string from the corresponding detection method — decrypt with
 * [RootKit.decryptResult] or use the convenience `Status` properties.
 *
 * ```kotlin
 * val report = rootKit.runAllDetections()
 * if (report.isRooted) { /* handle */ }
 * if (report.anyThreatFound) { /* handle */ }
 * ```
 */
@Keep
data class SecurityReport(
    val rootDetection: String,
    val magiskDetection: String,
    val magiskHideDetection: String,
    val runtimeTampering: String,
    val emulatorDetection: String,
    val debuggerDetection: String,
    val fridaDetection: String? = null,
    val xposedDetection: String? = null,
    val memoryTamperingDetection: String? = null,
    val nativeHookDetection: String? = null,
    val timestamp: Long = System.currentTimeMillis()
) {
    /**
     * Decrypted status of the root detection result.
     * Requires the [RootKit] instance that produced this report.
     */
    fun rootStatus(rootKit: RootKit): Result = rootKit.decryptResult(rootDetection)

    /**
     * Decrypted status of the Magisk detection result.
     */
    fun magiskStatus(rootKit: RootKit): Result = rootKit.decryptResult(magiskDetection)

    /**
     * Decrypted status of the MagiskHide detection result.
     */
    fun magiskHideStatus(rootKit: RootKit): Result = rootKit.decryptResult(magiskHideDetection)

    /**
     * Decrypted status of the runtime tampering detection result.
     */
    fun runtimeTamperingStatus(rootKit: RootKit): Result = rootKit.decryptResult(runtimeTampering)

    /**
     * Decrypted status of the emulator detection result.
     */
    fun emulatorStatus(rootKit: RootKit): Result = rootKit.decryptResult(emulatorDetection)

    /**
     * Decrypted status of the debugger detection result.
     */
    fun debuggerStatus(rootKit: RootKit): Result = rootKit.decryptResult(debuggerDetection)

    /**
     * Returns `true` if any detection found a threat.
     * Requires the [RootKit] instance that produced this report.
     */
    fun anyThreatFound(rootKit: RootKit): Boolean {
        val coreResults = listOf(rootDetection, magiskDetection, magiskHideDetection,
            runtimeTampering, emulatorDetection, debuggerDetection)
        return coreResults.any { rootKit.decryptResult(it) == Result.FOUND }
    }

    /**
     * Returns a map of detection names to their decrypted [Result] values.
     */
    fun toDecodedMap(rootKit: RootKit): Map<String, Result> = buildMap {
        put("root", rootKit.decryptResult(rootDetection))
        put("magisk", rootKit.decryptResult(magiskDetection))
        put("magiskHide", rootKit.decryptResult(magiskHideDetection))
        put("runtimeTampering", rootKit.decryptResult(runtimeTampering))
        put("emulator", rootKit.decryptResult(emulatorDetection))
        put("debugger", rootKit.decryptResult(debuggerDetection))
        fridaDetection?.let { put("frida", rootKit.decryptResult(it)) }
        xposedDetection?.let { put("xposed", rootKit.decryptResult(it)) }
        memoryTamperingDetection?.let { put("memoryTampering", rootKit.decryptResult(it)) }
        nativeHookDetection?.let { put("nativeHook", rootKit.decryptResult(it)) }
    }
}
