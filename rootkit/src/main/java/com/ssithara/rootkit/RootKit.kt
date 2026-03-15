package com.ssithara.rootkit

import android.content.Context
import com.ssithara.rootkit.core.EncryptionService
import com.ssithara.rootkit.core.Result
import com.ssithara.rootkit.core.periodic.PeriodicCheckConfig
import com.ssithara.rootkit.core.periodic.PeriodicCheckController
import com.ssithara.rootkit.core.periodic.PeriodicCheckControllerImpl
import com.ssithara.rootkit.detection.environment.DebuggerDetection
import com.ssithara.rootkit.detection.environment.EmulatorDetection
import com.ssithara.rootkit.detection.root.MagiskDetection
import com.ssithara.rootkit.detection.root.MagiskHideDetection
import com.ssithara.rootkit.detection.root.RootDetection
import com.ssithara.rootkit.detection.runtime.RuntimeTamperingDetection

/**
 * RootKit - Android Security Detection Library
 *
 * This library provides comprehensive security detection including:
 * - Root detection (Root, Magisk, MagiskHide)
 * - Runtime tampering detection (Frida, Xposed, Memory tampering, Native hooks)
 * - Environment detection (Emulator, Debugger)
 *
 * Basic usage:
 * ```kotlin
 * val rootKit = RootKit(context)
 * rootKit.initialize()
 *
 * // On-demand checks
 * val isRooted = rootKit.isRootedDevice()
 * ```
 *
 * With periodic monitoring:
 * ```kotlin
 * val config = PeriodicCheckConfig.Builder()
 *     .setInterval(30_000L)
 *     .monitorAllDetections()
 *     .setCallback(myCallback)
 *     .build()
 *
 * val controller = rootKit.initialize(config)
 * controller.start()
 * ```
 */
class RootKit(private val context: Context) {
    private val magiskHideDetection by lazy { MagiskHideDetection(context) }
    private val magiskDetection by lazy { MagiskDetection(context) }
    private val rootDetection by lazy { RootDetection(context) }
    private val debuggerDetection by lazy { DebuggerDetection(context) }
    private val emulatorDetection by lazy { EmulatorDetection(context) }
    private val runtimeTamperingDetection by lazy { RuntimeTamperingDetection(context) }

    /**
     * Initialize the SDK with native library loading only.
     * Backward compatible with existing usage.
     *
     * Call this before using any detection methods.
     */
    fun initialize() {
        System.loadLibrary("rootkit")
    }

    /**
     * Initialize the SDK with periodic security monitoring.
     *
     * This loads the native library and returns a controller for managing
     * periodic security checks.
     *
     * @param config Configuration for periodic checks
     * @return PeriodicCheckController to control the monitoring lifecycle
     * @throws IllegalStateException if native library fails to load
     *
     * Example:
     * ```kotlin
     * val config = PeriodicCheckConfig.Builder()
     *     .setInterval(30_000L)
     *     .monitorAllDetections()
     *     .setCallback(object : PeriodicCheckConfig.SecurityCallback {
     *         override fun onDetectionResult(type: DetectionType, result: DetectionResult) {
     *             // Handle individual detection result
     *         }
     *         override fun onCheckCycleComplete(summary: SecuritySummary) {
     *             // Handle complete check cycle
     *         }
     *         override fun onError(type: DetectionType, error: Throwable) {
     *             // Handle errors
     *         }
     *     })
     *     .build()
     *
     * val controller = rootKit.initialize(config)
     * controller.start()
     * ```
     */
    fun initialize(config: PeriodicCheckConfig): PeriodicCheckController {
        System.loadLibrary("rootkit")
        return PeriodicCheckControllerImpl(context, config)
    }

    /**
     * Initialize with a simplified configuration using DSL-style builder.
     *
     * @param block Configuration builder lambda
     * @return PeriodicCheckController to control the monitoring lifecycle
     *
     * Example:
     * ```kotlin
     * val controller = rootKit.initialize {
     *     setInterval(60_000L)
     *     addDetections(
     *         PeriodicCheckConfig.DetectionType.ROOT,
     *         PeriodicCheckConfig.DetectionType.FRIDA
     *     )
     *     setCallback(myCallback)
     * }
     * controller.start()
     * ```
     */
    fun initialize(block: PeriodicCheckConfig.Builder.() -> Unit): PeriodicCheckController {
        val config = PeriodicCheckConfig.Builder().apply(block).build()
        return initialize(config)
    }

    fun isRootedDevice(): String {
        val detections = listOf(
            magiskHideDetection.run(),
            magiskDetection.run(),
            rootDetection.run()
        )

        val isRooted = if (Result.FOUND in detections)
            Result.FOUND
        else
            Result.NOT_FOUND

        return EncryptionService.encryptWithBase64Key(isRooted.name)
    }


    fun isDebuggerDetected(): String {
        val result = debuggerDetection.run()
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    fun isEmulatorDevice(): String {
        val result = emulatorDetection.run()
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Comprehensive runtime tampering detection
     * Checks for Frida, Xposed, memory tampering, and native hooks
     */
    fun isRuntimeTamperingDetected(): String {
        val result = runtimeTamperingDetection.run()
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Frida-specific detection
     */
    fun isFridaDetected(): String {
        val result = if (runtimeTamperingDetection.isFridaDetected())
            Result.FOUND
        else
            Result.NOT_FOUND
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Xposed/LSPosed-specific detection
     */
    fun isXposedDetected(): String {
        val result = if (runtimeTamperingDetection.isXposedDetected())
            Result.FOUND
        else
            Result.NOT_FOUND
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Memory tampering-specific detection
     */
    fun isMemoryTamperingDetected(): String {
        val result = if (runtimeTamperingDetection.isMemoryTamperingDetected())
            Result.FOUND
        else
            Result.NOT_FOUND
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Native hook-specific detection
     */
    fun isNativeHookDetected(): String {
        val result = if (runtimeTamperingDetection.isNativeHookDetected())
            Result.FOUND
        else
            Result.NOT_FOUND
        return EncryptionService.encryptWithBase64Key(result.name)
    }

    /**
     * Get detailed detection results for all runtime tampering checks
     */
    fun getRuntimeTamperingDetails(): Map<String, Map<String, Boolean>> {
        return runtimeTamperingDetection.getComprehensiveDetectionDetails()
    }

    /**
     * Get a summary of runtime tampering detections
     */
    fun getRuntimeTamperingSummary(): RuntimeTamperingDetection.DetectionSummary {
        return runtimeTamperingDetection.getDetectionSummary()
    }

    /**
     * Get detailed detection results for emulator checks
     */
    fun getEmulatorDetails(): Map<String, Boolean> {
        return emulatorDetection.getDetectionDetails()
    }

    /**
     * Get detailed detection results for debugger checks
     */
    fun getDebuggerDetails(): Map<String, Boolean> {
        return debuggerDetection.getDetectionDetails()
    }
}
