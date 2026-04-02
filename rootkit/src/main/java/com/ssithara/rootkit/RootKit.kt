package com.ssithara.rootkit

import android.content.Context
import android.util.Base64
import android.util.Log
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
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

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
 * // Decrypt results using the session key
 * val key = rootKit.getEncryptionKey()
 * val isRooted = rootKit.isRootedDevice() // encrypted — decrypt with key
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
class RootKit(context: Context) {

    // Always hold the application context to prevent leaking Activity/Fragment references.
    private val context: Context = context.applicationContext

    /**
     * Per-instance AES-256-GCM session key generated at construction time.
     * The key is never stored on disk or embedded in the binary.
     * Call [getEncryptionKey] to retrieve it for decrypting detection results.
     */
    private val sessionKey: String = run {
        val keyBytes = ByteArray(32)
        SecureRandom().nextBytes(keyBytes)
        Base64.encodeToString(keyBytes, Base64.NO_WRAP)
    }

    /**
     * Flag to track if the SDK has been initialized.
     */
    private val isInitialized = AtomicBoolean(false)

    /**
     * Flag to prevent duplicate library loading.
     */
    private val isLibraryLoaded = AtomicBoolean(false)

    private val magiskHideDetection by lazy { MagiskHideDetection(context) }
    private val magiskDetection by lazy { MagiskDetection(context) }
    private val rootDetection by lazy { RootDetection(context) }
    private val debuggerDetection by lazy { DebuggerDetection(context) }
    private val emulatorDetection by lazy { EmulatorDetection(context) }
    private val runtimeTamperingDetection by lazy { RuntimeTamperingDetection(context) }

    /**
     * Returns the Base64-encoded AES-256-GCM session key used to encrypt all
     * detection results returned by this instance.
     *
     * The key is unique per [RootKit] instance and is generated in memory at
     * construction time — it is never stored in the binary or on disk.
     *
     * Use this key with your own AES-GCM decrypt implementation (IV is the first
     * 12 bytes of the decoded ciphertext, followed by the 16-byte auth tag and
     * ciphertext from [javax.crypto.Cipher] with "AES/GCM/NoPadding").
     *
     * @return Base64-encoded 32-byte AES key (NO_WRAP encoding).
     */
    fun getEncryptionKey(): String = sessionKey

    /**
     * Returns whether the SDK has been initialized.
     *
     * @return true if [initialize] has been called, false otherwise.
     */
    fun isInitialized(): Boolean = isInitialized.get()

    /**
     * Ensures the SDK has been initialized before allowing detection methods to be called.
     *
     * @throws IllegalStateException if initialize() has not been called
     */
    private fun checkInitialized() {
        if (!isInitialized.get()) {
            throw IllegalStateException("RootKit is not initialized. Call initialize() first.")
        }
    }

    /**
     * Loads the native library only once, preventing duplicate loading attempts.
     * Thread-safe implementation using AtomicBoolean.
     *
     * @throws UnsatisfiedLinkError if the library cannot be loaded
     */
    @Throws(UnsatisfiedLinkError::class)
    private fun loadLibraryOnce() {
        if (isLibraryLoaded.get()) {
            return
        }
        synchronized(isLibraryLoaded) {
            if (isLibraryLoaded.get()) {
                return
            }
            System.loadLibrary("rootkit")
            isLibraryLoaded.set(true)
        }
    }

    /**
     * Initialize the SDK with native library loading only.
     * Backward compatible with existing usage.
     *
     * Call this before using any detection methods.
     *
     * @throws IllegalStateException if already initialized
     * @throws UnsatisfiedLinkError if the native library cannot be loaded
     */
    @Throws(IllegalStateException::class, UnsatisfiedLinkError::class)
    fun initialize() {
        if (!isInitialized.compareAndSet(false, true)) {
            throw IllegalStateException("RootKit is already initialized")
        }
        loadLibraryOnce()
    }

    /**
     * Initialize the SDK with periodic security monitoring.
     *
     * This loads the native library and returns a controller for managing
     * periodic security checks.
     *
     * @param config Configuration for periodic checks
     * @return PeriodicCheckController to control the monitoring lifecycle
     * @throws IllegalStateException if already initialized or native library fails to load
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
    @Throws(IllegalStateException::class, UnsatisfiedLinkError::class)
    fun initialize(config: PeriodicCheckConfig): PeriodicCheckController {
        if (!isInitialized.compareAndSet(false, true)) {
            throw IllegalStateException("RootKit is already initialized")
        }
        loadLibraryOnce()
        return PeriodicCheckControllerImpl(context, config, sessionKey)
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
        checkInitialized()
        val detections = listOf(
            magiskHideDetection.runSafely(),
            magiskDetection.runSafely(),
            rootDetection.runSafely()
        )

        val isRooted = if (Result.FOUND in detections)
            Result.FOUND
        else if (Result.ERROR in detections)
            Result.ERROR
        else
            Result.NOT_FOUND

        return EncryptionService.encryptWithBase64Key(isRooted.name, sessionKey)
    }

    /**
     * Individual root detection (binaries, SU commands, root management apps).
     */
    fun isRootDetected(): String {
        checkInitialized()
        val result = rootDetection.runSafely()
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Individual Magisk framework detection.
     */
    fun isMagiskDetected(): String {
        checkInitialized()
        val result = magiskDetection.runSafely()
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Individual MagiskHide/DenyList stub detection.
     */
    fun isMagiskHideDetected(): String {
        checkInitialized()
        val result = magiskHideDetection.runSafely()
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    fun isDebuggerDetected(): String {
        checkInitialized()
        val result = debuggerDetection.runSafely()
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    fun isEmulatorDevice(): String {
        checkInitialized()
        val result = emulatorDetection.runSafely()
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Comprehensive runtime tampering detection.
     * Checks for Frida, Xposed, memory tampering, and native hooks.
     */
    fun isRuntimeTamperingDetected(): String {
        checkInitialized()
        val result = runtimeTamperingDetection.runSafely()
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Frida-specific detection.
     */
    fun isFridaDetected(): String {
        checkInitialized()
        val result = try {
            if (runtimeTamperingDetection.isFridaDetected()) Result.FOUND else Result.NOT_FOUND
        } catch (e: Throwable) {
            Log.e(TAG, "Frida detection failed: ${e.message}", e)
            Result.ERROR
        }
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Xposed/LSPosed-specific detection.
     */
    fun isXposedDetected(): String {
        checkInitialized()
        val result = try {
            if (runtimeTamperingDetection.isXposedDetected()) Result.FOUND else Result.NOT_FOUND
        } catch (e: Throwable) {
            Log.e(TAG, "Xposed detection failed: ${e.message}", e)
            Result.ERROR
        }
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Memory tampering-specific detection.
     */
    fun isMemoryTamperingDetected(): String {
        checkInitialized()
        val result = try {
            if (runtimeTamperingDetection.isMemoryTamperingDetected()) Result.FOUND else Result.NOT_FOUND
        } catch (e: Throwable) {
            Log.e(TAG, "Memory tampering detection failed: ${e.message}", e)
            Result.ERROR
        }
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Native hook-specific detection.
     */
    fun isNativeHookDetected(): String {
        checkInitialized()
        val result = try {
            if (runtimeTamperingDetection.isNativeHookDetected()) Result.FOUND else Result.NOT_FOUND
        } catch (e: Throwable) {
            Log.e(TAG, "Native hook detection failed: ${e.message}", e)
            Result.ERROR
        }
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Get detailed detection results for all runtime tampering checks.
     * 
     * Note: Native hook detection details may contain null values indicating
     * detection failures.
     */
    fun getRuntimeTamperingDetails(): Map<String, Map<String, Any?>> {
        checkInitialized()
        return try {
            runtimeTamperingDetection.getComprehensiveDetectionDetails()
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to get runtime tampering details: ${e.message}", e)
            emptyMap()
        }
    }

    /**
     * Get a summary of runtime tampering detections.
     */
    fun getRuntimeTamperingSummary(): RuntimeTamperingDetection.DetectionSummary? {
        checkInitialized()
        return try {
            runtimeTamperingDetection.getDetectionSummary()
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to get runtime tampering summary: ${e.message}", e)
            null
        }
    }

    /**
     * Get detailed detection results for emulator checks.
     */
    fun getEmulatorDetails(): Map<String, Boolean> {
        checkInitialized()
        return emulatorDetection.getDetectionDetails()
    }

    /**
     * Get detailed detection results for debugger checks.
     */
    fun getDebuggerDetails(): Map<String, Boolean> {
        checkInitialized()
        return debuggerDetection.getDetectionDetails()
    }

    companion object {
        private const val TAG = "RootKit"
    }
}
