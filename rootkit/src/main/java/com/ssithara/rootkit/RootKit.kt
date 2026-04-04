package com.ssithara.rootkit

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.annotation.Keep
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
import java.io.Closeable
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * RootKit — Android Security Detection Library
 *
 * Single entry point for all security detection. Provides:
 * - **Root detection** (Root, Magisk, MagiskHide/DenyList)
 * - **Runtime tampering detection** (Frida, Xposed, Memory tampering, Native hooks)
 * - **Environment detection** (Emulator, Debugger)
 * - **Periodic monitoring** with lifecycle-aware scheduling
 *
 * All detection methods return **AES-256-GCM encrypted** strings. Use [decryptResult]
 * to obtain a [Result] enum, or call [runAllDetections] for a typed [SecurityReport].
 *
 * ## Quick Start
 * ```kotlin
 * RootKit(context).use { rootKit ->
 *     rootKit.initialize()
 *     val report = rootKit.runAllDetections()
 *     if (report.anyThreatFound(rootKit)) {
 *         // Security threat detected
 *     }
 * }
 * ```
 *
 * ## Periodic Monitoring
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
 *
 * ## Thread Safety
 * This class is thread-safe. Initialization uses [java.util.concurrent.atomic.AtomicBoolean]
 * for lock-free state transitions.
 *
 * ## Lifecycle
 * Implements [Closeable] — use Kotlin `use {}` blocks for automatic cleanup,
 * or call [dispose] / [close] manually when done.
 *
 * @param context Any Android context. The [android.content.Context.getApplicationContext]
 *                is used internally to prevent Activity/Fragment leaks.
 * @see Result for detection result values
 * @see SecurityReport for typed result snapshots
 * @see PeriodicCheckConfig for periodic monitoring configuration
 */
@Keep
class RootKit(context: Context) : Closeable {

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

    /**
     * Active periodic check controller, if one was created via [initialize].
     * Stored so that [dispose] can clean up its underlying CoroutineScope.
     */
    private val activeController = java.util.concurrent.atomic.AtomicReference<PeriodicCheckController?>(null)

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
     * ## Security Limitations
     *
     * This key is accessible in-process, meaning a determined attacker with
     * memory access (e.g., via Frida or a debugger) can extract it. The
     * encryption provides **obfuscation** rather than true security — it
     * raises the bar for casual inspection but should not be relied upon
     * as a sole integrity guarantee.
     *
     * For stronger integrity guarantees, consider using HMAC-based
     * authentication (e.g., HMAC-SHA256) on detection results, or verify
     * results server-side where the signing key is not accessible to the
     * client process.
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
        if (isLibraryLoaded.compareAndSet(false, true)) {
            System.loadLibrary("rootkit")
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
        val controller = PeriodicCheckControllerImpl(context, config, sessionKey)
        activeController.set(controller)
        return controller
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

    /**
     * Release all resources held by this [RootKit] instance.
     *
     * If a [PeriodicCheckController] was created via [initialize], calling
     * `dispose()` stops any running periodic checks and cancels the underlying
     * CoroutineScope. After calling this method the instance should not be
     * used for further detection — create a new [RootKit] instance instead.
     *
     * **Important:** Consumers **must** call this method when the [RootKit]
     * instance is no longer needed (e.g., in `onDestroy` of an Activity or
     * Service, or in a `Closeable` wrapper). Failing to do so will leak the
     * CoroutineScope created by the periodic check controller.
     */
    fun dispose() {
        activeController.getAndSet(null)?.dispose()
    }

    /**
     * Closes this [RootKit] instance, releasing all held resources.
     *
     * Equivalent to calling [dispose]. Implementing [Closeable] allows
     * usage with Kotlin `use {}` blocks and Java try-with-resources.
     */
    override fun close() = dispose()

    /**
     * Combined root detection check.
     *
     * Runs Root, Magisk, and MagiskHide detectors. Returns [Result.FOUND] if any
     * detector finds a threat, [Result.ERROR] if any detector fails, or
     * [Result.NOT_FOUND] if all pass.
     *
     * @return Encrypted result string. Use [decryptResult] to decode.
     */
    fun isRootedDevice(): String {
        checkInitialized()
        val detections = listOf(
            magiskHideDetection.runSafely(),
            magiskDetection.runSafely(),
            rootDetection.runSafely()
        )

        val isRooted = when {
            detections.any { it == Result.FOUND } -> Result.FOUND
            detections.any { it == Result.ERROR } -> Result.ERROR
            else -> Result.NOT_FOUND
        }

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

    /**
     * Debugger detection check.
     *
     * Detects both native (ptrace) and Java-level debugging.
     *
     * @return Encrypted result string. Use [decryptResult] to decode.
     */
    fun isDebuggerDetected(): String {
        checkInitialized()
        val result = debuggerDetection.runSafely()
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Emulator detection check.
     *
     * Checks hardware properties, system properties, and other indicators
     * to detect Android emulator environments.
     *
     * @return Encrypted result string. Use [decryptResult] to decode.
     */
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
        val result = if (runtimeTamperingDetection.isFridaDetected()) Result.FOUND else Result.NOT_FOUND
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Xposed/LSPosed-specific detection.
     */
    fun isXposedDetected(): String {
        checkInitialized()
        val result = if (runtimeTamperingDetection.isXposedDetected()) Result.FOUND else Result.NOT_FOUND
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Memory tampering-specific detection.
     */
    fun isMemoryTamperingDetected(): String {
        checkInitialized()
        val result = if (runtimeTamperingDetection.isMemoryTamperingDetected()) Result.FOUND else Result.NOT_FOUND
        return EncryptionService.encryptWithBase64Key(result.name, sessionKey)
    }

    /**
     * Native hook-specific detection.
     */
    fun isNativeHookDetected(): String {
        checkInitialized()
        val result = if (runtimeTamperingDetection.isNativeHookDetected()) Result.FOUND else Result.NOT_FOUND
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
    internal fun getRuntimeTamperingSummary(): RuntimeDetectionSummary? {
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

    /**
     * Decrypt an encrypted detection result string back to a [Result] enum.
     *
     * This is a convenience method so consumers do not need to implement
     * AES-256-GCM decryption themselves. It uses the per-instance session
     * key returned by [getEncryptionKey].
     *
     * @param encryptedResult An encrypted result string returned by any detection method.
     * @return The decrypted [Result] enum value.
     * @throws IllegalArgumentException if the encrypted string cannot be decrypted
     *         or does not map to a known [Result].
     */
    fun decryptResult(encryptedResult: String): Result {
        val decrypted = EncryptionService.decryptWithBase64Key(encryptedResult, sessionKey)
        return when (decrypted) {
            Result.FOUND.name -> Result.FOUND
            Result.NOT_FOUND.name -> Result.NOT_FOUND
            Result.ERROR.name -> Result.ERROR
            else -> throw IllegalArgumentException("Unknown result value: $decrypted")
        }
    }

    /**
     * Run all security detections and return a typed [SecurityReport].
     *
     * This is a convenience method that runs every detection in sequence and
     * packages the encrypted results into a single report. Use [SecurityReport.toDecodedMap]
     * or [SecurityReport.anyThreatFound] to inspect results.
     *
     * ```kotlin
     * RootKit(context).use { rootKit ->
     *     rootKit.initialize()
     *     val report = rootKit.runAllDetections()
     *     if (report.anyThreatFound(rootKit)) {
     *         // Handle security threat
     *     }
     * }
     * ```
     *
     * @return A [SecurityReport] containing all encrypted detection results.
     */
    fun runAllDetections(): SecurityReport {
        checkInitialized()
        return SecurityReport(
            rootDetection = isRootDetected(),
            magiskDetection = isMagiskDetected(),
            magiskHideDetection = isMagiskHideDetected(),
            runtimeTampering = isRuntimeTamperingDetected(),
            emulatorDetection = isEmulatorDevice(),
            debuggerDetection = isDebuggerDetected(),
            fridaDetection = isFridaDetected(),
            xposedDetection = isXposedDetected(),
            memoryTamperingDetection = isMemoryTamperingDetected(),
            nativeHookDetection = isNativeHookDetected()
        )
    }

    companion object {
        private const val TAG = "RootKit"
    }
}
