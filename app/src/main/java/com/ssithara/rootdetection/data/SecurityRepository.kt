package com.ssithara.rootdetection.data

import android.content.Context
import android.util.Log
import com.ssithara.rootdetection.service.EncryptionService
import com.ssithara.rootdetection.ui.model.DetectionResult
import com.ssithara.rootdetection.ui.model.EnvironmentCheckType
import com.ssithara.rootdetection.ui.model.RootCheckType
import com.ssithara.rootdetection.ui.model.RuntimeCheckType
import com.ssithara.rootkit.RootKit
import com.ssithara.rootkit.core.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Repository layer that bridges the RootKit library with the UI.
 * Handles encryption/decryption of detection results and maps them to UI models.
 */
class SecurityRepository(private val context: Context) {

    private val rootKit: RootKit = RootKit(context)
    private val isInitialized = AtomicBoolean(false)

    companion object {
        private const val TAG = "SecurityRepository"
    }

    /**
     * Initialize the RootKit library. Must be called before any detection methods.
     * Tracks initialization state so errors can be surfaced to the UI.
     */
    fun initialize() {
        try {
            rootKit.initialize()
            isInitialized.set(true)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize RootKit", e)
            isInitialized.set(false)
        }
    }

    /**
     * Returns whether the library was successfully initialized.
     */
    fun isReady(): Boolean = isInitialized.get()

    /**
     * Process an encrypted detection result and convert to Result enum.
     * Maps ERROR and decryption failures to Result.ERROR instead of silently returning NOT_FOUND.
     */
    private fun processDetectionResult(encryptedResult: String): Result {
        return try {
            val decrypted = EncryptionService.decryptWithBase64Key(encryptedResult, rootKit.getEncryptionKey())
            when (decrypted) {
                Result.FOUND.name -> Result.FOUND
                Result.NOT_FOUND.name -> Result.NOT_FOUND
                Result.ERROR.name -> Result.ERROR
                else -> {
                    Log.e(TAG, "Unknown result: $decrypted")
                    Result.ERROR
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt result", e)
            Result.ERROR
        }
    }

    /**
     * Check for root access (binaries, SU commands, root management apps).
     */
    suspend fun checkRoot(): DetectionResult = withContext(Dispatchers.IO) {
        if (!isInitialized.get()) {
            return@withContext DetectionResult.Error("RootKit not initialized")
        }
        try {
            val encrypted = rootKit.isRootDetected()
            val result = processDetectionResult(encrypted)
            if (result == Result.ERROR) {
                DetectionResult.Error("Root detection failed")
            } else {
                DetectionResult.Complete(result = result)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Root check failed", e)
            DetectionResult.Error(e.message ?: "Root check failed")
        }
    }

    /**
     * Check for Magisk framework installation.
     */
    suspend fun checkMagisk(): DetectionResult = withContext(Dispatchers.IO) {
        if (!isInitialized.get()) {
            return@withContext DetectionResult.Error("RootKit not initialized")
        }
        try {
            val encrypted = rootKit.isMagiskDetected()
            val result = processDetectionResult(encrypted)
            if (result == Result.ERROR) {
                DetectionResult.Error("Magisk detection failed")
            } else {
                DetectionResult.Complete(result = result)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Magisk check failed", e)
            DetectionResult.Error(e.message ?: "Magisk check failed")
        }
    }

    /**
     * Check for MagiskHide/DenyList stubs.
     */
    suspend fun checkMagiskHide(): DetectionResult = withContext(Dispatchers.IO) {
        if (!isInitialized.get()) {
            return@withContext DetectionResult.Error("RootKit not initialized")
        }
        try {
            val encrypted = rootKit.isMagiskHideDetected()
            val result = processDetectionResult(encrypted)
            if (result == Result.ERROR) {
                DetectionResult.Error("MagiskHide detection failed")
            } else {
                DetectionResult.Complete(result = result)
            }
        } catch (e: Exception) {
            Log.e(TAG, "MagiskHide check failed", e)
            DetectionResult.Error(e.message ?: "MagiskHide check failed")
        }
    }

    /**
     * Check for debugger attachment.
     */
    suspend fun checkDebugger(): DetectionResult = withContext(Dispatchers.IO) {
        if (!isInitialized.get()) {
            return@withContext DetectionResult.Error("RootKit not initialized")
        }
        try {
            val encrypted = rootKit.isDebuggerDetected()
            val result = processDetectionResult(encrypted)
            val details = getDebuggerDetails()
            if (result == Result.ERROR) {
                DetectionResult.Error("Debugger detection failed")
            } else {
                DetectionResult.Complete(result = result, details = details)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Debugger check failed", e)
            DetectionResult.Error(e.message ?: "Debugger check failed")
        }
    }

    /**
     * Check if running on an emulator.
     */
    suspend fun checkEmulator(): DetectionResult = withContext(Dispatchers.IO) {
        if (!isInitialized.get()) {
            return@withContext DetectionResult.Error("RootKit not initialized")
        }
        try {
            val encrypted = rootKit.isEmulatorDevice()
            val result = processDetectionResult(encrypted)
            val details = getEmulatorDetails()
            if (result == Result.ERROR) {
                DetectionResult.Error("Emulator detection failed")
            } else {
                DetectionResult.Complete(result = result, details = details)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Emulator check failed", e)
            DetectionResult.Error(e.message ?: "Emulator check failed")
        }
    }

    /**
     * Check for runtime tampering (combined check).
     */
    suspend fun checkRuntimeTampering(): DetectionResult = withContext(Dispatchers.IO) {
        if (!isInitialized.get()) {
            return@withContext DetectionResult.Error("RootKit not initialized")
        }
        try {
            val encrypted = rootKit.isRuntimeTamperingDetected()
            val result = processDetectionResult(encrypted)
            if (result == Result.ERROR) {
                DetectionResult.Error("Runtime tampering detection failed")
            } else {
                DetectionResult.Complete(result = result)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Runtime tampering check failed", e)
            DetectionResult.Error(e.message ?: "Runtime tampering check failed")
        }
    }

    /**
     * Check for Frida instrumentation framework.
     * Returns detailed sub-check results.
     */
    suspend fun checkFrida(): DetectionResult = withContext(Dispatchers.IO) {
        if (!isInitialized.get()) {
            return@withContext DetectionResult.Error("RootKit not initialized")
        }
        try {
            val encrypted = rootKit.isFridaDetected()
            val result = processDetectionResult(encrypted)
            val details = getFridaDetails()
            if (result == Result.ERROR) {
                DetectionResult.Error("Frida detection failed")
            } else {
                DetectionResult.Complete(result = result, details = details)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Frida check failed", e)
            DetectionResult.Error(e.message ?: "Frida check failed")
        }
    }

    /**
     * Check for Xposed/LSPosed framework.
     */
    suspend fun checkXposed(): DetectionResult = withContext(Dispatchers.IO) {
        if (!isInitialized.get()) {
            return@withContext DetectionResult.Error("RootKit not initialized")
        }
        try {
            val encrypted = rootKit.isXposedDetected()
            val result = processDetectionResult(encrypted)
            val details = getXposedDetails()
            if (result == Result.ERROR) {
                DetectionResult.Error("Xposed detection failed")
            } else {
                DetectionResult.Complete(result = result, details = details)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Xposed check failed", e)
            DetectionResult.Error(e.message ?: "Xposed check failed")
        }
    }

    /**
     * Check for native hooks (PLT/GOT hooks).
     */
    suspend fun checkNativeHook(): DetectionResult = withContext(Dispatchers.IO) {
        if (!isInitialized.get()) {
            return@withContext DetectionResult.Error("RootKit not initialized")
        }
        try {
            val encrypted = rootKit.isNativeHookDetected()
            val result = processDetectionResult(encrypted)
            val details = getNativeHookDetails()
            if (result == Result.ERROR) {
                DetectionResult.Error("Native hook detection failed")
            } else {
                DetectionResult.Complete(result = result, details = details)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Native hook check failed", e)
            DetectionResult.Error(e.message ?: "Native hook check failed")
        }
    }

    /**
     * Check for memory tampering.
     */
    suspend fun checkMemoryTampering(): DetectionResult = withContext(Dispatchers.IO) {
        if (!isInitialized.get()) {
            return@withContext DetectionResult.Error("RootKit not initialized")
        }
        try {
            val encrypted = rootKit.isMemoryTamperingDetected()
            val result = processDetectionResult(encrypted)
            val details = getMemoryTamperingDetails()
            if (result == Result.ERROR) {
                DetectionResult.Error("Memory tampering detection failed")
            } else {
                DetectionResult.Complete(result = result, details = details)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Memory tampering check failed", e)
            DetectionResult.Error(e.message ?: "Memory tampering check failed")
        }
    }

    /**
     * Get Frida detection sub-check details.
     * Returns Map<String, Any?>? because the library may return nullable values.
     */
    private fun getFridaDetails(): Map<String, Any?>? {
        return try {
            val details = rootKit.getRuntimeTamperingDetails()
            details["frida"]
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get Frida details", e)
            null
        }
    }

    /**
     * Get Xposed detection sub-check details.
     */
    private fun getXposedDetails(): Map<String, Any?>? {
        return try {
            val details = rootKit.getRuntimeTamperingDetails()
            details["xposed"]
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get Xposed details", e)
            null
        }
    }

    /**
     * Get native hook detection sub-check details.
     */
    private fun getNativeHookDetails(): Map<String, Any?>? {
        return try {
            val details = rootKit.getRuntimeTamperingDetails()
            details["native_hooks"]
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get native hook details", e)
            null
        }
    }

    /**
     * Get memory tampering detection sub-check details.
     */
    private fun getMemoryTamperingDetails(): Map<String, Any?>? {
        return try {
            val details = rootKit.getRuntimeTamperingDetails()
            details["memory_tampering"]
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get memory tampering details", e)
            null
        }
    }

    /**
     * Get emulator detection sub-check details.
     */
    private fun getEmulatorDetails(): Map<String, Boolean>? {
        return try {
            rootKit.getEmulatorDetails()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get emulator details", e)
            null
        }
    }

    /**
     * Get debugger detection sub-check details.
     */
    private fun getDebuggerDetails(): Map<String, Boolean>? {
        return try {
            rootKit.getDebuggerDetails()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get debugger details", e)
            null
        }
    }

    /**
     * Run a specific root check by type.
     */
    suspend fun runRootCheck(checkType: RootCheckType): DetectionResult {
        return when (checkType) {
            RootCheckType.ROOT_DETECTION -> checkRoot()
            RootCheckType.MAGISK_DETECTION -> checkMagisk()
            RootCheckType.MAGISKHIDE_DETECTION -> checkMagiskHide()
        }
    }

    /**
     * Run a specific runtime check by type.
     */
    suspend fun runRuntimeCheck(checkType: RuntimeCheckType): DetectionResult {
        return when (checkType) {
            RuntimeCheckType.FRIDA -> checkFrida()
            RuntimeCheckType.XPOSED -> checkXposed()
            RuntimeCheckType.NATIVE_HOOK -> checkNativeHook()
            RuntimeCheckType.MEMORY_TAMPERING -> checkMemoryTampering()
        }
    }

    /**
     * Run a specific environment check by type.
     */
    suspend fun runEnvironmentCheck(checkType: EnvironmentCheckType): DetectionResult {
        return when (checkType) {
            EnvironmentCheckType.EMULATOR -> checkEmulator()
            EnvironmentCheckType.DEBUGGER -> checkDebugger()
        }
    }

    /**
     * Run all root detection checks.
     */
    suspend fun runAllRootChecks(): List<DetectionResult> {
        return listOf(
            checkRoot(),
            checkMagisk(),
            checkMagiskHide()
        )
    }

    /**
     * Run all runtime tampering checks.
     */
    suspend fun runAllRuntimeChecks(): List<DetectionResult> {
        return listOf(
            checkFrida(),
            checkXposed(),
            checkNativeHook(),
            checkMemoryTampering()
        )
    }

    /**
     * Run all environment checks.
     */
    suspend fun runAllEnvironmentChecks(): List<DetectionResult> {
        return listOf(
            checkEmulator(),
            checkDebugger()
        )
    }
}
