package com.ssithara.rootdetection.data

import android.app.Activity
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

/**
 * Repository layer that bridges the RootKit library with the UI.
 * Handles encryption/decryption of detection results and maps them to UI models.
 */
class SecurityRepository(private val context: Context) {

    private val rootKit: RootKit = RootKit(context)
    
    companion object {
        private const val TAG = "SecurityRepository"
    }

    /**
     * Initialize the RootKit library. Must be called before any detection methods.
     */
    fun initialize() {
        try {
            rootKit.initialize()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize RootKit", e)
        }
    }

    /**
     * Update the activity reference for overlay detection.
     * Required for overlay detection to work properly.
     */
    fun updateActivity(activity: Activity?) {
        rootKit.updateActivity(activity)
    }

    /**
     * Set secure flags for overlay detection.
     */
    fun setSecureFlags() {
        rootKit.setSecureFlags()
    }

    /**
     * Initialize overlay detection.
     */
    fun detectOverlay() {
        rootKit.detectOverlay()
    }

    /**
     * Process an encrypted detection result and convert to Result enum.
     */
    private fun processDetectionResult(encryptedResult: String): Result {
        return try {
            val decrypted = EncryptionService.decryptWithBase64Key(encryptedResult)
            when (decrypted) {
                Result.FOUND.name -> Result.FOUND
                Result.NOT_FOUND.name -> Result.NOT_FOUND
                else -> {
                    Log.e(TAG, "Unknown result: $decrypted")
                    Result.NOT_FOUND
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt result", e)
            Result.NOT_FOUND
        }
    }

    /**
     * Check for root access (combined check for root, magisk, magiskhide).
     */
    suspend fun checkRoot(): DetectionResult.Complete = withContext(Dispatchers.IO) {
        try {
            val encrypted = rootKit.isRootedDevice()
            val result = processDetectionResult(encrypted)
            DetectionResult.Complete(result = result)
        } catch (e: Exception) {
            Log.e(TAG, "Root check failed", e)
            DetectionResult.Complete(result = Result.NOT_FOUND)
        }
    }

    /**
     * Check for debugger attachment.
     */
    suspend fun checkDebugger(): DetectionResult.Complete = withContext(Dispatchers.IO) {
        try {
            val encrypted = rootKit.isDebuggerDetected()
            val result = processDetectionResult(encrypted)
            DetectionResult.Complete(result = result)
        } catch (e: Exception) {
            Log.e(TAG, "Debugger check failed", e)
            DetectionResult.Complete(result = Result.NOT_FOUND)
        }
    }

    /**
     * Check if running on an emulator.
     */
    suspend fun checkEmulator(): DetectionResult.Complete = withContext(Dispatchers.IO) {
        try {
            val encrypted = rootKit.isEmulatorDevice()
            val result = processDetectionResult(encrypted)
            DetectionResult.Complete(result = result)
        } catch (e: Exception) {
            Log.e(TAG, "Emulator check failed", e)
            DetectionResult.Complete(result = Result.NOT_FOUND)
        }
    }

    /**
     * Check for runtime tampering (combined check).
     */
    suspend fun checkRuntimeTampering(): DetectionResult.Complete = withContext(Dispatchers.IO) {
        try {
            val encrypted = rootKit.isRuntimeTamperingDetected()
            val result = processDetectionResult(encrypted)
            DetectionResult.Complete(result = result)
        } catch (e: Exception) {
            Log.e(TAG, "Runtime tampering check failed", e)
            DetectionResult.Complete(result = Result.NOT_FOUND)
        }
    }

    /**
     * Check for Frida instrumentation framework.
     * Returns detailed sub-check results.
     */
    suspend fun checkFrida(): DetectionResult.Complete = withContext(Dispatchers.IO) {
        try {
            val encrypted = rootKit.isFridaDetected()
            val result = processDetectionResult(encrypted)
            
            // Get detailed sub-checks from runtime tampering details
            val details = getFridaDetails()
            
            DetectionResult.Complete(result = result, details = details)
        } catch (e: Exception) {
            Log.e(TAG, "Frida check failed", e)
            DetectionResult.Complete(result = Result.NOT_FOUND)
        }
    }

    /**
     * Check for Xposed/LSPosed framework.
     */
    suspend fun checkXposed(): DetectionResult.Complete = withContext(Dispatchers.IO) {
        try {
            val encrypted = rootKit.isXposedDetected()
            val result = processDetectionResult(encrypted)
            
            // Get detailed sub-checks from runtime tampering details
            val details = getXposedDetails()
            
            DetectionResult.Complete(result = result, details = details)
        } catch (e: Exception) {
            Log.e(TAG, "Xposed check failed", e)
            DetectionResult.Complete(result = Result.NOT_FOUND)
        }
    }

    /**
     * Check for native hooks (PLT/GOT hooks).
     */
    suspend fun checkNativeHook(): DetectionResult.Complete = withContext(Dispatchers.IO) {
        try {
            val encrypted = rootKit.isNativeHookDetected()
            val result = processDetectionResult(encrypted)
            
            // Get detailed sub-checks from runtime tampering details
            val details = getNativeHookDetails()
            
            DetectionResult.Complete(result = result, details = details)
        } catch (e: Exception) {
            Log.e(TAG, "Native hook check failed", e)
            DetectionResult.Complete(result = Result.NOT_FOUND)
        }
    }

    /**
     * Check for memory tampering.
     */
    suspend fun checkMemoryTampering(): DetectionResult.Complete = withContext(Dispatchers.IO) {
        try {
            val encrypted = rootKit.isMemoryTamperingDetected()
            val result = processDetectionResult(encrypted)
            
            // Get detailed sub-checks from runtime tampering details
            val details = getMemoryTamperingDetails()
            
            DetectionResult.Complete(result = result, details = details)
        } catch (e: Exception) {
            Log.e(TAG, "Memory tampering check failed", e)
            DetectionResult.Complete(result = Result.NOT_FOUND)
        }
    }

    /**
     * Get Frida detection sub-check details.
     */
    private fun getFridaDetails(): Map<String, Boolean>? {
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
    private fun getXposedDetails(): Map<String, Boolean>? {
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
    private fun getNativeHookDetails(): Map<String, Boolean>? {
        return try {
            val details = rootKit.getRuntimeTamperingDetails()
            details["nativeHook"]
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get native hook details", e)
            null
        }
    }

    /**
     * Get memory tampering detection sub-check details.
     */
    private fun getMemoryTamperingDetails(): Map<String, Boolean>? {
        return try {
            val details = rootKit.getRuntimeTamperingDetails()
            details["memoryTampering"]
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get memory tampering details", e)
            null
        }
    }

    /**
     * Run a specific root check by type.
     */
    suspend fun runRootCheck(checkType: RootCheckType): DetectionResult.Complete {
        // Note: The RootKit library combines all root checks into isRootedDevice()
        // For individual checks, we still use the combined method but could be extended
        return when (checkType) {
            RootCheckType.ROOT_DETECTION -> checkRoot()
            RootCheckType.MAGISK_DETECTION -> checkRoot() // Combined in isRootedDevice
            RootCheckType.MAGISKHIDE_DETECTION -> checkRoot() // Combined in isRootedDevice
        }
    }

    /**
     * Run a specific runtime check by type.
     */
    suspend fun runRuntimeCheck(checkType: RuntimeCheckType): DetectionResult.Complete {
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
    suspend fun runEnvironmentCheck(checkType: EnvironmentCheckType): DetectionResult.Complete {
        return when (checkType) {
            EnvironmentCheckType.EMULATOR -> checkEmulator()
            EnvironmentCheckType.DEBUGGER -> checkDebugger()
            EnvironmentCheckType.OVERLAY -> {
                // Overlay detection requires Activity context and is callback-based
                // Return a simple result for now
                DetectionResult.Complete(result = Result.NOT_FOUND)
            }
        }
    }

    /**
     * Run all root detection checks.
     */
    suspend fun runAllRootChecks(): List<DetectionResult.Complete> {
        return listOf(
            checkRoot()
        )
    }

    /**
     * Run all runtime tampering checks.
     */
    suspend fun runAllRuntimeChecks(): List<DetectionResult.Complete> {
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
    suspend fun runAllEnvironmentChecks(): List<DetectionResult.Complete> {
        return listOf(
            checkEmulator(),
            checkDebugger()
            // Overlay detection is handled separately due to Activity requirement
        )
    }
}
