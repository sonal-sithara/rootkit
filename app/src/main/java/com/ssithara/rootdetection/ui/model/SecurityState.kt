package com.ssithara.rootdetection.ui.model

import com.ssithara.rootkit.core.Result

/**
 * Enum representing the overall security status of the device.
 */
enum class SecurityStatus {
    SECURE,      // All detections passed - Green
    WARNING,     // Some detections found - Orange
    INSECURE,    // Critical detections found - Red
    SCANNING     // Scan in progress - Blue/Pulsing
}

/**
 * Root detection state containing all root-related detection results.
 */
data class RootDetectionState(
    val isScanning: Boolean = false,
    val rootDetection: DetectionResult = DetectionResult.Idle,
    val magiskDetection: DetectionResult = DetectionResult.Idle,
    val magiskHideDetection: DetectionResult = DetectionResult.Idle
) {
    /**
     * Calculate the number of checks that have been completed
     */
    fun getCompletedCount(): Int {
        var count = 0
        if (rootDetection is DetectionResult.Complete) count++
        if (magiskDetection is DetectionResult.Complete) count++
        if (magiskHideDetection is DetectionResult.Complete) count++
        return count
    }
    
    /**
     * Calculate the number of checks that found threats
     */
    fun getThreatCount(): Int {
        var count = 0
        if (rootDetection is DetectionResult.Complete && rootDetection.result == Result.FOUND) count++
        if (magiskDetection is DetectionResult.Complete && magiskDetection.result == Result.FOUND) count++
        if (magiskHideDetection is DetectionResult.Complete && magiskHideDetection.result == Result.FOUND) count++
        return count
    }
    
    /**
     * Total number of checks in this category
     */
    val totalChecks: Int = 3
}

/**
 * Runtime detection state containing all runtime tampering detection results.
 */
data class RuntimeDetectionState(
    val isScanning: Boolean = false,
    val fridaDetection: DetectionResult = DetectionResult.Idle,
    val xposedDetection: DetectionResult = DetectionResult.Idle,
    val nativeHookDetection: DetectionResult = DetectionResult.Idle,
    val memoryTamperingDetection: DetectionResult = DetectionResult.Idle,
    val expandedCheck: RuntimeCheckType? = null
) {
    /**
     * Calculate the number of checks that have been completed
     */
    fun getCompletedCount(): Int {
        var count = 0
        if (fridaDetection is DetectionResult.Complete) count++
        if (xposedDetection is DetectionResult.Complete) count++
        if (nativeHookDetection is DetectionResult.Complete) count++
        if (memoryTamperingDetection is DetectionResult.Complete) count++
        return count
    }
    
    /**
     * Calculate the number of checks that found threats
     */
    fun getThreatCount(): Int {
        var count = 0
        if (fridaDetection is DetectionResult.Complete && fridaDetection.result == Result.FOUND) count++
        if (xposedDetection is DetectionResult.Complete && xposedDetection.result == Result.FOUND) count++
        if (nativeHookDetection is DetectionResult.Complete && nativeHookDetection.result == Result.FOUND) count++
        if (memoryTamperingDetection is DetectionResult.Complete && memoryTamperingDetection.result == Result.FOUND) count++
        return count
    }
    
    /**
     * Total number of checks in this category
     */
    val totalChecks: Int = 4
}

/**
 * Environment detection state containing all environment-related detection results.
 */
data class EnvironmentDetectionState(
    val isScanning: Boolean = false,
    val emulatorDetection: DetectionResult = DetectionResult.Idle,
    val debuggerDetection: DetectionResult = DetectionResult.Idle,
    val overlayDetection: DetectionResult = DetectionResult.Idle
) {
    /**
     * Calculate the number of checks that have been completed
     */
    fun getCompletedCount(): Int {
        var count = 0
        if (emulatorDetection is DetectionResult.Complete) count++
        if (debuggerDetection is DetectionResult.Complete) count++
        if (overlayDetection is DetectionResult.Complete) count++
        return count
    }
    
    /**
     * Calculate the number of checks that found threats
     */
    fun getThreatCount(): Int {
        var count = 0
        if (emulatorDetection is DetectionResult.Complete && emulatorDetection.result == Result.FOUND) count++
        if (debuggerDetection is DetectionResult.Complete && debuggerDetection.result == Result.FOUND) count++
        if (overlayDetection is DetectionResult.Complete && overlayDetection.result == Result.FOUND) count++
        return count
    }
    
    /**
     * Total number of checks in this category
     */
    val totalChecks: Int = 3
}

/**
 * Enum representing the different runtime check types.
 * Used for identifying which check to run or expand.
 */
enum class RuntimeCheckType {
    FRIDA,
    XPOSED,
    NATIVE_HOOK,
    MEMORY_TAMPERING
}

/**
 * Enum representing the different root check types.
 */
enum class RootCheckType {
    ROOT_DETECTION,
    MAGISK_DETECTION,
    MAGISKHIDE_DETECTION
}

/**
 * Enum representing the different environment check types.
 */
enum class EnvironmentCheckType {
    EMULATOR,
    DEBUGGER,
    OVERLAY
}

/**
 * Main security state container holding all detection states.
 * This is the root state used by the ViewModel and consumed by the UI.
 */
data class SecurityState(
    val overallStatus: SecurityStatus = SecurityStatus.SECURE,
    val isScanning: Boolean = false,
    val lastScanTimestamp: Long? = null,
    val rootState: RootDetectionState = RootDetectionState(),
    val runtimeState: RuntimeDetectionState = RuntimeDetectionState(),
    val environmentState: EnvironmentDetectionState = EnvironmentDetectionState()
) {
    /**
     * Calculate the overall security status based on detection results.
     */
    fun calculateOverallStatus(): SecurityStatus {
        if (isScanning || rootState.isScanning || runtimeState.isScanning || environmentState.isScanning) {
            return SecurityStatus.SCANNING
        }
        
        val totalThreats = rootState.getThreatCount() + 
                           runtimeState.getThreatCount() + 
                           environmentState.getThreatCount()
        
        return when {
            totalThreats == 0 -> SecurityStatus.SECURE
            totalThreats < 3 -> SecurityStatus.WARNING
            else -> SecurityStatus.INSECURE
        }
    }
    
    /**
     * Get the total number of completed checks across all categories
     */
    fun getTotalCompletedCount(): Int {
        return rootState.getCompletedCount() + 
               runtimeState.getCompletedCount() + 
               environmentState.getCompletedCount()
    }
    
    /**
     * Get the total number of checks across all categories
     */
    fun getTotalChecksCount(): Int {
        return rootState.totalChecks + 
               runtimeState.totalChecks + 
               environmentState.totalChecks
    }
    
    /**
     * Get the total number of threats found across all categories
     */
    fun getTotalThreatCount(): Int {
        return rootState.getThreatCount() + 
               runtimeState.getThreatCount() + 
               environmentState.getThreatCount()
    }
}
