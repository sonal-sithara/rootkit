package com.ssithara.rootdetection.ui.model

/**
 * Sealed class representing the result state of a detection check.
 * Used to model the different states a detection can be in.
 */
sealed class DetectionResult {
    
    /**
     * Initial state - detection has not been run yet
     */
    data object Idle : DetectionResult()
    
    /**
     * Detection is currently in progress
     */
    data object Scanning : DetectionResult()
    
    /**
     * Detection has completed with a result
     * 
     * @property result The result from the rootkit library (FOUND or NOT_FOUND)
     * @property timestamp When the detection was completed
     * @property details Optional map of sub-check names to their boolean results
     *                   (e.g., for Frida: "frida-server process" -> true if detected)
     */
    data class Complete(
        val result: com.ssithara.rootkit.core.Result,
        val timestamp: Long = System.currentTimeMillis(),
        val details: Map<String, Boolean>? = null
    ) : DetectionResult()
    
    /**
     * Detection failed with an error
     * 
     * @property message Error message describing what went wrong
     */
    data class Error(
        val message: String
    ) : DetectionResult()
}
