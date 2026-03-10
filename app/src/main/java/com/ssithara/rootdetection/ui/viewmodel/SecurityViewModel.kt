package com.ssithara.rootdetection.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.ssithara.rootdetection.data.SecurityRepository
import com.ssithara.rootdetection.ui.model.DetectionResult
import com.ssithara.rootdetection.ui.model.EnvironmentCheckType
import com.ssithara.rootdetection.ui.model.EnvironmentDetectionState
import com.ssithara.rootdetection.ui.model.RootCheckType
import com.ssithara.rootdetection.ui.model.RootDetectionState
import com.ssithara.rootdetection.ui.model.RuntimeCheckType
import com.ssithara.rootdetection.ui.model.RuntimeDetectionState
import com.ssithara.rootdetection.ui.model.SecurityState
import com.ssithara.rootdetection.ui.model.SecurityStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * ViewModel responsible for managing security detection UI state.
 * Handles running detection checks and updating the UI state accordingly.
 */
class SecurityViewModel(application: Application) : AndroidViewModel(application) {

    private val repository: SecurityRepository = SecurityRepository(application)

    private val _uiState = MutableStateFlow(SecurityState())
    val uiState: StateFlow<SecurityState> = _uiState.asStateFlow()

    init {
        // Initialize the RootKit library
        repository.initialize()
    }

    /**
     * Run a full security scan covering all detection categories.
     */
    fun runFullScan() {
        viewModelScope.launch {
            _uiState.update { currentState ->
                currentState.copy(
                    isScanning = true,
                    overallStatus = SecurityStatus.SCANNING
                )
            }

            // Run all categories in parallel
            runRootDetections()
            runRuntimeDetections()
            runEnvironmentDetections()

            // Calculate final status
            _uiState.update { currentState ->
                currentState.copy(
                    isScanning = false,
                    overallStatus = currentState.calculateOverallStatus(),
                    lastScanTimestamp = System.currentTimeMillis()
                )
            }
        }
    }

    /**
     * Run all root detection checks.
     */
    fun runRootDetections() {
        viewModelScope.launch {
            _uiState.update { currentState ->
                currentState.copy(
                    rootState = currentState.rootState.copy(isScanning = true)
                )
            }

            val rootResult = repository.checkRoot()

            _uiState.update { currentState ->
                currentState.copy(
                    rootState = currentState.rootState.copy(
                        isScanning = false,
                        rootDetection = rootResult,
                        magiskDetection = rootResult, // Combined in isRootedDevice
                        magiskHideDetection = rootResult // Combined in isRootedDevice
                    )
                )
            }

            updateOverallStatus()
        }
    }

    /**
     * Run all runtime tampering detection checks.
     */
    fun runRuntimeDetections() {
        viewModelScope.launch {
            _uiState.update { currentState ->
                currentState.copy(
                    runtimeState = currentState.runtimeState.copy(isScanning = true)
                )
            }

            // Run all runtime checks
            val fridaResult = repository.checkFrida()
            val xposedResult = repository.checkXposed()
            val nativeHookResult = repository.checkNativeHook()
            val memoryTamperingResult = repository.checkMemoryTampering()

            _uiState.update { currentState ->
                currentState.copy(
                    runtimeState = currentState.runtimeState.copy(
                        isScanning = false,
                        fridaDetection = fridaResult,
                        xposedDetection = xposedResult,
                        nativeHookDetection = nativeHookResult,
                        memoryTamperingDetection = memoryTamperingResult
                    )
                )
            }

            updateOverallStatus()
        }
    }

    /**
     * Run all environment detection checks.
     */
    fun runEnvironmentDetections() {
        viewModelScope.launch {
            _uiState.update { currentState ->
                currentState.copy(
                    environmentState = currentState.environmentState.copy(isScanning = true)
                )
            }

            // Run all environment checks
            val emulatorResult = repository.checkEmulator()
            val debuggerResult = repository.checkDebugger()
            // Overlay detection requires Activity context, handled separately

            _uiState.update { currentState ->
                currentState.copy(
                    environmentState = currentState.environmentState.copy(
                        isScanning = false,
                        emulatorDetection = emulatorResult,
                        debuggerDetection = debuggerResult
                    )
                )
            }

            updateOverallStatus()
        }
    }

    /**
     * Run a specific root check.
     */
    fun runRootCheck(checkType: RootCheckType) {
        viewModelScope.launch {
            // Set scanning state for the specific check
            _uiState.update { currentState ->
                val updatedRootState = when (checkType) {
                    RootCheckType.ROOT_DETECTION -> currentState.rootState.copy(
                        rootDetection = DetectionResult.Scanning
                    )
                    RootCheckType.MAGISK_DETECTION -> currentState.rootState.copy(
                        magiskDetection = DetectionResult.Scanning
                    )
                    RootCheckType.MAGISKHIDE_DETECTION -> currentState.rootState.copy(
                        magiskHideDetection = DetectionResult.Scanning
                    )
                }
                currentState.copy(rootState = updatedRootState)
            }

            // Run the check
            val result = repository.runRootCheck(checkType)

            // Update with result
            _uiState.update { currentState ->
                val updatedRootState = when (checkType) {
                    RootCheckType.ROOT_DETECTION -> currentState.rootState.copy(
                        rootDetection = result
                    )
                    RootCheckType.MAGISK_DETECTION -> currentState.rootState.copy(
                        magiskDetection = result
                    )
                    RootCheckType.MAGISKHIDE_DETECTION -> currentState.rootState.copy(
                        magiskHideDetection = result
                    )
                }
                currentState.copy(rootState = updatedRootState)
            }

            updateOverallStatus()
        }
    }

    /**
     * Run a specific runtime check.
     */
    fun runRuntimeCheck(checkType: RuntimeCheckType) {
        viewModelScope.launch {
            // Set scanning state for the specific check
            _uiState.update { currentState ->
                val updatedRuntimeState = when (checkType) {
                    RuntimeCheckType.FRIDA -> currentState.runtimeState.copy(
                        fridaDetection = DetectionResult.Scanning
                    )
                    RuntimeCheckType.XPOSED -> currentState.runtimeState.copy(
                        xposedDetection = DetectionResult.Scanning
                    )
                    RuntimeCheckType.NATIVE_HOOK -> currentState.runtimeState.copy(
                        nativeHookDetection = DetectionResult.Scanning
                    )
                    RuntimeCheckType.MEMORY_TAMPERING -> currentState.runtimeState.copy(
                        memoryTamperingDetection = DetectionResult.Scanning
                    )
                }
                currentState.copy(runtimeState = updatedRuntimeState)
            }

            // Run the check
            val result = repository.runRuntimeCheck(checkType)

            // Update with result
            _uiState.update { currentState ->
                val updatedRuntimeState = when (checkType) {
                    RuntimeCheckType.FRIDA -> currentState.runtimeState.copy(
                        fridaDetection = result
                    )
                    RuntimeCheckType.XPOSED -> currentState.runtimeState.copy(
                        xposedDetection = result
                    )
                    RuntimeCheckType.NATIVE_HOOK -> currentState.runtimeState.copy(
                        nativeHookDetection = result
                    )
                    RuntimeCheckType.MEMORY_TAMPERING -> currentState.runtimeState.copy(
                        memoryTamperingDetection = result
                    )
                }
                currentState.copy(runtimeState = updatedRuntimeState)
            }

            updateOverallStatus()
        }
    }

    /**
     * Run a specific environment check.
     */
    fun runEnvironmentCheck(checkType: EnvironmentCheckType) {
        viewModelScope.launch {
            // Set scanning state for the specific check
            _uiState.update { currentState ->
                val updatedEnvState = when (checkType) {
                    EnvironmentCheckType.EMULATOR -> currentState.environmentState.copy(
                        emulatorDetection = DetectionResult.Scanning
                    )
                    EnvironmentCheckType.DEBUGGER -> currentState.environmentState.copy(
                        debuggerDetection = DetectionResult.Scanning
                    )
                    EnvironmentCheckType.OVERLAY -> currentState.environmentState.copy(
                        overlayDetection = DetectionResult.Scanning
                    )
                }
                currentState.copy(environmentState = updatedEnvState)
            }

            // Run the check
            val result = repository.runEnvironmentCheck(checkType)

            // Update with result
            _uiState.update { currentState ->
                val updatedEnvState = when (checkType) {
                    EnvironmentCheckType.EMULATOR -> currentState.environmentState.copy(
                        emulatorDetection = result
                    )
                    EnvironmentCheckType.DEBUGGER -> currentState.environmentState.copy(
                        debuggerDetection = result
                    )
                    EnvironmentCheckType.OVERLAY -> currentState.environmentState.copy(
                        overlayDetection = result
                    )
                }
                currentState.copy(environmentState = updatedEnvState)
            }

            updateOverallStatus()
        }
    }

    /**
     * Toggle expansion of a runtime check to show/hide details.
     */
    fun toggleRuntimeCheckExpansion(checkType: RuntimeCheckType) {
        _uiState.update { currentState ->
            currentState.copy(
                runtimeState = currentState.runtimeState.copy(
                    expandedCheck = if (currentState.runtimeState.expandedCheck == checkType) {
                        null
                    } else {
                        checkType
                    }
                )
            )
        }
    }

    /**
     * Reset all detection results to idle state.
     */
    fun resetAllDetections() {
        _uiState.value = SecurityState()
    }

    /**
     * Update the overall status based on current detection results.
     */
    private fun updateOverallStatus() {
        _uiState.update { currentState ->
            currentState.copy(
                overallStatus = currentState.calculateOverallStatus(),
                lastScanTimestamp = System.currentTimeMillis()
            )
        }
    }
}
