package com.ssithara.rootdetection.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.ssithara.rootdetection.ui.components.DetectionResultItem
import com.ssithara.rootdetection.ui.components.OutlinedScanButton
import com.ssithara.rootdetection.ui.model.DetectionResult
import com.ssithara.rootdetection.ui.model.EnvironmentCheckType
import com.ssithara.rootdetection.ui.model.EnvironmentDetectionState
import com.ssithara.rootdetection.ui.theme.EnvironmentCategoryBlue
import com.ssithara.rootkit.core.Result

/**
 * Screen displaying environment detection results including Emulator and Debugger detections.
 *
 * @param environmentState The current environment detection state
 * @param onRunAllChecks Callback when "Run All Checks" button is clicked
 * @param onRunIndividualCheck Callback when an individual check's run button is clicked
 * @param onExpandCheck Callback when a check is expanded
 * @param modifier Optional modifier
 */
@Composable
fun EnvironmentDetectionScreen(
    environmentState: EnvironmentDetectionState,
    onRunAllChecks: () -> Unit,
    onRunIndividualCheck: (EnvironmentCheckType) -> Unit,
    onExpandCheck: (EnvironmentCheckType) -> Unit,
    modifier: Modifier = Modifier
) {
    val scrollState = rememberScrollState()

    // Track expanded states for each check
    var expandedEmulator by remember { mutableStateOf(false) }
    var expandedDebugger by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp)
    ) {
        // Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Environment Detection",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        color = EnvironmentCategoryBlue
                    )
                }
                Text(
                    text = "Detect emulator and debugging environments",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            OutlinedScanButton(
                isScanning = environmentState.isScanning,
                onClick = onRunAllChecks,
                text = "Scan All"
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Detection items
        Column(
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Emulator Detection - only show details after scan completes
            val emulatorDetails = (environmentState.emulatorDetection as? DetectionResult.Complete)?.details
            DetectionResultItem(
                name = "Emulator Detection",
                description = "Detects if the app is running on an Android emulator",
                result = environmentState.emulatorDetection,
                details = emulatorDetails,
                isExpanded = expandedEmulator,
                category = "emulator",
                onExpandToggle = {
                    expandedEmulator = !expandedEmulator
                    onExpandCheck(EnvironmentCheckType.EMULATOR)
                },
                onRunClick = { onRunIndividualCheck(EnvironmentCheckType.EMULATOR) }
            )

            // Debugger Detection
            val debuggerDetails = (environmentState.debuggerDetection as? DetectionResult.Complete)?.details
            DetectionResultItem(
                name = "Debugger Detection",
                description = "Detects if a debugger is attached to the app",
                result = environmentState.debuggerDetection,
                details = debuggerDetails,
                isExpanded = expandedDebugger,
                category = "debugger",
                onExpandToggle = {
                    expandedDebugger = !expandedDebugger
                    onExpandCheck(EnvironmentCheckType.DEBUGGER)
                },
                onRunClick = { onRunIndividualCheck(EnvironmentCheckType.DEBUGGER) }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Info card
        EnvironmentDetectionInfoCard()
    }
}

// Default detail structures for preview purposes
internal fun getDefaultEmulatorDetails() = mapOf<String, Any?>(
    "device_model_check" to false,
    "emulator_files_check" to false
)

internal fun getDefaultDebuggerDetails() = mapOf<String, Any?>(
    "adb_enabled_check" to false,
    "frida_detection_check" to false
)

@Composable
private fun EnvironmentDetectionInfoCard() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
    ) {
        Text(
            text = "About Environment Detection",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurface
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Environment detection identifies if your app is running in an unsafe environment. " +
                    "This includes emulators (often used for testing and reverse engineering) " +
                    "and attached debuggers (which can be used to analyze and modify app behavior).",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

// Previews
@Preview(showBackground = true)
@Composable
fun EnvironmentDetectionScreenSecurePreview() {
    MaterialTheme {
        EnvironmentDetectionScreen(
            environmentState = EnvironmentDetectionState(
                isScanning = false,
                emulatorDetection = DetectionResult.Complete(
                    result = Result.NOT_FOUND,
                    details = getDefaultEmulatorDetails()
                ),
                debuggerDetection = DetectionResult.Complete(
                    result = Result.NOT_FOUND,
                    details = getDefaultDebuggerDetails()
                )
            ),
            onRunAllChecks = {},
            onRunIndividualCheck = {},
            onExpandCheck = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun EnvironmentDetectionScreenInsecurePreview() {
    MaterialTheme {
        EnvironmentDetectionScreen(
            environmentState = EnvironmentDetectionState(
                isScanning = false,
                emulatorDetection = DetectionResult.Complete(
                    result = Result.FOUND,
                    details = mapOf<String, Any?>(
                        "device_model_check" to true,
                        "emulator_files_check" to true
                    )
                ),
                debuggerDetection = DetectionResult.Complete(Result.NOT_FOUND)
            ),
            onRunAllChecks = {},
            onRunIndividualCheck = {},
            onExpandCheck = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun EnvironmentDetectionScreenInitialPreview() {
    MaterialTheme {
        EnvironmentDetectionScreen(
            environmentState = EnvironmentDetectionState(),
            onRunAllChecks = {},
            onRunIndividualCheck = {},
            onExpandCheck = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun EnvironmentDetectionScreenScanningPreview() {
    MaterialTheme {
        EnvironmentDetectionScreen(
            environmentState = EnvironmentDetectionState(
                isScanning = true,
                emulatorDetection = DetectionResult.Scanning,
                debuggerDetection = DetectionResult.Idle
            ),
            onRunAllChecks = {},
            onRunIndividualCheck = {},
            onExpandCheck = {}
        )
    }
}
