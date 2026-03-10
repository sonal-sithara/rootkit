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
import androidx.compose.material.icons.filled.BugReport
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
import com.ssithara.rootdetection.ui.model.RuntimeCheckType
import com.ssithara.rootdetection.ui.model.RuntimeDetectionState
import com.ssithara.rootdetection.ui.theme.RuntimeCategoryOrange
import com.ssithara.rootkit.core.Result

/**
 * Screen displaying runtime tampering detection results including Frida, Xposed,
 * native hooks, and memory tampering detections.
 *
 * @param runtimeState The current runtime detection state
 * @param onRunAllChecks Callback when "Run All Checks" button is clicked
 * @param onRunIndividualCheck Callback when an individual check's run button is clicked
 * @param onExpandCheck Callback when a check is expanded/collapsed
 * @param modifier Optional modifier
 */
@Composable
fun RuntimeDetectionScreen(
    runtimeState: RuntimeDetectionState,
    onRunAllChecks: () -> Unit,
    onRunIndividualCheck: (RuntimeCheckType) -> Unit,
    onExpandCheck: (RuntimeCheckType) -> Unit,
    modifier: Modifier = Modifier
) {
    val scrollState = rememberScrollState()

    // Track expanded states for each check
    var expandedFrida by remember { mutableStateOf(false) }
    var expandedXposed by remember { mutableStateOf(false) }
    var expandedNativeHook by remember { mutableStateOf(false) }
    var expandedMemory by remember { mutableStateOf(false) }

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
                        text = "Runtime Tampering",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        color = RuntimeCategoryOrange
                    )
                }
                Text(
                    text = "Detect runtime modifications and hooks",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            OutlinedScanButton(
                isScanning = runtimeState.isScanning,
                onClick = onRunAllChecks,
                text = "Scan All"
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Detection items
        Column(
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Frida Detection
            val fridaDetails = (runtimeState.fridaDetection as? DetectionResult.Complete)?.details
            DetectionResultItem(
                name = "Frida Detection",
                description = "Detects Frida instrumentation framework",
                result = runtimeState.fridaDetection,
                details = fridaDetails ?: getDefaultFridaDetails(),
                category = "frida",
                isExpanded = expandedFrida,
                onExpandToggle = {
                    expandedFrida = !expandedFrida
                    onExpandCheck(RuntimeCheckType.FRIDA)
                }
            )

            // Xposed Detection
            val xposedDetails = (runtimeState.xposedDetection as? DetectionResult.Complete)?.details
            DetectionResultItem(
                name = "Xposed Detection",
                description = "Detects Xposed/LSPosed framework",
                result = runtimeState.xposedDetection,
                details = xposedDetails ?: getDefaultXposedDetails(),
                category = "xposed",
                isExpanded = expandedXposed,
                onExpandToggle = {
                    expandedXposed = !expandedXposed
                    onExpandCheck(RuntimeCheckType.XPOSED)
                }
            )

            // Native Hook Detection
            val hookDetails = (runtimeState.nativeHookDetection as? DetectionResult.Complete)?.details
            DetectionResultItem(
                name = "Native Hook Detection",
                description = "Detects PLT/GOT hooks and inline hooks",
                result = runtimeState.nativeHookDetection,
                details = hookDetails ?: getDefaultNativeHookDetails(),
                category = "native_hook",
                isExpanded = expandedNativeHook,
                onExpandToggle = {
                    expandedNativeHook = !expandedNativeHook
                    onExpandCheck(RuntimeCheckType.NATIVE_HOOK)
                }
            )

            // Memory Tampering Detection
            val memoryDetails = (runtimeState.memoryTamperingDetection as? DetectionResult.Complete)?.details
            DetectionResultItem(
                name = "Memory Tampering",
                description = "Detects memory modifications and code injection",
                result = runtimeState.memoryTamperingDetection,
                details = memoryDetails ?: getDefaultMemoryDetails(),
                category = "memory_tampering",
                isExpanded = expandedMemory,
                onExpandToggle = {
                    expandedMemory = !expandedMemory
                    onExpandCheck(RuntimeCheckType.MEMORY_TAMPERING)
                }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Info card
        RuntimeDetectionInfoCard()
    }
}

// Default detail structures for preview purposes
private fun getDefaultFridaDetails() = mapOf(
    "port_detection" to false,
    "memory_maps_detection" to false,
    "thread_detection" to false,
    "library_detection" to false,
    "file_descriptor_detection" to false,
    "env_var_detection" to false
)

private fun getDefaultXposedDetails() = mapOf(
    "stack_trace_detection" to false,
    "package_detection" to false,
    "loaded_classes_detection" to false,
    "memory_maps_detection" to false,
    "library_detection" to false,
    "zygote_detection" to false,
    "riru_detection" to false,
    "zygisk_detection" to false,
    "hook_memory_detection" to false
)

private fun getDefaultNativeHookDetails() = mapOf(
    "inline_hook_detection" to false,
    "got_hook_detection" to false,
    "plt_hook_detection" to false,
    "hook_framework_detection" to false,
    "modified_function_pointer_detection" to false
)

private fun getDefaultMemoryDetails() = mapOf(
    "suspicious_regions_detection" to false,
    "anonymous_exec_memory_detection" to false,
    "code_integrity_detection" to false,
    "unusual_permissions_detection" to false,
    "code_caves_detection" to false,
    "modified_base_address_detection" to false
)

@Composable
private fun RuntimeDetectionInfoCard() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
    ) {
        Text(
            text = "About Runtime Detection",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurface
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Runtime tampering detection identifies tools and techniques used to modify app behavior at runtime. " +
                    "This includes instrumentation frameworks like Frida and Xposed, native code hooks, and memory modifications. " +
                    "These techniques can be used to bypass security controls, extract sensitive data, or manipulate app logic.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

// Previews
@Preview(showBackground = true)
@Composable
fun RuntimeDetectionScreenSecurePreview() {
    MaterialTheme {
        RuntimeDetectionScreen(
            runtimeState = RuntimeDetectionState(
                isScanning = false,
                fridaDetection = DetectionResult.Complete(
                    result = Result.NOT_FOUND,
                    details = getDefaultFridaDetails()
                ),
                xposedDetection = DetectionResult.Complete(
                    result = Result.NOT_FOUND,
                    details = getDefaultXposedDetails()
                ),
                nativeHookDetection = DetectionResult.Complete(
                    result = Result.NOT_FOUND,
                    details = getDefaultNativeHookDetails()
                ),
                memoryTamperingDetection = DetectionResult.Complete(
                    result = Result.NOT_FOUND,
                    details = getDefaultMemoryDetails()
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
fun RuntimeDetectionScreenInsecurePreview() {
    MaterialTheme {
        RuntimeDetectionScreen(
            runtimeState = RuntimeDetectionState(
                isScanning = false,
                fridaDetection = DetectionResult.Complete(
                    result = Result.FOUND,
                    details = mapOf(
                        "port_detection" to true,
                        "memory_maps_detection" to true,
                        "library_detection" to false,
                        "thread_detection" to false
                    )
                ),
                xposedDetection = DetectionResult.Complete(Result.NOT_FOUND),
                nativeHookDetection = DetectionResult.Complete(Result.NOT_FOUND),
                memoryTamperingDetection = DetectionResult.Complete(Result.NOT_FOUND)
            ),
            onRunAllChecks = {},
            onRunIndividualCheck = {},
            onExpandCheck = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun RuntimeDetectionScreenInitialPreview() {
    MaterialTheme {
        RuntimeDetectionScreen(
            runtimeState = RuntimeDetectionState(),
            onRunAllChecks = {},
            onRunIndividualCheck = {},
            onExpandCheck = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun RuntimeDetectionScreenScanningPreview() {
    MaterialTheme {
        RuntimeDetectionScreen(
            runtimeState = RuntimeDetectionState(
                isScanning = true,
                fridaDetection = DetectionResult.Scanning,
                xposedDetection = DetectionResult.Idle,
                nativeHookDetection = DetectionResult.Idle,
                memoryTamperingDetection = DetectionResult.Idle
            ),
            onRunAllChecks = {},
            onRunIndividualCheck = {},
            onExpandCheck = {}
        )
    }
}
