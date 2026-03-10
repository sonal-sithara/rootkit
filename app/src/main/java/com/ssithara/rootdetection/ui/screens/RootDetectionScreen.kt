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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.ssithara.rootdetection.ui.components.DetectionResultItem
import com.ssithara.rootdetection.ui.components.OutlinedScanButton
import com.ssithara.rootdetection.ui.model.DetectionResult
import com.ssithara.rootdetection.ui.model.RootDetectionState
import com.ssithara.rootdetection.ui.model.RootCheckType
import com.ssithara.rootdetection.ui.theme.RootCategoryRed
import com.ssithara.rootkit.core.Result

@Composable
fun RootDetectionScreen(
    rootState: RootDetectionState,
    onRunAllChecks: () -> Unit,
    onRunIndividualCheck: (RootCheckType) -> Unit,
    modifier: Modifier = Modifier
) {
    val scrollState = rememberScrollState()

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
                        text = "Root Detection",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        color = RootCategoryRed
                    )
                }
                Text(
                    text = "Detect root access and modifications",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            OutlinedScanButton(
                isScanning = rootState.isScanning,
                onClick = onRunAllChecks,
                text = "Scan All"
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Detection items
        Column(
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Root Detection
            DetectionResultItem(
                name = "Root Detection",
                description = "Checks for root binaries, SU commands, and root management apps",
                result = rootState.rootDetection,
                details = null,
                isExpanded = false
            )

            // Magisk Detection
            DetectionResultItem(
                name = "Magisk Detection",
                description = "Detects Magisk framework installation and files",
                result = rootState.magiskDetection,
                details = null,
                isExpanded = false
            )

            // MagiskHide Detection
            DetectionResultItem(
                name = "MagiskHide Detection",
                description = "Detects MagiskHide/DenyList stubs and configuration",
                result = rootState.magiskHideDetection,
                details = null,
                isExpanded = false
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Info card
        RootDetectionInfoCard()
    }
}

@Composable
private fun RootDetectionInfoCard() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
    ) {
        Text(
            text = "About Root Detection",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurface
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Root detection identifies if your device has been modified to grant administrative (root) access. " +
                    "Root access can be used by malicious apps to bypass security measures, " +
                    "access sensitive data, " +
                    "or modify system behavior.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

// Previews
@Preview(showBackground = true)
@Composable
fun RootDetectionScreenSecurePreview() {
    MaterialTheme {
        RootDetectionScreen(
            rootState = RootDetectionState(
                isScanning = false,
                rootDetection = DetectionResult.Complete(Result.NOT_FOUND),
                magiskDetection = DetectionResult.Complete(Result.NOT_FOUND),
                magiskHideDetection = DetectionResult.Complete(Result.NOT_FOUND)
            ),
            onRunAllChecks = {},
            onRunIndividualCheck = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun RootDetectionScreenInsecurePreview() {
    MaterialTheme {
        RootDetectionScreen(
            rootState = RootDetectionState(
                isScanning = false,
                rootDetection = DetectionResult.Complete(Result.FOUND),
                magiskDetection = DetectionResult.Complete(Result.FOUND),
                magiskHideDetection = DetectionResult.Complete(Result.NOT_FOUND)
            ),
            onRunAllChecks = {},
            onRunIndividualCheck = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun RootDetectionScreenScanningPreview() {
    MaterialTheme {
        RootDetectionScreen(
            rootState = RootDetectionState(
                isScanning = true,
                rootDetection = DetectionResult.Scanning,
                magiskDetection = DetectionResult.Idle,
                magiskHideDetection = DetectionResult.Idle
            ),
            onRunAllChecks = {},
            onRunIndividualCheck = {}
        )
    }
}
