package com.ssithara.rootdetection.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.ssithara.rootdetection.ui.model.DetectionResult
import com.ssithara.rootdetection.ui.theme.InsecureRed
import com.ssithara.rootdetection.ui.theme.SecureGreen
import com.ssithara.rootkit.core.Result

/**
 * An individual detection result row with expand/collapse functionality.
 *
 * @param name The name of the detection
 * @param description A brief description of what this detection checks
 * @param result The current detection result state
 * @param details Optional map of sub-check names to their results
 * @param isExpanded Whether the item is currently expanded
 * @param onExpandToggle Callback when the expand/collapse is toggled
 * @param onRunClick Optional callback for running an individual check
 * @param modifier Optional modifier
 */
@Composable
fun DetectionResultItem(
    name: String,
    description: String,
    result: DetectionResult,
    details: Map<String, Boolean>? = null,
    isExpanded: Boolean = false,
    onExpandToggle: () -> Unit = {},
    onRunClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Column(
            modifier = Modifier.fillMaxWidth()
        ) {
            // Main row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(enabled = details != null) { onExpandToggle() }
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Status indicator
                StatusIndicator(
                    result = result,
                    size = 28.dp,
                    animated = true
                )

                Spacer(modifier = Modifier.width(12.dp))

                // Content
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    Text(
                        text = name,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Medium
                    )
                    Text(
                        text = description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                // Expand button (if has details)
                if (details != null && result is DetectionResult.Complete) {
                    IconButton(onClick = onExpandToggle) {
                        Icon(
                            imageVector = if (isExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                            contentDescription = if (isExpanded) "Collapse" else "Expand"
                        )
                    }
                }
            }

            // Expanded details
            AnimatedVisibility(
                visible = isExpanded && details != null && result is DetectionResult.Complete,
                enter = expandVertically(),
                exit = shrinkVertically()
            ) {
                details?.let { detailMap ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 16.dp, end = 16.dp, bottom = 16.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant)
                            .padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = "Sub-checks:",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        
                        detailMap.forEach { (checkName, isDetected) ->
                            DetailCheckRow(
                                name = checkName,
                                isDetected = isDetected
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailCheckRow(
    name: String,
    isDetected: Boolean,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        val (icon, color) = if (isDetected) {
            Icons.Default.Close to InsecureRed
        } else {
            Icons.Default.Check to SecureGreen
        }

        Icon(
            imageVector = icon,
            contentDescription = if (isDetected) "Detected" else "Not detected",
            tint = color,
            modifier = Modifier.size(18.dp)
        )

        Spacer(modifier = Modifier.width(8.dp))

        Text(
            text = name,
            style = MaterialTheme.typography.bodySmall,
            color = if (isDetected) InsecureRed else MaterialTheme.colorScheme.onSurface
        )

        Spacer(modifier = Modifier.weight(1f))

        Text(
            text = if (isDetected) "Found" else "Clear",
            style = MaterialTheme.typography.labelSmall,
            color = color,
            fontWeight = FontWeight.Medium
        )
    }
}

// Previews
@Preview(showBackground = true)
@Composable
fun DetectionResultItemSecurePreview() {
    MaterialTheme {
        DetectionResultItem(
            name = "Root Detection",
            description = "Checks for root access indicators",
            result = DetectionResult.Complete(Result.NOT_FOUND),
            details = mapOf(
                "su binary" to false,
                "busybox" to false,
                "root management apps" to false
            ),
            isExpanded = false
        )
    }
}

@Preview(showBackground = true)
@Composable
fun DetectionResultItemInsecurePreview() {
    MaterialTheme {
        DetectionResultItem(
            name = "Frida Detection",
            description = "Detects Frida instrumentation framework",
            result = DetectionResult.Complete(Result.FOUND),
            details = mapOf(
                "frida-server" to true,
                "frida ports" to false,
                "frida libraries" to true
            ),
            isExpanded = true
        )
    }
}

@Preview(showBackground = true)
@Composable
fun DetectionResultItemScanningPreview() {
    MaterialTheme {
        DetectionResultItem(
            name = "Xposed Detection",
            description = "Detects Xposed/LSPosed framework",
            result = DetectionResult.Scanning
        )
    }
}

@Preview(showBackground = true)
@Composable
fun DetectionResultItemIdlePreview() {
    MaterialTheme {
        DetectionResultItem(
            name = "Emulator Detection",
            description = "Checks if running on an emulator",
            result = DetectionResult.Idle
        )
    }
}

@Preview(showBackground = true)
@Composable
fun DetectionResultItemErrorPreview() {
    MaterialTheme {
        DetectionResultItem(
            name = "Memory Tampering",
            description = "Detects memory modifications",
            result = DetectionResult.Error("Failed to access memory regions")
        )
    }
}
