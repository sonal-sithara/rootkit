package com.ssithara.rootdetection.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.ssithara.rootdetection.ui.model.DetectionCategory
import com.ssithara.rootdetection.ui.model.DetectionResult
import com.ssithara.rootdetection.ui.model.SecurityStatus
import com.ssithara.rootdetection.ui.theme.EnvironmentCategoryBlue
import com.ssithara.rootdetection.ui.theme.InsecureRed
import com.ssithara.rootdetection.ui.theme.RootCategoryRed
import com.ssithara.rootdetection.ui.theme.RuntimeCategoryOrange
import com.ssithara.rootdetection.ui.theme.SecureGreen
import com.ssithara.rootdetection.ui.theme.WarningOrange
import com.ssithara.rootkit.core.Result

/**
 * A card displaying a detection category summary with status and item count.
 *
 * @param title The title of the category
 * @param icon The icon representing the category
 * @param category The detection category type
 * @param completedChecks Number of checks that have been completed
 * @param totalChecks Total number of checks in this category
 * @param threatCount Number of threats found in this category
 * @param isScanning Whether this category is currently being scanned
 * @param onClick Callback when the card is clicked
 * @param modifier Optional modifier
 */
@Composable
fun DetectionCategoryCard(
    title: String,
    icon: ImageVector,
    category: DetectionCategory,
    completedChecks: Int,
    totalChecks: Int,
    threatCount: Int,
    isScanning: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val accentColor = when (category) {
        DetectionCategory.ROOT -> RootCategoryRed
        DetectionCategory.RUNTIME -> RuntimeCategoryOrange
        DetectionCategory.ENVIRONMENT -> EnvironmentCategoryBlue
    }

    val statusColor = when {
        isScanning -> MaterialTheme.colorScheme.primary
        completedChecks == 0 -> MaterialTheme.colorScheme.onSurfaceVariant
        threatCount > 0 -> InsecureRed
        else -> SecureGreen
    }

    val statusText = when {
        isScanning -> "Scanning..."
        completedChecks == 0 -> "Not scanned"
        threatCount == 0 -> "Secure"
        else -> "$threatCount threat${if (threatCount > 1) "s" else ""}"
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Category icon
            Icon(
                imageVector = icon,
                contentDescription = title,
                tint = accentColor,
                modifier = Modifier.size(32.dp)
            )

            Spacer(modifier = Modifier.width(16.dp))

            // Content column
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Medium
                    )

                    // Status indicator
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        if (completedChecks > 0 && !isScanning) {
                            StatusIndicator(
                                result = if (threatCount > 0) {
                                    DetectionResult.Complete(Result.FOUND)
                                } else {
                                    DetectionResult.Complete(Result.NOT_FOUND)
                                },
                                size = 20.dp
                            )
                        }
                        Text(
                            text = statusText,
                            style = MaterialTheme.typography.bodyMedium,
                            color = statusColor,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }

                // Progress info
                Text(
                    text = "$completedChecks/$totalChecks checks completed",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                // Progress bar
                if (isScanning || completedChecks > 0) {
                    LinearProgressIndicator(
                        progress = { completedChecks.toFloat() / totalChecks },
                        modifier = Modifier.fillMaxWidth(),
                        color = if (threatCount > 0) InsecureRed else accentColor,
                        trackColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                }
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Navigation arrow
            Icon(
                imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = "View details",
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * Get the icon for a detection category.
 */
fun getCategoryIcon(category: DetectionCategory): ImageVector {
    return when (category) {
        DetectionCategory.ROOT -> Icons.Default.Warning
        DetectionCategory.RUNTIME -> Icons.Default.BugReport
        DetectionCategory.ENVIRONMENT -> Icons.Default.Devices
    }
}

/**
 * Get the title for a detection category.
 */
fun getCategoryTitle(category: DetectionCategory): String {
    return when (category) {
        DetectionCategory.ROOT -> "Root Detection"
        DetectionCategory.RUNTIME -> "Runtime Tampering"
        DetectionCategory.ENVIRONMENT -> "Environment"
    }
}

// Previews
@Preview(showBackground = true)
@Composable
fun DetectionCategoryCardSecurePreview() {
    MaterialTheme {
        DetectionCategoryCard(
            title = "Root Detection",
            icon = Icons.Default.Warning,
            category = DetectionCategory.ROOT,
            completedChecks = 3,
            totalChecks = 3,
            threatCount = 0,
            isScanning = false,
            onClick = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun DetectionCategoryCardThreatPreview() {
    MaterialTheme {
        DetectionCategoryCard(
            title = "Runtime Tampering",
            icon = Icons.Default.BugReport,
            category = DetectionCategory.RUNTIME,
            completedChecks = 4,
            totalChecks = 4,
            threatCount = 2,
            isScanning = false,
            onClick = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun DetectionCategoryCardScanningPreview() {
    MaterialTheme {
        DetectionCategoryCard(
            title = "Environment",
            icon = Icons.Default.Devices,
            category = DetectionCategory.ENVIRONMENT,
            completedChecks = 1,
            totalChecks = 3,
            threatCount = 0,
            isScanning = true,
            onClick = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun DetectionCategoryCardNotScannedPreview() {
    MaterialTheme {
        DetectionCategoryCard(
            title = "Root Detection",
            icon = Icons.Default.Warning,
            category = DetectionCategory.ROOT,
            completedChecks = 0,
            totalChecks = 3,
            threatCount = 0,
            isScanning = false,
            onClick = {}
        )
    }
}
