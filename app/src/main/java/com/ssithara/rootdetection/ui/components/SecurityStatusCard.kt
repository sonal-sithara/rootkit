package com.ssithara.rootdetection.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.ssithara.rootdetection.ui.model.SecurityStatus
import com.ssithara.rootdetection.ui.theme.InsecureRed
import com.ssithara.rootdetection.ui.theme.SecureGreen
import com.ssithara.rootdetection.ui.theme.WarningOrange
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * A large card displaying the overall security status with a scan button.
 *
 * @param status The current security status
 * @param lastScanTime The timestamp of the last scan (null if never scanned)
 * @param totalChecks The total number of checks available
 * @param completedChecks The number of checks that have been completed
 * @param threatCount The number of threats detected
 * @param isScanning Whether a scan is currently in progress
 * @param onScanClick Callback when the scan button is clicked
 * @param modifier Optional modifier
 */
@Composable
fun SecurityStatusCard(
    status: SecurityStatus,
    lastScanTime: Long?,
    totalChecks: Int,
    completedChecks: Int,
    threatCount: Int,
    isScanning: Boolean,
    onScanClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Status indicator
            SecurityStatusIndicator(
                status = status,
                size = 100.dp,
                animated = true
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Status text
            val statusText = when (status) {
                SecurityStatus.SECURE -> "Device Secure"
                SecurityStatus.WARNING -> "Potential Threats"
                SecurityStatus.INSECURE -> "Threats Detected"
                SecurityStatus.SCANNING -> "Scanning..."
            }

            val statusColor = when (status) {
                SecurityStatus.SECURE -> SecureGreen
                SecurityStatus.WARNING -> WarningOrange
                SecurityStatus.INSECURE -> InsecureRed
                SecurityStatus.SCANNING -> MaterialTheme.colorScheme.primary
            }

            Text(
                text = statusText,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = statusColor
            )

            Spacer(modifier = Modifier.height(8.dp))

            // Summary text
            if (status != SecurityStatus.SCANNING) {
                Text(
                    text = getSummaryText(completedChecks, totalChecks, threatCount),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Last scan time
            lastScanTime?.let { timestamp ->
                Text(
                    text = "Last scanned: ${formatTimestamp(timestamp)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Scan button
            ScanButton(
                isScanning = isScanning,
                onClick = onScanClick,
                text = if (completedChecks == 0) "Run Full Scan" else "Scan Again"
            )
        }
    }
}

@Composable
private fun getSummaryText(completed: Int, total: Int, threats: Int): String {
    return when {
        completed == 0 -> "No scans performed yet"
        threats == 0 -> "All $completed checks passed • No threats detected"
        threats == 1 -> "$threats threat found in $completed checks"
        else -> "$threats threats found in $completed checks"
    }
}

private fun formatTimestamp(timestamp: Long): String {
    val now = System.currentTimeMillis()
    val diff = now - timestamp

    return when {
        diff < 60_000 -> "Just now"
        diff < 3600_000 -> "${diff / 60_000} min ago"
        diff < 86400_000 -> "${diff / 3600_000} hours ago"
        else -> {
            val sdf = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault())
            sdf.format(Date(timestamp))
        }
    }
}

// Previews
@Preview(showBackground = true)
@Composable
fun SecurityStatusCardSecurePreview() {
    MaterialTheme {
        SecurityStatusCard(
            status = SecurityStatus.SECURE,
            lastScanTime = System.currentTimeMillis() - 300000,
            totalChecks = 10,
            completedChecks = 10,
            threatCount = 0,
            isScanning = false,
            onScanClick = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun SecurityStatusCardWarningPreview() {
    MaterialTheme {
        SecurityStatusCard(
            status = SecurityStatus.WARNING,
            lastScanTime = System.currentTimeMillis() - 300000,
            totalChecks = 10,
            completedChecks = 10,
            threatCount = 1,
            isScanning = false,
            onScanClick = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun SecurityStatusCardScanningPreview() {
    MaterialTheme {
        SecurityStatusCard(
            status = SecurityStatus.SCANNING,
            lastScanTime = null,
            totalChecks = 10,
            completedChecks = 0,
            threatCount = 0,
            isScanning = true,
            onScanClick = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun SecurityStatusCardInitialPreview() {
    MaterialTheme {
        SecurityStatusCard(
            status = SecurityStatus.SECURE,
            lastScanTime = null,
            totalChecks = 10,
            completedChecks = 0,
            threatCount = 0,
            isScanning = false,
            onScanClick = {}
        )
    }
}
