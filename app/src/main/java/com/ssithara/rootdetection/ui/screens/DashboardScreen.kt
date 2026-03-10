package com.ssithara.rootdetection.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.ssithara.rootdetection.ui.components.DetectionCategoryCard
import com.ssithara.rootdetection.ui.components.SecurityStatusCard
import com.ssithara.rootdetection.ui.components.getCategoryIcon
import com.ssithara.rootdetection.ui.components.getCategoryTitle
import com.ssithara.rootdetection.ui.model.DetectionCategory
import com.ssithara.rootdetection.ui.model.DetectionResult
import com.ssithara.rootdetection.ui.model.EnvironmentDetectionState
import com.ssithara.rootdetection.ui.model.RootDetectionState
import com.ssithara.rootdetection.ui.model.RuntimeDetectionState
import com.ssithara.rootdetection.ui.model.SecurityState
import com.ssithara.rootdetection.ui.model.SecurityStatus
import com.ssithara.rootkit.core.Result

@Composable
fun DashboardScreen(
    securityState: SecurityState,
    onRunFullScan: () -> Unit,
    onNavigateToCategory: (DetectionCategory) -> Unit,
    modifier: Modifier = Modifier
) {
    val scrollState = rememberScrollState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SecurityStatusCard(
            status = securityState.calculateOverallStatus(),
            lastScanTime = securityState.lastScanTimestamp,
            totalChecks = securityState.getTotalChecksCount(),
            completedChecks = securityState.getTotalCompletedCount(),
            threatCount = securityState.getTotalThreatCount(),
            isScanning = securityState.isScanning,
            onScanClick = onRunFullScan
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Detection Categories",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onSurface
        )

        DetectionCategoryCard(
            title = getCategoryTitle(DetectionCategory.ROOT),
            icon = getCategoryIcon(DetectionCategory.ROOT),
            category = DetectionCategory.ROOT,
            completedChecks = securityState.rootState.getCompletedCount(),
            totalChecks = securityState.rootState.totalChecks,
            threatCount = securityState.rootState.getThreatCount(),
            isScanning = securityState.rootState.isScanning,
            onClick = { onNavigateToCategory(DetectionCategory.ROOT) }
        )

        DetectionCategoryCard(
            title = getCategoryTitle(DetectionCategory.RUNTIME),
            icon = getCategoryIcon(DetectionCategory.RUNTIME),
            category = DetectionCategory.RUNTIME,
            completedChecks = securityState.runtimeState.getCompletedCount(),
            totalChecks = securityState.runtimeState.totalChecks,
            threatCount = securityState.runtimeState.getThreatCount(),
            isScanning = securityState.runtimeState.isScanning,
            onClick = { onNavigateToCategory(DetectionCategory.RUNTIME) }
        )

        DetectionCategoryCard(
            title = getCategoryTitle(DetectionCategory.ENVIRONMENT),
            icon = getCategoryIcon(DetectionCategory.ENVIRONMENT),
            category = DetectionCategory.ENVIRONMENT,
            completedChecks = securityState.environmentState.getCompletedCount(),
            totalChecks = securityState.environmentState.totalChecks,
            threatCount = securityState.environmentState.getThreatCount(),
            isScanning = securityState.environmentState.isScanning,
            onClick = { onNavigateToCategory(DetectionCategory.ENVIRONMENT) }
        )

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Preview(showBackground = true)
@Composable
fun DashboardScreenSecurePreview() {
    MaterialTheme {
        DashboardScreen(
            securityState = SecurityState(
                overallStatus = SecurityStatus.SECURE,
                isScanning = false,
                lastScanTimestamp = System.currentTimeMillis() - 300000,
                rootState = RootDetectionState(
                    rootDetection = DetectionResult.Complete(Result.NOT_FOUND),
                    magiskDetection = DetectionResult.Complete(Result.NOT_FOUND),
                    magiskHideDetection = DetectionResult.Complete(Result.NOT_FOUND)
                ),
                runtimeState = RuntimeDetectionState(
                    fridaDetection = DetectionResult.Complete(Result.NOT_FOUND),
                    xposedDetection = DetectionResult.Complete(Result.NOT_FOUND),
                    nativeHookDetection = DetectionResult.Complete(Result.NOT_FOUND),
                    memoryTamperingDetection = DetectionResult.Complete(Result.NOT_FOUND)
                ),
                environmentState = EnvironmentDetectionState(
                    emulatorDetection = DetectionResult.Complete(Result.NOT_FOUND),
                    debuggerDetection = DetectionResult.Complete(Result.NOT_FOUND),
                    overlayDetection = DetectionResult.Complete(Result.NOT_FOUND)
                )
            ),
            onRunFullScan = {},
            onNavigateToCategory = {}
        )
    }
}

@Preview(showBackground = true)
@Composable
fun DashboardScreenInitialPreview() {
    MaterialTheme {
        DashboardScreen(
            securityState = SecurityState(),
            onRunFullScan = {},
            onNavigateToCategory = {}
        )
    }
}
