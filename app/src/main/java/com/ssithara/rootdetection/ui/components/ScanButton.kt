package com.ssithara.rootdetection.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.ssithara.rootdetection.ui.theme.ScanningBlue
import com.ssithara.rootdetection.ui.theme.SecureGreen

/**
 * An animated scan button component that shows loading state during scans.
 * The infinite rotation animation only runs when [isScanning] is true.
 */
@Composable
fun ScanButton(
    isScanning: Boolean,
    onClick: () -> Unit,
    text: String = "Run Full Scan",
    modifier: Modifier = Modifier
) {
    val infiniteTransition = rememberInfiniteTransition(label = "rotation")
    val rotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )

    Button(
        onClick = onClick,
        enabled = !isScanning,
        modifier = modifier,
        colors = ButtonDefaults.buttonColors(
            containerColor = SecureGreen,
            disabledContainerColor = ScanningBlue
        )
    ) {
        Row(
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (isScanning) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = null,
                    modifier = Modifier
                        .size(20.dp)
                        .rotate(rotation)
                )
            } else {
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp)
                )
            }
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = if (isScanning) "Scanning..." else text,
                fontWeight = FontWeight.Medium
            )
        }
    }
}

/**
 * An outlined scan button variant for individual category scans.
 */
@Composable
fun OutlinedScanButton(
    isScanning: Boolean,
    onClick: () -> Unit,
    text: String = "Scan",
    modifier: Modifier = Modifier
) {
    OutlinedButton(
        onClick = onClick,
        enabled = !isScanning,
        modifier = modifier
    ) {
        Row(
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Refresh,
                contentDescription = null,
                modifier = Modifier.size(18.dp)
            )
            Spacer(modifier = Modifier.width(4.dp))
            Text(
                text = if (isScanning) "Scanning..." else text,
                fontWeight = FontWeight.Medium
            )
        }
    }
}

/**
 * A compact icon-only scan button.
 */
@Composable
fun CompactScanButton(
    isScanning: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    OutlinedButton(
        onClick = onClick,
        enabled = !isScanning,
        modifier = modifier
    ) {
        Icon(
            imageVector = Icons.Default.Refresh,
            contentDescription = if (isScanning) "Scanning" else "Run scan",
            modifier = Modifier.size(18.dp)
        )
    }
}

// Previews
@Preview(showBackground = true)
@Composable
fun ScanButtonPreview() {
    MaterialTheme {
        ScanButton(
            isScanning = false,
            onClick = {},
            text = "Run Full Scan"
        )
    }
}

@Preview(showBackground = true)
@Composable
fun ScanButtonScanningPreview() {
    MaterialTheme {
        ScanButton(
            isScanning = true,
            onClick = {},
            text = "Run Full Scan"
        )
    }
}

@Preview(showBackground = true)
@Composable
fun OutlinedScanButtonPreview() {
    MaterialTheme {
        OutlinedScanButton(
            isScanning = false,
            onClick = {},
            text = "Scan Category"
        )
    }
}

@Preview(showBackground = true)
@Composable
fun CompactScanButtonPreview() {
    MaterialTheme {
        CompactScanButton(
            isScanning = false,
            onClick = {}
        )
    }
}
