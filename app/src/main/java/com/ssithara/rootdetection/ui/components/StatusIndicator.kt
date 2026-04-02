package com.ssithara.rootdetection.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.ssithara.rootdetection.ui.model.DetectionResult
import com.ssithara.rootdetection.ui.model.SecurityStatus
import com.ssithara.rootdetection.ui.theme.InsecureRed
import com.ssithara.rootdetection.ui.theme.ScanningBlue
import com.ssithara.rootdetection.ui.theme.SecureGreen
import com.ssithara.rootdetection.ui.theme.WarningOrange
import com.ssithara.rootkit.core.Result

/**
 * A circular status indicator component that displays different states
 * based on the detection result.
 *
 * @param result The detection result to display (FOUND, NOT_FOUND, or scanning state)
 * @param size The size of the indicator
 * @param animated Whether to animate the indicator
 * @param modifier Optional modifier
 */
@Composable
fun StatusIndicator(
    result: DetectionResult,
    size: Dp = 24.dp,
    animated: Boolean = true,
    modifier: Modifier = Modifier
) {
    when (result) {
        is DetectionResult.Idle -> {
            IdleIndicator(size = size, modifier = modifier)
        }
        is DetectionResult.Scanning -> {
            ScanningIndicator(
                size = size,
                animated = animated,
                modifier = modifier
            )
        }
        is DetectionResult.Complete -> {
            ResultIndicator(
                result = result.result,
                size = size,
                animated = animated,
                modifier = modifier
            )
        }
        is DetectionResult.Error -> {
            ErrorIndicator(size = size, modifier = modifier)
        }
    }
}

/**
 * Status indicator for overall security status.
 */
@Composable
fun SecurityStatusIndicator(
    status: SecurityStatus,
    size: Dp = 80.dp,
    animated: Boolean = true,
    modifier: Modifier = Modifier
) {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")

    val scale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "scale"
    )

    val (backgroundColor, icon) = when (status) {
        SecurityStatus.SECURE -> SecureGreen to Icons.Default.Check
        SecurityStatus.WARNING -> WarningOrange to Icons.Default.Warning
        SecurityStatus.INSECURE -> InsecureRed to Icons.Default.Close
        SecurityStatus.SCANNING -> ScanningBlue to null
    }

    val animatedScale = if (animated && status == SecurityStatus.SCANNING) {
        scale
    } else 1f

    Box(
        modifier = modifier
            .size(size)
            .scale(animatedScale)
            .clip(CircleShape)
            .background(backgroundColor),
        contentAlignment = Alignment.Center
    ) {
        if (status == SecurityStatus.SCANNING) {
            CircularProgressIndicator(
                modifier = Modifier.size(size * 0.6f),
                color = Color.White,
                strokeWidth = 3.dp
            )
        } else {
            icon?.let {
                Icon(
                    imageVector = it,
                    contentDescription = status.name,
                    tint = Color.White,
                    modifier = Modifier.size(size * 0.5f)
                )
            }
        }
    }
}

@Composable
private fun IdleIndicator(
    size: Dp,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(MaterialTheme.colorScheme.surfaceVariant)
    )
}

@Composable
private fun ScanningIndicator(
    size: Dp,
    animated: Boolean,
    modifier: Modifier = Modifier
) {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val progress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "progress"
    )

    Box(
        modifier = modifier.size(size),
        contentAlignment = Alignment.Center
    ) {
        if (animated) {
            CircularProgressIndicator(
                progress = { progress },
                modifier = Modifier.size(size),
                color = ScanningBlue,
                strokeWidth = size * 0.1f
            )
        } else {
            CircularProgressIndicator(
                modifier = Modifier.size(size),
                color = ScanningBlue,
                strokeWidth = size * 0.1f
            )
        }
    }
}

@Composable
private fun ResultIndicator(
    result: Result,
    size: Dp,
    animated: Boolean,
    modifier: Modifier = Modifier
) {
    val (backgroundColor, icon) = when (result) {
        Result.FOUND -> InsecureRed to Icons.Default.Close
        Result.NOT_FOUND -> SecureGreen to Icons.Default.Check
        Result.ERROR -> WarningOrange to Icons.Default.Warning
    }

    // Only pulse for FOUND results when animated
    val animatedScale = if (animated && result == Result.FOUND) {
        val infiniteTransition = rememberInfiniteTransition(label = "scale")
        val scale by infiniteTransition.animateFloat(
            initialValue = 1f,
            targetValue = 1.05f,
            animationSpec = infiniteRepeatable(
                animation = tween(500, easing = LinearEasing),
                repeatMode = RepeatMode.Reverse
            ),
            label = "scale"
        )
        scale
    } else {
        1f
    }

    Box(
        modifier = modifier
            .size(size)
            .scale(animatedScale)
            .clip(CircleShape)
            .background(backgroundColor),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            imageVector = icon,
            contentDescription = result.name,
            tint = Color.White,
            modifier = Modifier.size(size * 0.6f)
        )
    }
}

@Composable
private fun ErrorIndicator(
    size: Dp,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(MaterialTheme.colorScheme.error),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            imageVector = Icons.Default.Warning,
            contentDescription = "Error",
            tint = Color.White,
            modifier = Modifier.size(size * 0.6f)
        )
    }
}
