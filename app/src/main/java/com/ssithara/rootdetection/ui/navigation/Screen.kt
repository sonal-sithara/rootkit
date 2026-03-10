package com.ssithara.rootdetection.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Devices
import androidx.compose.ui.graphics.vector.ImageVector

/**
 * Sealed class representing navigation destinations in the app.
 * Each destination has a route, icon, and label for the navigation bar.
 * 
 * IMPORTANT: Route strings are defined as constants to ensure string comparison
 * works reliably without any nullable Screen references.
 */
sealed class Screen(
    val route: String,
    val icon: ImageVector,
    val label: String
) {
    /**
     * Dashboard screen showing overall security status and category summaries.
     */
    data object Dashboard : Screen(
        route = ROUTE_DASHBOARD,
        icon = Icons.Default.Security,
        label = "Security"
    )

    /**
     * Root detection screen showing root, Magisk, and MagiskHide detection results.
     */
    data object Root : Screen(
        route = ROUTE_ROOT,
        icon = Icons.Default.Warning,
        label = "Root"
    )

    /**
     * Runtime detection screen showing Frida, Xposed, native hooks, and memory tampering results.
     */
    data object Runtime : Screen(
        route = ROUTE_RUNTIME,
        icon = Icons.Default.BugReport,
        label = "Runtime"
    )

    /**
     * Environment detection screen showing emulator, debugger, and overlay detection results.
     */
    data object Environment : Screen(
        route = ROUTE_ENVIRONMENT,
        icon = Icons.Default.Devices,
        label = "Environment"
    )
}

/**
 * Route string constants - use these for string comparisons to avoid nullable Screen issues.
 */
const val ROUTE_DASHBOARD = "dashboard"
const val ROUTE_ROOT = "root"
const val ROUTE_RUNTIME = "runtime"
const val ROUTE_ENVIRONMENT = "environment"

/**
 * List of all screens for navigation bar items.
 */
val allScreens = listOf(
    Screen.Dashboard,
    Screen.Root,
    Screen.Runtime,
    Screen.Environment
)
