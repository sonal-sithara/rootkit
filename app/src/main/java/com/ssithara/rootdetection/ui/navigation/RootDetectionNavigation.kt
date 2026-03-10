package com.ssithara.rootdetection.ui.navigation

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.ssithara.rootdetection.ui.model.DetectionCategory
import com.ssithara.rootdetection.ui.model.EnvironmentCheckType
import com.ssithara.rootdetection.ui.model.RootCheckType
import com.ssithara.rootdetection.ui.model.RuntimeCheckType
import com.ssithara.rootdetection.ui.model.SecurityState
import com.ssithara.rootdetection.ui.screens.DashboardScreen
import com.ssithara.rootdetection.ui.screens.EnvironmentDetectionScreen
import com.ssithara.rootdetection.ui.screens.RootDetectionScreen
import com.ssithara.rootdetection.ui.screens.RuntimeDetectionScreen
import com.ssithara.rootdetection.ui.theme.EnvironmentCategoryBlue
import com.ssithara.rootdetection.ui.theme.RootCategoryRed
import com.ssithara.rootdetection.ui.theme.RuntimeCategoryOrange

/**
 * Main navigation host for the Root Detection app.
 * 
 * Uses a simple string-based route tracking approach to avoid nullable Screen issues.
 * The current route is tracked as a String state, not as a Screen object.
 *
 * @param securityState The current security state from ViewModel
 * @param onRunFullScan Callback when full scan is requested
 * @param onRunRootCheck Callback when individual root check is requested
 * @param onRunRuntimeCheck Callback when individual runtime check is requested
 * @param onRunEnvironmentCheck Callback when individual environment check is requested
 * @param onExpandEnvironmentCheck Callback when environment check is expanded
 * @param modifier Optional modifier
 */
@Composable
fun RootDetectionNavigation(
    securityState: SecurityState,
    onRunFullScan: () -> Unit,
    onRunRootCheck: (RootCheckType) -> Unit,
    onRunRuntimeCheck: (RuntimeCheckType) -> Unit,
    onRunEnvironmentCheck: (EnvironmentCheckType) -> Unit,
    onExpandEnvironmentCheck: (EnvironmentCheckType) -> Unit,
    modifier: Modifier = Modifier,
    navController: NavHostController = rememberNavController()
) {
    // Track current route as a simple String - never null, defaults to dashboard
    var currentRoute by remember { mutableStateOf(ROUTE_DASHBOARD) }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        bottomBar = {
            RootDetectionBottomBar(
                currentRoute = currentRoute,
                onNavigate = { route ->
                    currentRoute = route
                    navController.navigate(route) {
                        popUpTo(ROUTE_DASHBOARD) {
                            saveState = true
                        }
                        launchSingleTop = true
                        restoreState = true
                    }
                }
            )
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = ROUTE_DASHBOARD,
            modifier = Modifier.padding(innerPadding)
        ) {
            // Dashboard screen
            composable(ROUTE_DASHBOARD) {
                DashboardScreen(
                    securityState = securityState,
                    onRunFullScan = onRunFullScan,
                    onNavigateToCategory = { category ->
                        val route = when (category) {
                            DetectionCategory.ROOT -> ROUTE_ROOT
                            DetectionCategory.RUNTIME -> ROUTE_RUNTIME
                            DetectionCategory.ENVIRONMENT -> ROUTE_ENVIRONMENT
                        }
                        currentRoute = route
                        navController.navigate(route) {
                            popUpTo(ROUTE_DASHBOARD) {
                                saveState = true
                            }
                            launchSingleTop = true
                            restoreState = true
                        }
                    }
                )
            }

            // Root detection screen
            composable(ROUTE_ROOT) {
                RootDetectionScreen(
                    rootState = securityState.rootState,
                    onRunAllChecks = onRunFullScan,
                    onRunIndividualCheck = onRunRootCheck
                )
            }

            // Runtime detection screen
            composable(ROUTE_RUNTIME) {
                RuntimeDetectionScreen(
                    runtimeState = securityState.runtimeState,
                    onRunAllChecks = onRunFullScan,
                    onRunIndividualCheck = onRunRuntimeCheck,
                    onExpandCheck = { /* Handle expand */ }
                )
            }

            // Environment detection screen
            composable(ROUTE_ENVIRONMENT) {
                EnvironmentDetectionScreen(
                    environmentState = securityState.environmentState,
                    onRunAllChecks = onRunFullScan,
                    onRunIndividualCheck = onRunEnvironmentCheck,
                    onExpandCheck = onExpandEnvironmentCheck
                )
            }
        }
    }
}

/**
 * Bottom navigation bar for the Root Detection app.
 * Uses string comparison for route matching - no nullable Screen references.
 */
@Composable
private fun RootDetectionBottomBar(
    currentRoute: String,
    onNavigate: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    NavigationBar(
        modifier = modifier,
        containerColor = MaterialTheme.colorScheme.surface,
        contentColor = MaterialTheme.colorScheme.onSurface
    ) {
        allScreens.forEach { screen ->
            // Capture route as local string to avoid any lambda capture issues
            val screenRoute = screen.route
            val screenIcon = screen.icon
            val screenLabel = screen.label

            val selected = currentRoute == screenRoute
            val iconColor = when {
                selected && screenRoute == ROUTE_ROOT -> RootCategoryRed
                selected && screenRoute == ROUTE_RUNTIME -> RuntimeCategoryOrange
                selected && screenRoute == ROUTE_ENVIRONMENT -> EnvironmentCategoryBlue
                selected -> MaterialTheme.colorScheme.primary
                else -> MaterialTheme.colorScheme.onSurfaceVariant
            }

            NavigationBarItem(
                selected = selected,
                onClick = { onNavigate(screenRoute) },
                icon = {
                    Icon(
                        imageVector = screenIcon,
                        contentDescription = screenLabel,
                        tint = iconColor
                    )
                },
                label = {
                    Text(
                        text = screenLabel,
                        fontWeight = if (selected) FontWeight.Medium else FontWeight.Normal,
                        color = iconColor
                    )
                },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = iconColor,
                    selectedTextColor = iconColor,
                    indicatorColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        }
    }
}
