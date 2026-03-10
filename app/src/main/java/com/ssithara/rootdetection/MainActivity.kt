package com.ssithara.rootdetection

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ssithara.rootdetection.ui.navigation.RootDetectionNavigation
import com.ssithara.rootdetection.ui.theme.RootDetectionTheme
import com.ssithara.rootdetection.ui.viewmodel.SecurityViewModel

/**
 * Main Activity for the Root Detection demo app.
 * Sets up the Compose UI with navigation and ViewModel.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Load the native library
        System.loadLibrary("rootkit")

        enableEdgeToEdge()

        setContent {
            RootDetectionTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    RootDetectionApp()
                }
            }
        }
    }
}

/**
 * Main composable for the Root Detection app.
 * Sets up the ViewModel and navigation.
 */
@Composable
fun RootDetectionApp() {
    val context = LocalContext.current
    val activity = context as? Activity

    // Get the ViewModel
    val viewModel: SecurityViewModel = viewModel()

    // Collect the UI state as Compose state
    val securityState by viewModel.uiState.collectAsStateWithLifecycle()

    // Update activity context for overlay detection
    LaunchedEffect(activity) {
        activity?.let {
            // Activity context is needed for overlay detection
            // This is handled internally by the repository when needed
        }
    }

    // Set up navigation with the security state
    RootDetectionNavigation(
        securityState = securityState,
        onRunFullScan = { viewModel.runFullScan() },
        onRunRootCheck = { checkType -> viewModel.runRootCheck(checkType) },
        onRunRuntimeCheck = { checkType -> viewModel.runRuntimeCheck(checkType) },
        onRunEnvironmentCheck = { checkType -> viewModel.runEnvironmentCheck(checkType) }
    )
}
