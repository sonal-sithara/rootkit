package com.ssithara.rootdetection

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBox
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.Home
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.tooling.preview.PreviewScreenSizes
import androidx.compose.ui.unit.dp
import com.ssithara.rootdetection.service.EncryptionService
import com.ssithara.rootdetection.ui.theme.RootDetectionTheme
import com.ssithara.rootkit.RootKit

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        System.loadLibrary("rootkit")
        enableEdgeToEdge()
        setContent {
            RootDetectionTheme {
                RootDetectionApp()
            }
        }
    }
}

@PreviewScreenSizes
@Composable
fun RootDetectionApp() {
    val context = LocalContext.current
    val activity = context as? Activity
    val rootKit by lazy { RootKit(context) }

    var checkSecurity by rememberSaveable {
        mutableStateOf(
            Triple(
                "NOT_FOUND",
                "NOT_FOUND",
                "NOT_FOUND"
            )
        )
    }

    LaunchedEffect(Unit) {
        rootKit.updateActivity(activity)
        checkSecurity = checkSecurity(rootKit = rootKit)
    }

    var currentDestination by rememberSaveable { mutableStateOf(AppDestinations.HOME) }

    NavigationSuiteScaffold(
        navigationSuiteItems = {
            AppDestinations.entries.forEach {
                item(
                    icon = {
                        Icon(
                            it.icon,
                            contentDescription = it.label
                        )
                    },
                    label = { Text(it.label) },
                    selected = it == currentDestination,
                    onClick = { currentDestination = it }
                )
            }
        }
    ) {
        Scaffold(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 20.dp, vertical = 30.dp)
        ) { innerPadding ->
            Column {
                Text(
                    text = "Emulator Detection: ${checkSecurity.first}",
                    modifier = Modifier.padding(innerPadding)
                )
                Text(
                    text = "Debugger Detection: ${checkSecurity.second}",
                    modifier = Modifier.padding(innerPadding)
                )
                Text(
                    text = "Root Detection: ${checkSecurity.third}",
                    modifier = Modifier.padding(innerPadding)
                )
            }
        }
    }
}

fun checkSecurity(rootKit: RootKit): Triple<String, String, String> {
    val base64Emulator = rootKit.isEmulatorDevice()
    val base64Debugger = rootKit.isDebuggerDetected()
    val base64Rooted = rootKit.isRootedDevice()

    val isEmulator = EncryptionService.decryptWithBase64Key(base64Emulator)
    val isDebugger = EncryptionService.decryptWithBase64Key(base64Debugger)
    val isRooted = EncryptionService.decryptWithBase64Key(base64Rooted)

    return Triple(isEmulator, isDebugger, isRooted)
}

enum class AppDestinations(
    val label: String,
    val icon: ImageVector,
) {
    HOME("Home", Icons.Default.Home),
    FAVORITES("Favorites", Icons.Default.Favorite),
    PROFILE("Profile", Icons.Default.AccountBox),
}
