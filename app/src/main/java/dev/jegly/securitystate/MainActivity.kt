package dev.jegly.securitystate

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import dev.jegly.securitystate.ui.AppRoot
import dev.jegly.securitystate.ui.DeviceViewModel
import dev.jegly.securitystate.ui.InspectorTheme
import dev.jegly.securitystate.ui.InspectorViewModel

class MainActivity : ComponentActivity() {
    private val vm: InspectorViewModel by viewModels()
    private val deviceVm: DeviceViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            InspectorTheme { AppRoot(vm, deviceVm) }
        }
    }
}
