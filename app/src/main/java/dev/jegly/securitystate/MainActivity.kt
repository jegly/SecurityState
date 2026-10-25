package dev.jegly.securitystate

import android.app.AlertDialog
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import dev.jegly.securitystate.security.SignatureVerifier
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
        // Repackaging detection: a re-signed (tampered) build never renders and can only exit.
        if (!SignatureVerifier.isSignedByTrustedCert(this)) {
            showTamperDialog()
            return
        }
        setContent {
            InspectorTheme { AppRoot(vm, deviceVm) }
        }
    }

    private fun showTamperDialog() {
        AlertDialog.Builder(this)
            .setTitle(R.string.tamper_dialog_title)
            .setMessage(R.string.tamper_dialog_message)
            .setCancelable(false)
            .setPositiveButton(R.string.tamper_dialog_exit) { _, _ -> finishAndRemoveTask() }
            .show()
    }
}
