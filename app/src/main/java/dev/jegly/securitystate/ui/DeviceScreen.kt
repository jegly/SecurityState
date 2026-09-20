package dev.jegly.securitystate.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.jegly.securitystate.data.DeviceInfo
import java.util.Locale
import kotlin.math.roundToInt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceScreen(vm: DeviceViewModel) {
    val info by vm.info.collectAsStateWithLifecycle()

    DisposableEffect(Unit) {
        vm.startPolling()
        onDispose { vm.stopPolling() }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Device Info") }) }) { pad ->
        Column(Modifier.fillMaxSize().padding(pad).verticalScroll(rememberScrollState())) {
            val d = info
            if (d == null) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text("Reading device telemetry...", Modifier.padding(16.dp))
                return@Column
            }

            SectionCard("SoC and CPU", "Live, refreshing every 2s.") {
                d.socManufacturer?.let { KeyValue("SoC vendor", it) }
                d.socModel?.let { KeyValue("SoC model", it) }
                KeyValue("Board", d.board ?: "-")
                KeyValue("Hardware", d.hardware ?: "-")
                KeyValue("ABIs", d.abis.joinToString(", "))
                KeyValue("Cores", d.cpuCores.toString())
                d.cpuUsagePercent?.let { KeyValue("Total CPU load", "$it%") }
                Spacer(Modifier.height(6.dp))
                d.cores.forEach { c ->
                    val cur = c.curKhz?.let { "%,d MHz".format(it / 1000) } ?: "offline"
                    val range = if (c.minKhz != null && c.maxKhz != null)
                        " (${c.minKhz / 1000}-${c.maxKhz / 1000})" else ""
                    val load = c.usagePercent?.let { "  $it%" } ?: ""
                    KeyValue("cpu${c.index}", cur + range + load, mono = true)
                }
            }

            SectionCard("Memory") {
                KeyValue("RAM total", bytes(d.ramTotalBytes))
                KeyValue("RAM available", bytes(d.ramAvailBytes) +
                    "  (" + pct(d.ramAvailBytes, d.ramTotalBytes) + " free)")
                KeyValue("Low-memory state", if (d.ramLow) "YES" else "no")
                d.swapTotalBytes?.let { KeyValue("Swap total", bytes(it)) }
            }

            SectionCard("Storage (data)") {
                KeyValue("Total", bytes(d.storageTotalBytes))
                KeyValue("Free", bytes(d.storageFreeBytes) +
                    "  (" + pct(d.storageFreeBytes, d.storageTotalBytes) + " free)")
            }

            SectionCard("Battery and temperature") {
                d.batteryPercent?.let { KeyValue("Charge", "$it%") }
                d.batteryStatus?.let { KeyValue("Status", it) }
                d.batteryTempC?.let { KeyValue("Battery temp", "%.1f C".format(it)) }
                d.batteryVoltageMv?.let { KeyValue("Voltage", "$it mV") }
                d.batteryTech?.let { KeyValue("Technology", it) }
                d.batteryHealth?.let { KeyValue("Health", it) }
                if (d.thermalZones.isEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    Text("Other thermal zones are not readable on this device (SELinux).",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    Spacer(Modifier.height(6.dp))
                    d.thermalZones.forEach { z ->
                        KeyValue(z.label, "%.1f C".format(z.celsius), mono = true)
                    }
                }
            }

            SectionCard("Display") {
                KeyValue("Resolution", "${d.screenWidth} x ${d.screenHeight}")
                KeyValue("Density", "${d.densityDpi} dpi")
                KeyValue("Refresh rate", "%.0f Hz".format(d.refreshHz))
            }

            SectionCard("System") {
                KeyValue("Android", "${d.androidRelease} (API ${d.sdkInt})")
                KeyValue("Uptime", uptime(d.uptimeMillis))
                d.kernel?.let {
                    Spacer(Modifier.height(4.dp))
                    Text(it, style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

private fun bytes(b: Long): String {
    if (b <= 0) return "0 B"
    val u = arrayOf("B", "KB", "MB", "GB", "TB")
    var v = b.toDouble(); var i = 0
    while (v >= 1024 && i < u.size - 1) { v /= 1024; i++ }
    return String.format(Locale.US, "%.1f %s", v, u[i])
}

private fun pct(part: Long, whole: Long): String =
    if (whole <= 0) "-" else "${(part * 100.0 / whole).roundToInt()}%"

private fun uptime(ms: Long): String {
    val s = ms / 1000
    val h = s / 3600; val m = (s % 3600) / 60
    return if (h > 0) "${h}h ${m}m" else "${m}m"
}
