package dev.jegly.securitystate.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.ui.platform.LocalContext
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import android.content.Intent
import dev.jegly.securitystate.data.AttestationProbe
import dev.jegly.securitystate.data.ChainTrust
import androidx.compose.foundation.layout.size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.sp
import dev.jegly.securitystate.data.AppInventory
import dev.jegly.securitystate.data.AppTrust
import dev.jegly.securitystate.data.ComponentRow
import dev.jegly.securitystate.data.Grade
import dev.jegly.securitystate.data.InstalledApp
import dev.jegly.securitystate.data.OverallVerdict
import dev.jegly.securitystate.data.ProbeOutcome
import dev.jegly.securitystate.data.ReportFormatter
import dev.jegly.securitystate.data.SecurityLevel
import dev.jegly.securitystate.data.Status
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InspectorScreen(vm: InspectorViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Device Security State") },
                actions = {
                    val ready = state.software != null || state.hardware != null
                    var menuOpen by remember { mutableStateOf(false) }

                    // Save-as-.txt via the Storage Access Framework: real file the user picks.
                    val saveLauncher = rememberLauncherForActivityResult(
                        ActivityResultContracts.CreateDocument("text/plain")
                    ) { uri ->
                        if (uri != null) {
                            val text = ReportFormatter.build(state.software, state.hardware, state.overall, state.apps)
                            runCatching {
                                context.contentResolver.openOutputStream(uri)?.use {
                                    it.write(text.toByteArray())
                                }
                            }
                            Toast.makeText(context, "Report saved", Toast.LENGTH_SHORT).show()
                        }
                    }

                    IconButton(onClick = { vm.refresh() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                    }
                    IconButton(enabled = ready, onClick = { menuOpen = true }) {
                        Icon(Icons.Default.MoreVert, contentDescription = "Export")
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = { Text("Export as .txt file") },
                            onClick = {
                                menuOpen = false
                                saveLauncher.launch("security-state-report.txt")
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("Share report") },
                            onClick = {
                                menuOpen = false
                                val text = ReportFormatter.build(state.software, state.hardware, state.overall, state.apps)
                                val send = Intent(Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(Intent.EXTRA_SUBJECT, "Device Security State report")
                                    putExtra(Intent.EXTRA_TEXT, text)
                                }
                                context.startActivity(
                                    Intent.createChooser(send, "Share security report")
                                )
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("Copy to clipboard") },
                            onClick = {
                                menuOpen = false
                                val text = ReportFormatter.build(state.software, state.hardware, state.overall, state.apps)
                                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE)
                                    as ClipboardManager
                                cm.setPrimaryClip(
                                    ClipData.newPlainText("Security State report", text)
                                )
                                Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
                            },
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()),
        ) {
            if (state.loading) LinearProgressIndicator(Modifier.fillMaxWidth())

            state.error?.let {
                SectionCard("Something went wrong") { Text(it) }
            }

            OverallCard(state)

            state.software?.let { sw ->
                SectionCard(
                    "Software patch level",
                    "Per-component, from androidx.security:security-state. Software-reported.",
                ) {
                    KeyValue("Release channel", sw.channel)
                    HorizontalDivider(Modifier.padding(vertical = 8.dp))
                    sw.components.forEachIndexed { i, row ->
                        if (i > 0) HorizontalDivider(Modifier.padding(vertical = 8.dp))
                        ComponentBlock(row)
                    }
                    sw.vendorSpl?.let {
                        HorizontalDivider(Modifier.padding(vertical = 8.dp))
                        KeyValue("Vendor SPL", it, mono = true)
                        Text(
                            "Read directly from the security-state bundle (the library keeps " +
                                "vendor SPL disabled by default).",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                UpdatesCard(sw)
                SupplementalCard(sw)
                CveCheckerCard(vm, state)
                PatchedCvesCard(sw)
                GlobalStateCard(sw)
            }

            HardwareSection(state)

            state.apps?.let { inv ->
                val systemVerified = state.hardware?.probes?.any {
                    it.record?.rootOfTrust?.let { r ->
                        r.verifiedBootState == dev.jegly.securitystate.data.VerifiedBootState.VERIFIED &&
                            r.deviceLocked
                    } == true
                } == true
                AppInventoryCard(inv, systemVerified)
            }

            Spacer(Modifier.height(24.dp))
            Text(
                "This is a diagnostic inspector, not a security gate. Attestation is verified " +
                    "on-device; on a compromised device the verifier is compromised too. For " +
                    "trust decisions, verify attestation on a server and pair with Play Integrity.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
            )
        }
    }
}

@Composable
private fun OverallCard(state: UiState) {
    val v = state.overall ?: return
    val (color, icon) = when (v.grade) {
        Grade.SECURE -> Color(0xFF2E7D32) to Icons.Default.CheckCircle
        Grade.ATTENTION -> Color(0xFFF9A825) to Icons.Default.Warning
        Grade.AT_RISK -> Color(0xFFC62828) to Icons.Default.Error
        Grade.UNKNOWN -> MaterialTheme.colorScheme.outline to Icons.AutoMirrored.Filled.HelpOutline
    }
    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.12f)),
    ) {
        Column(Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(44.dp))
                Spacer(Modifier.padding(end = 14.dp))
                Column {
                    Text(v.headline, style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold, color = color)
                    state.software?.latestBulletin?.let {
                        Text("Latest bulletin $it", style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            Spacer(Modifier.height(14.dp))
            v.bad.forEach { ReasonLine("✖", it, Color(0xFFC62828)) }
            v.warn.forEach { ReasonLine("⚠", it, Color(0xFFF9A825)) }
            v.good.forEach { ReasonLine("✔", it, Color(0xFF2E7D32)) }
        }
    }
}

@Composable
private fun ReasonLine(mark: String, text: String, color: Color) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.Top) {
        Text(mark, color = color, fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(end = 8.dp), fontSize = 14.sp)
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun AppInventoryCard(inv: AppInventory, systemVerified: Boolean) {
    val review = inv.review
    SectionCard(
        "Installed Google apps",
        "Each app is checked for how it can be verified: Google signer, the verified-boot system " +
            "image, or Play install. Only genuinely sideloaded apps are flagged.",
    ) {
        KeyValue("Google apps found", inv.googleApps.size.toString())
        KeyValue("Verified by origin", inv.trusted.toString())
        KeyValue("To review (sideloaded)", review.size.toString())
        if (!systemVerified) {
            Text(
                "Verified boot is not confirmed, so system-image trust is not hardware-backed here.",
                style = MaterialTheme.typography.bodySmall, color = Color(0xFFF9A825),
                modifier = Modifier.padding(top = 4.dp),
            )
        }
        if (!inv.couldEnumerateAll) {
            Text("Package visibility looks restricted; list may be partial.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (review.isNotEmpty()) {
            HorizontalDivider(Modifier.padding(vertical = 8.dp))
            Text("Sideloaded, verify these:", fontWeight = FontWeight.SemiBold,
                color = Color(0xFFC62828), style = MaterialTheme.typography.bodyMedium)
            review.forEach { AppRow(it, systemVerified) }
        } else {
            Text("No sideloaded Google-named apps. Every one is verifiable by origin.",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF2E7D32), modifier = Modifier.padding(top = 6.dp))
        }
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        var expanded by remember { mutableStateOf(false) }
        TextButton(onClick = { expanded = !expanded }) {
            Text(if (expanded) "Hide verified apps" else "Show all ${inv.trusted} verified apps")
        }
        if (expanded) inv.googleApps.filter { it.trusted }.forEach { AppRow(it, systemVerified) }
    }
}

@Composable
private fun AppRow(app: InstalledApp, systemVerified: Boolean) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val tint = if (app.trusted) Color(0xFF2E7D32) else Color(0xFFC62828)
        Icon(
            if (app.trusted) Icons.Default.Verified else Icons.Default.Warning,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(20.dp),
        )
        Spacer(Modifier.padding(end = 10.dp))
        Column(Modifier.weight(1f)) {
            Text(app.label, fontWeight = FontWeight.Medium,
                style = MaterialTheme.typography.bodyMedium)
            Text(app.packageName, style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            val reason = when (app.trust) {
                AppTrust.SIGNER_GOOGLE -> "Signed by Google's certificate"
                AppTrust.SYSTEM_IMAGE ->
                    if (systemVerified) "Verified by verified boot (AVB)"
                    else "System image (boot not verified)"
                AppTrust.PLAY -> "Delivered and managed by Play"
                AppTrust.SIDELOADED -> "Sideloaded from " + (app.installer ?: "an unknown source")
            }
            Text(reason, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ComponentBlock(row: ComponentRow) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(row.label, fontWeight = FontWeight.Medium, style = MaterialTheme.typography.bodyLarge)
        StatusPill(row.status.name.replace('_', ' '), row.status)
    }
    Spacer(Modifier.height(6.dp))
    row.deviceSpl?.let {
        val label = if (row.declaredSpl != null && row.declaredSpl != it) "Effective" else "On device"
        KeyValue(label, it, mono = true)
    }
    row.declaredSpl?.let { d ->
        if (d != row.deviceSpl) KeyValue("Declared", d, mono = true)
    }
    row.publishedSpl?.let { KeyValue("Published / target", it, mono = true) }
    row.availableSpl?.let { KeyValue("Available now", it, mono = true) }
    Text(
        row.detail,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 2.dp),
    )
}

@Composable
private fun UpdatesCard(sw: dev.jegly.securitystate.data.SoftwareState) {
    SectionCard(
        "Available updates (ASPL)",
        "From trusted on-device update providers over IPC.",
    ) {
        if (sw.providers.isEmpty()) {
            Text("No trusted update providers responded.",
                style = MaterialTheme.typography.bodyMedium)
        } else {
            sw.providers.forEach { p ->
                Text(p.packageName, fontWeight = FontWeight.Medium,
                    fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
                Text("last checked ${relTime(p.lastCheckTimeMillis)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                p.updates.forEach { u -> KeyValue("  ${u.component}", u.spl, mono = true) }
                Spacer(Modifier.height(6.dp))
            }
        }
    }
}

@Composable
private fun SupplementalCard(sw: dev.jegly.securitystate.data.SoftwareState) {
    val s = sw.supplemental
    SectionCard(
        "Supplemental patches",
        "CVEs the OEM declares fixed beyond the monthly SPL (Android 17 spec).",
    ) {
        if (s.total == 0) {
            Text("None declared on this device.", style = MaterialTheme.typography.bodyMedium)
        } else {
            KeyValue("System-side CVEs", s.systemCves.size.toString())
            KeyValue("Vendor-side CVEs", s.vendorCves.size.toString())
            val all = (s.systemCves + s.vendorCves).sorted()
            Spacer(Modifier.height(6.dp))
            Text(all.joinToString(", "),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun CveCheckerCard(vm: InspectorViewModel, state: UiState) {
    SectionCard("Check specific CVEs", "Are these patched on this device?") {
        OutlinedTextField(
            value = state.cveInput,
            onValueChange = vm::setCveInput,
            label = { Text("CVE-2026-1234, CVE-2025-…") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = false,
        )
        Spacer(Modifier.height(8.dp))
        Button(onClick = { vm.checkCves() }) { Text("Check") }
        state.cveResult?.let { r ->
            Spacer(Modifier.height(8.dp))
            when {
                r.cves.isEmpty() -> Text("Enter one or more CVE IDs.")
                r.allPatched == null -> Text("Need the vulnerability report loaded to answer.")
                r.allPatched -> StatusPill("All ${r.cves.size} patched", Status.OK)
                else -> StatusPill("Not all patched", Status.BEHIND)
            }
        }
    }
}

@Composable
private fun PatchedCvesCard(sw: dev.jegly.securitystate.data.SoftwareState) {
    if (sw.patchedCves.isEmpty()) return
    SectionCard("Patched CVEs at this SPL", "Grouped by component and severity.") {
        sw.patchedCves.forEach { (component, buckets) ->
            Text(component, fontWeight = FontWeight.SemiBold,
                style = MaterialTheme.typography.bodyLarge)
            buckets.forEach { b -> KeyValue("  ${b.severity}", b.cves.size.toString()) }
            Spacer(Modifier.height(6.dp))
        }
    }
}

@Composable
private fun GlobalStateCard(sw: dev.jegly.securitystate.data.SoftwareState) {
    if (sw.globalState.isEmpty()) return
    SectionCard("Raw security-state bundle") {
        sw.globalState.forEach { (k, v) -> KeyValue(k, v, mono = true) }
    }
}

@Composable
private fun HardwareSection(state: UiState) {
    val hw = state.hardware ?: return
    SectionCard(
        "Hardware-backed attestation",
        "Key generated in secure hardware; claims below are signed by the device.",
    ) {
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier.fillMaxWidth()) {
            Text("Verify chain to Google root (needs network)",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f).padding(end = 8.dp))
        }
        KeyValue("StrongBox feature", yesNo(hw.strongBoxFeature))
        KeyValue("App-attest key", yesNo(hw.attestKeyFeature))
        KeyValue("ID attestation", yesNo(hw.idAttestationFeature))
    }
    hw.probes.forEach { ProbeCard(it) }
}

@Composable
private fun ProbeCard(probe: AttestationProbe) {
    val levelName = when (probe.requestedLevel) {
        SecurityLevel.STRONGBOX -> "StrongBox (secure element)"
        SecurityLevel.TRUSTED_ENVIRONMENT -> "TEE (TrustZone)"
        else -> probe.requestedLevel.name
    }
    SectionCard(levelName) {
        when (probe.outcome) {
            ProbeOutcome.UNAVAILABLE -> {
                StatusPill("Not available", Status.UNKNOWN)
                Spacer(Modifier.height(6.dp)); Text(probe.message)
                return@SectionCard
            }
            ProbeOutcome.FAILED -> {
                StatusPill("Failed", Status.BEHIND)
                Spacer(Modifier.height(6.dp)); Text(probe.message)
                return@SectionCard
            }
            ProbeOutcome.ATTESTED -> StatusPill("Attested", Status.OK)
        }
        val rec = probe.record ?: return@SectionCard
        Spacer(Modifier.height(8.dp))
        KeyValue("Security level", rec.attestationSecurityLevel.name)
        KeyValue("KeyMint version", "v${rec.keymintVersion}")
        KeyValue("Challenge matched", yesNo(rec.challengeMatched))
        KeyValue("Values are", if (rec.hardwareEnforced) "hardware-enforced" else "software (untrusted)")
        rec.rootOfTrust?.let { rot ->
            HorizontalDivider(Modifier.padding(vertical = 8.dp))
            KeyValue("Verified boot", rot.verifiedBootState.name)
            KeyValue("Bootloader", if (rot.deviceLocked) "LOCKED" else "UNLOCKED")
            KeyValue("Verified boot key", rot.verifiedBootKeyHex.take(24) + "…", mono = true)
            rot.verifiedBootHashHex?.let { KeyValue("Boot hash", it.take(24) + "…", mono = true) }
        }
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        rec.osVersion?.let { KeyValue("Attested OS version", it, mono = true) }
        rec.osPatchLevel?.let { KeyValue("Attested OS patch", it, mono = true) }
        rec.vendorPatchLevel?.let { KeyValue("Attested vendor patch", it, mono = true) }
        rec.bootPatchLevel?.let { KeyValue("Attested boot patch", it, mono = true) }
        rec.moduleHashHex?.let { KeyValue("Module hash", it.take(24) + "…", mono = true) }
        if (rec.attestedBrand != null || rec.attestedModel != null) {
            HorizontalDivider(Modifier.padding(vertical = 8.dp))
            rec.attestedBrand?.let { KeyValue("Attested brand", it) }
            rec.attestedManufacturer?.let { KeyValue("Attested maker", it) }
            rec.attestedModel?.let { KeyValue("Attested model", it) }
            rec.attestedProduct?.let { KeyValue("Attested product", it) }
        }
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        val (pill, st) = when (probe.verdict.trust) {
            ChainTrust.TRUSTED -> "Chains to Google root" to Status.OK
            ChainTrust.REVOKED -> "Key REVOKED" to Status.BEHIND
            ChainTrust.UNTRUSTED_ROOT -> "Unknown root" to Status.PENDING_UPDATE
            ChainTrust.BROKEN -> "Chain broken" to Status.BEHIND
            ChainTrust.OFFLINE -> "Offline" to Status.UNKNOWN
            ChainTrust.NOT_CHECKED -> "Not verified" to Status.UNKNOWN
        }
        StatusPill(pill, st)
        Spacer(Modifier.height(6.dp))
        Text(probe.verdict.message, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        probe.verdict.revokedSerialHex?.let {
            KeyValue("Revoked serial", it, mono = true)
        }
        if (probe.chain.isNotEmpty()) {
            Spacer(Modifier.height(6.dp))
            KeyValue("Chain length", "${probe.chain.size} certs")
        }
    }
}

private fun yesNo(b: Boolean) = if (b) "Yes" else "No"

private fun relTime(millis: Long): String {
    if (millis <= 0) return "unknown"
    val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
    return fmt.format(Date(millis))
}
