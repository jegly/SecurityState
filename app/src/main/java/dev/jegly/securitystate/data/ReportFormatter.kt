package dev.jegly.securitystate.data

import android.os.Build
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Renders the full inspection to plain text so it can be shared and pasted back for analysis.
 * Deliberately verbose: build identity + every attested field is exactly what's needed to tell a
 * real regression from a library false positive on a beta build.
 */
object ReportFormatter {

    fun build(
        software: SoftwareState?,
        hardware: HardwareState?,
        overall: OverallVerdict? = null,
        apps: AppInventory? = null,
    ): String = buildString {
        val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        line("=== Device Security State report ===")
        line("generated: $ts")
        blank()

        overall?.let { v ->
            line("[Overall verdict]  ${v.grade}  -  ${v.headline}")
            v.bad.forEach { line("  FAIL: $it") }
            v.warn.forEach { line("  WARN: $it") }
            v.info.forEach { line("  INFO: $it") }
            v.good.forEach { line("  OK:   $it") }
            blank()
        }

        line("[Build identity]")
        kv("model", Build.MODEL)
        kv("device", Build.DEVICE)
        kv("manufacturer", Build.MANUFACTURER)
        kv("product", Build.PRODUCT)
        kv("fingerprint", Build.FINGERPRINT)
        kv("sdk_int", Build.VERSION.SDK_INT.toString())
        kv("release", Build.VERSION.RELEASE)
        kv("sdk_full", prop("ro.build.version.sdk_full"))
        kv("security_patch", Build.VERSION.SECURITY_PATCH)
        kv("build.type", Build.TYPE)
        kv("build.tags", Build.TAGS)
        kv("bootloader", Build.BOOTLOADER)
        blank()

        if (software != null) softwareSection(software) else line("[Software] not loaded")
        blank()
        if (hardware != null) hardwareSection(hardware) else line("[Hardware] not loaded")
        blank()
        apps?.let { appsSection(it) }
    }

    private fun StringBuilder.appsSection(inv: AppInventory) {
        line("[Installed Google apps]  found=${inv.googleApps.size} " +
            "verifiedByOrigin=${inv.trusted} toReview=${inv.review.size} " +
            "signerConfirmed=${inv.signerConfirmed} totalInstalled=${inv.totalInstalled}")
        if (inv.review.isNotEmpty()) {
            line("  -- sideloaded, review these --")
            inv.review.forEach { a ->
                line("  [REVIEW] ${a.packageName}  v${a.versionName ?: "-"}  (${a.installer ?: "unknown"})")
                line("        signer: ${a.signerSha256.joinToString(",")}")
            }
        }
        inv.googleApps.filter { it.trusted }.forEach { a ->
            line("  [OK ${a.trust}] ${a.packageName}  v${a.versionName ?: "-"}")
        }
    }

    private fun StringBuilder.softwareSection(s: SoftwareState) {
        line("[Software patch level]")
        kv("report loaded", s.reportLoaded.toString())
        s.reportFetchedAtMillis?.let { kv("report fetched", time(it)) }
        kv("latest bulletin", s.latestBulletin ?: "-")
        kv("release channel", s.channel)
        kv("isDeviceFullyUpdated", s.isFullyUpdated?.toString() ?: "unknown")
        s.vendorSpl?.let { kv("vendor SPL", it) }
        s.moduleNote?.let { kv("mainline note", it) }
        blank()
        s.components.forEach { c ->
            line("  - ${c.label} [${c.status}]")
            c.deviceSpl?.let { kv("effective/device", it, 6) }
            c.declaredSpl?.let { if (it != c.deviceSpl) kv("declared", it, 6) }
            c.publishedSpl?.let { kv("published/target", it, 6) }
            c.availableSpl?.let { kv("available now", it, 6) }
            kv("detail", c.detail, 6)
        }
        blank()
        line("[Available updates (ASPL)]")
        if (s.providers.isEmpty()) line("  none")
        s.providers.forEach { p ->
            line("  provider: ${p.packageName}  (checked ${time(p.lastCheckTimeMillis)})")
            p.updates.forEach { u -> kv(u.component, u.spl, 6) }
        }
        blank()
        line("[Supplemental patches]  system=${s.supplemental.systemCves.size} vendor=${s.supplemental.vendorCves.size}")
        if (s.supplemental.systemCves.isNotEmpty())
            line("  system: " + s.supplemental.systemCves.joinToString(", "))
        if (s.supplemental.vendorCves.isNotEmpty())
            line("  vendor: " + s.supplemental.vendorCves.joinToString(", "))
        blank()
        if (s.patchedCves.isNotEmpty()) {
            line("[Patched CVE counts]")
            s.patchedCves.forEach { (comp, buckets) ->
                line("  $comp: " + buckets.joinToString(", ") { "${it.severity}=${it.cves.size}" })
            }
            blank()
        }
        if (s.globalState.isNotEmpty()) {
            line("[Raw security-state bundle]")
            s.globalState.forEach { (k, v) -> kv(k, v, 2) }
        }
    }

    private fun StringBuilder.hardwareSection(h: HardwareState) {
        line("[Hardware features]")
        kv("StrongBox", h.strongBoxFeature.toString())
        kv("app-attest key", h.attestKeyFeature.toString())
        kv("ID attestation", h.idAttestationFeature.toString())
        blank()
        h.probes.forEach { p ->
            line("[Attestation probe: ${p.requestedLevel}]  -> ${p.outcome}")
            if (p.message.isNotBlank()) kv("note", p.message, 2)
            kv("device-properties requested", p.devicePropertiesRequested.toString(), 2)
            p.record?.let { r ->
                kv("attestation security level", r.attestationSecurityLevel.name, 2)
                kv("keymint version", "v${r.keymintVersion}", 2)
                kv("attestation version", r.attestationVersion.toString(), 2)
                kv("challenge matched", r.challengeMatched.toString(), 2)
                kv("values hardware-enforced", r.hardwareEnforced.toString(), 2)
                r.rootOfTrust?.let { rot ->
                    kv("verified boot state", rot.verifiedBootState.name, 2)
                    kv("device locked", rot.deviceLocked.toString(), 2)
                    kv("verified boot key", rot.verifiedBootKeyHex, 2)
                    rot.verifiedBootHashHex?.let { kv("verified boot hash", it, 2) }
                }
                r.osVersion?.let { kv("attested os version", it, 2) }
                r.osPatchLevel?.let { kv("attested os patch", it, 2) }
                r.vendorPatchLevel?.let { kv("attested vendor patch", it, 2) }
                r.bootPatchLevel?.let { kv("attested boot patch", it, 2) }
                r.moduleHashHex?.let { kv("module hash", it, 2) }
                r.attestedBrand?.let { kv("attested brand", it, 2) }
                r.attestedModel?.let { kv("attested model", it, 2) }
                if (r.attestedApps.isNotEmpty())
                    kv("attested apps", r.attestedApps.joinToString { "${it.packageName}@${it.version}" }, 2)
            }
            kv("chain trust", p.verdict.trust.name, 2)
            kv("chain message", p.verdict.message, 2)
            p.verdict.rootSubject?.let { kv("root subject", it, 2) }
            p.verdict.revokedSerialHex?.let { kv("revoked serial", it, 2) }
            if (p.chain.isNotEmpty()) {
                kv("chain length", "${p.chain.size} certs", 2)
                p.chain.forEachIndexed { i, c ->
                    kv("cert[$i] subject", c.subject, 4)
                    kv("cert[$i] issuer", c.issuer, 4)
                    kv("cert[$i] serial", c.serialHex, 4)
                }
            }
            blank()
        }
    }

    private fun StringBuilder.line(s: String) = append(s).append('\n')
    private fun StringBuilder.blank() = append('\n')
    private fun StringBuilder.kv(k: String, v: String, indent: Int = 2) =
        append(" ".repeat(indent)).append(k).append(": ").append(v).append('\n')

    private fun time(millis: Long): String =
        if (millis <= 0) "unknown"
        else SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(millis))

    private fun prop(name: String): String = runCatching {
        @Suppress("PrivateApi")
        val c = Class.forName("android.os.SystemProperties")
        val m = c.getMethod("get", String::class.java)
        (m.invoke(null, name) as? String)?.ifEmpty { "-" } ?: "-"
    }.getOrDefault("-")
}
