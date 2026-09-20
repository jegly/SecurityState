package dev.jegly.securitystate.data

import android.content.Context
import android.os.Build
import androidx.security.state.SecurityPatchState
import androidx.security.state.SecurityStateManagerCompat
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Wraps androidx.security:security-state into a single [SoftwareState] snapshot.
 *
 * Design decisions that came out of testing against a real Android 17 device:
 *  - The default Mainline package list is all `com.google.*`. On AOSP / GSI builds none resolve
 *    and the library silently returns the 1970 epoch. We detect that and report "unavailable"
 *    instead of "56 years behind", which would be alarming and wrong.
 *  - Vendor SPL is gated off inside the library (USE_VENDOR_SPL = false), so we read it straight
 *    from the SecurityStateManagerCompat bundle to surface it anyway.
 */
class SecurityStateRepository(private val context: Context) {

    private val reportCache = ReportCache(context)

    private val componentLabels = mapOf(
        SecurityPatchState.COMPONENT_SYSTEM to "System (OS)",
        SecurityPatchState.COMPONENT_SYSTEM_MODULES to "Mainline modules",
        SecurityPatchState.COMPONENT_KERNEL to "Kernel",
    )

    suspend fun load(preferNetworkReport: Boolean): SoftwareState = withContext(Dispatchers.IO) {
        val compat = SecurityStateManagerCompat(context)
        val bundle = runCatching { compat.getGlobalSecurityState() }.getOrNull()

        // Resolve the OSV report: cache first, network only if asked / cache empty.
        var reportJson: String? = null
        var fetchedAt: Long? = null
        reportCache.read()?.let { (json, at) -> reportJson = json; fetchedAt = at }
        if (preferNetworkReport || reportJson == null) {
            fetchReport()?.let { json ->
                val now = System.currentTimeMillis()
                reportJson = json
                fetchedAt = now
                reportCache.write(json, now)
            }
        }

        val sps = SecurityPatchState(context)
        var reportLoaded = false
        reportJson?.let {
            runCatching { sps.loadVulnerabilityReport(it) }.onSuccess { reportLoaded = true }
        }

        val providers = runCatching { queryProviders(sps) }.getOrDefault(emptyList())
        val channel = deviceChannel()
        val declaredSystemSpl = bundle?.getString(SecurityStateManagerCompat.KEY_SYSTEM_SPL)

        val components = componentLabels.map { (component, label) ->
            val declared = if (component == SecurityPatchState.COMPONENT_SYSTEM) declaredSystemSpl else null
            buildComponentRow(sps, component, label, reportLoaded, declared, providers, channel)
        }
        val supplemental = extractSupplemental(bundle)
        val globalState = bundle?.let { b ->
            b.keySet().sorted().mapNotNull { k -> b.getString(k)?.let { k to it } }
        } ?: emptyList()

        val patched = if (reportLoaded) patchedCveSummary(sps) else emptyMap()
        val fully = if (reportLoaded) runCatching { sps.isDeviceFullyUpdated() }.getOrNull() else null
        val latest = if (reportLoaded) {
            runCatching {
                sps.getPublishedSecurityPatchLevel(SecurityPatchState.COMPONENT_SYSTEM)
                    .firstOrNull()?.toString()
            }.getOrNull()
        } else null

        val moduleNote = components.firstOrNull {
            it.component == SecurityPatchState.COMPONENT_SYSTEM_MODULES && it.status == Status.UNKNOWN
        }?.detail

        SoftwareState(
            components = components,
            providers = providers,
            supplemental = supplemental,
            globalState = globalState,
            patchedCves = patched,
            isFullyUpdated = fully,
            reportLoaded = reportLoaded,
            reportFetchedAtMillis = fetchedAt,
            latestBulletin = latest,
            moduleNote = moduleNote,
            vendorSpl = bundle?.getString(SecurityStateManagerCompat.KEY_VENDOR_SPL),
            channel = channel,
        )
    }

    private fun buildComponentRow(
        sps: SecurityPatchState,
        component: String,
        label: String,
        reportLoaded: Boolean,
        declaredSpl: String?,
        providers: List<ProviderRow>,
        channel: String,
    ): ComponentRow {
        val deviceSpl = runCatching { sps.getDeviceSecurityPatchLevel(component) }.getOrNull()
        val deviceStr = deviceSpl?.toString()

        // The library's epoch fallback for an unresolved Mainline module.
        if (component == SecurityPatchState.COMPONENT_SYSTEM_MODULES && deviceStr == "1970-01-01") {
            return ComponentRow(
                component, label, null, null, null, null, Status.UNKNOWN,
                "No Mainline metadata package resolved on this build " +
                    "(expected on AOSP/GSI; retail Google builds report a real date).",
            )
        }

        val published = if (reportLoaded) {
            runCatching { sps.getPublishedSecurityPatchLevel(component) }.getOrNull()
        } else null

        // Kernel is versioned and compared per LTS branch, not as a single date. Kernel updates
        // ship inside the system image, so there is no separate ASPL for it.
        if (component == SecurityPatchState.COMPONENT_KERNEL) {
            val targets = published?.map { it.toString() } ?: emptyList()
            val branch = deviceStr?.split(".")?.take(2)?.joinToString(".")
            val target = targets.firstOrNull { it.startsWith("$branch.") }
            val status = when {
                deviceStr == null -> Status.UNKNOWN
                target == null -> Status.UNKNOWN
                comparePatch(deviceStr, target) >= 0 -> Status.AHEAD
                else -> Status.BEHIND
            }
            return ComponentRow(
                component, label, deviceStr, null, target ?: targets.joinToString(", "),
                null, status,
                when (status) {
                    Status.AHEAD -> "At or ahead of the $branch LTS target."
                    Status.BEHIND -> "Behind the $branch LTS target - kernel CVEs may be open."
                    else -> "No published LTS target for branch $branch."
                },
            )
        }

        // What an on-device provider says is actually installable right now (ASPL), if newer.
        val availableStr = availableSplFor(component, providers, deviceSpl)

        // Update availability is the authority on "behind", not the raw bulletin max.
        //   - If a provider offers a newer SPL, that is a real, installable update.
        //   - If nothing is offered, the device is on its latest available build. A same-cycle gap
        //     to the bulletin (e.g. -01 vs -05, or Mainline's own Play cadence) is not "behind";
        //     the app cannot install patches Google has not shipped to this device.
        val publishedStr = published?.getOrNull(0)?.toString()
        val meetsBulletin = deviceSpl != null && published != null && deviceSpl >= published[0]
        val status = when {
            deviceSpl == null -> Status.UNKNOWN
            availableStr != null -> Status.PENDING_UPDATE
            else -> Status.OK
        }
        val detail = when {
            status == Status.UNKNOWN -> "Could not read this component's patch level."
            status == Status.PENDING_UPDATE ->
                "Update available ($availableStr). Install it from system settings."
            meetsBulletin -> "Up to date. Meets the latest published bulletin ($publishedStr)."
            publishedStr != null ->
                "Up to date. On the latest build offered; bulletin level $publishedStr is not " +
                    "shipped to this device yet, and nothing is pending."
            else -> "Up to date. No pending update from on-device providers."
        }
        return ComponentRow(
            component, label, deviceStr, declaredSpl, publishedStr, availableStr, status, detail,
        )
    }

    /** Max SPL an update provider advertises for [component], returned only if newer than device. */
    private fun availableSplFor(
        component: String,
        providers: List<ProviderRow>,
        deviceSpl: SecurityPatchState.SecurityPatchLevel?,
    ): String? {
        if (deviceSpl == null) return null
        val maxAvail = providers.asSequence()
            .flatMap { it.updates.asSequence() }
            .filter { it.component == component }
            .mapNotNull { u ->
                runCatching {
                    SecurityPatchState.getComponentSecurityPatchLevel(component, u.spl)
                }.getOrNull()
            }
            .filter { it::class == deviceSpl::class }
            .maxWithOrNull(naturalOrder())
        return if (maxAvail != null && maxAvail > deviceSpl) maxAvail.toString() else null
    }

    /** Best-effort release channel from build identity. */
    private fun deviceChannel(): String {
        val codename = android.os.Build.VERSION.CODENAME
        val fp = android.os.Build.FINGERPRINT.lowercase(Locale.US)
        val product = android.os.Build.PRODUCT.lowercase(Locale.US)
        return when {
            codename != "REL" -> "Developer Preview ($codename)"
            "beta" in product || "beta" in fp -> "Beta"
            else -> "Stable"
        }
    }

    private suspend fun queryProviders(sps: SecurityPatchState): List<ProviderRow> {
        val results = sps.queryAllAvailableUpdates()
        return results.map { r ->
            ProviderRow(
                packageName = r.providerPackageName,
                lastCheckTimeMillis = r.lastCheckTimeMillis,
                updates = r.updates.map { u ->
                    UpdateRow(u.component, u.securityPatchLevel.toString(),
                        u.publishedDateMillis, u.lastCheckTimeMillis)
                },
            )
        }
    }

    private fun patchedCveSummary(sps: SecurityPatchState): Map<String, List<CveBucket>> {
        val out = LinkedHashMap<String, List<CveBucket>>()
        listOf(
            SecurityPatchState.COMPONENT_SYSTEM to "System (OS)",
            SecurityPatchState.COMPONENT_SYSTEM_MODULES to "Mainline modules",
        ).forEach { (component, label) ->
            runCatching {
                val spl = sps.getDeviceSecurityPatchLevel(component)
                if (spl.toString() == "1970-01-01") return@forEach
                val map = sps.getPatchedCves(component, spl)
                val buckets = map.entries
                    .filter { it.value.isNotEmpty() }
                    .map { CveBucket(it.key.name, it.value.toList().sorted()) }
                    .sortedBy { it.severity }
                if (buckets.isNotEmpty()) out[label] = buckets
            }
        }
        return out
    }

    private fun extractSupplemental(bundle: android.os.Bundle?): SupplementalPatches {
        fun read(key: String): List<String> =
            bundle?.getStringArray(key)?.toList()?.sorted() ?: emptyList()
        return SupplementalPatches(
            systemCves = read(SecurityStateManagerCompat.KEY_SYSTEM_SUPPLEMENTAL_PATCHES),
            vendorCves = read(SecurityStateManagerCompat.KEY_VENDOR_SUPPLEMENTAL_PATCHES),
        )
    }

    suspend fun checkCves(cves: List<String>): Boolean? = withContext(Dispatchers.IO) {
        val json = reportCache.read()?.first ?: fetchReport() ?: return@withContext null
        val sps = SecurityPatchState(context)
        runCatching {
            sps.loadVulnerabilityReport(json)
            sps.areCvesPatched(cves)
        }.getOrNull()
    }

    private suspend fun fetchReport(): String? = runCatching {
        val url = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            SecurityPatchState.createVulnerabilityReportUrl().toString()
        } else {
            "https://android-api.osv.dev/v1/android_sdk_${Build.VERSION.SDK_INT}.json"
        }
        Http.getText(url)
    }.getOrNull()

    private fun comparePatch(a: String, b: String): Int {
        val pa = a.split(".").map { it.toIntOrNull() ?: 0 }
        val pb = b.split(".").map { it.toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(pa.size, pb.size)) {
            val d = (pa.getOrElse(i) { 0 }) - (pb.getOrElse(i) { 0 })
            if (d != 0) return d
        }
        return 0
    }
}
