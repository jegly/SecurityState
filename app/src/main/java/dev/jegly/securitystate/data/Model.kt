package dev.jegly.securitystate.data

/** How a single component compares against the published bulletin. */
enum class Status { OK, AHEAD, PENDING_UPDATE, BEHIND, UNKNOWN }

/**
 * One row of the software patch table. [publishedSpl] is the bulletin baseline, [availableSpl]
 * is what an on-device update provider says it can install right now.
 */
data class ComponentRow(
    val component: String,
    val label: String,
    val deviceSpl: String?,
    val declaredSpl: String?,
    val publishedSpl: String?,
    val availableSpl: String?,
    val status: Status,
    val detail: String,
    val error: String? = null,
)

data class UpdateRow(
    val component: String,
    val spl: String,
    val publishedDateMillis: Long,
    val lastCheckTimeMillis: Long,
)

data class ProviderRow(
    val packageName: String,
    val lastCheckTimeMillis: Long,
    val updates: List<UpdateRow>,
)

/** CVEs an OEM declares fixed *beyond* its declared SPL, per the supplemental patch spec. */
data class SupplementalPatches(
    val systemCves: List<String>,
    val vendorCves: List<String>,
) {
    val total: Int get() = systemCves.size + vendorCves.size
}

data class CveBucket(val severity: String, val cves: List<String>)

data class SoftwareState(
    val components: List<ComponentRow>,
    val providers: List<ProviderRow>,
    val supplemental: SupplementalPatches,
    val globalState: List<Pair<String, String>>,
    val patchedCves: Map<String, List<CveBucket>>,
    val isFullyUpdated: Boolean?,
    val reportLoaded: Boolean,
    val reportFetchedAtMillis: Long?,
    val latestBulletin: String?,
    val moduleNote: String?,
    val vendorSpl: String?,
    val channel: String,
)

// ---------------------------------------------------------------- attestation

enum class SecurityLevel { SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX, UNKNOWN }

enum class VerifiedBootState { VERIFIED, SELF_SIGNED, UNVERIFIED, FAILED, UNKNOWN }

enum class ProbeOutcome { ATTESTED, UNAVAILABLE, FAILED }

data class RootOfTrust(
    val verifiedBootKeyHex: String,
    val deviceLocked: Boolean,
    val verifiedBootState: VerifiedBootState,
    val verifiedBootHashHex: String?,
)

data class AttestedApp(val packageName: String, val version: Long)

/**
 * The decoded contents of the KeyMint attestation extension
 * (OID 1.3.6.1.4.1.11129.2.1.17) on the leaf certificate.
 */
data class AttestationRecord(
    val attestationVersion: Int,
    val keymintVersion: Int,
    val attestationSecurityLevel: SecurityLevel,
    val keymintSecurityLevel: SecurityLevel,
    val challengeMatched: Boolean,
    /** True when root of trust / patch levels came from the hardware-enforced list. */
    val hardwareEnforced: Boolean,
    val rootOfTrust: RootOfTrust?,
    val osVersion: String?,
    val osPatchLevel: String?,
    val vendorPatchLevel: String?,
    val bootPatchLevel: String?,
    val moduleHashHex: String?,
    val attestedApps: List<AttestedApp>,
    val signatureDigestsHex: List<String>,
    val attestedBrand: String?,
    val attestedDevice: String?,
    val attestedProduct: String?,
    val attestedManufacturer: String?,
    val attestedModel: String?,
)

enum class ChainTrust { NOT_CHECKED, TRUSTED, UNTRUSTED_ROOT, REVOKED, BROKEN, OFFLINE }

data class ChainVerdict(
    val trust: ChainTrust,
    val rootSubject: String?,
    val revokedSerialHex: String?,
    val revocationReason: String?,
    val message: String,
)

data class CertSummary(
    val subject: String,
    val issuer: String,
    val serialHex: String,
    val notAfter: Long,
)

/** One attempt at one security level. Probing all levels is the point - report every outcome. */
data class AttestationProbe(
    val requestedLevel: SecurityLevel,
    val outcome: ProbeOutcome,
    val record: AttestationRecord?,
    val chain: List<CertSummary>,
    val verdict: ChainVerdict,
    val devicePropertiesRequested: Boolean,
    val message: String,
)

data class HardwareState(
    val probes: List<AttestationProbe>,
    val strongBoxFeature: Boolean,
    val attestKeyFeature: Boolean,
    val idAttestationFeature: Boolean,
)

// ---------------------------------------------------------------- app inventory

/** Why an app is (or is not) trusted, most-trusted first. */
enum class AppTrust { SIGNER_GOOGLE, SYSTEM_IMAGE, PLAY, SIDELOADED }

data class InstalledApp(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val signerSha256: List<String>,
    val signedByGoogle: Boolean,
    val installer: String?,
    val fromPlay: Boolean,
    val system: Boolean,
    val trust: AppTrust,
) {
    val trusted: Boolean get() = trust != AppTrust.SIDELOADED
}

data class AppInventory(
    val googleApps: List<InstalledApp>,
    val totalInstalled: Int,
    val couldEnumerateAll: Boolean,
) {
    val trusted: Int get() = googleApps.count { it.trusted }
    val review: List<InstalledApp> get() = googleApps.filter { !it.trusted }
    val signerConfirmed: Int get() = googleApps.count { it.trust == AppTrust.SIGNER_GOOGLE }
}

// ---------------------------------------------------------------- overall grade

enum class Grade { SECURE, ATTENTION, AT_RISK, UNKNOWN }

data class OverallVerdict(
    val grade: Grade,
    val headline: String,
    val good: List<String>,
    val warn: List<String>,
    val bad: List<String>,
    val info: List<String>,
)
