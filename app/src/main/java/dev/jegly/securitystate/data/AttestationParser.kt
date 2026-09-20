package dev.jegly.securitystate.data

/**
 * Decodes the KeyMint `KeyDescription` structure carried in certificate extension
 * 1.3.6.1.4.1.11129.2.1.17.
 *
 * Schema: https://source.android.com/docs/security/features/keystore/attestation#schema
 */
internal object AttestationParser {

    const val OID = "1.3.6.1.4.1.11129.2.1.17"

    // AuthorizationList context tags we care about.
    private const val TAG_ROOT_OF_TRUST = 704
    private const val TAG_OS_VERSION = 705
    private const val TAG_OS_PATCH_LEVEL = 706
    private const val TAG_ATTESTATION_APPLICATION_ID = 709
    private const val TAG_ID_BRAND = 710
    private const val TAG_ID_DEVICE = 711
    private const val TAG_ID_PRODUCT = 712
    private const val TAG_ID_MANUFACTURER = 716
    private const val TAG_ID_MODEL = 717
    private const val TAG_VENDOR_PATCH_LEVEL = 718
    private const val TAG_BOOT_PATCH_LEVEL = 719
    private const val TAG_MODULE_HASH = 724

    private class AuthList {
        var rootOfTrust: RootOfTrust? = null
        var osVersion: Long? = null
        var osPatchLevel: Long? = null
        var vendorPatchLevel: Long? = null
        var bootPatchLevel: Long? = null
        var moduleHash: String? = null
        var apps: List<AttestedApp> = emptyList()
        var digests: List<String> = emptyList()
        var brand: String? = null
        var device: String? = null
        var product: String? = null
        var manufacturer: String? = null
        var model: String? = null

        val isEmpty: Boolean
            get() = rootOfTrust == null && osPatchLevel == null && vendorPatchLevel == null &&
                bootPatchLevel == null
    }

    fun parse(extension: ByteArray, expectedChallenge: ByteArray): AttestationRecord {
        val outer = DerReader(extension)
        val keyDescription = outer.next()
        val r = outer.reader(keyDescription)

        val attestationVersion = r.long(r.next()).toInt()
        val attestationSecurityLevel = securityLevel(r.long(r.next()).toInt())
        val keymintVersion = r.long(r.next()).toInt()
        val keymintSecurityLevel = securityLevel(r.long(r.next()).toInt())
        val challenge = r.bytes(r.next())
        r.next() // uniqueId - always empty for non-privileged callers

        val softwareEnforced = authList(r, r.next())
        val hardwareEnforced = authList(r, r.next())

        // Root of trust and patch levels live in the hardware list for a hardware-backed key.
        // Fall back to the software list so a software-only device still renders something,
        // but flag it so the UI never presents software claims as attested facts.
        val useHardware = !hardwareEnforced.isEmpty
        val effective = if (useHardware) hardwareEnforced else softwareEnforced
        val ids = if (hardwareEnforced.brand != null) hardwareEnforced else softwareEnforced
        val appSource = if (softwareEnforced.apps.isNotEmpty()) softwareEnforced else hardwareEnforced

        return AttestationRecord(
            attestationVersion = attestationVersion,
            keymintVersion = keymintVersion,
            attestationSecurityLevel = attestationSecurityLevel,
            keymintSecurityLevel = keymintSecurityLevel,
            challengeMatched = challenge.contentEquals(expectedChallenge),
            hardwareEnforced = useHardware,
            rootOfTrust = effective.rootOfTrust,
            osVersion = effective.osVersion?.let(::formatOsVersion),
            osPatchLevel = effective.osPatchLevel?.let(::formatYearMonth),
            vendorPatchLevel = effective.vendorPatchLevel?.let(::formatPatchDate),
            bootPatchLevel = effective.bootPatchLevel?.let(::formatPatchDate),
            moduleHashHex = effective.moduleHash,
            attestedApps = appSource.apps,
            signatureDigestsHex = appSource.digests,
            attestedBrand = ids.brand,
            attestedDevice = ids.device,
            attestedProduct = ids.product,
            attestedManufacturer = ids.manufacturer,
            attestedModel = ids.model,
        )
    }

    private fun authList(parent: DerReader, tlv: Tlv): AuthList {
        val out = AuthList()
        val list = parent.reader(tlv)
        while (list.hasNext()) {
            val t = try { list.next() } catch (e: IllegalArgumentException) { break }
            if (t.tagClass != 2) continue
            runCatching {
                when (t.tagNumber) {
                    TAG_ROOT_OF_TRUST -> out.rootOfTrust = rootOfTrust(list, t)
                    TAG_OS_VERSION -> out.osVersion = explicitLong(list, t)
                    TAG_OS_PATCH_LEVEL -> out.osPatchLevel = explicitLong(list, t)
                    TAG_VENDOR_PATCH_LEVEL -> out.vendorPatchLevel = explicitLong(list, t)
                    TAG_BOOT_PATCH_LEVEL -> out.bootPatchLevel = explicitLong(list, t)
                    TAG_MODULE_HASH -> out.moduleHash = explicitBytes(list, t).toHex()
                    TAG_ID_BRAND -> out.brand = explicitString(list, t)
                    TAG_ID_DEVICE -> out.device = explicitString(list, t)
                    TAG_ID_PRODUCT -> out.product = explicitString(list, t)
                    TAG_ID_MANUFACTURER -> out.manufacturer = explicitString(list, t)
                    TAG_ID_MODEL -> out.model = explicitString(list, t)
                    TAG_ATTESTATION_APPLICATION_ID -> {
                        val (apps, digests) = attestationApplicationId(explicitBytes(list, t))
                        out.apps = apps
                        out.digests = digests
                    }
                }
            }
        }
        return out
    }

    private fun explicitLong(r: DerReader, t: Tlv): Long {
        val (inner, v) = r.explicit(t)
        return inner.long(v)
    }

    private fun explicitBytes(r: DerReader, t: Tlv): ByteArray {
        val (inner, v) = r.explicit(t)
        return inner.bytes(v)
    }

    private fun explicitString(r: DerReader, t: Tlv): String {
        val (inner, v) = r.explicit(t)
        return inner.string(v)
    }

    private fun rootOfTrust(r: DerReader, t: Tlv): RootOfTrust {
        val (inner, seq) = r.explicit(t)
        val rot = inner.reader(seq)
        val key = rot.bytes(rot.next())
        val locked = rot.boolean(rot.next())
        val state = verifiedBootState(rot.long(rot.next()).toInt())
        // verifiedBootHash is only present from attestation version 3 onward.
        val hash = if (rot.hasNext()) runCatching { rot.bytes(rot.next()).toHex() }.getOrNull() else null
        return RootOfTrust(key.toHex(), locked, state, hash)
    }

    /**
     * AttestationApplicationId ::= SEQUENCE {
     *   package_infos      SET OF AttestationPackageInfo,
     *   signature_digests  SET OF OCTET_STRING
     * }
     */
    private fun attestationApplicationId(der: ByteArray): Pair<List<AttestedApp>, List<String>> {
        val apps = mutableListOf<AttestedApp>()
        val digests = mutableListOf<String>()
        val top = DerReader(der)
        val seq = top.next()
        val r = top.reader(seq)

        val packageSet = r.next()
        val packages = r.reader(packageSet)
        while (packages.hasNext()) {
            val infoTlv = packages.next()
            val info = packages.reader(infoTlv)
            val name = info.string(info.next())
            val version = if (info.hasNext()) info.long(info.next()) else 0L
            apps += AttestedApp(name, version)
        }

        if (r.hasNext()) {
            val digestSet = r.next()
            val ds = r.reader(digestSet)
            while (ds.hasNext()) digests += ds.bytes(ds.next()).toHex()
        }
        return apps to digests
    }

    private fun securityLevel(v: Int) = when (v) {
        0 -> SecurityLevel.SOFTWARE
        1 -> SecurityLevel.TRUSTED_ENVIRONMENT
        2 -> SecurityLevel.STRONGBOX
        else -> SecurityLevel.UNKNOWN
    }

    private fun verifiedBootState(v: Int) = when (v) {
        0 -> VerifiedBootState.VERIFIED
        1 -> VerifiedBootState.SELF_SIGNED
        2 -> VerifiedBootState.UNVERIFIED
        3 -> VerifiedBootState.FAILED
        else -> VerifiedBootState.UNKNOWN
    }

    /** osVersion is encoded major*10000 + minor*100 + sub. */
    private fun formatOsVersion(v: Long): String {
        if (v == 0L) return "0 (not set)"
        return "${v / 10000}.${(v / 100) % 100}.${v % 100}"
    }

    /** osPatchLevel is YYYYMM. */
    private fun formatYearMonth(v: Long): String {
        val s = v.toString().padStart(6, '0')
        return if (s.length == 6) "${s.substring(0, 4)}-${s.substring(4, 6)}" else s
    }

    /** vendorPatchLevel / bootPatchLevel are YYYYMMDD. */
    private fun formatPatchDate(v: Long): String {
        val s = v.toString()
        return if (s.length == 8) "${s.substring(0, 4)}-${s.substring(4, 6)}-${s.substring(6, 8)}"
        else formatYearMonth(v)
    }
}
