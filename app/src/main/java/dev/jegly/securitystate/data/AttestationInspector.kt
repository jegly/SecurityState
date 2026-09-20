package dev.jegly.securitystate.data

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Generates a throwaway hardware-backed key at each available security level and decodes the
 * attestation certificate it comes back with.
 *
 * Deliberately probes *every* level rather than asking the user to pick one: which levels exist
 * is itself the diagnostic. StrongBox is tried first, then TEE, then plain software.
 *
 * This is an inspector, not a gate. Google's guidance is to verify attestation server-side,
 * because on a compromised device the verifying code is compromised too. The UI says so.
 */
class AttestationInspector(private val context: Context) {

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    fun features() = Triple(
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE),
        context.packageManager.hasSystemFeature("android.hardware.keystore.app_attest_key"),
        context.packageManager.hasSystemFeature("android.software.device_id_attestation"),
    )

    suspend fun inspect(verifyChainOnline: Boolean): HardwareState = withContext(Dispatchers.IO) {
        val (strongBox, attestKey, idAttest) = features()
        val roots = if (verifyChainOnline) fetchRoots() else emptyList()
        val crl = if (verifyChainOnline) fetchRevocations() else null

        val levels = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) add(SecurityLevel.STRONGBOX)
            add(SecurityLevel.TRUSTED_ENVIRONMENT)
        }

        val probes = levels.map { level ->
            probe(level, verifyChainOnline, roots, crl)
        }
        HardwareState(probes, strongBox, attestKey, idAttest)
    }

    private fun probe(
        level: SecurityLevel,
        verifyOnline: Boolean,
        roots: List<X509Certificate>,
        crl: Map<String, Pair<String, String>>?,
    ): AttestationProbe {
        val alias = "ssi_probe_${level.name.lowercase()}_${System.nanoTime()}"
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val wantStrongBox = level == SecurityLevel.STRONGBOX

        // Device-properties attestation throws on some OEMs; fall back without it.
        var withProps = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
        var chain: Array<java.security.cert.Certificate>? = null
        var failure: Throwable? = null

        for (attempt in 0..1) {
            try {
                generate(alias, challenge, wantStrongBox, withProps)
                chain = keyStore.getCertificateChain(alias)
                failure = null
                break
            } catch (e: StrongBoxUnavailableException) {
                cleanup(alias)
                return AttestationProbe(
                    requestedLevel = level,
                    outcome = ProbeOutcome.UNAVAILABLE,
                    record = null,
                    chain = emptyList(),
                    verdict = ChainVerdict(ChainTrust.NOT_CHECKED, null, null, null, ""),
                    devicePropertiesRequested = withProps,
                    message = "No StrongBox on this device (no separate secure element).",
                )
            } catch (e: Throwable) {
                cleanup(alias)
                failure = e
                if (attempt == 0 && withProps) {
                    withProps = false // retry without device-properties attestation
                    continue
                }
                break
            }
        }

        if (chain == null || chain.isEmpty()) {
            return AttestationProbe(
                level, ProbeOutcome.FAILED, null, emptyList(),
                ChainVerdict(ChainTrust.NOT_CHECKED, null, null, null, ""),
                withProps,
                "Key generation failed: ${failure?.javaClass?.simpleName}: ${failure?.message}",
            )
        }

        try {
            val x509 = chain.filterIsInstance<X509Certificate>()
            val leaf = x509.first()
            val ext = leaf.getExtensionValue(AttestationParser.OID)
            val record = ext?.let {
                // The extension value is an OCTET STRING wrapping the real DER.
                val r = DerReader(it)
                val octet = r.next()
                runCatching { AttestationParser.parse(r.bytes(octet), challenge) }.getOrNull()
            }
            val summaries = x509.map {
                CertSummary(
                    subject = it.subjectX500Principal.name,
                    issuer = it.issuerX500Principal.name,
                    serialHex = it.serialNumber.toString(16),
                    notAfter = it.notAfter.time,
                )
            }
            val verdict = if (verifyOnline) verify(x509, roots, crl)
            else ChainVerdict(
                ChainTrust.NOT_CHECKED, null, null, null,
                "Chain not verified - online verification is off.",
            )

            return AttestationProbe(
                requestedLevel = level,
                outcome = if (record != null) ProbeOutcome.ATTESTED else ProbeOutcome.FAILED,
                record = record,
                chain = summaries,
                verdict = verdict,
                devicePropertiesRequested = withProps,
                message = when {
                    record == null -> "Certificate had no parsable attestation extension."
                    !withProps -> "Device-properties attestation unsupported; probed without it."
                    else -> ""
                },
            )
        } finally {
            cleanup(alias)
        }
    }

    private fun generate(alias: String, challenge: ByteArray, strongBox: Boolean, props: Boolean) {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)

        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        if (props && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setDevicePropertiesAttestationIncluded(true)
        }

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
            initialize(builder.build())
            generateKeyPair()
        }
    }

    private fun cleanup(alias: String) {
        runCatching { if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias) }
    }

    // ------------------------------------------------------------ chain trust

    private fun verify(
        chain: List<X509Certificate>,
        roots: List<X509Certificate>,
        crl: Map<String, Pair<String, String>>?,
    ): ChainVerdict {
        if (chain.isEmpty()) {
            return ChainVerdict(ChainTrust.BROKEN, null, null, null, "Empty certificate chain.")
        }

        // 1. Each certificate must be signed by the next one up.
        for (i in 0 until chain.size - 1) {
            val result = runCatching { chain[i].verify(chain[i + 1].publicKey) }
            if (result.isFailure) {
                return ChainVerdict(
                    ChainTrust.BROKEN, null, null, null,
                    "Link ${i + 1} of the chain is not signed by its issuer.",
                )
            }
        }

        // 2. Revocation - serials are lowercase hex with leading zeros stripped.
        crl?.let { list ->
            chain.forEach { cert ->
                val serial = cert.serialNumber.toString(16)
                list[serial]?.let { (status, reason) ->
                    return ChainVerdict(
                        ChainTrust.REVOKED, null, serial, reason,
                        "Attestation key $status ($reason). This batch's key material is known bad.",
                    )
                }
            }
        }

        // 3. The top of the chain must be, or be signed by, a Google attestation root.
        val top = chain.last()
        val topSpki = spkiSha256(top)
        val pinned = topSpki in PINNED_ROOT_SPKI_SHA256
        val matchesFetched = roots.any { spkiSha256(it) == topSpki } ||
            roots.any { root -> runCatching { top.verify(root.publicKey) }.isSuccess }

        return if (pinned || matchesFetched) {
            ChainVerdict(
                ChainTrust.TRUSTED,
                top.subjectX500Principal.name,
                null,
                null,
                if (pinned) "Chains to a pinned Google attestation root."
                else "Chains to a Google attestation root fetched from android.googleapis.com.",
            )
        } else {
            ChainVerdict(
                ChainTrust.UNTRUSTED_ROOT,
                top.subjectX500Principal.name,
                null,
                null,
                "Chain is internally consistent but its root is not a Google attestation root. " +
                    "Expected on devices that are not Play-certified, and on emulators.",
            )
        }
    }

    private fun spkiSha256(cert: X509Certificate): String =
        MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded).toHex()

    private suspend fun fetchRoots(): List<X509Certificate> = runCatching {
        val body = Http.getText(ROOT_URL).replace("\\n", "\n")
        val cf = CertificateFactory.getInstance("X.509")
        PEM.findAll(body).mapNotNull { m ->
            runCatching {
                cf.generateCertificate(m.value.byteInputStream()) as X509Certificate
            }.getOrNull()
        }.toList()
    }.onFailure { Log.w(TAG, "root fetch failed", it) }.getOrDefault(emptyList())

    /** serial(hex) -> (status, reason) */
    private suspend fun fetchRevocations(): Map<String, Pair<String, String>>? = runCatching {
        val body = Http.getText(STATUS_URL)
        val out = HashMap<String, Pair<String, String>>()
        // Small hand-rolled scan: the payload is a flat {"entries":{serial:{status,reason}}} map.
        ENTRY.findAll(body).forEach { m ->
            val serial = m.groupValues[1].lowercase()
            val blob = m.groupValues[2]
            val status = FIELD("status").find(blob)?.groupValues?.get(1) ?: "REVOKED"
            val reason = FIELD("reason").find(blob)?.groupValues?.get(1) ?: "UNSPECIFIED"
            out[serial] = status to reason
        }
        out
    }.onFailure { Log.w(TAG, "revocation fetch failed", it) }.getOrNull()

    private companion object {
        const val TAG = "AttestationInspector"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ROOT_URL = "https://android.googleapis.com/attestation/root"
        const val STATUS_URL = "https://android.googleapis.com/attestation/status"

        val PEM = Regex("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----")
        val ENTRY = Regex("\"([0-9a-fA-F]+)\"\\s*:\\s*\\{([^}]*)\\}")
        fun FIELD(name: String) = Regex("\"$name\"\\s*:\\s*\"([^\"]*)\"")

        /**
         * SHA-256 of the SubjectPublicKeyInfo of Google's two live attestation roots, so the app
         * can still recognise a genuine root with the network toggle off.
         *
         *  - f92009e853b6b045        RSA,  valid 2022-03-20 .. 2042-03-15
         *  - CN=Key Attestation CA1  EC,   valid 2025-07-17 .. 2035-07-15, signing from 2026-02-01
         *
         * Newer hardware (Pixel 11 / Titan M3) chains to the EC root; older (Pixel 6a) to the RSA.
         */
        val PINNED_ROOT_SPKI_SHA256 = setOf(
            "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
            "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
        )
    }
}
