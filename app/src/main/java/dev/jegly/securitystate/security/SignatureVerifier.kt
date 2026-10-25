package dev.jegly.securitystate.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

/**
 * Repackaging / tamper detection for this app itself (distinct from [dev.jegly.securitystate.data.AppVerifier],
 * which inspects other apps). Compares the running APK's current signing certificate against the
 * pinned release certificate; a re-signed build fails and the app refuses to run.
 *
 * Defense-in-depth, not a security boundary: an attacker who can patch this file can remove it.
 */
object SignatureVerifier {

    // Expected signing-cert SHA-256 digests, stored XOR-masked (never as greppable hex — string
    // literals survive R8) and compared as raw bytes. M = jegly key0 (98d324d4…),
    // P = ML-DSA-87 PQC key (5f99de5b…).
    // API 37+ verifies the APK Signature Scheme v3.2 hybrid block, so the current signer is the PQC
    // key there. key0 is deliberately NOT accepted on API 37+: an APK re-signed with only key0 would
    // otherwise pass. Older releases ignore v3.2 and still see key0.
    private val K = intArrayOf(0x41, 0x03, 0x8C, 0x77, 0x13, 0x01, 0x00, 0xA0, 0x8D)
    private val M = intArrayOf(
        0xD9, 0xD0, 0xA8, 0xA3, 0x03, 0x6B, 0x36, 0x2C, 0xEF, 0x33, 0x99, 0x86, 0x53, 0xCA, 0xAD, 0x9A,
        0xCB, 0xCA, 0xB9, 0xAF, 0xC0, 0x12, 0x96, 0x35, 0x85, 0x91, 0x7D, 0xAF, 0x4D, 0x3A, 0xD7, 0x5F,
    )
    private val P = intArrayOf(
        0x1E, 0x9A, 0x52, 0x2C, 0x22, 0x94, 0x75, 0x9D, 0xC2, 0xA9, 0xDE, 0x27, 0x9C, 0xC1, 0xFA, 0x27,
        0x95, 0xE6, 0x60, 0x0A, 0x5A, 0x8C, 0xA1, 0x46, 0x1F, 0x6B, 0x30, 0xB3, 0x19, 0x12, 0x01, 0xB5,
    )

    /** Reconstruct the expected 32-byte cert digest from the masked form (never materialized as hex). */
    private fun expected(): ByteArray {
        val masked = if (Build.VERSION.SDK_INT >= 37) P else M
        return ByteArray(masked.size) { (masked[it] xor K[it % K.size]).toByte() }
    }

    /**
     * True if the running APK's current signer is the pinned release certificate, or if this is a
     * debuggable build (signed per-machine with ~/.android/debug.keystore, nothing stable to pin).
     * Fails closed: any error returns false.
     */
    fun isSignedByTrustedCert(context: Context): Boolean {
        if ((context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) return true
        return try {
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES,
                )
                // Current signer only — never signingCertificateHistory, which still contains key0.
                info.signingInfo?.apkContentsSigners ?: return false
            } else {
                // Pre-P has no key rotation; the only signer is key0.
                @Suppress("DEPRECATION")
                val info = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES,
                )
                @Suppress("DEPRECATION")
                info.signatures ?: return false
            }
            val md = MessageDigest.getInstance("SHA-256")
            val want = expected()
            signatures.any { md.digest(it.toByteArray()).contentEquals(want) }
        } catch (_: Exception) {
            false
        }
    }
}
