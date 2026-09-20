package dev.jegly.securitystate.data

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Enumerates installed apps and checks, for each Google-looking package, whether it is actually
 * signed by a known Google signing certificate and where it was installed from.
 *
 * This is signature verification, not hardware attestation: there is no API to attest another
 * app's binary to the hardware root. But comparing a package's signer against Google's known certs
 * reliably catches a repackaged app masquerading under a com.google.* name. With Play App Signing
 * some legitimate Google apps use per-app keys, so a non-match means "unconfirmed", never "fake".
 */
class AppVerifier(private val context: Context) {

    suspend fun scan(): AppInventory = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
        }

        val all = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION") pm.getInstalledPackages(flags)
            }
        }.getOrDefault(emptyList())

        // If package visibility is restricted we still see our own + a few; note that.
        val couldEnumerateAll = all.size > 20

        val google = all.mapNotNull { pkgInfo ->
            val pkg = pkgInfo.packageName
            val signers = signerDigests(pkgInfo)
            val signedByGoogle = signers.any { it in KNOWN_GOOGLE_SIGNERS }
            val looksGoogle = pkg.startsWith("com.google.") ||
                pkg == "com.android.vending" || pkg == "com.android.chrome" || signedByGoogle
            if (!looksGoogle) return@mapNotNull null

            val app = pkgInfo.applicationInfo
            val label = app?.let { pm.getApplicationLabel(it).toString() } ?: pkg
            val system = app != null &&
                (app.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
            val installer = installerOf(pm, pkg)

            val fromPlay = installer == "com.android.vending"
            val trust = when {
                signedByGoogle -> AppTrust.SIGNER_GOOGLE
                system -> AppTrust.SYSTEM_IMAGE
                fromPlay -> AppTrust.PLAY
                else -> AppTrust.SIDELOADED
            }
            InstalledApp(
                packageName = pkg,
                label = label,
                versionName = pkgInfo.versionName,
                signerSha256 = signers,
                signedByGoogle = signedByGoogle,
                installer = installer,
                fromPlay = fromPlay,
                system = system,
                trust = trust,
            )
        }.sortedWith(
            // Surface anything to review first, then by trust tier, then name.
            compareBy<InstalledApp> { it.trusted }.thenBy { it.trust }.thenBy { it.label.lowercase() },
        )

        AppInventory(google, all.size, couldEnumerateAll)
    }

    private fun signerDigests(pkgInfo: android.content.pm.PackageInfo): List<String> {
        val md = MessageDigest.getInstance("SHA-256")
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val si = pkgInfo.signingInfo ?: return emptyList()
                val sigs = if (si.hasMultipleSigners()) si.apkContentsSigners
                else si.signingCertificateHistory
                sigs.map { md.digest(it.toByteArray()).toHex() }
            } else {
                @Suppress("DEPRECATION")
                (pkgInfo.signatures ?: emptyArray()).map { md.digest(it.toByteArray()).toHex() }
            }
        }.getOrDefault(emptyList())
    }

    private fun installerOf(pm: PackageManager, pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
        }
    }.getOrNull()

    private companion object {
        /**
         * SHA-256 of Google signing certificates. The first is the long-standing Google release
         * cert used by the GMS app family; extend as more are confirmed.
         */
        val KNOWN_GOOGLE_SIGNERS = setOf(
            "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83",
        )
    }
}
