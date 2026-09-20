package dev.jegly.securitystate.data

/**
 * Reduces the software + hardware findings to one headline verdict with supporting reasons.
 *
 * Grade rules:
 *  - AT_RISK  if any hard integrity failure: bootloader unlocked, verified boot not VERIFIED,
 *             or an attested chain that is REVOKED / broken / untrusted.
 *  - ATTENTION if integrity is sound but patches are behind the published bulletin.
 *  - SECURE   if fully updated AND a hardware-attested, locked, verified, Google-rooted key exists.
 *  - UNKNOWN  if we could not establish enough to judge.
 */
object OverallGrader {

    fun grade(software: SoftwareState?, hardware: HardwareState?, apps: AppInventory? = null): OverallVerdict {
        val good = mutableListOf<String>()
        val warn = mutableListOf<String>()
        val bad = mutableListOf<String>()
        val info = mutableListOf<String>()

        val attested = hardware?.probes?.filter { it.outcome == ProbeOutcome.ATTESTED && it.record != null }
            .orEmpty()
        val best = attested.firstOrNull { it.requestedLevel == SecurityLevel.STRONGBOX }
            ?: attested.firstOrNull()

        // ---- hardware integrity
        if (best?.record != null) {
            val rot = best.record.rootOfTrust
            when {
                rot == null -> warn += "Attestation returned no root-of-trust block."
                rot.verifiedBootState != VerifiedBootState.VERIFIED ->
                    bad += "Verified boot is ${rot.verifiedBootState.name}, not VERIFIED."
                else -> good += "Verified boot: VERIFIED."
            }
            if (rot != null) {
                if (rot.deviceLocked) good += "Bootloader is locked."
                else bad += "Bootloader is UNLOCKED."
            }
            when (best.verdict.trust) {
                ChainTrust.TRUSTED -> good += "Attestation chains to a Google root."
                ChainTrust.REVOKED -> bad += "Attestation key is REVOKED."
                ChainTrust.UNTRUSTED_ROOT -> bad += "Attestation root is not a Google root."
                ChainTrust.BROKEN -> bad += "Attestation certificate chain is broken."
                ChainTrust.NOT_CHECKED -> warn += "Attestation chain not verified (offline)."
                ChainTrust.OFFLINE -> warn += "Could not verify chain (offline)."
            }
            if (best.record.attestationSecurityLevel == SecurityLevel.STRONGBOX)
                good += "Key is StrongBox-backed (dedicated secure element)."
        } else {
            warn += "No hardware attestation was obtained."
        }

        // ---- software patch posture
        // Only an actually-installable update is actionable. Being behind the published bulletin
        // with nothing offered (common on Beta/DP, or mid-rollout) is informational, not a warning.
        if (software == null) {
            warn += "Patch compliance not evaluated (no vulnerability report)."
        } else {
            var installable = 0
            software.components.forEach { c ->
                if (c.status == Status.PENDING_UPDATE) {
                    warn += "${c.label}: update available (${c.availableSpl}). Install it."
                    installable++
                }
            }
            if (installable == 0) good += "On the latest build available; no updates pending."
        }

        // ---- app provenance
        apps?.let { inv ->
            val review = inv.review
            when {
                review.isNotEmpty() ->
                    bad += "${review.size} Google-named app(s) are sideloaded, not from Play or the " +
                        "system image: ${review.take(3).joinToString { it.packageName }}" +
                        (if (review.size > 3) ", ..." else "") + "."
                inv.googleApps.isNotEmpty() ->
                    good += "All ${inv.googleApps.size} Google apps are from the system image or Play."
            }
        }

        val grade = when {
            bad.isNotEmpty() -> Grade.AT_RISK
            best?.record == null && software == null -> Grade.UNKNOWN
            warn.isNotEmpty() -> Grade.ATTENTION
            else -> Grade.SECURE
        }

        val headline = when (grade) {
            Grade.SECURE -> "Device looks secure"
            Grade.ATTENTION -> "Action recommended"
            Grade.AT_RISK -> "Security concerns found"
            Grade.UNKNOWN -> "Not enough data"
        }

        return OverallVerdict(grade, headline, good, warn, bad, info)
    }
}
