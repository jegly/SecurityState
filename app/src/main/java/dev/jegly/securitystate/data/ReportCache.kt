package dev.jegly.securitystate.data

import android.content.Context
import java.io.File

/** Caches the monthly OSV report on disk so launches are offline-first. */
class ReportCache(context: Context) {
    private val file = File(context.filesDir, "osv_report.json")
    private val stamp = File(context.filesDir, "osv_report.stamp")

    fun read(): Pair<String, Long>? {
        if (!file.exists()) return null
        val json = runCatching { file.readText() }.getOrNull() ?: return null
        val at = runCatching { stamp.readText().trim().toLong() }.getOrNull() ?: file.lastModified()
        return json to at
    }

    fun write(json: String, atMillis: Long) {
        runCatching {
            file.writeText(json)
            stamp.writeText(atMillis.toString())
        }
    }
}
