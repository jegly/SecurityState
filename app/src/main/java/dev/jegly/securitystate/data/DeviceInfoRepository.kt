package dev.jegly.securitystate.data

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.hardware.display.DisplayManager
import android.os.SystemClock
import android.view.Display
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/**
 * Reads live device telemetry from public APIs and world-readable sysfs/procfs nodes.
 *
 * Everything here is permission-free. Where a value is gated (most SoC thermal zones on recent
 * Pixels block untrusted_app via SELinux), the read fails softly and the field is simply absent
 * rather than faked.
 */
class DeviceInfoRepository(private val context: Context) {

    suspend fun snapshot(): DeviceInfo = withContext(Dispatchers.IO) {
        val cpuBefore = readProcStat()
        delay(300) // sample window for CPU usage
        val cpuAfter = readProcStat()
        val usage = cpuUsage(cpuBefore, cpuAfter)

        val cores = (0 until cpuCount()).map { i ->
            CoreInfo(
                index = i,
                curKhz = readLong("/sys/devices/system/cpu/cpu$i/cpufreq/scaling_cur_freq"),
                minKhz = readLong("/sys/devices/system/cpu/cpu$i/cpufreq/cpuinfo_min_freq"),
                maxKhz = readLong("/sys/devices/system/cpu/cpu$i/cpufreq/cpuinfo_max_freq"),
                governor = readText("/sys/devices/system/cpu/cpu$i/cpufreq/scaling_governor"),
                online = readText("/sys/devices/system/cpu/cpu$i/online")?.trim() != "0",
                usagePercent = usage.perCore.getOrNull(i),
            )
        }

        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mem = ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }
        val meminfo = readMemInfo()

        val dataDir = context.filesDir
        val stat = android.os.StatFs(dataDir.absolutePath)

        val battery = readBattery()

        val dm = context.resources.displayMetrics
        // DisplayManager works from any context (Application included); context.display does not.
        val display = runCatching {
            (context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager)
                .getDisplay(Display.DEFAULT_DISPLAY)
        }.getOrNull()
        val refresh = display?.refreshRate ?: 0f

        DeviceInfo(
            socManufacturer = if (Build.VERSION.SDK_INT >= 31) Build.SOC_MANUFACTURER.orDashNull() else null,
            socModel = if (Build.VERSION.SDK_INT >= 31) Build.SOC_MODEL.orDashNull() else null,
            board = Build.BOARD,
            hardware = Build.HARDWARE,
            abis = Build.SUPPORTED_ABIS.toList(),
            cpuCores = cores.size,
            cores = cores,
            cpuUsagePercent = usage.total,
            ramTotalBytes = mem.totalMem,
            ramAvailBytes = mem.availMem,
            ramLow = mem.lowMemory,
            ramThresholdBytes = mem.threshold,
            swapTotalBytes = meminfo["SwapTotal"]?.times(1024),
            storageTotalBytes = stat.totalBytes,
            storageFreeBytes = stat.availableBytes,
            batteryPercent = battery.percent,
            batteryTempC = battery.tempC,
            batteryVoltageMv = battery.voltageMv,
            batteryTech = battery.tech,
            batteryHealth = battery.health,
            batteryStatus = battery.status,
            thermalZones = readThermalZones(),
            screenWidth = dm.widthPixels,
            screenHeight = dm.heightPixels,
            densityDpi = dm.densityDpi,
            refreshHz = refresh,
            kernel = readText("/proc/version")?.trim() ?: System.getProperty("os.version"),
            uptimeMillis = SystemClock.elapsedRealtime(),
            androidRelease = Build.VERSION.RELEASE,
            sdkInt = Build.VERSION.SDK_INT,
        )
    }

    // -------- CPU

    private fun cpuCount(): Int =
        (File("/sys/devices/system/cpu").listFiles { f -> f.name.matches(Regex("cpu[0-9]+")) }?.size)
            ?.takeIf { it > 0 } ?: Runtime.getRuntime().availableProcessors()

    private data class Jiffies(val idle: Long, val total: Long)
    private data class CpuUsage(val total: Int?, val perCore: List<Int?>)

    private fun readProcStat(): Map<String, Jiffies> {
        val out = HashMap<String, Jiffies>()
        runCatching {
            File("/proc/stat").readLines().forEach { line ->
                if (!line.startsWith("cpu")) return@forEach
                val parts = line.trim().split(Regex("\\s+"))
                val name = parts[0]
                val nums = parts.drop(1).mapNotNull { it.toLongOrNull() }
                if (nums.size >= 5) {
                    val idle = nums[3] + (nums.getOrElse(4) { 0 }) // idle + iowait
                    out[name] = Jiffies(idle, nums.sum())
                }
            }
        }
        return out
    }

    private fun cpuUsage(before: Map<String, Jiffies>, after: Map<String, Jiffies>): CpuUsage {
        fun pct(a: Jiffies?, b: Jiffies?): Int? {
            if (a == null || b == null) return null
            val dTotal = b.total - a.total
            val dIdle = b.idle - a.idle
            if (dTotal <= 0) return null
            return (((dTotal - dIdle).toDouble() / dTotal) * 100).toInt().coerceIn(0, 100)
        }
        val total = pct(before["cpu"], after["cpu"])
        val n = maxOf(before.keys.count { it != "cpu" }, after.keys.count { it != "cpu" })
        val per = (0 until n).map { pct(before["cpu$it"], after["cpu$it"]) }
        return CpuUsage(total, per)
    }

    // -------- memory

    private fun readMemInfo(): Map<String, Long> {
        val out = HashMap<String, Long>()
        runCatching {
            File("/proc/meminfo").readLines().forEach { line ->
                val m = Regex("^(\\w+):\\s+(\\d+)").find(line) ?: return@forEach
                out[m.groupValues[1]] = m.groupValues[2].toLong()
            }
        }
        return out
    }

    // -------- battery

    private data class Battery(
        val percent: Int?, val tempC: Float?, val voltageMv: Int?,
        val tech: String?, val health: String?, val status: String?,
    )

    private fun readBattery(): Battery {
        val i: Intent? = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = i?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = i?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val percent = if (level >= 0 && scale > 0) (level * 100 / scale) else null
        val tempTenths = i?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE) ?: Int.MIN_VALUE
        val tempC = if (tempTenths != Int.MIN_VALUE) tempTenths / 10f else null
        val voltage = i?.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1)?.takeIf { it > 0 }
        return Battery(
            percent, tempC, voltage,
            i?.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY),
            healthName(i?.getIntExtra(BatteryManager.EXTRA_HEALTH, -1) ?: -1),
            statusName(i?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1),
        )
    }

    private fun healthName(v: Int) = when (v) {
        BatteryManager.BATTERY_HEALTH_GOOD -> "Good"
        BatteryManager.BATTERY_HEALTH_OVERHEAT -> "Overheat"
        BatteryManager.BATTERY_HEALTH_DEAD -> "Dead"
        BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "Over voltage"
        BatteryManager.BATTERY_HEALTH_COLD -> "Cold"
        BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "Failure"
        else -> null
    }

    private fun statusName(v: Int) = when (v) {
        BatteryManager.BATTERY_STATUS_CHARGING -> "Charging"
        BatteryManager.BATTERY_STATUS_DISCHARGING -> "Discharging"
        BatteryManager.BATTERY_STATUS_FULL -> "Full"
        BatteryManager.BATTERY_STATUS_NOT_CHARGING -> "Not charging"
        else -> null
    }

    // -------- thermal (best effort; often blocked by SELinux on recent devices)

    private fun readThermalZones(): List<ThermalZone> {
        val base = File("/sys/class/thermal")
        val zones = base.listFiles { f -> f.name.startsWith("thermal_zone") } ?: return emptyList()
        return zones.mapNotNull { z ->
            val milli = readLong("${z.absolutePath}/temp") ?: return@mapNotNull null
            val type = readText("${z.absolutePath}/type")?.trim() ?: z.name
            val c = milli / 1000f
            if (c <= 0f || c > 200f) null else ThermalZone(type, c)
        }.sortedByDescending { it.celsius }.take(12)
    }

    // -------- helpers

    private fun readText(path: String): String? =
        runCatching { File(path).readText().trim() }.getOrNull()?.ifEmpty { null }

    private fun readLong(path: String): Long? = readText(path)?.trim()?.toLongOrNull()

    private fun String?.orDashNull(): String? = this?.takeIf { it.isNotBlank() && it != "unknown" }
}
