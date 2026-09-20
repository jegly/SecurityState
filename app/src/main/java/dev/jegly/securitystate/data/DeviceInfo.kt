package dev.jegly.securitystate.data

data class CoreInfo(
    val index: Int,
    val curKhz: Long?,
    val minKhz: Long?,
    val maxKhz: Long?,
    val governor: String?,
    val online: Boolean,
    val usagePercent: Int?,
)

data class ThermalZone(val label: String, val celsius: Float)

data class DeviceInfo(
    // SoC / identity
    val socManufacturer: String?,
    val socModel: String?,
    val board: String?,
    val hardware: String?,
    val abis: List<String>,
    val cpuCores: Int,
    val cores: List<CoreInfo>,
    val cpuUsagePercent: Int?,
    // memory
    val ramTotalBytes: Long,
    val ramAvailBytes: Long,
    val ramLow: Boolean,
    val ramThresholdBytes: Long,
    val swapTotalBytes: Long?,
    // storage
    val storageTotalBytes: Long,
    val storageFreeBytes: Long,
    // battery + thermal
    val batteryPercent: Int?,
    val batteryTempC: Float?,
    val batteryVoltageMv: Int?,
    val batteryTech: String?,
    val batteryHealth: String?,
    val batteryStatus: String?,
    val thermalZones: List<ThermalZone>,
    // display
    val screenWidth: Int,
    val screenHeight: Int,
    val densityDpi: Int,
    val refreshHz: Float,
    // system
    val kernel: String?,
    val uptimeMillis: Long,
    val androidRelease: String,
    val sdkInt: Int,
)
