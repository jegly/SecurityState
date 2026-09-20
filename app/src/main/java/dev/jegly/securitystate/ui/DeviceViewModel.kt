package dev.jegly.securitystate.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.jegly.securitystate.data.DeviceInfo
import dev.jegly.securitystate.data.DeviceInfoRepository
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class DeviceViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = DeviceInfoRepository(app)

    private val _info = MutableStateFlow<DeviceInfo?>(null)
    val info: StateFlow<DeviceInfo?> = _info.asStateFlow()

    private var pollJob: Job? = null

    /** Poll while the tab is visible; stop when it is not, to save power and avoid self-heating. */
    fun startPolling() {
        if (pollJob?.isActive == true) return
        pollJob = viewModelScope.launch {
            while (isActive) {
                _info.value = runCatching { repo.snapshot() }.getOrNull() ?: _info.value
                delay(2000)
            }
        }
    }

    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }
}
