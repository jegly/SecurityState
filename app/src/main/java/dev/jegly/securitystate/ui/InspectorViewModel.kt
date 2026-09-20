package dev.jegly.securitystate.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.jegly.securitystate.data.AppInventory
import dev.jegly.securitystate.data.AppVerifier
import dev.jegly.securitystate.data.AttestationInspector
import dev.jegly.securitystate.data.HardwareState
import dev.jegly.securitystate.data.OverallGrader
import dev.jegly.securitystate.data.OverallVerdict
import dev.jegly.securitystate.data.SecurityStateRepository
import dev.jegly.securitystate.data.SoftwareState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class UiState(
    val loading: Boolean = false,
    val software: SoftwareState? = null,
    val hardware: HardwareState? = null,
    val apps: AppInventory? = null,
    val overall: OverallVerdict? = null,
    val verifyChainOnline: Boolean = true,
    val cveInput: String = "",
    val cveResult: CveResult? = null,
    val error: String? = null,
)

data class CveResult(val cves: List<String>, val allPatched: Boolean?)

class InspectorViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = SecurityStateRepository(app)
    private val attestation = AttestationInspector(app)
    private val appVerifier = AppVerifier(app)

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    init { refresh() }

    fun setVerifyChainOnline(enabled: Boolean) {
        _state.value = _state.value.copy(verifyChainOnline = enabled)
    }

    fun setCveInput(text: String) {
        _state.value = _state.value.copy(cveInput = text)
    }

    fun refresh() {
        val online = _state.value.verifyChainOnline
        _state.value = _state.value.copy(loading = true, error = null)
        viewModelScope.launch {
            val software = runCatching { repo.load(preferNetworkReport = online) }
                .getOrElse { _state.value = _state.value.copy(error = it.message); null }
            val hardware = runCatching { attestation.inspect(online) }
                .getOrElse { _state.value = _state.value.copy(error = it.message); null }
            val apps = runCatching { appVerifier.scan() }.getOrNull()
            val overall = OverallGrader.grade(software, hardware, apps)
            _state.value = _state.value.copy(
                loading = false, software = software, hardware = hardware,
                apps = apps, overall = overall,
            )
        }
    }

    fun checkCves() {
        val cves = _state.value.cveInput
            .split(Regex("[,\\s]+"))
            .map { it.trim().uppercase() }
            .filter { it.startsWith("CVE-") }
        if (cves.isEmpty()) {
            _state.value = _state.value.copy(cveResult = CveResult(emptyList(), null))
            return
        }
        viewModelScope.launch {
            val patched = repo.checkCves(cves)
            _state.value = _state.value.copy(cveResult = CveResult(cves, patched))
        }
    }
}
