package com.bettermifitness.sync.ui.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.bettermifitness.sync.data.MiRegionDiscovery
import com.bettermifitness.sync.data.MiSessionManager
import com.bettermifitness.sync.data.preferences.CredentialsStore
import com.bettermifitness.sync.i18n.L10n
import com.mifitness.miclient.auth.LoginResult
import com.mifitness.miclient.auth.MiAuth
import com.mifitness.miclient.auth.MiCredentials
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

enum class LoginStep {
    Credentials,
    Otp,
    BrowserFallback,
}

data class LoginUiState(
    val step: LoginStep = LoginStep.Credentials,
    val email: String = "",
    val password: String = "",
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val otpMaskedTarget: String = "",
    val loginSucceeded: Boolean = false,
    val browserLoginUrl: String = "",
)

class LoginViewModel(
    private val miAuth: MiAuth,
    private val sessionManager: MiSessionManager,
    private val credentialsStore: CredentialsStore,
    private val regionDiscovery: MiRegionDiscovery,
) : ViewModel() {

    val uiState: StateFlow<LoginUiState>
        field = MutableStateFlow(LoginUiState())

    private var otpChallenge: LoginResult.OtpRequired? = null

    /**
     * When true, Back on browser returns to OTP (user chose browser from OTP).
     * When false, Back returns to credentials (OTP was skipped — e.g. send rate-limited).
     */
    private var browserBackGoesToOtp: Boolean = false

    fun onEmailChange(value: String) {
        uiState.update { it.copy(email = value) }
    }

    fun onPasswordChange(value: String) {
        uiState.update { it.copy(password = value) }
    }

    fun signIn() {
        val email = uiState.value.email.trim()
        val password = uiState.value.password
        if (email.isBlank() || password.isBlank()) return

        viewModelScope.launch {
            uiState.update { it.copy(isLoading = true, errorMessage = null) }
            try {
                val deviceId = credentialsStore.ensureDeviceId()
                when (val result = miAuth.login(email = email, password = password, deviceId = deviceId)) {
                    is LoginResult.Success -> persistAndSucceed(result.credentials)
                    is LoginResult.OtpRequired -> {
                        otpChallenge = result
                        // 87001 (2FA) and 81003 (captcha) never produce an email OTP:
                        // route straight to browser instead of stranding the user.
                        // A real OTP challenge always carries notificationUrl.
                        if (result.notificationUrl.isBlank()) {
                            browserBackGoesToOtp = false
                            otpChallenge = null
                            val url = browserLoginUrl()
                            uiState.update {
                                it.copy(
                                    isLoading = false,
                                    step = LoginStep.BrowserFallback,
                                    otpMaskedTarget = "",
                                    browserLoginUrl = url,
                                    errorMessage = L10n.text(L10n.loginBrowserRequired),
                                )
                            }
                            return@launch
                        }
                        try {
                            result.sendOtp()
                            browserBackGoesToOtp = false
                            uiState.update {
                                it.copy(
                                    isLoading = false,
                                    step = LoginStep.Otp,
                                    otpMaskedTarget = result.maskedTarget,
                                    errorMessage = null,
                                )
                            }
                        } catch (e: Exception) {
                            // Rate-limit / send failure: skip OTP UI entirely.
                            browserBackGoesToOtp = false
                            otpChallenge = null
                            val url = browserLoginUrl()
                            uiState.update {
                                it.copy(
                                    isLoading = false,
                                    step = LoginStep.BrowserFallback,
                                    otpMaskedTarget = "",
                                    browserLoginUrl = url,
                                    errorMessage = e.message ?: L10n.text(L10n.loginSendCodeFailed),
                                )
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                uiState.update {
                    it.copy(isLoading = false, errorMessage = e.message ?: L10n.text(L10n.loginFailed))
                }
            }
        }
    }

    fun verifyOtp(code: String) {
        val challenge = otpChallenge ?: return
        viewModelScope.launch {
            uiState.update { it.copy(isLoading = true, errorMessage = null) }
            try {
                val credentials = challenge.verifyOtp(code)
                persistAndSucceed(credentials)
            } catch (e: Exception) {
                val msg = e.message ?: L10n.text(L10n.loginVerificationFailed)
                if (shouldFallbackToBrowser(msg)) {
                    browserBackGoesToOtp = true
                    val url = browserLoginUrl()
                    uiState.update {
                        it.copy(
                            isLoading = false,
                            step = LoginStep.BrowserFallback,
                            browserLoginUrl = url,
                            errorMessage =
                                L10n.text(L10n.loginBrowserRequired),
                        )
                    }
                } else {
                    uiState.update { it.copy(isLoading = false, errorMessage = msg) }
                }
            }
        }
    }

    fun resendOtp() {
        viewModelScope.launch {
            uiState.update { it.copy(errorMessage = null) }
            try {
                otpChallenge?.sendOtp()
                uiState.update { it.copy(errorMessage = L10n.text(L10n.loginCodeResent)) }
            } catch (e: Exception) {
                uiState.update {
                    it.copy(errorMessage = L10n.textFmt(L10n.loginResendFailed, e.message ?: ""))
                }
            }
        }
    }

    fun completeBrowserLogin(callbackUrl: String) {
        val cleaned = callbackUrl.trim()
        if (cleaned.isBlank()) {
            uiState.update {
                it.copy(errorMessage = "Paste the full redirect URL from the address bar first.")
            }
            return
        }

        viewModelScope.launch {
            uiState.update { it.copy(isLoading = true, errorMessage = null) }
            try {
                // Correct path: finish STS session from the pasted URL.
                // Re-running password login with only deviceId still hits OTP and shows
                // "Still requires verification" even with a valid redirect.
                val credentials = miAuth.completeFromCallbackUrl(cleaned)
                persistAndSucceed(credentials)
            } catch (e: Exception) {
                // Optional fallback: retry password on the stable install id
                // (the pasted URL's d= belongs to the browser session, not the app).
                val email = uiState.value.email.trim()
                val password = uiState.value.password
                if (email.isNotBlank() && password.isNotBlank()) {
                    try {
                        val deviceId = credentialsStore.ensureDeviceId()
                        when (
                            val result = miAuth.login(
                                email = email,
                                password = password,
                                deviceId = deviceId,
                            )
                        ) {
                            is LoginResult.Success -> {
                                persistAndSucceed(result.credentials)
                                return@launch
                            }
                            is LoginResult.OtpRequired -> {
                                // Fall through to user-facing error from STS attempt.
                            }
                        }
                    } catch (_: Exception) {
                        // Prefer the STS error message below.
                    }
                }
                uiState.update {
                    it.copy(
                        isLoading = false,
                        errorMessage = e.message
                            ?: "Could not finish browser login from that URL. Paste the full sts-hlth URL.",
                    )
                }
            }
        }
    }

    fun goToBrowserFallback() {
        // User left OTP intentionally (“Having trouble?”) — Back should restore OTP.
        browserBackGoesToOtp = otpChallenge != null
        viewModelScope.launch {
            val url = browserLoginUrl()
            uiState.update {
                it.copy(step = LoginStep.BrowserFallback, errorMessage = null, browserLoginUrl = url)
            }
        }
    }

    /** Resolves the per-install browser URL for the UI layer (blank until loaded). */
    fun openBrowserLogin(onUrl: (String) -> Unit) {
        viewModelScope.launch {
            onUrl(browserLoginUrl())
        }
    }

    /**
     * Browser login URL bound to this install's stable device identity, so the trust
     * granted in the browser lands on the device id the app refreshes with.
     */
    suspend fun browserLoginUrl(): String {
        val deviceId = credentialsStore.ensureDeviceId()
        return miAuth.buildLoginUrl(deviceId = deviceId)
    }

    /**
     * Back from browser login:
     * - OTP if the user opened browser from the OTP step
     * - Credentials if OTP was skipped (e.g. email send rate-limited)
     */
    fun goBackFromBrowser() {
        if (browserBackGoesToOtp && otpChallenge != null) {
            uiState.update {
                it.copy(step = LoginStep.Otp, errorMessage = null)
            }
            return
        }
        browserBackGoesToOtp = false
        otpChallenge = null
        uiState.update {
            it.copy(
                step = LoginStep.Credentials,
                errorMessage = null,
                otpMaskedTarget = "",
                browserLoginUrl = "",
            )
        }
    }

    fun goBackToCredentials() {
        otpChallenge = null
        browserBackGoesToOtp = false
        uiState.update {
            it.copy(
                step = LoginStep.Credentials,
                errorMessage = null,
                otpMaskedTarget = "",
                browserLoginUrl = "",
            )
        }
    }

    fun consumeLoginSuccess() {
        uiState.update { it.copy(loginSucceeded = false) }
    }

    private suspend fun persistAndSucceed(credentials: MiCredentials) {
        // Refresh binds trust to this install's id; keep using it even when the
        // STS response echoes the browser's id from the pasted redirect URL.
        // Stable before the blank checks so a same-id success is never rejected.
        val stableDeviceId = credentialsStore.ensureDeviceId()
        val effective = credentials.copy(deviceId = stableDeviceId)
        if (effective.passToken.isBlank()) {
            uiState.update {
                it.copy(
                    isLoading = false,
                    errorMessage = "Login did not return a passToken, so the app cannot stay " +
                        "signed in across days. Try again or use the other login method.",
                )
            }
            return
        }
        if (effective.deviceId.isBlank()) {
            uiState.update {
                it.copy(
                    isLoading = false,
                    errorMessage = "Login missing device id — try again.",
                )
            }
            return
        }
        sessionManager.activate(effective)
        credentialsStore.saveCredentials(effective)
        // Pick the health cloud shard that actually holds the newest samples.
        try {
            val discovered = regionDiscovery.discover(effective)
            credentialsStore.setDiscoveredRegion(discovered)
            sessionManager.reloadFromStore()
        } catch (_: Exception) {
            // Keep STS provisional region if probing fails entirely.
        }
        uiState.update {
            it.copy(
                isLoading = false,
                loginSucceeded = true,
                errorMessage = null,
                // Drop OTP/browser step so Back cannot reopen them after success.
                step = LoginStep.Credentials,
                browserLoginUrl = "",
            )
        }
    }

    companion object {
        private val OTP_BROWSER_HINTS = listOf(
            "OTP_ACCEPTED_NEEDS_BROWSER",
            "still require",
            "still won't",
            "browser login",
        )

        fun shouldFallbackToBrowser(message: String): Boolean =
            OTP_BROWSER_HINTS.any { message.contains(it, ignoreCase = true) }

        // Kept for tests: older builds matched the pasted STS redirect d= id.
        // The app now uses the stable install id from CredentialsStore instead.
        fun extractDeviceId(url: String): String {
            val cleaned = url.trim().lines().firstOrNull { it.isNotBlank() }?.trim() ?: return ""
            // Xiaomi uses d= on STS; some pages also use deviceId=
            val patterns = listOf(
                Regex("[?&]d=([^&]+)"),
                Regex("[?&]deviceId=([^&]+)"),
                Regex("[?&]device_id=([^&]+)"),
            )
            for (regex in patterns) {
                val value = regex.find(cleaned)?.groupValues?.get(1)
                if (!value.isNullOrBlank()) return value
            }
            return ""
        }
    }
}
