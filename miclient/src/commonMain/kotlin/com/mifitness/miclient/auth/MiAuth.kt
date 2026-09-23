package com.mifitness.miclient.auth

import com.mifitness.miclient.crypto.MiCloudSigner
import io.ktor.client.HttpClient
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Cookie
import io.ktor.http.Parameters
import io.ktor.http.Url
import io.ktor.http.encodeURLParameter
import io.ktor.http.parseQueryString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/**
 * Mi Account authentication façade (password, OTP handoff, STS browser callback).
 *
 * Session refresh follows the official passport path:
 * passToken cookies → `/pass/serviceLogin` → signed STS (`clientSign`) → new serviceToken.
 */
@Suppress("LargeClass")
class MiAuth(
    private val userAgent: String = PassportAuthUtils.DEFAULT_USER_AGENT,
) : MiAuthHost {
    private val json = PassportAuthUtils.json

    suspend fun login(
        email: String,
        password: String,
        deviceId: String = "",
        sid: String = PassportAuthUtils.DEFAULT_SID,
        callback: String = PassportAuthUtils.DEFAULT_STS_CALLBACK,
    ): LoginResult {
        val effectiveDeviceId = deviceId.ifEmpty { PassportAuthUtils.generateDeviceId() }
        val cookieStorage = AcceptAllCookiesStorage()
        val client = PassportHttpSession.buildClient(cookieStorage)
        PassportHttpSession.seedDeviceIdCookie(cookieStorage, effectiveDeviceId)

        return try {
            passwordLoginStep(
                client = client,
                cookieStorage = cookieStorage,
                email = email,
                password = password,
                deviceId = effectiveDeviceId,
                sid = sid,
                callback = callback,
                closeClientOnSuccess = true,
            )
        } catch (e: Exception) {
            client.close()
            throw e
        }
    }

    /**
     * Completes browser login from the final STS redirect URL (paste from Safari/Chrome).
     * Follows redirects and collects serviceToken — does **not** re-run password/OTP login
     * (which would ask for verification again).
     */
    suspend fun completeFromCallbackUrl(
        stsCallbackUrl: String,
        sid: String = PassportAuthUtils.DEFAULT_SID,
    ): MiCredentials {
        val cleaned = stsCallbackUrl.trim().lines().firstOrNull { it.isNotBlank() }?.trim()
            ?: throw MiAuthException("Empty redirect URL")
        val parsedUrl = Url(cleaned)
        val params = parseQueryString(parsedUrl.encodedQuery)
        val deviceId = params["d"]
            ?: params["deviceId"]
            ?: throw MiAuthException(
                "Missing device id (d=…) in redirect URL — copy the full address bar URL",
                kind = MiAuthException.Kind.MissingDeviceId,
            )
        val regionFromUrl = params["p_ur"] ?: ""

        val cookieStorage = AcceptAllCookiesStorage()
        val client = PassportHttpSession.buildClient(cookieStorage)
        PassportHttpSession.seedDeviceIdCookie(cookieStorage, deviceId)

        try {
            val (serviceToken, regionFromRedirects) = followRedirectsCollectingServiceToken(
                client,
                cleaned,
            )
            if (serviceToken.isEmpty()) {
                throw MiAuthException(
                    "Could not get a session from that redirect URL. " +
                        "Open the login page again, finish sign-in, then paste the new full URL " +
                        "(it should start with https://sts-hlth.io.mi.com/).",
                    kind = MiAuthException.Kind.StsFailed,
                )
            }

            val accountCookies = cookieStorage.get(Url("https://account.xiaomi.com/"))
            val stsCookies = cookieStorage.get(Url("https://sts-hlth.io.mi.com/"))
            fun cookie(name: String): String =
                stsCookies.firstOrNull { it.name == name }?.value
                    ?: accountCookies.firstOrNull { it.name == name }?.value
                    ?: ""

            val userId = cookie("userId")
            val passToken = cookie("passToken")
            val cUserId = cookie("cUserId")
            if (passToken.isBlank()) {
                throw MiAuthException(
                    "Browser login did not yield a passToken, so the session cannot be refreshed later. " +
                        "Try password login or paste the URL immediately after Xiaomi shows “ok”.",
                    kind = MiAuthException.Kind.MissingPassToken,
                )
            }
            val harvested = if (userId.isNotEmpty()) {
                harvestSsecurity(client, userId, passToken, deviceId, sid)
            } else {
                null
            }
            val ssecurity = harvested?.ssecurity.orEmpty()
            // That call can already rotate the passToken; store the newest one.
            val effectivePassToken = harvested?.rotatedPassToken?.takeIf { it.isNotBlank() } ?: passToken
            if (ssecurity.isEmpty() || userId.isEmpty()) {
                throw MiAuthException(
                    "Got a service token but not full session details. " +
                        "Try browser login again and paste the URL as soon as the page says “ok”.",
                    kind = MiAuthException.Kind.StsFailed,
                )
            }

            return MiCredentials(
                userId = userId,
                ssecurity = ssecurity,
                serviceToken = serviceToken,
                passToken = effectivePassToken,
                deviceId = deviceId,
                region = PassportAuthUtils.resolveRegion(
                    regionFromUrl.ifBlank { regionFromRedirects },
                ),
                cUserId = cUserId,
            )
        } finally {
            client.close()
        }
    }

    fun buildLoginUrl(
        sid: String = PassportAuthUtils.DEFAULT_SID,
        callback: String = PassportAuthUtils.DEFAULT_STS_CALLBACK,
        deviceId: String = "",
    ): String {
        val base =
            "https://account.xiaomi.com/pass/serviceLogin?sid=${sid.encodeURLParameter()}" +
                "&callback=${callback.encodeURLParameter()}&_locale=en"
        if (deviceId.isBlank()) return base
        return "$base&d=${deviceId.encodeURLParameter()}"
    }

    /**
     * Re-mint serviceToken (and ssecurity when needed) using a stored [passToken].
     * Mirrors APK force-refresh via [XMPassport.loginByPassToken] + signed STS.
     */
    suspend fun refreshWithPassToken(
        credentials: MiCredentials,
        sid: String = PassportAuthUtils.DEFAULT_SID,
        callback: String = PassportAuthUtils.DEFAULT_STS_CALLBACK,
    ): MiCredentials {
        if (credentials.passToken.isBlank()) {
            throw MiAuthException(
                "No passToken saved — sign in again",
                kind = MiAuthException.Kind.MissingPassToken,
            )
        }
        if (credentials.userId.isBlank()) {
            throw MiAuthException(
                "No userId saved — sign in again",
                kind = MiAuthException.Kind.InvalidCredential,
            )
        }
        if (credentials.deviceId.isBlank()) {
            throw MiAuthException(
                "No deviceId saved — sign in again (device identity is required for refresh)",
                kind = MiAuthException.Kind.MissingDeviceId,
            )
        }

        val deviceId = credentials.deviceId
        val cookieStorage = AcceptAllCookiesStorage()
        val client = PassportHttpSession.buildClient(cookieStorage)
        PassportHttpSession.seedDeviceIdCookie(cookieStorage, deviceId)
        cookieStorage.addCookie(
            Url("https://account.xiaomi.com/"),
            Cookie(name = "userId", value = credentials.userId, domain = ".xiaomi.com", path = "/"),
        )
        cookieStorage.addCookie(
            Url("https://account.xiaomi.com/"),
            Cookie(name = "passToken", value = credentials.passToken, domain = ".xiaomi.com", path = "/"),
        )

        return try {
            val refreshed = loginWithPassTokenCookies(
                client = client,
                cookieStorage = cookieStorage,
                deviceId = deviceId,
                sid = sid,
                callback = callback,
                previousPassToken = credentials.passToken,
                previousCUserId = credentials.cUserId,
            )

            val region = refreshed.region.takeIf { it.isNotBlank() }
                ?: credentials.region.takeIf { it.isNotBlank() }
                ?: "sg"
            refreshed.copy(
                deviceId = deviceId,
                region = region,
            )
        } finally {
            client.close()
        }
    }

    private suspend fun passwordLoginStep(
        client: HttpClient,
        cookieStorage: AcceptAllCookiesStorage,
        email: String,
        password: String,
        deviceId: String,
        sid: String,
        callback: String,
        closeClientOnSuccess: Boolean,
    ): LoginResult {
        val sign = fetchSign(client, sid, deviceId)
        val authResponse = postServiceLoginAuth2(client, email, password, deviceId, sid, callback, sign)

        val code = authResponse["code"]?.jsonPrimitive?.int ?: -1
        if (code != 0) {
            val desc = authResponse["desc"]?.jsonPrimitive?.content
                ?: authResponse["description"]?.jsonPrimitive?.content
                ?: "Login failed"
            throw MiAuthException(
                PassportAuthUtils.friendlyLoginError(code, desc),
                kind = MiAuthException.Kind.InvalidCredential,
                businessCode = code,
            )
        }

        val securityStatus = authResponse["securityStatus"]?.jsonPrimitive?.int ?: 0
        val notification = authResponse["notificationUrl"]?.jsonPrimitive?.content ?: ""

        if (securityStatus != 0 || notification.isNotEmpty()) {
            return LoginResult.OtpRequired(
                host = this,
                client = client,
                cookieStorage = cookieStorage,
                email = email,
                password = password,
                sid = sid,
                callback = callback,
                notificationUrl = PassportAuthUtils.absUrl(notification),
                maskedTarget = PassportAuthUtils.inferMaskedEmail(email),
                deviceId = deviceId,
            )
        }

        val credentials = exchangeLocationForCredentials(
            client = client,
            cookieStorage = cookieStorage,
            authResponse = authResponse,
            deviceId = deviceId,
        )
        if (closeClientOnSuccess) client.close()
        return LoginResult.Success(credentials)
    }

    override suspend fun finishLoginAfterOtp(
        client: HttpClient,
        cookieStorage: AcceptAllCookiesStorage,
        email: String,
        password: String,
        deviceId: String,
        sid: String,
        callback: String,
    ): MiCredentials {
        PassportHttpSession.seedDeviceIdCookie(cookieStorage, deviceId)

        val result = passwordLoginStep(
            client = client,
            cookieStorage = cookieStorage,
            email = email,
            password = password,
            deviceId = deviceId,
            sid = sid,
            callback = callback,
            closeClientOnSuccess = false,
        )
        when (result) {
            is LoginResult.Success -> {
                client.close()
                return result.credentials
            }
            is LoginResult.OtpRequired -> {
                // Same client reused; do not open a nested OTP challenge.
            }
        }

        return try {
            val passTokenCreds = loginWithPassTokenCookies(
                client = client,
                cookieStorage = cookieStorage,
                deviceId = deviceId,
                sid = sid,
                callback = callback,
                previousPassToken = null,
                previousCUserId = "",
            )
            client.close()
            passTokenCreds
        } catch (e: MiAuthException) {
            client.close()
            throw MiAuthException(
                "OTP_ACCEPTED_NEEDS_BROWSER: Email code was accepted, but Xiaomi still " +
                    "won't finish app login for this session. Use browser login once to trust this device. " +
                    "(${e.message})",
                kind = MiAuthException.Kind.NeedsVerification,
            )
        }
    }

    /**
     * passToken cookie login + STS — APK [XMPassport.loginByPassToken] shape.
     * Throws [MiAuthException] with typed [MiAuthException.kind] instead of silent null.
     */
    private suspend fun loginWithPassTokenCookies(
        client: HttpClient,
        cookieStorage: AcceptAllCookiesStorage,
        deviceId: String,
        sid: String,
        callback: String,
        previousPassToken: String?,
        previousCUserId: String,
    ): MiCredentials {
        val accountCookies = cookieStorage.get(Url("https://account.xiaomi.com/"))
        val userId = accountCookies.firstOrNull { it.name == "userId" }?.value?.takeIf { it.isNotBlank() }
        val passToken = accountCookies.firstOrNull { it.name == "passToken" }?.value?.takeIf { it.isNotBlank() }
        if (userId.isNullOrEmpty() || passToken.isNullOrEmpty()) {
            throw MiAuthException(
                "Missing userId/passToken cookies for session refresh",
                kind = MiAuthException.Kind.MissingPassToken,
            )
        }

        PassportHttpSession.seedDeviceIdCookie(cookieStorage, deviceId)
        cookieStorage.addCookie(
            Url("https://account.xiaomi.com/"),
            Cookie(name = "userId", value = userId, domain = ".xiaomi.com", path = "/"),
        )
        cookieStorage.addCookie(
            Url("https://account.xiaomi.com/"),
            Cookie(name = "passToken", value = passToken, domain = ".xiaomi.com", path = "/"),
        )

        val loginUrl =
            "https://account.xiaomi.com/pass/serviceLogin?sid=${sid.encodeURLParameter()}" +
                "&_json=true&callback=${callback.encodeURLParameter()}" +
                "&d=${deviceId.encodeURLParameter()}"
        val response = client.get(loginUrl) {
            header("User-Agent", userAgent)
        }
        val body = PassportAuthUtils.stripJsonPrefix(response.bodyAsText())
        val obj = try {
            json.parseToJsonElement(body).jsonObject
        } catch (_: Exception) {
            throw MiAuthException(
                "Session refresh returned non-JSON from serviceLogin",
                kind = MiAuthException.Kind.StsFailed,
            )
        }
        val code = obj["code"]?.jsonPrimitive?.int ?: -1
        if (code != 0) {
            val desc = obj["desc"]?.jsonPrimitive?.content
                ?: obj["description"]?.jsonPrimitive?.content
                ?: "passToken login failed"
            // 70016 == XMPassport.RESULT_CODE_AUTHENTICATE_FAILED / ServerErrorCode.ERROR_PASSWORD.
            // The APK maps it to InvalidCredentialException on this path (processLoginContent),
            // and XMPassport.refreshPassToken rejects it too — there is no automatic recovery,
            // the passToken is dead. Only a fresh sign-in helps.
            throw MiAuthException(
                if (code == 70016) {
                    "Saved Mi session was rejected by Xiaomi (code 70016) — sign in again"
                } else {
                    PassportAuthUtils.friendlyLoginError(code, desc)
                },
                kind = MiAuthException.Kind.InvalidCredential,
                businessCode = code,
            )
        }
        val securityStatus = obj["securityStatus"]?.jsonPrimitive?.int ?: 0
        if (securityStatus != 0) {
            val notification = obj["notificationUrl"]?.jsonPrimitive?.content
            throw MiAuthException(
                "Xiaomi requires re-verification to renew the session (securityStatus=$securityStatus)",
                kind = MiAuthException.Kind.NeedsVerification,
                notificationUrl = notification?.let { PassportAuthUtils.absUrl(it) },
                businessCode = securityStatus,
            )
        }

        // Passport rotates passToken on every successful passToken login and hands the new
        // value back as a response cookie/header — NOT in the JSON body. The APK reads it via
        // `StringContent.getHeader("passToken")` (XMPassport.parseLoginResult, non-CA branch)
        // and persists it whenever it differs from the old one
        // (OwnAppXiaomiAccountAuthenticator.getAuthTokenBundle → addAccountOrUpdatePassToken).
        // Keeping the old token instead makes the session die once the server-side grace
        // window for the superseded token closes (~days), which looks like a random logout.
        //
        // Resolved before any further passport call so follow-up requests never present the
        // superseded token (which would rotate it again and orphan the value we just read).
        val oldPass = previousPassToken ?: passToken
        var effectivePass = responseCredential(response, "passToken")
            ?: PassportSts.preferRotatedPassToken(
                oldPassToken = oldPass,
                newPassToken = obj["passToken"]?.jsonPrimitive?.content,
                rePassTokenHeader = response.headers["re-pass-token"]
                    ?: response.headers["Re-Pass-Token"],
            )
        if (effectivePass != oldPass) {
            updatePassTokenCookie(cookieStorage, effectivePass)
        }

        var ssecurity = obj["ssecurity"]?.jsonPrimitive?.content.orEmpty()
        if (ssecurity.isEmpty()) {
            val harvested = harvestSsecurity(client, userId, effectivePass, deviceId, sid)
            ssecurity = harvested.ssecurity
            harvested.rotatedPassToken?.takeIf { it != effectivePass }?.let {
                effectivePass = it
                updatePassTokenCookie(cookieStorage, it)
            }
        }
        if (ssecurity.isEmpty()) {
            throw MiAuthException(
                "Session refresh missing ssecurity",
                kind = MiAuthException.Kind.StsFailed,
            )
        }

        val location = obj["location"]?.jsonPrimitive?.content
        val nonce = obj["nonce"]?.let { el ->
            try {
                el.jsonPrimitive.long.toString()
            } catch (_: Exception) {
                el.jsonPrimitive.content
            }
        }.orEmpty()

        val uid = PassportAuthUtils.jsonUserId(obj)
            .ifEmpty { responseCredential(response, "userId").orEmpty() }
            .ifEmpty { userId }
        val cUserId = responseCredential(response, "cUserId")
            ?: obj["cUserId"]?.jsonPrimitive?.content
            ?: obj["encryptedUserId"]?.jsonPrimitive?.content
            ?: previousCUserId

        val serviceToken: String
        val region: String
        if (!location.isNullOrEmpty()) {
            val pair = exchangeStsLocation(
                client = client,
                location = PassportAuthUtils.absUrl(location),
                ssecurity = ssecurity,
                nonce = nonce,
                sid = sid,
            )
            serviceToken = pair.first
            region = pair.second
        } else {
            serviceToken = cookieStorage.get(Url("https://sts-hlth.io.mi.com/"))
                .firstOrNull { it.name == "serviceToken" }?.value
                ?: cookieStorage.get(Url("https://account.xiaomi.com/"))
                    .firstOrNull { it.name == "serviceToken" }?.value
                ?: ""
            region = ""
        }
        if (serviceToken.isEmpty()) {
            throw MiAuthException(
                "Session refresh did not yield a serviceToken",
                kind = MiAuthException.Kind.StsFailed,
            )
        }

        return MiCredentials(
            userId = uid,
            ssecurity = ssecurity,
            serviceToken = serviceToken,
            passToken = effectivePass,
            deviceId = deviceId,
            region = PassportAuthUtils.resolveRegion(region),
            cUserId = cUserId,
        )
    }

    private suspend fun fetchSign(client: HttpClient, sid: String, deviceId: String): String {
        val url = "https://account.xiaomi.com/pass/serviceLogin" +
            "?sid=${sid.encodeURLParameter()}&_json=true&d=${deviceId.encodeURLParameter()}"
        val response = client.get(url) {
            header("User-Agent", userAgent)
        }
        val body = PassportAuthUtils.stripJsonPrefix(response.bodyAsText())
        val obj = json.parseToJsonElement(body).jsonObject
        return obj["_sign"]?.jsonPrimitive?.content ?: ""
    }

    private suspend fun postServiceLoginAuth2(
        client: HttpClient,
        email: String,
        password: String,
        deviceId: String,
        sid: String,
        callback: String,
        sign: String,
    ): JsonObject {
        val hash = MiCloudSigner.hashPassword(password)
        val response = client.submitForm(
            url = "https://account.xiaomi.com/pass/serviceLoginAuth2",
            formParameters = Parameters.build {
                append("sid", sid)
                append("hash", hash)
                append("callback", callback)
                append("qs", "?sid=$sid&_json=true")
                append("user", email)
                // Bind the credential check to the same install the cookies carry,
                // mirroring the official app's deviceId/d body params.
                append("deviceId", deviceId)
                append("d", deviceId)
                append("_json", "true")
                if (sign.isNotEmpty()) append("_sign", sign)
            },
        ) {
            header("User-Agent", userAgent)
        }
        val body = PassportAuthUtils.stripJsonPrefix(response.bodyAsText())
        return json.parseToJsonElement(body).jsonObject
    }

    private suspend fun exchangeLocationForCredentials(
        client: HttpClient,
        cookieStorage: AcceptAllCookiesStorage,
        authResponse: JsonObject,
        deviceId: String,
    ): MiCredentials {
        val location = authResponse["location"]?.jsonPrimitive?.content
            ?: throw MiAuthException(
                "Login succeeded but no location URL (can't get serviceToken)",
                kind = MiAuthException.Kind.StsFailed,
            )
        val userId = PassportAuthUtils.jsonUserId(authResponse)
        val ssecurity = authResponse["ssecurity"]?.jsonPrimitive?.content ?: ""
        // Xiaomi can issue the passToken as a Set-Cookie instead of the JSON body.
        val cookiePassToken = cookieStorage.get(Url("https://account.xiaomi.com/"))
            .firstOrNull { cookie -> cookie.name == "passToken" }?.value.orEmpty()
        val passToken = authResponse["passToken"]?.jsonPrimitive?.content
            ?.takeIf { it.isNotBlank() }
            ?: cookiePassToken.takeIf { it.isNotBlank() }.orEmpty()
        if (passToken.isBlank()) {
            throw MiAuthException(
                "Login succeeded but no passToken — session cannot be refreshed later",
                kind = MiAuthException.Kind.MissingPassToken,
            )
        }
        val cUserId = authResponse["cUserId"]?.jsonPrimitive?.content
            ?: authResponse["encryptedUserId"]?.jsonPrimitive?.content
            ?: cookieStorage.get(Url("https://account.xiaomi.com/"))
                .firstOrNull { cookie -> cookie.name == "cUserId" }?.value
                .takeIf { it?.isNotBlank() == true }
            ?: cookieStorage.get(Url("https://sts-hlth.io.mi.com/"))
                .firstOrNull { cookie -> cookie.name == "cUserId" }?.value
                .takeIf { it?.isNotBlank() == true }
            ?: ""
        val nonce = authResponse["nonce"]?.let { el ->
            try {
                el.jsonPrimitive.long.toString()
            } catch (_: Exception) {
                el.jsonPrimitive.content
            }
        }.orEmpty()

        val (serviceToken, region) = exchangeStsLocation(
            client = client,
            location = PassportAuthUtils.absUrl(location),
            ssecurity = ssecurity,
            nonce = nonce,
            sid = PassportAuthUtils.DEFAULT_SID,
        )
        if (serviceToken.isEmpty()) {
            throw MiAuthException(
                "STS did not set serviceToken — location follow failed",
                kind = MiAuthException.Kind.StsFailed,
            )
        }

        return MiCredentials(
            userId = userId,
            ssecurity = ssecurity,
            serviceToken = serviceToken,
            passToken = passToken,
            deviceId = deviceId,
            region = PassportAuthUtils.resolveRegion(region),
            cUserId = cUserId,
        )
    }

    /**
     * Prefer APK signed STS (`clientSign` + `_userIdNeedEncrypt`); fall back to bare redirect follow.
     */
    private suspend fun exchangeStsLocation(
        client: HttpClient,
        location: String,
        ssecurity: String,
        nonce: String,
        sid: String,
    ): Pair<String, String> {
        if (ssecurity.isNotEmpty() && nonce.isNotEmpty()) {
            val signed = PassportSts.signedLocationUrl(location, nonce, ssecurity)
            val signedResult = followRedirectsCollectingServiceToken(client, signed, sid)
            if (signedResult.first.isNotEmpty()) return signedResult
        }
        return followRedirectsCollectingServiceToken(client, location, sid)
    }

    override suspend fun followRedirectsCollectingServiceToken(
        client: HttpClient,
        startUrl: String,
    ): Pair<String, String> = followRedirectsCollectingServiceToken(client, startUrl, PassportAuthUtils.DEFAULT_SID)

    private suspend fun followRedirectsCollectingServiceToken(
        client: HttpClient,
        startUrl: String,
        sid: String,
    ): Pair<String, String> {
        var serviceToken = ""
        var region = ""
        var currentUrl = startUrl
        repeat(12) {
            val response = client.get(currentUrl) {
                header("User-Agent", userAgent)
            }
            val cookieHeaders = (response.headers.getAll("Set-Cookie") ?: emptyList()) +
                (response.headers.getAll("set-cookie") ?: emptyList())
            cookieHeaders.forEach { cookie ->
                PassportSts.extractServiceTokenFromCookieHeader(cookie, sid)?.let {
                    serviceToken = it
                }
            }
            // Some STS responses put tokens in plain headers (APK SimpleRequest headers map).
            val headerToken = response.headers["serviceToken"]
                ?: response.headers["${sid}_serviceToken"]
            if (!headerToken.isNullOrBlank()) serviceToken = headerToken

            if (currentUrl.contains("p_ur=")) {
                region = try {
                    parseQueryString(Url(currentUrl).encodedQuery)["p_ur"] ?: region
                } catch (_: Exception) {
                    region
                }
            }
            val redirectUrl = response.headers["Location"]
            if (redirectUrl.isNullOrEmpty() || response.status.value !in 300..399) {
                return@repeat
            }
            currentUrl = PassportAuthUtils.absUrl(redirectUrl)
        }
        return serviceToken to region
    }

    /**
     * Reads a credential that passport returns as a response **cookie or header**
     * (`passToken`, `userId`, `cUserId`).
     *
     * The APK merges `Set-Cookie` values into its response header map
     * (`SimpleRequest.parseCookies` → `HeaderContent.putCookies`) and then reads them with
     * `StringContent.getHeader(name)`; this reproduces that lookup.
     */
    private fun responseCredential(response: HttpResponse, name: String): String? {
        val setCookies = (response.headers.getAll("Set-Cookie") ?: emptyList()) +
            (response.headers.getAll("set-cookie") ?: emptyList())
        return PassportAuthUtils.setCookieValue(setCookies, name)
            ?: response.headers[name]?.takeIf { it.isNotBlank() }
    }

    /** Keeps the cookie jar on the freshly rotated passToken so later legs don't reuse a dead one. */
    private suspend fun updatePassTokenCookie(cookieStorage: AcceptAllCookiesStorage, passToken: String) {
        cookieStorage.addCookie(
            Url("https://account.xiaomi.com/"),
            Cookie(name = "passToken", value = passToken, domain = ".xiaomi.com", path = "/"),
        )
    }

    private data class SsecurityHarvest(
        val ssecurity: String,
        /** This extra serviceLogin can rotate passToken again — never drop that value. */
        val rotatedPassToken: String?,
    )

    private suspend fun harvestSsecurity(
        client: HttpClient,
        userId: String,
        passToken: String,
        deviceId: String,
        sid: String,
    ): SsecurityHarvest {
        val url = "https://account.xiaomi.com/pass/serviceLogin" +
            "?sid=${sid.encodeURLParameter()}&_json=true&d=${deviceId.encodeURLParameter()}"
        val response = client.get(url) {
            header("User-Agent", userAgent)
            header("Cookie", "userId=$userId; passToken=$passToken; deviceId=$deviceId")
        }
        val rotated = responseCredential(response, "passToken")
        val pragma = response.headers["Extension-Pragma"] ?: response.headers["extension-pragma"]
        if (pragma != null) {
            val ssec = PassportAuthUtils.parseJsonField(pragma, "ssecurity")
            if (ssec.isNotEmpty()) return SsecurityHarvest(ssec, rotated)
        }
        return SsecurityHarvest(
            PassportAuthUtils.parseJsonField(
                PassportAuthUtils.stripJsonPrefix(response.bodyAsText()),
                "ssecurity",
            ),
            rotated,
        )
    }

    companion object {
        const val DEFAULT_SID = PassportAuthUtils.DEFAULT_SID
        const val DEFAULT_STS_CALLBACK = PassportAuthUtils.DEFAULT_STS_CALLBACK
        const val DEFAULT_USER_AGENT = PassportAuthUtils.DEFAULT_USER_AGENT

        fun generateDeviceId(): String = PassportAuthUtils.generateDeviceId()
    }
}
