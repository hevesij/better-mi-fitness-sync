package com.mifitness.miclient.auth

import io.ktor.client.HttpClient
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class MetaLoginDataTest {

    @Test
    fun metaLoginData_equalityHolds() {
        val first = MetaLoginData(sign = "s123", qs = "q456", callback = "https://cb")
        val second = MetaLoginData(sign = "s123", qs = "q456", callback = "https://cb")
        assertEquals(first, second)
    }

    @Test
    fun metaLoginData_copyPreservesFields() {
        val original = MetaLoginData(sign = "s123", qs = "q456", callback = "https://cb")
        val copied = original.copy(sign = "s789")
        assertEquals("s789", copied.sign)
        assertEquals(original.qs, copied.qs)
        assertEquals(original.callback, copied.callback)
    }

    @Test
    fun setCookieValue_readsStep1Token() {
        val headers = listOf(
            "cUserId=abc; Domain=.xiaomi.com; Path=/; HttpOnly",
            "step1Token=ST1.ABC123; Domain=.xiaomi.com; Path=/; HttpOnly",
        )
        assertEquals("ST1.ABC123", PassportAuthUtils.setCookieValue(headers, "step1Token"))
    }

    @Test
    fun finishLoginAfterOtp_defaultsRouteToCannedCredentials() = runTest {
        val canned = MiCredentials(
            userId = "123",
            ssecurity = "ssec",
            serviceToken = "token",
            passToken = "pass",
            deviceId = "wb_0123456789abcdef0123456789abcdef",
            region = "sg",
        )
        val fake = FakeAuthHost(canned)
        val storage = AcceptAllCookiesStorage()
        val client = PassportHttpSession.buildClient(storage)
        try {
            val result = fake.finishLoginAfterOtp(
                client,
                storage,
                "user@example.com",
                "pw",
                "wb_0123456789abcdef0123456789abcdef",
                "miothealth",
                "https://sts-hlth.io.mi.com/healthapp/sts",
            )
            assertEquals(canned, result)
            assertEquals("", fake.lastStep1Token)
            assertNull(fake.lastMeta)
        } finally {
            client.close()
        }
    }

    private class FakeAuthHost(val canned: MiCredentials) : MiAuthHost {
        var lastStep1Token = ""
        var lastMeta: MetaLoginData? = null

        override suspend fun finishLoginAfterOtp(
            client: HttpClient,
            cookieStorage: AcceptAllCookiesStorage,
            email: String,
            password: String,
            deviceId: String,
            sid: String,
            callback: String,
            step1Token: String,
            meta: MetaLoginData?,
            step2code: String,
            userId: String,
        ): MiCredentials {
            lastStep1Token = step1Token
            lastMeta = meta
            return canned
        }

        override suspend fun followRedirectsCollectingServiceToken(
            client: HttpClient,
            startUrl: String,
        ): Pair<String, String> = "" to ""
    }
}
