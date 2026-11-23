package com.example.executorchllamademo

import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ExperimentalPhishingMlTest {
    private val asset = File("src/main/assets/phishing_lr_v1.model")

    @Test fun pythonExportScoreParityForKnownCases() {
        val engine = PhishingMlEngine { asset.inputStream() }
        val fixtures = listOf(
            Triple("https://google.com", 0.40559556108626577, MlPattern.BENIGN_LIKE),
            Triple("https://github.com", 0.10965461604379849, MlPattern.BENIGN_LIKE),
            Triple("https://microsoft.com", 0.0345244700520489, MlPattern.BENIGN_LIKE),
            Triple("https://wikipedia.org", 0.0014719927924350207, MlPattern.BENIGN_LIKE),
            Triple("https://cloudflare.com", 0.6201580203688184, MlPattern.PHISHING_LIKE),
            Triple("google.com", 0.40559556108626577, MlPattern.BENIGN_LIKE),
            Triple("http://github.com/", 0.1069093113886409, MlPattern.BENIGN_LIKE),
            Triple("https://example.com:443/path", 0.19817113887088308, MlPattern.BENIGN_LIKE),
            Triple("https://secure-login-account-verify.example.com/login?token=synthetic123",
                0.9999994158106307, MlPattern.PHISHING_LIKE),
            Triple("http://192.0.2.5/login", 0.9980886362107502, MlPattern.PHISHING_LIKE),
            Triple("https://example.org/a/b?x=123&y=abc#fragment",
                0.562855971738442, MlPattern.PHISHING_LIKE),
            Triple("https://example.org/%2Fadmin%20login", 0.9745379892003349, MlPattern.PHISHING_LIKE)
        )
        fixtures.forEachIndexed { index, (url, expected, pattern) ->
            val scored = engine.assess(url) as ExperimentalMlResult.Scored
            assertEquals("fixture $index", expected, scored.score, 1e-6)
            assertEquals("fixture $index", pattern, scored.pattern)
            assertEquals(0.4566655133236989, scored.threshold, 1e-12)
            assertEquals(1, scored.modelVersion)
        }
    }

    @Test fun unsupportedAndMalformedInputsAreExplicitlyUnavailable() {
        val engine = PhishingMlEngine { asset.inputStream() }
        for (url in listOf("https://example.org/café", "http://[2001:db8::1]/path", "ftp://example.org/")) {
            val result = engine.assess(url) as ExperimentalMlResult.Unavailable
            assertEquals(MlUnavailableReason.UNSUPPORTED_INPUT, result.reason)
        }
        for (url in listOf("", "https://", "https://exa mple.org/path",
            "https://user:pass@example.org/", "https://example.org:99999/path")) {
            val result = engine.assess(url) as ExperimentalMlResult.Unavailable
            assertEquals(MlUnavailableReason.INVALID_INPUT, result.reason)
        }
    }

    @Test fun modelLoadsOnceAndFailureDoesNotThrow() {
        var loads = 0
        val engine = PhishingMlEngine {
            loads++
            asset.inputStream()
        }
        assertTrue(engine.assess("google.com") is ExperimentalMlResult.Scored)
        assertTrue(engine.assess("github.com") is ExperimentalMlResult.Scored)
        assertEquals(1, loads)

        var failedLoads = 0
        val missing = PhishingMlEngine {
            failedLoads++
            throw IOException("missing test asset")
        }
        repeat(2) {
            val result = missing.assess("https://example.org") as ExperimentalMlResult.Unavailable
            assertEquals(MlUnavailableReason.MODEL_UNAVAILABLE, result.reason)
        }
        assertEquals(1, failedLoads)

        val corrupt = PhishingMlEngine { ByteArrayInputStream(byteArrayOf(1, 2, 3)) }
        val result = corrupt.assess("https://example.org") as ExperimentalMlResult.Unavailable
        assertEquals(MlUnavailableReason.MODEL_UNAVAILABLE, result.reason)
    }
}
