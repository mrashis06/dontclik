package com.example.executorchllamademo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlSecurityScannerTest {
    private fun scan(url: String) = UrlSecurityScanner.scan(url)

    @Test fun ordinaryWebUrlsHaveNoObviousIndicators() {
        for (url in listOf("https://www.google.com/search?q=private#part", "http://example.org", "example.org/path")) {
            val result = scan(url)
            assertEquals(url, ScanOutcome.NO_OBVIOUS_INDICATORS, result.outcome)
            assertTrue(result.indicators.isEmpty())
            assertTrue(result.explanation.contains("does not verify"))
            assertFalse(result.toString().contains("private"))
        }
    }

    @Test fun ipLiteralHostsAreStrongIndicators() {
        for (url in listOf("http://192.0.2.1/login", "https://[2001:db8::1]/", "https://[::ffff:192.0.2.1]/")) {
            val result = scan(url)
            assertEquals(url, ScanOutcome.SUSPICIOUS, result.outcome)
            assertTrue(result.indicators.contains(UrlIndicator.IP_LITERAL))
        }
    }

    @Test fun userinfoPointsToHostAfterAt() {
        val result = scan("https://trusted.example@other.example/signin")
        assertEquals(ScanOutcome.SUSPICIOUS, result.outcome)
        assertEquals("other.example", result.hostname)
        assertTrue(result.indicators.contains(UrlIndicator.USERINFO))
        assertFalse(scan("https://example.org/a@b?x=c@d").indicators.contains(UrlIndicator.USERINFO))
    }

    @Test fun punycodeAndUnicodeHostsAreWeakIndicators() {
        for (url in listOf("https://xn--bcher-kva.example", "https://bücher.example")) {
            val result = scan(url)
            assertEquals(url, ScanOutcome.INCONCLUSIVE, result.outcome)
            assertTrue(result.indicators.contains(UrlIndicator.IDN))
            assertEquals(1, result.indicatorCount)
        }
    }

    @Test fun depthAndLongLabelsHaveExplicitThresholds() {
        val deep = scan("https://a.b.c.example.org")
        assertEquals(ScanOutcome.INCONCLUSIVE, deep.outcome)
        assertTrue(deep.indicators.contains(UrlIndicator.DEEP_SUBDOMAINS))
        val longLabel = "a".repeat(40)
        val long = scan("https://$longLabel.example.org")
        assertEquals(ScanOutcome.INCONCLUSIVE, long.outcome)
        assertTrue(long.indicators.contains(UrlIndicator.LONG_LABEL))
        val combined = scan("https://a.b.c.$longLabel.org")
        assertEquals(ScanOutcome.SUSPICIOUS, combined.outcome)
        assertEquals(2, combined.indicatorCount)
    }

    @Test fun malformedOrAmbiguousUrlsAreInconclusive() {
        for (url in listOf("", "https:///missing.example", "https://a@@example.org", "https://[2001:::1]/", "https://256.1.1.1", "https://example.org:99999", "https://example.org\\@evil.org", "ftp://example.org", "https://example.org/has space", "https://example.org/%zz")) {
            assertEquals(url, ScanOutcome.INCONCLUSIVE, scan(url).outcome)
        }
    }

    @Test fun httpsIsNeutralAndNeverGuaranteesSafety() {
        val http = scan("http://example.org")
        val https = scan("https://example.org")
        assertEquals(http.outcome, https.outcome)
        assertEquals(http.indicators, https.indicators)
        assertEquals(0, https.indicatorCount)
        assertEquals(ScanOutcome.SUSPICIOUS, scan("https://192.0.2.1").outcome)
        assertFalse(https.explanation.contains("verified safe"))
    }
}
