package com.example.executorchllamademo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanAdviceSelectionTest {
    private val suspicious = ScanOutcome.SUSPICIOUS
    private val userinfo = listOf(UrlIndicator.USERINFO)

    @Test fun parsesOneOrTwoPermittedIds() {
        assertEquals(AdviceParseResult(AdviceParseReason.ACCEPTED, listOf(SecurityAdviceId.USERINFO_AT)),
            ScanAdviceSelection.parse("IDS=USERINFO_AT;END", suspicious, userinfo))
        assertEquals(AdviceParseResult(AdviceParseReason.ACCEPTED,
            listOf(SecurityAdviceId.USERINFO_AT, SecurityAdviceId.VERIFY_INDEPENDENTLY)),
            ScanAdviceSelection.parse("IDS=USERINFO_AT,VERIFY_INDEPENDENTLY;END", suspicious, userinfo))
        assertEquals(AdviceParseReason.ACCEPTED,
            ScanAdviceSelection.parse(" \nIDS = USERINFO_AT , VERIFY_INDEPENDENTLY ; END\r\n",
                suspicious, userinfo).reason)
    }

    @Test fun rejectsUnknownOrUnsupportedIds() {
        assertEquals(AdviceParseReason.UNKNOWN_ID,
            ScanAdviceSelection.parse("IDS=INVENTED;END", suspicious, userinfo).reason)
        assertEquals(AdviceParseReason.DISALLOWED_ID,
            ScanAdviceSelection.parse("IDS=IP_LITERAL;END", suspicious, userinfo).reason)
    }

    @Test fun rejectsIncompleteExtraDuplicateAndTruncatedOutput() {
        listOf("", "IDS=USERINFO_AT", "IDS=USERINFO_AT;EN", "IDS=USERINFO_AT;END extra",
            "ids=USERINFO_AT;END", "IDS=USER INFO_AT;END", "IDS=USERINFO_AT;END extra",
            "IDS=USERINFO_AT,VERIFY_INDEPENDENTLY,KEEP_CREDENTIALS_PRIVATE;END",
            "                 IDS=USERINFO_AT;END").forEach {
            assertEquals(AdviceParseReason.FORMAT_REJECTION,
                ScanAdviceSelection.parse(it, suspicious, userinfo).reason)
        }
        assertEquals(AdviceParseReason.DUPLICATE_ID,
            ScanAdviceSelection.parse("IDS=USERINFO_AT,USERINFO_AT;END", suspicious, userinfo).reason)
        assertEquals(AdviceParseReason.TRUNCATED,
            ScanAdviceSelection.parse("IDS=USERINFO_AT;END", suspicious, userinfo, truncated = true).reason)
    }

    @Test fun fixedCredentialAdviceIsSafeNegatedGuidance() {
        val advice = SecurityAdviceId.KEEP_CREDENTIALS_PRIVATE.advice
        assertTrue(advice.contains("Do not share your password or one-time code (OTP)"))
        assertEquals(listOf(SecurityAdviceId.KEEP_CREDENTIALS_PRIVATE),
            ScanAdviceSelection.parse("IDS=KEEP_CREDENTIALS_PRIVATE;END", suspicious, userinfo).ids)
    }

    @Test fun fallbackIsDeterministicAndEvidenceSpecific() {
        assertEquals(listOf(SecurityAdviceId.USERINFO_AT, SecurityAdviceId.VERIFY_INDEPENDENTLY),
            ScanAdviceSelection.fallback(suspicious, userinfo))
        assertEquals(listOf(SecurityAdviceId.IP_LITERAL, SecurityAdviceId.VERIFY_INDEPENDENTLY),
            ScanAdviceSelection.fallback(suspicious, listOf(UrlIndicator.IP_LITERAL)))
        assertEquals(listOf(SecurityAdviceId.IDN_CAUTION, SecurityAdviceId.VERIFY_INDEPENDENTLY),
            ScanAdviceSelection.fallback(ScanOutcome.INCONCLUSIVE, listOf(UrlIndicator.IDN)))
        assertEquals(listOf(SecurityAdviceId.HOSTNAME_STRUCTURE, SecurityAdviceId.VERIFY_INDEPENDENTLY),
            ScanAdviceSelection.fallback(ScanOutcome.INCONCLUSIVE, listOf(UrlIndicator.LONG_LABEL)))
        assertEquals(listOf(SecurityAdviceId.INCONCLUSIVE_CAUTION, SecurityAdviceId.VERIFY_INDEPENDENTLY),
            ScanAdviceSelection.fallback(ScanOutcome.INCONCLUSIVE, emptyList()))
        assertEquals(listOf(SecurityAdviceId.NO_OBVIOUS_CAUTION, SecurityAdviceId.VERIFY_INDEPENDENTLY),
            ScanAdviceSelection.fallback(ScanOutcome.NO_OBVIOUS_INDICATORS, emptyList()))
    }

    @Test fun promptAndSelectionNeverReceivePrivateUrlParts() {
        val scan = UrlSecurityScanner.scan("https://private-user@192.0.2.1/path?token=private-value#fragment")
        val original = scan.copy()
        assertEquals(ScanOutcome.SUSPICIOUS, scan.outcome)
        assertEquals(listOf(UrlIndicator.USERINFO, UrlIndicator.IP_LITERAL), scan.indicators)
        val prompt = ScanAdviceSelection.build(scan.outcome, scan.indicators)
        assertTrue(prompt.contains("USERINFO"))
        assertTrue(prompt.contains("IP_LITERAL"))
        listOf("private-user", "192.0.2.1", "path", "token", "private-value", "fragment").forEach {
            assertFalse(prompt.contains(it))
        }
        assertEquals("192.0.2.1", scan.hostname)
        assertEquals(original, scan)
    }
}
