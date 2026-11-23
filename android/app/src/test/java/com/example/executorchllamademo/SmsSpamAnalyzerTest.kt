package com.example.executorchllamademo

import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SmsSpamAnalyzerTest {
    private val asset = File("src/main/assets/sms_spam_v1.model")

    @Test fun pythonKotlinRawScoreParityAndConservativePresentation() {
        val model = SmsSpamModel.load(asset.inputStream())
        assertEquals(1, model.version)
        assertEquals(0.95, model.threshold, 1e-12)
        val fixtures = listOf(
            "Your OTP is 123456. Do not share it." to 0.4129720102685066,
            "URGENT verify KYC now to avoid account block" to 0.9947969126226613,
            "Congratulations you won a prize claim now" to 0.9999999947302884,
            "Your bank statement is ready in the app" to 0.9990453324997851,
            "Are we meeting at 6 tonight?" to 1.496927398482257e-05
        )
        fixtures.forEachIndexed { i, (message, expected) ->
            assertEquals("fixture $i", expected, model.rawScore(message), 1e-12)
        }
        assertEquals(SmsAssessmentLabel.INCONCLUSIVE,
            model.assess("Your bank statement is ready in the app").label)
        assertEquals(SmsAssessmentReason.BANKING_UNCERTAINTY,
            model.assess("Your OTP is 123456. Do not share it.").reason)
        assertEquals(SmsAssessmentLabel.INCONCLUSIVE,
            model.assess("Your salary was deposited").label)
        assertEquals(SmsAssessmentLabel.INCONCLUSIVE,
            model.assess("Rs 500 was debited").label)
        assertEquals(SmsAssessmentLabel.SPAM_LIKE,
            model.assess("Congratulations you won a prize claim now").label)
        assertEquals(SmsAssessmentLabel.HAM_LIKE,
            model.assess("Are we meeting at 6 tonight?").label)
    }

    @Test fun malformedAndUnsupportedInputIsExplicit() {
        val engine = SmsSpamEngine { asset.inputStream() }
        val cases = listOf(
            "" to SmsAssessmentReason.EMPTY,
            "   " to SmsAssessmentReason.EMPTY,
            "नमस्ते" to SmsAssessmentReason.UNSUPPORTED_LANGUAGE,
            "café" to SmsAssessmentReason.UNSUPPORTED_LANGUAGE,
            "bad\u0000text" to SmsAssessmentReason.MALFORMED,
            "!!!" to SmsAssessmentReason.MALFORMED,
            "x".repeat(4097) to SmsAssessmentReason.TOO_LONG
        )
        cases.forEach { (text, expected) ->
            val result = engine.assess(text)
            assertEquals(SmsAssessmentLabel.INCONCLUSIVE, result.label)
            assertEquals(expected, result.reason)
        }
    }

    @Test fun assetFailureAndCacheDoNotCrash() {
        var loads = 0
        val engine = SmsSpamEngine { loads++; asset.inputStream() }
        assertEquals(SmsAssessmentLabel.HAM_LIKE, engine.assess("Are we meeting tonight?").label)
        engine.assess("Claim your prize now")
        assertEquals(1, loads)

        var failures = 0
        val missing = SmsSpamEngine { failures++; throw IOException("synthetic missing asset") }
        repeat(2) {
            val result = missing.assess("A normal message")
            assertEquals(SmsAssessmentLabel.MODEL_UNAVAILABLE, result.label)
            assertEquals(SmsAssessmentReason.LOAD_FAILURE, result.reason)
        }
        assertEquals(1, failures)
        val corrupt = SmsSpamEngine { ByteArrayInputStream(byteArrayOf(1, 2, 3)) }
        assertEquals(SmsAssessmentLabel.MODEL_UNAVAILABLE,
            corrupt.assess("A normal message").label)
        assertTrue(asset.length() > 0)
    }
}
