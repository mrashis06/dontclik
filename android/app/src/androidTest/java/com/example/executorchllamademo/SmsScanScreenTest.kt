package com.example.executorchllamademo

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.executorchllamademo.ui.screens.SmsScanScreen
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SmsScanScreenTest {
    @get:Rule val composeRule = createAndroidComposeRule<UrlScanTestActivity>()

    @Test fun analysisClearsInputAndShowsSeparatedGuidance() {
        var submitted = ""
        composeRule.setContent {
            SmsScanScreen(analyze = { text ->
                submitted = text
                SmsAssessment(SmsAssessmentLabel.SPAM_LIKE, score = 0.99, threshold = 0.95, version = 1)
            })
        }
        composeRule.onNodeWithTag("sms_input").performTextInput("Synthetic prize message")
        composeRule.onNodeWithTag("sms_analyze").performClick()
        composeRule.runOnIdle { assertEquals("Synthetic prize message", submitted) }
        composeRule.onNodeWithText("Spam-like pattern").assertIsDisplayed()
        composeRule.onNodeWithText("Practical checks").assertExists()
        composeRule.onNodeWithTag("sms_input").assert(
            SemanticsMatcher.expectValue(SemanticsProperties.EditableText, AnnotatedString("")))
    }

    @Test fun unavailableAndUncertainStatesAreHonest() {
        composeRule.setContent {
            SmsScanScreen(analyze = {
                SmsAssessment(SmsAssessmentLabel.INCONCLUSIVE,
                    SmsAssessmentReason.BANKING_UNCERTAINTY)
            })
        }
        composeRule.onNodeWithTag("sms_input").performTextInput("Synthetic bank alert")
        composeRule.onNodeWithTag("sms_analyze").performClick()
        composeRule.onNodeWithText("Inconclusive").assertIsDisplayed()
        composeRule.onNodeWithText("Experimental spam classification — not verified scam detection")
            .assertExists()
    }

    @Test fun packagedAssetLoadsThroughProductionEntryPoint() {
        val context = composeRule.activity.applicationContext
        val banking = ExperimentalSmsSpam.assess(context, "Your bank statement is ready in the app")
        assertEquals(SmsAssessmentLabel.INCONCLUSIVE, banking.label)
        assertEquals(SmsAssessmentReason.BANKING_UNCERTAINTY, banking.reason)
        val prize = ExperimentalSmsSpam.assess(context, "Congratulations you won a prize claim now")
        assertEquals(SmsAssessmentLabel.SPAM_LIKE, prize.label)
        assertEquals(1, prize.version)
    }
}
