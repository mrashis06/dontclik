package com.example.executorchllamademo

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.runtime.mutableStateOf
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.executorchllamademo.ui.components.UrlScanPanel
import com.example.executorchllamademo.ui.theme.LlamaDemoTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.assertEquals

@RunWith(AndroidJUnit4::class)
class UrlScanPanelTest {
    @get:Rule val composeRule = createAndroidComposeRule<UrlScanTestActivity>()

    @Test fun scanShowsEvidenceAndClearsPrivateInput() {
        composeRule.setContent { LlamaDemoTheme { UrlScanPanel() } }
        composeRule.onNodeWithTag("url_scan_input").performTextInput(
            "https://trusted.example@192.0.2.1/path?token=private-value#fragment"
        )
        composeRule.onNodeWithTag("url_scan_button").performClick()

        composeRule.onNodeWithTag("url_scan_input").assert(
            SemanticsMatcher.expectValue(SemanticsProperties.EditableText, AnnotatedString(""))
        )
        composeRule.onNodeWithText("Hostname: 192.0.2.1").assertExists()
        composeRule.onNodeWithText("Outcome: Suspicious").assertExists()
        composeRule.onNodeWithText("Indicators (2):").assertExists()
        composeRule.onNodeWithText("Deterministic guidance (scanner indicators)").assertExists()
        composeRule.onNodeWithText("Text before @ can make a link look familiar", substring = true).assertExists()
        composeRule.onNodeWithTag("url_explain_button").assertIsNotEnabled()
        composeRule.onNodeWithText("private-value", substring = true).assertDoesNotExist()
        composeRule.onNodeWithText("fragment", substring = true).assertDoesNotExist()
    }

    @Test fun emptyInputIsInconclusive() {
        composeRule.setContent { LlamaDemoTheme { UrlScanPanel() } }
        composeRule.onNodeWithTag("url_scan_button").performClick()
        composeRule.onNodeWithText("Outcome: Inconclusive").assertExists()
        composeRule.onNodeWithText("Indicators (0):").assertExists()
    }

    @Test fun explanationIsDisabledDuringGenerationAndReceivesOnlyEnums() {
        val generating = mutableStateOf(true)
        var receivedOutcome: ScanOutcome? = null
        var receivedIndicators: List<UrlIndicator>? = null
        composeRule.setContent {
            LlamaDemoTheme {
                UrlScanPanel(
                    canExplain = true,
                    isGenerating = generating.value,
                    onExplain = { outcome, indicators ->
                        receivedOutcome = outcome
                        receivedIndicators = indicators
                    }
                )
            }
        }
        composeRule.onNodeWithTag("url_scan_input").performTextInput("https://192.0.2.1/private?token=hidden")
        composeRule.onNodeWithTag("url_scan_button").performClick()
        composeRule.onNodeWithTag("url_explain_button").assertIsNotEnabled()
        composeRule.runOnIdle { generating.value = false }
        composeRule.onNodeWithTag("url_explain_button").assertIsEnabled().performClick()
        assertEquals(ScanOutcome.SUSPICIOUS, receivedOutcome)
        assertEquals(listOf(UrlIndicator.IP_LITERAL), receivedIndicators)
    }

    @Test fun acceptedSelectionRendersOnlyPrewrittenAdviceAndKeepsVerdict() {
        composeRule.setContent {
            LlamaDemoTheme {
                UrlScanPanel(adviceIds = listOf(SecurityAdviceId.KEEP_CREDENTIALS_PRIVATE))
            }
        }
        composeRule.onNodeWithTag("url_scan_input").performTextInput("https://example.org/?secret=query-value")
        composeRule.onNodeWithTag("url_scan_button").performClick()
        composeRule.onNodeWithText("Outcome: No obvious indicators").assertExists()
        composeRule.onNodeWithText("AI-selected, prewritten guidance (not the scanner verdict)").assertExists()
        composeRule.onNodeWithText("Do not share your password or one-time code (OTP)", substring = true).assertExists()
        composeRule.onNodeWithText("query-value", substring = true).assertDoesNotExist()
    }

    @Test fun experimentalMlIsSeparateFromHeuristicVerdict() {
        composeRule.setContent {
            LlamaDemoTheme {
                UrlScanPanel(mlAssessor = {
                    ExperimentalMlResult.Scored(MlPattern.BENIGN_LIKE, 0.1234, 0.4567, 1)
                })
            }
        }
        composeRule.onNodeWithTag("url_scan_input").performTextInput(
            "https://example.org/path?token=private-query"
        )
        composeRule.onNodeWithTag("url_scan_button").performClick()
        composeRule.waitUntil(5_000) {
            composeRule.onAllNodesWithText("Benign-like pattern", substring = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithText("Outcome: No obvious indicators").assertExists()
        composeRule.onNodeWithText("Experimental ML assessment — not a verified phishing verdict.")
            .assertExists()
        composeRule.onNodeWithText("Benign-like pattern (not verified safe)").assertExists()
        composeRule.onNodeWithText("Model score: 0.1234", substring = true).assertExists()
        composeRule.onNodeWithText("private-query", substring = true).assertDoesNotExist()
    }

    @Test fun mlUnavailableStillShowsHeuristicResult() {
        composeRule.setContent {
            LlamaDemoTheme {
                UrlScanPanel(mlAssessor = {
                    ExperimentalMlResult.Unavailable(MlUnavailableReason.MODEL_UNAVAILABLE)
                })
            }
        }
        composeRule.onNodeWithTag("url_scan_input").performTextInput("https://192.0.2.1/login")
        composeRule.onNodeWithTag("url_scan_button").performClick()
        composeRule.waitUntil(5_000) {
            composeRule.onAllNodesWithText("ML unavailable: local model could not load.")
                .fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithText("Outcome: Suspicious").assertExists()
        composeRule.onNodeWithText("ML unavailable: local model could not load.").assertExists()
    }

    @Test fun bundledModelScoresLocallyAndRejectsUnsupportedUnicode() {
        composeRule.setContent { LlamaDemoTheme { UrlScanPanel() } }
        composeRule.onNodeWithTag("url_scan_input").performTextInput("https://google.com")
        composeRule.onNodeWithTag("url_scan_button").performClick()
        composeRule.waitUntil(10_000) {
            composeRule.onAllNodesWithText("Benign-like pattern", substring = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithText("Outcome: No obvious indicators").assertExists()
        composeRule.onNodeWithText("Model score: 0.4056", substring = true).assertExists()

        composeRule.onNodeWithTag("url_scan_input").performTextInput("https://example.org/café")
        composeRule.onNodeWithTag("url_scan_button").performClick()
        composeRule.waitUntil(5_000) {
            composeRule.onAllNodesWithText("ML unavailable: unsupported URL form.")
                .fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithText("ML unavailable: unsupported URL form.").assertExists()
        composeRule.onNodeWithText("Outcome: No obvious indicators").assertExists()
    }
}
