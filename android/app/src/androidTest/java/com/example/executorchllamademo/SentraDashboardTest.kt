package com.example.executorchllamademo

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.executorchllamademo.ui.screens.WelcomeScreen
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AppDashboardTest {
    @get:Rule val composeRule = createAndroidComposeRule<UrlScanTestActivity>()

    @Test fun homeShowsHonestModelStatusAndOpensScanner() {
        var opened = false
        composeRule.setContent {
            WelcomeScreen(modelReady = false, onScannerClick = { opened = true })
        }
        composeRule.onNodeWithText("Don'tClik").assertIsDisplayed()
        composeRule.onNodeWithText("Model not loaded").assertIsDisplayed()
        composeRule.onNodeWithText("Scan a link").performClick()
        composeRule.runOnIdle { assertTrue(opened) }
        composeRule.onNodeWithText("In development").assertExists()
    }

    @Test fun smsEntryIsExperimentalAndNavigates() {
        var opened = false
        composeRule.setContent { WelcomeScreen(onSmsClick = { opened = true }) }
        composeRule.onNodeWithText("SMS patterns").performClick()
        composeRule.runOnIdle { assertTrue(opened) }
        composeRule.onNodeWithText("Experimental · paste a message").assertExists()
    }
}
