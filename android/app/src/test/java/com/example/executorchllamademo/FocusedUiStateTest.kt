package com.example.executorchllamademo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FocusedUiStateTest {
    @Test fun smsDoesNotSelectAnyPrimaryDestination() {
        assertFalse(isPrimaryDestinationSelected("sms", "home"))
        assertFalse(isPrimaryDestinationSelected("sms", "scanner"))
        assertFalse(isPrimaryDestinationSelected("sms", "advisor"))
        assertTrue(isPrimaryDestinationSelected("home", "home"))
        listOf("home", "scanner", "advisor").forEach { assertFalse(isPrimaryDestinationSelected("malware", it)) }
    }

    @Test fun readyModelStatusRemovesSetupInstructionAndOldLoadStatuses() {
        val setup = "To get started, open Home and configure a local model and tokenizer."
        val messages = mutableListOf(
            Message(setup, false, MessageType.SYSTEM, 0),
            Message("Successfully loaded model. old", false, MessageType.SYSTEM, 0),
            Message("Keep this chat response", false, MessageType.TEXT, 1),
            Message("Successfully loaded 2 model(s). old", false, MessageType.SYSTEM, 0)
        )
        ChatSystemMessages.reconcileForReadyModel(messages, setup, "Successfully loaded model. current")
        assertEquals(2, messages.size)
        assertEquals("Keep this chat response", messages[0].text)
        assertEquals("Successfully loaded model. current", messages[1].text)
    }
}
