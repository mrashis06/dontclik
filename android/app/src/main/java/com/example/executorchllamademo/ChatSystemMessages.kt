package com.example.executorchllamademo

internal object ChatSystemMessages {
    fun reconcileForReadyModel(
        messages: MutableList<Message>,
        setupInstruction: String,
        loadedStatus: String
    ) {
        messages.removeAll { message ->
            message.messageType == MessageType.SYSTEM &&
                (message.text == setupInstruction || message.text.startsWith("Successfully loaded"))
        }
        messages.add(Message(loadedStatus, false, MessageType.SYSTEM, 0))
    }
}
