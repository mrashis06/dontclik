package com.example.executorchllamademo

/** Privacy-safe diagnostic categories for the closed-set advice selection path. */
enum class ScanExplanationReason {
    EMPTY_OUTPUT,
    TOO_SHORT_OR_TRUNCATED,
    OTHER_VALIDATION_REJECTION,
    GENERATION_EXCEPTION,
    CANCELLED,
    ACCEPTED,
    UNKNOWN
}

/** Prevents chat and scan advice from using the one LlmModule concurrently. */
class GenerationGate {
    enum class Kind { CHAT, SCAN_EXPLANATION }

    private var active: Kind? = null

    @Synchronized fun tryStart(kind: Kind): Boolean {
        if (active != null) return false
        active = kind
        return true
    }

    @Synchronized fun finish(kind: Kind) {
        if (active == kind) active = null
    }

    @Synchronized fun isBusy(): Boolean = active != null
}
