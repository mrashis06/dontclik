package com.example.executorchllamademo

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GenerationGateTest {
    @Test fun oneGenerationAtATimeAndOnlyOwnerCanRelease() {
        val gate = GenerationGate()
        assertTrue(gate.tryStart(GenerationGate.Kind.CHAT))
        assertTrue(gate.isBusy())
        assertFalse(gate.tryStart(GenerationGate.Kind.SCAN_EXPLANATION))
        assertFalse(gate.tryStart(GenerationGate.Kind.CHAT))
        gate.finish(GenerationGate.Kind.SCAN_EXPLANATION)
        assertTrue(gate.isBusy())
        gate.finish(GenerationGate.Kind.CHAT)
        assertTrue(gate.tryStart(GenerationGate.Kind.SCAN_EXPLANATION))
        gate.finish(GenerationGate.Kind.SCAN_EXPLANATION)
        assertFalse(gate.isBusy())
    }
}
