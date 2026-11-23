package com.example.executorchllamademo

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.pytorch.executorch.extension.llm.LlmCallback
import org.pytorch.executorch.extension.llm.LlmModule

/** Explicitly targeted device check; it never receives or logs URL text. */
@RunWith(AndroidJUnit4::class)
class OnDeviceAdviceSelectionTest {
    @Test fun localLlamaReturnsAcceptedAllowlistedSelection() {
        val args = InstrumentationRegistry.getArguments()
        val modelName = args.getString("modelFile")
            ?: "Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte"
        val tokenizerName = args.getString("tokenizerFile") ?: "tokenizer.model"
        val root = "/data/local/tmp/llama/"
        val module = LlmModule(File(root, modelName).path, File(root, tokenizerName).path, 0.0f)
        module.load()

        val outcome = ScanOutcome.SUSPICIOUS
        val indicators = listOf(UrlIndicator.USERINFO)
        val answer = StringBuilder()
        var inHeader = false
        val callback = object : LlmCallback {
            override fun onResult(result: String) {
                when (result) {
                    PromptFormat.getStopToken(ModelType.LLAMA_3) -> module.stop()
                    "<|start_header_id|>" -> inHeader = true
                    "<|end_header_id|>" -> inHeader = false
                    else -> if (!inHeader && !result.startsWith("<|") && answer.length < 256) {
                        answer.append(result.take(256 - answer.length))
                        if (ScanAdviceSelection.parse(answer.toString(), outcome, indicators).reason ==
                            AdviceParseReason.ACCEPTED
                        ) module.stop()
                    }
                }
            }
            override fun onStats(stats: String) = Unit
        }
        module.generate(ScanAdviceSelection.build(outcome, indicators), 512, callback, false)
        val parsed = ScanAdviceSelection.parse(answer.toString(), outcome, indicators)
        val whitespace = answer.count { it == ' ' || it == '\t' || it == '\r' || it == '\n' }
        val contractCharsOnly = answer.all { it in 'A'..'Z' || it == '_' || it == '=' ||
            it == ',' || it == ';' || it == ' ' || it == '\t' || it == '\r' || it == '\n' }
        val diagnostics = "reason=${parsed.reason} chars=${answer.length} whitespace=$whitespace " +
            "startsIds=${answer.startsWith("IDS")} containsIds=${answer.contains("IDS=")} " +
            "containsEnd=${answer.contains(";END")} contractCharsOnly=$contractCharsOnly"
        assertEquals(diagnostics, AdviceParseReason.ACCEPTED, parsed.reason)
    }
}
