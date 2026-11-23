package com.example.executorchllamademo

import android.content.Context
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.zip.GZIPInputStream
import kotlin.math.exp

enum class SmsAssessmentLabel { SPAM_LIKE, HAM_LIKE, INCONCLUSIVE, MODEL_UNAVAILABLE }
enum class SmsAssessmentReason { EMPTY, TOO_LONG, UNSUPPORTED_LANGUAGE, MALFORMED,
    BANKING_UNCERTAINTY, NO_KNOWN_FEATURES, LOAD_FAILURE }

data class SmsAssessment(
    val label: SmsAssessmentLabel,
    val reason: SmsAssessmentReason? = null,
    /** Uncalibrated classifier output. Never present it as a scam probability. */
    val score: Double? = null,
    val threshold: Double? = null,
    val version: Int? = null
)

/** Injectable loader for JVM tests. A failed load is cached and never blocks other app features. */
internal class SmsSpamEngine(private val openArtifact: () -> InputStream) {
    private sealed interface LoadState {
        data class Ready(val model: SmsSpamModel) : LoadState
        data object Failed : LoadState
    }

    @Volatile private var state: LoadState? = null

    private fun model(): SmsSpamModel? {
        val current = state
        if (current != null) return (current as? LoadState.Ready)?.model
        return synchronized(this) {
            val again = state
            if (again != null) (again as? LoadState.Ready)?.model else {
                val loaded = try { SmsSpamModel.load(openArtifact()) } catch (_: Exception) { null }
                state = if (loaded == null) LoadState.Failed else LoadState.Ready(loaded)
                loaded
            }
        }
    }

    fun assess(message: String): SmsAssessment {
        SmsSpamModel.validate(message)?.let { return it }
        val loaded = model() ?: return SmsAssessment(SmsAssessmentLabel.MODEL_UNAVAILABLE,
            SmsAssessmentReason.LOAD_FAILURE)
        return try { loaded.assess(message) } catch (_: RuntimeException) {
            SmsAssessment(SmsAssessmentLabel.MODEL_UNAVAILABLE, SmsAssessmentReason.LOAD_FAILURE)
        }
    }
}

object ExperimentalSmsSpam {
    // AAPT may strip .gz; the .model asset retains the original compressed bytes.
    private const val ASSET = "sms_spam_v1.model"
    @Volatile private var engine: SmsSpamEngine? = null

    fun assess(context: Context, message: String): SmsAssessment {
        val current = engine ?: synchronized(this) {
            engine ?: SmsSpamEngine { context.applicationContext.assets.open(ASSET) }
                .also { engine = it }
        }
        return current.assess(message)
    }
}

/** Exact ASCII tokenization, digit masking, unigram/bigram counts and MNB summation. */
internal class SmsSpamModel private constructor(
    private val vocabulary: Map<String, Int>,
    private val weights: DoubleArray,
    private val bias: Double,
    val threshold: Double,
    val version: Int
) {
    companion object {
        private val WORD = Regex("[A-Za-z0-9]+")
        private val DIGITS = Regex("[0-9]+")
        // These terms trigger abstention only. They never declare a message safe.
        private val BANKING_TERMS = setOf("bank", "banking", "otp", "kyc", "upi", "account",
            "card", "debit", "debited", "credit", "credited", "statement", "transaction",
            "payment", "balance", "salary", "loan", "deposit", "deposited", "withdrawal",
            "transfer", "transferred", "pin", "emi")

        fun validate(message: String): SmsAssessment? {
            if (message.isBlank()) return SmsAssessment(SmsAssessmentLabel.INCONCLUSIVE,
                SmsAssessmentReason.EMPTY)
            if (message.length > 4096) return SmsAssessment(SmsAssessmentLabel.INCONCLUSIVE,
                SmsAssessmentReason.TOO_LONG)
            if (message.any { it.code > 127 }) return SmsAssessment(SmsAssessmentLabel.INCONCLUSIVE,
                SmsAssessmentReason.UNSUPPORTED_LANGUAGE)
            if (message.any { it.code < 32 && it != '\n' && it != '\r' && it != '\t' })
                return SmsAssessment(SmsAssessmentLabel.INCONCLUSIVE, SmsAssessmentReason.MALFORMED)
            if (!WORD.containsMatchIn(message)) return SmsAssessment(SmsAssessmentLabel.INCONCLUSIVE,
                SmsAssessmentReason.MALFORMED)
            return null
        }

        fun load(stream: InputStream): SmsSpamModel {
            DataInputStream(BufferedInputStream(GZIPInputStream(stream))).use { input ->
                val magic = ByteArray(4)
                input.readFully(magic)
                require(String(magic, StandardCharsets.US_ASCII) == "SMS1")
                val version = input.readUnsignedByte()
                require(version == 1)
                val kind = input.readUnsignedByte()
                require(kind == 2) // This integration accepts only the selected MNB export.
                val count = input.readInt()
                require(count == 8000)
                val bias = input.readDouble()
                val threshold = input.readDouble()
                require(bias.isFinite() && threshold > 0.0 && threshold < 1.0)
                val vocabulary = HashMap<String, Int>(count * 2)
                val weights = DoubleArray(count)
                repeat(count) { i ->
                    val length = input.readUnsignedShort()
                    require(length in 1..512)
                    val bytes = ByteArray(length)
                    input.readFully(bytes)
                    require(bytes.all { it.toInt() in 32..126 })
                    val term = String(bytes, StandardCharsets.US_ASCII)
                    require(vocabulary.put(term, i) == null)
                    weights[i] = input.readDouble()
                    require(weights[i].isFinite())
                }
                require(input.read() == -1)
                return SmsSpamModel(vocabulary, weights, bias, threshold, version)
            }
        }

        internal fun words(message: String): List<String> = WORD.findAll(message.lowercase(Locale.ROOT))
            .map { DIGITS.replace(it.value, "0") }.toList()
    }

    fun assess(message: String): SmsAssessment {
        validate(message)?.let { return it }
        val words = words(message)
        if (words.any(BANKING_TERMS::contains)) return SmsAssessment(
            SmsAssessmentLabel.INCONCLUSIVE, SmsAssessmentReason.BANKING_UNCERTAINTY,
            threshold = threshold, version = version)
        val counts = HashMap<Int, Int>()
        fun add(term: String) { vocabulary[term]?.let { counts[it] = (counts[it] ?: 0) + 1 } }
        words.forEach(::add)
        for (i in 0 until words.size - 1) add(words[i] + "_" + words[i + 1])
        if (counts.isEmpty()) return SmsAssessment(SmsAssessmentLabel.INCONCLUSIVE,
            SmsAssessmentReason.NO_KNOWN_FEATURES, threshold = threshold, version = version)
        var raw = bias
        for (i in weights.indices) {
            val count = counts[i] ?: continue
            raw += weights[i] * count
        }
        val score = if (raw >= 0) 1.0 / (1.0 + exp(-raw)) else exp(raw) / (1.0 + exp(raw))
        return SmsAssessment(if (score >= threshold) SmsAssessmentLabel.SPAM_LIKE
            else SmsAssessmentLabel.HAM_LIKE, score = score, threshold = threshold, version = version)
    }

    /** Raw classifier score before conservative app-facing abstention, for parity tests only. */
    internal fun rawScore(message: String): Double {
        require(validate(message) == null)
        val words = words(message)
        val counts = HashMap<Int, Int>()
        fun add(term: String) { vocabulary[term]?.let { counts[it] = (counts[it] ?: 0) + 1 } }
        words.forEach(::add)
        for (i in 0 until words.size - 1) add(words[i] + "_" + words[i + 1])
        var raw = bias
        for (i in weights.indices) {
            val count = counts[i] ?: continue
            raw += weights[i] * count
        }
        return if (raw >= 0) 1.0 / (1.0 + exp(-raw)) else exp(raw) / (1.0 + exp(raw))
    }
}
