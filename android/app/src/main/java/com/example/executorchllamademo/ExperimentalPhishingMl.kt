package com.example.executorchllamademo

import android.content.Context
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.InputStream
import java.net.IDN
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.zip.GZIPInputStream
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.min

enum class MlPattern { PHISHING_LIKE, BENIGN_LIKE }
enum class MlUnavailableReason { INVALID_INPUT, UNSUPPORTED_INPUT, MODEL_UNAVAILABLE }

sealed interface ExperimentalMlResult {
    data class Scored(
        val pattern: MlPattern,
        /** Uncalibrated classifier output, not a verified threat likelihood. */
        val score: Double,
        val threshold: Double,
        val modelVersion: Int
    ) : ExperimentalMlResult

    data class Unavailable(
        val reason: MlUnavailableReason,
        val modelVersion: Int? = null
    ) : ExperimentalMlResult
}

/** Loads once per engine. A broken asset remains unavailable without affecting the heuristic scan. */
internal class PhishingMlEngine(private val openArtifact: () -> InputStream) {
    private sealed interface LoadState {
        data class Ready(val model: PhishingUrlModel) : LoadState
        data object Failed : LoadState
    }

    @Volatile private var loadState: LoadState? = null

    private fun model(): PhishingUrlModel? {
        val cached = loadState
        if (cached != null) return (cached as? LoadState.Ready)?.model
        return synchronized(this) {
            when (val current = loadState) {
                is LoadState.Ready -> current.model
                LoadState.Failed -> null
                null -> {
                    val next = try {
                        LoadState.Ready(PhishingUrlModel.load(openArtifact()))
                    } catch (_: Exception) {
                        LoadState.Failed
                    }
                    loadState = next
                    (next as? LoadState.Ready)?.model
                }
            }
        }
    }

    fun assess(raw: String): ExperimentalMlResult {
        val loaded = model() ?: return ExperimentalMlResult.Unavailable(MlUnavailableReason.MODEL_UNAVAILABLE)
        return try {
            loaded.assess(raw)
        } catch (_: RuntimeException) {
            ExperimentalMlResult.Unavailable(MlUnavailableReason.MODEL_UNAVAILABLE, loaded.version)
        }
    }
}

object ExperimentalPhishingMl {
    // AAPT strips .gz asset extensions; .model preserves the exact gzip bytes.
    private const val ASSET = "phishing_lr_v1.model"
    @Volatile private var engine: PhishingMlEngine? = null

    fun assess(context: Context, raw: String): ExperimentalMlResult {
        val current = engine ?: synchronized(this) {
            engine ?: PhishingMlEngine {
                context.applicationContext.assets.open(ASSET)
            }.also { engine = it }
        }
        return current.assess(raw)
    }
}

/** PHURLLR1 loader and the validated ASCII/IPv4 subset of the Python preprocessing. */
internal class PhishingUrlModel private constructor(
    private val weights: DoubleArray,
    private val vocabulary: Map<String, Int>,
    private val numericWeights: DoubleArray,
    private val caps: FloatArray,
    private val intercept: Double,
    val threshold: Double,
    private val numericScale: Double,
    private val minN: Int,
    private val maxN: Int,
    val version: Int
) {
    private data class Parts(
        val text: String, val host: String, val path: String, val query: String,
        val group: String, val isIp: Float
    )

    companion object {
        fun load(stream: InputStream): PhishingUrlModel {
            DataInputStream(BufferedInputStream(GZIPInputStream(stream))).use { input ->
                val magic = ByteArray(8)
                input.readFully(magic)
                require(String(magic, StandardCharsets.US_ASCII) == "PHURLLR1")
                val version = input.readInt()
                require(version == 1)
                val charCount = input.readInt()
                val numericCount = input.readInt()
                val minN = input.readInt()
                val maxN = input.readInt()
                require(charCount == 75000 && numericCount == 14 && minN == 3 && maxN == 4)
                val intercept = input.readDouble()
                val threshold = input.readDouble()
                val numericScale = input.readDouble()
                require(intercept.isFinite() && threshold > 0.0 && threshold < 1.0 && numericScale == 0.25)
                val caps = FloatArray(numericCount) { input.readFloat() }
                require(caps.all { it.isFinite() && it > 0f })
                val numericWeights = DoubleArray(numericCount) { input.readDouble() }
                require(numericWeights.all(Double::isFinite))
                val weights = DoubleArray(charCount)
                val vocabulary = HashMap<String, Int>(charCount * 2)
                repeat(charCount) { index ->
                    val size = input.readUnsignedShort()
                    require(size in 1..32)
                    val bytes = ByteArray(size)
                    input.readFully(bytes)
                    val feature = String(bytes, StandardCharsets.UTF_8)
                    require(vocabulary.put(feature, index) == null)
                    weights[index] = input.readDouble()
                    require(weights[index].isFinite())
                }
                require(input.read() == -1)
                return PhishingUrlModel(
                    weights, vocabulary, numericWeights, caps, intercept, threshold,
                    numericScale, minN, maxN, version
                )
            }
        }
    }

    private fun parse(raw: String): Pair<Parts?, MlUnavailableReason?> {
        if (raw.isEmpty() || raw.length > 4096) return null to MlUnavailableReason.INVALID_INPUT
        if (raw.any { it.code <= 0x20 || it.code == 0x7f }) return null to MlUnavailableReason.INVALID_INPUT
        if (raw.any { it.code > 0x7f }) return null to MlUnavailableReason.UNSUPPORTED_INPUT
        val explicit = Regex("^[A-Za-z][A-Za-z0-9+.-]*://").containsMatchIn(raw)
        if (!explicit && raw.contains("://")) return null to MlUnavailableReason.INVALID_INPUT
        val uri = try { URI(if (explicit) raw else "http://$raw") }
        catch (_: Exception) { return null to MlUnavailableReason.INVALID_INPUT }
        if (explicit && uri.scheme?.lowercase(Locale.ROOT) !in listOf("http", "https"))
            return null to MlUnavailableReason.UNSUPPORTED_INPUT
        if (uri.rawUserInfo != null) return null to MlUnavailableReason.INVALID_INPUT
        var host = uri.host ?: return null to MlUnavailableReason.INVALID_INPUT
        if (host.startsWith("[") || host.contains(':')) return null to MlUnavailableReason.UNSUPPORTED_INPUT
        host = try { IDN.toASCII(host.trimEnd('.').lowercase(Locale.ROOT)) }
        catch (_: Exception) { return null to MlUnavailableReason.INVALID_INPUT }
        if (host.isEmpty() || uri.port > 65535) return null to MlUnavailableReason.INVALID_INPUT
        val ipv4 = isIpv4(host)
        val group: String
        val isIp: Float
        if (ipv4) {
            group = "ip:$host"
            isIp = 1f
        } else {
            val labels = host.split('.')
            val dnsLabel = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
            if (labels.size < 2 || labels.any { !dnsLabel.matches(it) })
                return null to MlUnavailableReason.INVALID_INPUT
            group = labels.takeLast(2).joinToString(".")
            isIp = 0f
        }
        val path = uri.rawPath ?: ""
        val query = uri.rawQuery ?: ""
        val text = host + (if (path.isEmpty()) "/" else path) +
            (if (query.isNotEmpty()) "?$query" else "")
        return Parts(text, host, path, query, group, isIp) to null
    }

    private fun isIpv4(host: String): Boolean {
        val bits = host.split('.')
        if (bits.size != 4) return false
        return bits.all { it.isNotEmpty() && (it == "0" || !it.startsWith('0')) &&
            it.all(Char::isDigit) && (it.toIntOrNull() ?: 256) in 0..255 }
    }

    private fun entropy(host: String): Double {
        val counts = HashMap<Char, Int>()
        host.forEach { counts[it] = (counts[it] ?: 0) + 1 }
        return counts.values.sumOf { count ->
            val p = count.toDouble() / host.length
            -p * (ln(p) / ln(2.0))
        }
    }

    private fun numerical(parts: Parts): FloatArray {
        val text = parts.text
        val host = parts.host
        val path = parts.path
        val query = parts.query
        val subdepth = (host.split('.').size - parts.group.split('.').size).coerceAtLeast(0)
        val original = doubleArrayOf(
            host.length.toDouble(), path.length.toDouble(), query.length.toDouble(),
            text.count(Char::isDigit).toDouble(), text.count { it == '-' }.toDouble(),
            host.count { it == '.' }.toDouble(), subdepth.toDouble(),
            text.count { it == '@' }.toDouble(), text.count { it == '%' }.toDouble(),
            path.count { it == '/' }.toDouble(),
            (query.count { it == '&' } + if (query.isNotEmpty()) 1 else 0).toDouble(),
            entropy(host), text.length.toDouble(), parts.isIp.toDouble()
        )
        val raw = FloatArray(14) { index ->
            kotlin.math.expm1(
                kotlin.math.ln1p(original[index].toFloat().toDouble()).toFloat().toDouble()
            ).toFloat()
        }
        val total = maxOf(raw[12], 1f)
        val ratios = floatArrayOf(
            raw[0], raw[1], raw[2], raw[3] / total, raw[4] / total,
            raw[5], raw[6], raw[7], raw[8], raw[9], raw[10], raw[11], raw[12], raw[13]
        )
        return FloatArray(14) { index ->
            numericScale.toFloat() * min(ratios[index] / caps[index], 1f)
        }
    }

    fun assess(raw: String): ExperimentalMlResult {
        val (parts, reason) = parse(raw)
        if (parts == null) return ExperimentalMlResult.Unavailable(reason!!, version)
        val lower = parts.text.lowercase(Locale.ROOT)
        val active = HashSet<Int>()
        for (n in minN..maxN) {
            for (start in 0..(lower.length - n)) {
                vocabulary[lower.substring(start, start + n)]?.let(active::add)
            }
        }
        var logit = intercept
        active.sorted().forEach { logit += weights[it] }
        val numeric = numerical(parts)
        for (index in numeric.indices) logit += numericWeights[index] * numeric[index]
        val score = if (logit >= 0) 1.0 / (1.0 + exp(-logit))
                    else exp(logit) / (1.0 + exp(logit))
        return ExperimentalMlResult.Scored(
            if (score >= threshold) MlPattern.PHISHING_LIKE else MlPattern.BENIGN_LIKE,
            score, threshold, version
        )
    }
}
