import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.File
import java.net.IDN
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale
import java.util.zip.GZIPInputStream
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.min

/** Standalone JVM/Kotlin parity prototype. No Android or Python dependency. */
class PhishingUrlModel private constructor(
    private val weights: DoubleArray,
    private val vocabulary: Map<String, Int>,
    private val numericWeights: DoubleArray,
    private val caps: FloatArray,
    private val intercept: Double,
    val threshold: Double,
    private val numericScale: Double,
    private val minN: Int,
    private val maxN: Int,
) {
    data class Result(val score: Double?, val label: String?, val error: String?)
    private data class Parts(
        val text: String, val host: String, val path: String, val query: String,
        val group: String, val isIp: Float
    )

    companion object {
        fun load(file: File): PhishingUrlModel {
            DataInputStream(BufferedInputStream(GZIPInputStream(file.inputStream()))).use { input ->
                val magic = ByteArray(8)
                input.readFully(magic)
                require(String(magic, StandardCharsets.US_ASCII) == "PHURLLR1") { "Bad artifact magic" }
                val version = input.readInt()
                require(version == 1) { "Unsupported artifact version $version" }
                val charCount = input.readInt()
                val numericCount = input.readInt()
                val minN = input.readInt()
                val maxN = input.readInt()
                require(charCount in 1..200000 && numericCount == 14 && minN == 3 && maxN == 4) {
                    "Unexpected feature layout"
                }
                val intercept = input.readDouble()
                val threshold = input.readDouble()
                val numericScale = input.readDouble()
                require(threshold > 0.0 && threshold < 1.0 && numericScale == 0.25)
                val caps = FloatArray(numericCount) { input.readFloat() }
                val numericWeights = DoubleArray(numericCount) { input.readDouble() }
                val weights = DoubleArray(charCount)
                val vocabulary = HashMap<String, Int>(charCount * 2)
                repeat(charCount) { index ->
                    val size = input.readUnsignedShort()
                    require(size in 1..32) { "Invalid n-gram size" }
                    val bytes = ByteArray(size)
                    input.readFully(bytes)
                    val feature = String(bytes, StandardCharsets.UTF_8)
                    require(vocabulary.put(feature, index) == null) { "Duplicate n-gram" }
                    weights[index] = input.readDouble()
                }
                require(input.read() == -1) { "Unexpected artifact trailing bytes" }
                return PhishingUrlModel(weights, vocabulary, numericWeights, caps,
                    intercept, threshold, numericScale, minN, maxN)
            }
        }
    }

    private fun parse(raw: String): Pair<Parts?, String?> {
        if (raw.isEmpty() || raw.length > 4096) return null to "empty_or_overlong"
        if (raw.any { it.code <= 0x20 || it.code == 0x7f }) return null to "control_or_space"
        if (raw.any { it.code > 0x7f }) return null to "unsupported_non_ascii"
        val explicit = Regex("^[A-Za-z][A-Za-z0-9+.-]*://").containsMatchIn(raw)
        if (!explicit && raw.contains("://")) return null to "malformed_scheme"
        val uri = try { URI(if (explicit) raw else "http://$raw") }
                  catch (_: Exception) { return null to "malformed_url" }
        if (explicit && uri.scheme?.lowercase(Locale.ROOT) !in listOf("http", "https"))
            return null to "unsupported_scheme"
        if (uri.rawUserInfo != null) return null to "userinfo"
        var host = uri.host ?: return null to "bad_host_or_port"
        if (host.startsWith("[") || host.contains(':')) return null to "unsupported_ipv6"
        host = try { IDN.toASCII(host.trimEnd('.').lowercase(Locale.ROOT)) }
               catch (_: Exception) { return null to "bad_host_or_port" }
        if (host.isEmpty()) return null to "missing_host"
        if (uri.port > 65535) return null to "bad_host_or_port"
        val ipv4 = isIpv4(host)
        val group: String
        val isIp: Float
        if (ipv4) {
            group = "ip:$host"
            isIp = 1.0f
        } else {
            val labels = host.split('.')
            val dnsLabel = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
            if (labels.size < 2 || labels.any { !dnsLabel.matches(it) })
                return null to "bad_dns_name"
            group = labels.takeLast(2).joinToString(".")
            isIp = 0.0f
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
        // Mirror numpy float32 log1p -> expm1 -> ratio -> capped scale.
        val raw = FloatArray(14) { index ->
            kotlin.math.expm1(kotlin.math.ln1p(original[index].toFloat().toDouble()).toFloat().toDouble()).toFloat()
        }
        val total = maxOf(raw[12], 1.0f)
        val ratios = floatArrayOf(
            raw[0], raw[1], raw[2], raw[3] / total, raw[4] / total,
            raw[5], raw[6], raw[7], raw[8], raw[9], raw[10],
            raw[11], raw[12], raw[13]
        )
        return FloatArray(14) { index ->
            (numericScale.toFloat() * min(ratios[index] / caps[index], 1.0f))
        }
    }

    fun predict(raw: String): Result {
        val (parts, error) = parse(raw)
        if (parts == null) return Result(null, null, error)
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
        return Result(score, if (score >= threshold) "phishing" else "benign", null)
    }
}

fun main(args: Array<String>) {
    require(args.size == 1) { "Usage: java -jar prototype.jar artifact.bin.gz" }
    val model = PhishingUrlModel.load(File(args[0]))
    System.`in`.bufferedReader(StandardCharsets.UTF_8).forEachLine { line ->
        val tab = line.indexOf('\t')
        require(tab > 0) { "Expected case-id<TAB>base64-url" }
        val caseId = line.substring(0, tab)
        val raw = String(Base64.getDecoder().decode(line.substring(tab + 1)), StandardCharsets.UTF_8)
        val result = model.predict(raw)
        if (result.error != null) {
            println("$caseId\tERROR\t${result.error}")
        } else {
            println("$caseId\tOK\t${result.score}\t${result.label}")
        }
    }
}
