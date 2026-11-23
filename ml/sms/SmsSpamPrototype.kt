import java.io.DataInputStream
import java.io.File
import java.util.Locale
import java.util.zip.GZIPInputStream
import kotlin.math.exp

/** Research-only offline inference reference. No Android project dependency. */
class SmsSpamPrototype(path: File) {
    private val vocabulary = HashMap<String, Int>()
    private val weights: DoubleArray
    private val bias: Double
    val threshold: Double
    val version: Int
    private val kind: Int

    init {
        DataInputStream(GZIPInputStream(path.inputStream())).use { input ->
            val magic = ByteArray(4)
            input.readFully(magic)
            require(String(magic, Charsets.US_ASCII) == "SMS1") { "Invalid artifact" }
            version = input.readUnsignedByte()
            require(version == 1) { "Unsupported version" }
            kind = input.readUnsignedByte()
            require(kind == 1 || kind == 2) { "Unsupported model" }
            val n = input.readInt()
            require(n in 1..100000) { "Invalid vocabulary size" }
            bias = input.readDouble()
            threshold = input.readDouble()
            weights = DoubleArray(n)
            repeat(n) { i ->
                val len = input.readUnsignedShort()
                require(len in 1..512) { "Invalid term size" }
                val bytes = ByteArray(len)
                input.readFully(bytes)
                vocabulary[String(bytes, Charsets.US_ASCII)] = i
                weights[i] = input.readDouble()
            }
        }
    }

    data class Result(val available: Boolean, val score: Double? = null,
                      val spam: Boolean? = null, val reason: String? = null)

    fun predict(message: String): Result {
        if (message.isBlank()) return Result(false, reason = "empty")
        if (message.length > 4096) return Result(false, reason = "too_long")
        if (message.any { it.code > 127 || (it.code < 32 && it != '\n' && it != '\r' && it != '\t') })
            return Result(false, reason = "unsupported_character")
        val digits = Regex("[0-9]+")
        val words = Regex("[A-Za-z0-9]+").findAll(message.lowercase(Locale.ROOT))
            .map { digits.replace(it.value, "0") }.toList()
        if (words.isEmpty()) return Result(false, reason = "no_tokens")
        val counts = HashMap<Int, Int>()
        fun add(term: String) { vocabulary[term]?.let { counts[it] = (counts[it] ?: 0) + 1 } }
        words.forEach(::add)
        for (i in 0 until words.size - 1) add(words[i] + "_" + words[i+1])
        var raw = bias
        // Feature order follows vocabulary export order, matching Python summation.
        for (i in weights.indices) {
            val count = counts[i] ?: continue
            raw += weights[i] * if (kind == 1) 1 else count
        }
        val score = if (raw >= 0) 1.0 / (1.0 + exp(-raw)) else exp(raw) / (1.0 + exp(raw))
        return Result(true, score, score >= threshold)
    }
}

fun main(args: Array<String>) {
    require(args.size == 1) { "Usage: SmsSpamPrototype <artifact>" }
    val model = SmsSpamPrototype(File(args[0]))
    val examples = listOf(
        "Your OTP is 123456. Do not share it.",
        "URGENT verify KYC now to avoid account block",
        "Congratulations you won a prize claim now",
        "Your bank statement is ready in the app",
        "Are we meeting at 6 tonight?",
        "", "नमस्ते", "Hello!", "Please call me tomorrow", "Your package arrives today",
        "Claim your cash reward now", "Update your account details immediately",
        "Your salary was deposited", "Meeting moved to 10 AM", "A", "123456", "http://example.invalid",
        "\u0000", " ", "x".repeat(4097)
    )
    for (message in examples) {
        val result = model.predict(message)
        println(if (result.available) "${result.score}\t${result.spam}" else "UNSUPPORTED\t${result.reason}")
    }
}
