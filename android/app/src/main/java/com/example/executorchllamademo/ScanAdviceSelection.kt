package com.example.executorchllamademo

/** Fixed security guidance. Model output is never shown to the user. */
enum class SecurityAdviceId(val advice: String) {
    USERINFO_AT("Text before @ can make a link look familiar, but the destination is the hostname after @. Open the service through a trusted app or address instead."),
    IP_LITERAL("An IP address as the destination gives less recognizable identity information than a familiar domain name. Verify the destination independently."),
    IDN_CAUTION("Internationalized or punycode labels can be hard to recognize at a glance. Check the destination through a trusted source."),
    HOSTNAME_STRUCTURE("An unusually deep or long hostname deserves a closer look. Verify the intended site independently."),
    KEEP_CREDENTIALS_PRIVATE("Do not share your password or one-time code (OTP) through a link. Use the service's trusted app or address."),
    VERIFY_INDEPENDENTLY("Open a known official app or type a trusted address yourself before signing in or entering private information."),
    INCONCLUSIVE_CAUTION("This structural check is inconclusive. It cannot establish whether the destination is safe."),
    NO_OBVIOUS_CAUTION("No obvious structural indicators were found. This does not verify that the destination is safe.")
}

enum class AdviceParseReason { ACCEPTED, FORMAT_REJECTION, UNKNOWN_ID, DISALLOWED_ID, DUPLICATE_ID, TRUNCATED }

data class AdviceParseResult(val reason: AdviceParseReason, val ids: List<SecurityAdviceId> = emptyList())

/** A closed selection contract; all input types are scanner enums, never URL text. */
object ScanAdviceSelection {
    private const val MAX_STRUCTURAL_WHITESPACE = 16
    private val exactResponse = Regex(
        "\\A[ \\t\\r\\n]*IDS[ \\t\\r\\n]*=[ \\t\\r\\n]*([A-Z_]+)" +
            "(?:[ \\t\\r\\n]*,[ \\t\\r\\n]*([A-Z_]+))?" +
            "[ \\t\\r\\n]*;[ \\t\\r\\n]*END[ \\t\\r\\n]*\\z"
    )

    fun allowed(outcome: ScanOutcome, indicators: List<UrlIndicator>): Set<SecurityAdviceId> {
        val allowed = linkedSetOf(SecurityAdviceId.KEEP_CREDENTIALS_PRIVATE, SecurityAdviceId.VERIFY_INDEPENDENTLY)
        if (UrlIndicator.USERINFO in indicators) allowed += SecurityAdviceId.USERINFO_AT
        if (UrlIndicator.IP_LITERAL in indicators) allowed += SecurityAdviceId.IP_LITERAL
        if (UrlIndicator.IDN in indicators) allowed += SecurityAdviceId.IDN_CAUTION
        if (UrlIndicator.DEEP_SUBDOMAINS in indicators || UrlIndicator.LONG_LABEL in indicators) {
            allowed += SecurityAdviceId.HOSTNAME_STRUCTURE
        }
        when (outcome) {
            ScanOutcome.INCONCLUSIVE -> allowed += SecurityAdviceId.INCONCLUSIVE_CAUTION
            ScanOutcome.NO_OBVIOUS_INDICATORS -> allowed += SecurityAdviceId.NO_OBVIOUS_CAUTION
            ScanOutcome.SUSPICIOUS -> Unit
        }
        return allowed
    }

    /** The END marker and full-string match reject incomplete, extra, and truncated output. */
    fun parse(
        output: String,
        outcome: ScanOutcome,
        indicators: List<UrlIndicator>,
        truncated: Boolean = false
    ): AdviceParseResult {
        if (truncated) return AdviceParseResult(AdviceParseReason.TRUNCATED)
        val whitespaceCount = output.count { it == ' ' || it == '\t' || it == '\r' || it == '\n' }
        if (whitespaceCount > MAX_STRUCTURAL_WHITESPACE) {
            return AdviceParseResult(AdviceParseReason.FORMAT_REJECTION)
        }
        val match = exactResponse.matchEntire(output)
            ?: return AdviceParseResult(AdviceParseReason.FORMAT_REJECTION)
        val names = listOfNotNull(match.groupValues[1], match.groupValues[2].takeIf { it.isNotEmpty() })
        if (names.size != names.distinct().size) return AdviceParseResult(AdviceParseReason.DUPLICATE_ID)
        val ids = names.map { name -> SecurityAdviceId.entries.find { it.name == name }
            ?: return AdviceParseResult(AdviceParseReason.UNKNOWN_ID) }
        if (!allowed(outcome, indicators).containsAll(ids)) return AdviceParseResult(AdviceParseReason.DISALLOWED_ID)
        return AdviceParseResult(AdviceParseReason.ACCEPTED, ids)
    }

    fun fallback(outcome: ScanOutcome, indicators: List<UrlIndicator>): List<SecurityAdviceId> {
        val primary = when {
            UrlIndicator.USERINFO in indicators -> SecurityAdviceId.USERINFO_AT
            UrlIndicator.IP_LITERAL in indicators -> SecurityAdviceId.IP_LITERAL
            UrlIndicator.IDN in indicators -> SecurityAdviceId.IDN_CAUTION
            UrlIndicator.DEEP_SUBDOMAINS in indicators || UrlIndicator.LONG_LABEL in indicators ->
                SecurityAdviceId.HOSTNAME_STRUCTURE
            outcome == ScanOutcome.NO_OBVIOUS_INDICATORS -> SecurityAdviceId.NO_OBVIOUS_CAUTION
            else -> SecurityAdviceId.INCONCLUSIVE_CAUTION
        }
        return listOf(primary, SecurityAdviceId.VERIFY_INDEPENDENTLY)
    }

    fun build(outcome: ScanOutcome, indicators: List<UrlIndicator>): String {
        val permitted = allowed(outcome, indicators).joinToString(",") { it.name }
        val system = "Select one or two security advice IDs from the permitted IDs only. " +
            "Use only the supplied scanner outcome and indicator IDs. Do not infer other URL features. " +
            "Reply with exactly IDS=ID or IDS=ID1,ID2 followed immediately by ;END. " +
            "No explanation, quotes, code fence, or other text. " +
            "Example valid syntax: IDS=VERIFY_INDEPENDENTLY;END. " +
            "The IDs select fixed advice; do not write advice."
        val user = "Outcome=${outcome.name}\nIndicators=${indicators.distinct().joinToString(",") { it.name }.ifEmpty { "NONE" }}\n" +
            "Permitted IDs=$permitted\nSelect one or two IDs."
        return PromptFormat.getSystemPromptTemplate(ModelType.LLAMA_3)
            .replace(PromptFormat.SYSTEM_PLACEHOLDER, system) +
            PromptFormat.getUserPromptTemplate(ModelType.LLAMA_3)
                .replace(PromptFormat.USER_PLACEHOLDER, user)
    }
}
