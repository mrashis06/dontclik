package com.example.executorchllamademo

import java.net.IDN
import java.net.URI
import java.net.URISyntaxException
import java.util.Locale

/** Local URL evidence only. This is a heuristic scanner, not a trained classifier. */
enum class ScanOutcome { SUSPICIOUS, INCONCLUSIVE, NO_OBVIOUS_INDICATORS }

enum class UrlIndicator(val description: String, val strong: Boolean) {
    IP_LITERAL("The hostname is an IP address rather than a domain name.", true),
    USERINFO("Text before @ is URI userinfo; the destination is the hostname after @.", true),
    IDN("The hostname contains an internationalized or punycode label.", false),
    DEEP_SUBDOMAINS("The hostname has at least three subdomain levels.", false),
    LONG_LABEL("A hostname label is unusually long (at least 40 characters).", false)
}

data class ScanResult(
    val outcome: ScanOutcome,
    val hostname: String?,
    val indicators: List<UrlIndicator>,
    val explanation: String
) {
    /** A count of observed heuristics, not a probability or safety rating. */
    val indicatorCount: Int get() = indicators.size
}

object UrlSecurityScanner {
    private const val MAX_INPUT_LENGTH = 8192
    private const val LONG_LABEL_LENGTH = 40
    private const val DEEP_HOST_LABEL_COUNT = 5

    fun scan(input: String): ScanResult {
        val value = input.trim()
        if (value.isEmpty() || value.length > MAX_INPUT_LENGTH ||
            value.any { it.isWhitespace() || Character.isISOControl(it) || it == '\\' }
        ) return inconclusive()

        // Bare domains are accepted for convenience. The added scheme is only for parsing.
        val explicitScheme = Regex("^[A-Za-z][A-Za-z0-9+.-]*:").find(value)?.value
        if (explicitScheme != null && explicitScheme.dropLast(1).lowercase(Locale.ROOT) !in setOf("http", "https")) {
            return inconclusive()
        }
        if (value.startsWith("//") || (explicitScheme == null && value.contains("://"))) return inconclusive()
        val candidate = if (explicitScheme == null) "https://$value" else value
        val uri = try { URI(candidate) } catch (_: URISyntaxException) { return inconclusive() }
        if (uri.isOpaque || uri.rawAuthority.isNullOrEmpty()) return inconclusive()

        val authority = uri.rawAuthority
        if (authority.any { it == '%' || it == '\\' }) return inconclusive()
        val atCount = authority.count { it == '@' }
        if (atCount > 1) return inconclusive()
        val hostAndPort = authority.substringAfterLast('@')
        val hadUserinfo = atCount == 1
        val host: String
        val ipLiteral: Boolean
        if (hostAndPort.startsWith('[')) {
            val close = hostAndPort.indexOf(']')
            if (close < 0 || !validPort(hostAndPort.substring(close + 1))) return inconclusive()
            host = hostAndPort.substring(1, close)
            if (!isIpv6(host)) return inconclusive()
            ipLiteral = true
        } else {
            if (hostAndPort.count { it == ':' } > 1) return inconclusive()
            host = hostAndPort.substringBefore(':')
            if (!validPort(hostAndPort.removePrefix(host))) return inconclusive()
            ipLiteral = isIpv4(host)
            // Numeric dotted hosts have alternate interpretations in some URL parsers.
            if (!ipLiteral && host.matches(Regex("[0-9.]+"))) return inconclusive()
        }
        if (host.isEmpty()) return inconclusive()

        val indicators = mutableListOf<UrlIndicator>()
        if (hadUserinfo) indicators += UrlIndicator.USERINFO
        if (ipLiteral) indicators += UrlIndicator.IP_LITERAL
        val displayHost: String
        if (ipLiteral) {
            displayHost = host.lowercase(Locale.ROOT)
        } else {
            val withoutTrailingDot = host.removeSuffix(".")
            if (withoutTrailingDot.isEmpty() || withoutTrailingDot.startsWith('.') || ".." in withoutTrailingDot) return inconclusive()
            val ascii = try { IDN.toASCII(withoutTrailingDot, IDN.USE_STD3_ASCII_RULES) }
            catch (_: IllegalArgumentException) { return inconclusive() }
            val labels = ascii.lowercase(Locale.ROOT).split('.')
            if (ascii.length > 253 || labels.size < 2 || labels.any { it.isEmpty() || it.length > 63 || it.startsWith('-') || it.endsWith('-') }) {
                return inconclusive()
            }
            displayHost = ascii.lowercase(Locale.ROOT)
            if (host.any { it.code > 127 } || labels.any { it.startsWith("xn--") }) indicators += UrlIndicator.IDN
            if (labels.size >= DEEP_HOST_LABEL_COUNT) indicators += UrlIndicator.DEEP_SUBDOMAINS
            if (labels.any { it.length >= LONG_LABEL_LENGTH }) indicators += UrlIndicator.LONG_LABEL
        }
        val outcome = when {
            indicators.any { it.strong } || indicators.size >= 2 -> ScanOutcome.SUSPICIOUS
            indicators.isNotEmpty() -> ScanOutcome.INCONCLUSIVE
            else -> ScanOutcome.NO_OBVIOUS_INDICATORS
        }
        val explanation = when (outcome) {
            ScanOutcome.SUSPICIOUS -> "URL structure has suspicious indicators. This is not proof of phishing."
            ScanOutcome.INCONCLUSIVE -> "The URL needs caution or could not be interpreted confidently."
            ScanOutcome.NO_OBVIOUS_INDICATORS -> "No obvious structural indicators found. This does not verify that the URL is safe."
        }
        return ScanResult(outcome, displayHost, indicators, explanation)
    }

    private fun inconclusive() = ScanResult(
        ScanOutcome.INCONCLUSIVE, null, emptyList(),
        "The URL could not be interpreted confidently. Do not treat it as verified safe."
    )

    private fun validPort(suffix: String): Boolean = suffix.isEmpty() ||
        (suffix.startsWith(':') && suffix.length in 2..6 &&
            suffix.drop(1).all { it in '0'..'9' } &&
            (suffix.drop(1).toIntOrNull() ?: 65536) in 0..65535)

    private fun isIpv4(host: String): Boolean {
        val parts = host.split('.')
        return parts.size == 4 && parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all { it in '0'..'9' } &&
                (part.length == 1 || part[0] != '0') && (part.toIntOrNull() ?: 256) <= 255
        }
    }

    private fun isIpv6(host: String): Boolean {
        if (host.isEmpty() || '%' in host || ":::" in host || host.count { it == ':' } < 2) return false
        val compression = host.indexOf("::")
        if (compression >= 0 && host.indexOf("::", compression + 2) >= 0) return false
        if (compression < 0 && (host.startsWith(':') || host.endsWith(':'))) return false
        if (compression >= 0 &&
            (host.startsWith(':') && !host.startsWith("::") || host.endsWith(':') && !host.endsWith("::"))
        ) return false
        val groups = if (compression >= 0) {
            val left = host.substring(0, compression).split(':').filter { it.isNotEmpty() }
            val right = host.substring(compression + 2).split(':').filter { it.isNotEmpty() }
            left + right
        } else host.split(':')
        val hasEmbeddedIpv4 = groups.lastOrNull()?.contains('.') == true
        if (hasEmbeddedIpv4 && !isIpv4(groups.last())) return false
        val hexGroups = if (hasEmbeddedIpv4) groups.dropLast(1) else groups
        if (hexGroups.any { it.isEmpty() || it.length > 4 || !it.all { c -> c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F' } }) return false
        val groupCount = hexGroups.size + if (hasEmbeddedIpv4) 2 else 0
        return if (compression >= 0) groupCount < 8 else groupCount == 8
    }
}
