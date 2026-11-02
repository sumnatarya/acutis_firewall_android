package com.acutis.firewall.blocklist

import java.net.IDN
import java.util.Locale

/** Parses all hostnames in each hosts-file mapping row. */
internal object HostsFileParser {
    fun parseLine(line: String): Set<String> {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("!")) {
            return emptySet()
        }

        val tokens = trimmed.split(Regex("\\s+"))
        if (tokens.isEmpty()) return emptySet()

        val candidates = if (isAddressToken(tokens.first())) tokens.drop(1) else tokens.take(1)
        return candidates
            .takeWhile { !it.startsWith("#") && !it.startsWith("!") }
            .mapNotNull(::normalizeHostname)
            .toSet()
    }

    private fun isAddressToken(token: String): Boolean {
        val parts = token.split('.')
        if (parts.size == 4 && parts.all { part ->
                part.isNotEmpty() && part.all(Char::isDigit) && part.toIntOrNull() in 0..255
            }
        ) return true

        return token.contains(':') &&
            token.matches(Regex("^[0-9a-fA-F:.]+$")) &&
            token.count { it == ':' } >= 2
    }

    private fun normalizeHostname(candidate: String): String? {
        val trimmed = candidate.trim().trimEnd('.')
        if (trimmed.isEmpty() || trimmed.startsWith("*")) return null

        val ascii = try {
            IDN.toASCII(trimmed.lowercase(Locale.ROOT), IDN.USE_STD3_ASCII_RULES)
        } catch (_: IllegalArgumentException) {
            return null
        }

        if (ascii.length > 253 || !ascii.contains('.')) return null
        if (ascii == "localhost" || ascii.endsWith(".localhost") ||
            ascii == "local" || ascii.endsWith(".local")
        ) return null

        val labels = ascii.split('.')
        if (labels.any { label ->
                label.isEmpty() || label.length > 63 ||
                    !label.matches(Regex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"))
            }
        ) return null

        return ascii
    }
}
