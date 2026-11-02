package com.acutis.firewall.service

import java.net.IDN
import java.util.Locale

/** Shared host matching for the DNS policy engine. */
internal object DomainMatcher {

    fun normalizePattern(value: String): String? {
        val trimmed = value.trim().trimEnd('.').lowercase(Locale.ROOT)
        if (trimmed.isEmpty()) return null

        val wildcard = trimmed.startsWith("*.")
        val rawHost = if (wildcard) trimmed.removePrefix("*.") else trimmed
        if (rawHost.isEmpty() || rawHost.contains('*')) return null

        val host = normalizeHost(rawHost) ?: return null
        return if (wildcard) "*.$host" else host
    }

    fun matches(hostname: String, patterns: Set<String>): Boolean {
        val host = normalizeHost(hostname.trim().trimEnd('.')) ?: return false

        return patterns.any { rawPattern ->
            val pattern = normalizePattern(rawPattern) ?: return@any false
            val wildcard = pattern.startsWith("*.")
            val base = if (wildcard) pattern.removePrefix("*.") else pattern

            if (wildcard) {
                host != base && host.endsWith(".$base")
            } else {
                host == base || host.endsWith(".$base")
            }
        }
    }

    private fun normalizeHost(value: String): String? {
        val trimmed = value.trim().trimEnd('.')
        if (trimmed.isEmpty() || trimmed.contains('*')) return null

        val ascii = try {
            IDN.toASCII(trimmed.lowercase(Locale.ROOT), IDN.USE_STD3_ASCII_RULES)
        } catch (_: IllegalArgumentException) {
            return null
        }

        if (ascii.length > 253) return null
        val labels = ascii.split('.')
        if (labels.any { label ->
                label.isEmpty() || label.length > 63 ||
                    !label.matches(Regex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"))
            }
        ) return null

        return ascii
    }
}
