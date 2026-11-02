package com.acutis.firewall.service

import java.nio.charset.StandardCharsets
import java.util.Locale

/**
 * Extracts the single QNAME evaluated by the DNS policy engine.
 *
 * Multi-question and compressed QNAME messages are rejected here because the
 * forwarder validates the standard, uncompressed question format as well.
 * Unsupported/malformed questions must not silently bypass local policy.
 */
internal object DnsQuestionNameParser {
    private const val DNS_HEADER_LENGTH = 12

    fun extractSingleQuestionName(message: ByteArray): String? {
        if (message.size < DNS_HEADER_LENGTH) return null

        val flags = message[2].toInt() and 0xFF
        if ((flags and 0x80) != 0) return null

        val questionCount = readU16(message, 4)
        if (questionCount != 1) return null

        val labels = mutableListOf<String>()
        var offset = DNS_HEADER_LENGTH
        var expandedNameLength = 1

        while (offset < message.size) {
            val labelLength = message[offset].toInt() and 0xFF
            offset++

            when {
                labelLength == 0 -> {
                    if (offset + 4 > message.size) return null
                    return labels.joinToString(".").lowercase(Locale.ROOT)
                }
                (labelLength and 0xC0) != 0 -> return null
                labelLength > 63 -> return null
                offset + labelLength > message.size -> return null
                else -> {
                    val labelBytes = message.copyOfRange(offset, offset + labelLength)
                    if (labelBytes.any { byte ->
                            val value = byte.toInt() and 0xFF
                            value !in 0x21..0x7E
                        }
                    ) {
                        return null
                    }

                    val label = String(labelBytes, StandardCharsets.US_ASCII)
                    labels += label
                    expandedNameLength += labelLength + 1
                    if (expandedNameLength > 255) return null
                    offset += labelLength
                }
            }
        }

        return null
    }

    private fun readU16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or
            (data[offset + 1].toInt() and 0xFF)
}
