package com.acutis.firewall.service

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class DnsQuestionNameParserTest {

    private fun query(name: String): ByteArray {
        val labels = name.split(".")
        val qname = buildList<Byte> {
            labels.forEach { label ->
                add(label.length.toByte())
                label.toByteArray(Charsets.US_ASCII).forEach(::add)
            }
            add(0)
        }.toByteArray()

        return byteArrayOf(
            0x12, 0x34, // ID
            0x01, 0x00, // RD
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00  // ARCOUNT
        ) + qname + byteArrayOf(0x00, 0x01, 0x00, 0x01)
    }

    @Test
    fun `extracts a standard QNAME`() {
        assertThat(DnsQuestionNameParser.extractSingleQuestionName(query("WWW.Example.COM")))
            .isEqualTo("www.example.com")
    }

    @Test
    fun `rejects packets with no question or multiple questions`() {
        val noQuestion = query("example.com").apply {
            this[4] = 0
            this[5] = 0
        }
        val multipleQuestions = query("example.com").apply {
            this[5] = 2
        }

        assertThat(DnsQuestionNameParser.extractSingleQuestionName(noQuestion)).isNull()
        assertThat(DnsQuestionNameParser.extractSingleQuestionName(multipleQuestions)).isNull()
    }

    @Test
    fun `rejects DNS responses as input queries`() {
        assertThat(
            DnsQuestionNameParser.extractSingleQuestionName(query("example.com").apply {
                this[2] = 0x81.toByte()
            })
        ).isNull()
    }

    @Test
    fun `rejects truncated labels and missing question fields`() {
        val truncated = query("example.com").copyOfRange(0, 17)
        val missingTypeClass = query("example.com").copyOfRange(0, query("example.com").size - 2)

        assertThat(DnsQuestionNameParser.extractSingleQuestionName(truncated)).isNull()
        assertThat(DnsQuestionNameParser.extractSingleQuestionName(missingTypeClass)).isNull()
    }

    @Test
    fun `rejects reserved label encodings`() {
        val malformed = query("example.com")
        malformed[12] = 0x40
        assertThat(DnsQuestionNameParser.extractSingleQuestionName(malformed)).isNull()
    }
}
