package com.acutis.firewall.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue

class DnsMessageTest {
    private val forwarder = DnsOverHttpsForwarder { true }

    @Test
    fun validSingleQuestionHasCorrectEnd() {
        val query = query("www.google.com")
        assertTrue(forwarder.isValidQuery(query))
        val end = forwarder.findQuestionEnd(query)
        assertNotNull(end)
        assertEquals(query.size, end)
    }

    @Test
    fun servFailPreservesIdAndQuestionAndSetsResponseFlags() {
        val query = query("www.google.com")
        val response = forwarder.createServFailResponse(query)
        assertNotNull(response)
        assertEquals(query[0], response!![0])
        assertEquals(query[1], response[1])
        assertEquals(0x81, response[2].toInt() and 0xFF)
        assertEquals(0x82, response[3].toInt() and 0xFF)
        assertEquals(query.size, response.size)
        assertEquals(query.copyOfRange(12, query.size).toList(), response.copyOfRange(12, response.size).toList())
        assertTrue(forwarder.isValidResponse(query, response))
    }

    @Test
    fun truncatedOrMalformedQuestionIsRejected() {
        assertFalse(forwarder.isValidQuery(byteArrayOf(0, 1, 0)))
        assertNull(forwarder.findQuestionEnd(byteArrayOf(0, 1, 0)))
        val malformed = query("www.google.com").copyOf().apply { this[12] = 0x40 }
        assertNull(forwarder.findQuestionEnd(malformed))
    }

    private fun query(name: String): ByteArray {
        val out = ArrayList<Byte>()
        out += listOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00).map { it.toByte() }
        name.split(".").forEach { label ->
            out += label.length.toByte()
            label.toByteArray(Charsets.US_ASCII).forEach { out += it }
        }
        out += 0
        out += listOf(0x00, 0x01, 0x00, 0x01).map { it.toByte() } // A, IN
        return out.toByteArray()
    }
}
