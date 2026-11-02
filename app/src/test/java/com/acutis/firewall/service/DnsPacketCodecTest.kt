package com.acutis.firewall.service

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class DnsPacketCodecTest {

    private val sourceIp = byteArrayOf(10, 0, 0, 2)
    private val dnsIp = byteArrayOf(10, 0, 0, 1)

    private fun sampleDnsQuery(): ByteArray {
        return byteArrayOf(
            0x12, 0x34, // ID
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
            'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00, // root label
            0x00, 0x01, // A
            0x00, 0x01  // IN
        )
    }

    private fun ipv4UdpPacket(
        payload: ByteArray = sampleDnsQuery(),
        destinationPort: Int = 53,
        protocol: Int = 17,
        fragmentField: Int = 0,
        headerLength: Int = 20,
        totalLengthOverride: Int? = null
    ): ByteArray {
        val udpLength = 8 + payload.size
        val totalLength = totalLengthOverride ?: headerLength + udpLength
        val packet = ByteArray(maxOf(totalLength, headerLength + udpLength))
        packet[0] = ((4 shl 4) or (headerLength / 4)).toByte()
        packet[2] = (totalLength ushr 8).toByte()
        packet[3] = totalLength.toByte()
        packet[6] = (fragmentField ushr 8).toByte()
        packet[7] = fragmentField.toByte()
        packet[8] = 64
        packet[9] = protocol.toByte()
        sourceIp.copyInto(packet, 12)
        dnsIp.copyInto(packet, 16)

        if (headerLength >= 20 && packet.size >= headerLength + 8) {
            packet[headerLength] = 0xC0.toByte()
            packet[headerLength + 1] = 0x00
            packet[headerLength + 2] = (destinationPort ushr 8).toByte()
            packet[headerLength + 3] = destinationPort.toByte()
            packet[headerLength + 4] = (udpLength ushr 8).toByte()
            packet[headerLength + 5] = udpLength.toByte()
            payload.copyInto(packet, headerLength + 8)
        }
        return packet
    }

    @Test
    fun `parses a valid IPv4 UDP DNS query`() {
        val parsed = DnsPacketCodec.parseIpv4UdpQuery(ipv4UdpPacket())

        assertThat(parsed).isNotNull()
        assertThat(parsed!!.sourceAddress).isEqualTo(sourceIp)
        assertThat(parsed.destinationAddress).isEqualTo(dnsIp)
        assertThat(parsed.sourcePort).isEqualTo(49152)
        assertThat(parsed.destinationPort).isEqualTo(53)
        assertThat(parsed.payload).isEqualTo(sampleDnsQuery())
    }

    @Test
    fun `supports IPv4 header options`() {
        val parsed = DnsPacketCodec.parseIpv4UdpQuery(ipv4UdpPacket(headerLength = 24))

        assertThat(parsed).isNotNull()
        assertThat(parsed!!.payload).isEqualTo(sampleDnsQuery())
    }

    @Test
    fun `rejects packets shorter than an IPv4 header`() {
        assertThat(DnsPacketCodec.parseIpv4UdpQuery(ByteArray(19))).isNull()
    }

    @Test
    fun `rejects non IPv4 packets`() {
        val packet = ipv4UdpPacket()
        packet[0] = 0x60
        assertThat(DnsPacketCodec.parseIpv4UdpQuery(packet)).isNull()
    }

    @Test
    fun `rejects invalid IPv4 header lengths`() {
        val packet = ipv4UdpPacket()
        packet[0] = 0x44
        assertThat(DnsPacketCodec.parseIpv4UdpQuery(packet)).isNull()
    }

    @Test
    fun `rejects non UDP packets`() {
        assertThat(DnsPacketCodec.parseIpv4UdpQuery(ipv4UdpPacket(protocol = 6))).isNull()
    }

    @Test
    fun `rejects non DNS destination ports`() {
        assertThat(DnsPacketCodec.parseIpv4UdpQuery(ipv4UdpPacket(destinationPort = 5353))).isNull()
    }

    @Test
    fun `rejects fragmented IPv4 packets`() {
        assertThat(
            DnsPacketCodec.parseIpv4UdpQuery(ipv4UdpPacket(fragmentField = 0x2000))
        ).isNull()
        assertThat(
            DnsPacketCodec.parseIpv4UdpQuery(ipv4UdpPacket(fragmentField = 0x0001))
        ).isNull()
    }

    @Test
    fun `rejects invalid IP total length`() {
        val packet = ipv4UdpPacket(totalLengthOverride = 10)
        assertThat(DnsPacketCodec.parseIpv4UdpQuery(packet)).isNull()
    }

    @Test
    fun `rejects truncated UDP datagrams`() {
        val packet = ipv4UdpPacket()
        packet[24] = 0x7F
        packet[25] = 0xFF
        assertThat(DnsPacketCodec.parseIpv4UdpQuery(packet)).isNull()
    }

    @Test
    fun `rejects DNS responses passed as queries`() {
        val response = sampleDnsQuery()
        response[2] = 0x81.toByte()
        assertThat(DnsPacketCodec.parseIpv4UdpQuery(ipv4UdpPacket(payload = response))).isNull()
    }

    @Test
    fun `builds an IPv4 UDP response with valid IP and UDP checksums`() {
        val packet = DnsPacketCodec.buildIpv4UdpPacket(
            sourceAddress = dnsIp,
            destinationAddress = sourceIp,
            sourcePort = 53,
            destinationPort = 49152,
            payload = sampleDnsQuery()
        )

        assertThat(packet).isNotNull()
        val actual = packet!!
        assertThat(actual.size).isEqualTo(20 + 8 + sampleDnsQuery().size)
        assertThat(actual[9].toInt() and 0xFF).isEqualTo(17)
        assertThat(actual.copyOfRange(12, 16)).isEqualTo(dnsIp)
        assertThat(actual.copyOfRange(16, 20)).isEqualTo(sourceIp)
        assertThat(internetChecksum(actual.copyOfRange(0, 20))).isEqualTo(0)

        val udpLength = ((actual[24].toInt() and 0xFF) shl 8) or
            (actual[25].toInt() and 0xFF)
        val pseudoHeaderAndUdp = ByteArray(12 + udpLength)
        dnsIp.copyInto(pseudoHeaderAndUdp, 0)
        sourceIp.copyInto(pseudoHeaderAndUdp, 4)
        pseudoHeaderAndUdp[9] = 17
        pseudoHeaderAndUdp[10] = (udpLength ushr 8).toByte()
        pseudoHeaderAndUdp[11] = udpLength.toByte()
        actual.copyInto(pseudoHeaderAndUdp, 12, 20, actual.size)
        assertThat(internetChecksum(pseudoHeaderAndUdp)).isEqualTo(0)
    }

    @Test
    fun `rejects response addresses that are not IPv4`() {
        assertThat(
            DnsPacketCodec.buildIpv4UdpPacket(
                sourceAddress = ByteArray(16),
                destinationAddress = sourceIp,
                sourcePort = 53,
                destinationPort = 10000,
                payload = sampleDnsQuery()
            )
        ).isNull()
    }

    @Test
    fun `creates a truncated DNS response preserving the question`() {
        val query = sampleDnsQuery()
        val truncated = DnsPacketCodec.createTruncatedDnsResponse(query)

        assertThat(truncated).isNotNull()
        val response = truncated!!
        assertThat(response.size).isEqualTo(query.size)
        assertThat(response[0]).isEqualTo(query[0])
        assertThat(response[1]).isEqualTo(query[1])
        assertThat(response[2].toInt() and 0x80).isEqualTo(0x80) // QR
        assertThat(response[2].toInt() and 0x02).isEqualTo(0x02) // TC
        assertThat(response[3].toInt() and 0x80).isEqualTo(0x80) // RA
        assertThat(response[4]).isEqualTo(0)
        assertThat(response[5]).isEqualTo(1)
        assertThat(response[6]).isEqualTo(0)
        assertThat(response[7]).isEqualTo(0)
        assertThat(response[8]).isEqualTo(0)
        assertThat(response[9]).isEqualTo(0)
        assertThat(response[10]).isEqualTo(0)
        assertThat(response[11]).isEqualTo(0)
    }

    private fun internetChecksum(data: ByteArray): Int {
        var sum = 0L
        var offset = 0
        while (offset + 1 < data.size) {
            sum += (((data[offset].toInt() and 0xFF) shl 8) or
                (data[offset + 1].toInt() and 0xFF)).toLong()
            offset += 2
        }
        if (offset < data.size) sum += ((data[offset].toInt() and 0xFF) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFFL) + (sum ushr 16)
        return sum.inv().toInt() and 0xFFFF
    }
}
