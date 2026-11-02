package com.acutis.firewall.service

/**
 * A validated DNS query carried in an IPv4/UDP packet.
 *
 * Address arrays are always four bytes and are copied from the source packet.
 */
internal data class DnsUdpQuery(
    val sourceAddress: ByteArray,
    val destinationAddress: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray
)

/**
 * Small, Android-independent codec for the IPv4/UDP packets used by the DNS-only VPN.
 *
 * This codec deliberately rejects fragmented IPv4 datagrams. Correctly reassembling
 * fragments requires state across packets; DNS queries sent through this app should
 * fit within the TUN MTU and must not be partially interpreted.
 */
internal object DnsPacketCodec {
    private const val IPV4_HEADER_MIN_LENGTH = 20
    private const val UDP_HEADER_LENGTH = 8
    private const val DNS_HEADER_LENGTH = 12
    private const val IP_PROTOCOL_UDP = 17
    private const val DNS_PORT = 53

    fun parseIpv4UdpQuery(packet: ByteArray): DnsUdpQuery? {
        if (packet.size < IPV4_HEADER_MIN_LENGTH) return null

        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        if (ipHeaderLength < IPV4_HEADER_MIN_LENGTH || ipHeaderLength > packet.size) return null

        val totalLength = readUnsignedShort(packet, 2)
        if (totalLength < ipHeaderLength + UDP_HEADER_LENGTH || totalLength > packet.size) return null

        // Reject packets with MF set or a non-zero fragment offset. DF is allowed.
        val flagsAndOffset = readUnsignedShort(packet, 6)
        if ((flagsAndOffset and 0x3FFF) != 0) return null

        if ((packet[9].toInt() and 0xFF) != IP_PROTOCOL_UDP) return null

        val udpOffset = ipHeaderLength
        val sourcePort = readUnsignedShort(packet, udpOffset)
        val destinationPort = readUnsignedShort(packet, udpOffset + 2)
        if (destinationPort != DNS_PORT) return null

        val udpLength = readUnsignedShort(packet, udpOffset + 4)
        if (udpLength < UDP_HEADER_LENGTH + DNS_HEADER_LENGTH) return null
        if (udpLength > totalLength - ipHeaderLength) return null

        val dnsPayload = packet.copyOfRange(
            udpOffset + UDP_HEADER_LENGTH,
            udpOffset + udpLength
        )

        // This entry point accepts queries, not packets already marked as responses.
        if ((dnsPayload[2].toInt() and 0x80) != 0) return null

        return DnsUdpQuery(
            sourceAddress = packet.copyOfRange(12, 16),
            destinationAddress = packet.copyOfRange(16, 20),
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            payload = dnsPayload
        )
    }

    /**
     * Builds a complete IPv4/UDP packet and calculates both the IPv4 and UDP checksums.
     * Returns null when the supplied values cannot form a valid IPv4 datagram.
     */
    fun buildIpv4UdpPacket(
        sourceAddress: ByteArray,
        destinationAddress: ByteArray,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray
    ): ByteArray? {
        if (sourceAddress.size != 4 || destinationAddress.size != 4) return null
        if (sourcePort !in 0..65535 || destinationPort !in 0..65535) return null

        val udpLength = UDP_HEADER_LENGTH + payload.size
        val totalLength = IPV4_HEADER_MIN_LENGTH + udpLength
        if (udpLength > 65535 || totalLength > 65535) return null

        val udpSegment = ByteArray(udpLength)
        writeUnsignedShort(udpSegment, 0, sourcePort)
        writeUnsignedShort(udpSegment, 2, destinationPort)
        writeUnsignedShort(udpSegment, 4, udpLength)
        // UDP checksum is filled after calculating the IPv4 pseudo-header checksum.
        payload.copyInto(udpSegment, UDP_HEADER_LENGTH)

        val pseudoHeaderAndUdp = ByteArray(12 + udpLength)
        sourceAddress.copyInto(pseudoHeaderAndUdp, 0)
        destinationAddress.copyInto(pseudoHeaderAndUdp, 4)
        pseudoHeaderAndUdp[8] = 0
        pseudoHeaderAndUdp[9] = IP_PROTOCOL_UDP.toByte()
        writeUnsignedShort(pseudoHeaderAndUdp, 10, udpLength)
        udpSegment.copyInto(pseudoHeaderAndUdp, 12)

        var udpChecksum = internetChecksum(pseudoHeaderAndUdp)
        // In IPv4, a computed zero checksum is transmitted as all ones.
        if (udpChecksum == 0) udpChecksum = 0xFFFF
        writeUnsignedShort(udpSegment, 6, udpChecksum)

        val packet = ByteArray(totalLength)
        packet[0] = 0x45
        packet[1] = 0
        writeUnsignedShort(packet, 2, totalLength)
        writeUnsignedShort(packet, 4, 0)
        writeUnsignedShort(packet, 6, 0x4000) // Don't Fragment
        packet[8] = 64
        packet[9] = IP_PROTOCOL_UDP.toByte()
        writeUnsignedShort(packet, 10, 0)
        sourceAddress.copyInto(packet, 12)
        destinationAddress.copyInto(packet, 16)

        val ipChecksum = internetChecksum(packet.copyOfRange(0, IPV4_HEADER_MIN_LENGTH))
        writeUnsignedShort(packet, 10, ipChecksum)
        udpSegment.copyInto(packet, IPV4_HEADER_MIN_LENGTH)

        return packet
    }

    /**
     * Creates a standards-compliant truncated DNS response from the original query.
     * It preserves the question section and sets TC so the resolver knows that the
     * UDP answer was intentionally shortened.
     */
    fun createTruncatedDnsResponse(query: ByteArray): ByteArray? {
        if (query.size < DNS_HEADER_LENGTH) return null
        if ((query[2].toInt() and 0x80) != 0) return null

        val questionCount = readUnsignedShort(query, 4)
        if (questionCount == 0) return null

        var offset = DNS_HEADER_LENGTH
        repeat(questionCount) {
            var nameComplete = false

            while (offset < query.size) {
                val labelLength = query[offset].toInt() and 0xFF
                when {
                    (labelLength and 0xC0) == 0xC0 -> {
                        if (offset + 1 >= query.size) return null
                        offset += 2
                        nameComplete = true
                        break
                    }
                    (labelLength and 0xC0) != 0 -> return null
                    labelLength == 0 -> {
                        offset++
                        nameComplete = true
                        break
                    }
                    labelLength > 63 -> return null
                    else -> {
                        offset++
                        if (offset + labelLength > query.size) return null
                        offset += labelLength
                    }
                }
            }

            if (!nameComplete || offset + 4 > query.size) return null
            offset += 4 // QTYPE and QCLASS
        }

        val response = query.copyOfRange(0, offset)
        val requestFlags1 = query[2].toInt() and 0xFF
        val requestFlags2 = query[3].toInt() and 0xFF

        // QR=1, TC=1; preserve opcode and RD.
        response[2] = (0x80 or (requestFlags1 and 0x79) or 0x02).toByte()
        // RA=1; preserve the Checking Disabled bit.
        response[3] = (0x80 or (requestFlags2 and 0x10)).toByte()

        // No answer, authority or additional records are included in this response.
        writeUnsignedShort(response, 6, 0)
        writeUnsignedShort(response, 8, 0)
        writeUnsignedShort(response, 10, 0)

        return response
    }

    private fun readUnsignedShort(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 8) or
            (data[offset + 1].toInt() and 0xFF)
    }

    private fun writeUnsignedShort(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }

    private fun internetChecksum(data: ByteArray): Int {
        var sum = 0L
        var offset = 0

        while (offset + 1 < data.size) {
            val word = ((data[offset].toInt() and 0xFF) shl 8) or
                (data[offset + 1].toInt() and 0xFF)
            sum += word.toLong()
            offset += 2
        }

        if (offset < data.size) {
            sum += ((data[offset].toInt() and 0xFF) shl 8).toLong()
        }

        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }

        return sum.inv().toInt() and 0xFFFF
    }
}
