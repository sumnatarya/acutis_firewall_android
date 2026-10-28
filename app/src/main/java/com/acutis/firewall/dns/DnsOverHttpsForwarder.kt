package com.acutis.firewall.dns

import android.util.Log
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import javax.net.SocketFactory
import java.util.concurrent.TimeUnit

/**
 * DNS-over-HTTPS forwarder. Its socket-preparation callback must route upstream
 * HTTPS traffic over the physical network, outside this DNS-only VPN tunnel.
 */
class DnsOverHttpsForwarder(private val prepareSocket: (Socket) -> Boolean) : AutoCloseable {
    companion object {
        private const val TAG = "DnsOverHttps"
        private const val HOST = "sky.rethinkdns.com"
        private const val ENDPOINT = "https://sky.rethinkdns.com/1:OPw_5Repnw_64h4AwIAGAOHRAJA="
        private val DNS_MEDIA_TYPE = "application/dns-message".toMediaType()
        private const val MAX_DNS_UDP_PAYLOAD = 1232
        private const val BOOTSTRAP_REFRESH_MIN_INTERVAL_MS = 15_000L
    }

    @Volatile private var bootstrapAddresses: List<InetAddress> = emptyList()
    @Volatile private var lastBootstrapAttemptMs: Long = 0L

    private val client = OkHttpClient.Builder()
        .dns(object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                if (!hostname.equals(HOST, ignoreCase = true)) {
                    throw IOException("Unexpected DNS lookup: $hostname")
                }
                return bootstrapAddresses.takeIf { it.isNotEmpty() }
                    ?: throw IOException("DoH bootstrap unavailable; restart VPN on the current network")
            }
        })
        .socketFactory(UpstreamSocketFactory(prepareSocket))
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .writeTimeout(5, TimeUnit.SECONDS)
        .callTimeout(8, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    /**
     * Resolves before the VPN is established. Refresh this after network changes,
     * because cached endpoint addresses may no longer be reachable on a new network.
     */
    @Synchronized
    fun refreshBootstrap(force: Boolean = true): Boolean {
        val now = System.nanoTime() / 1_000_000L
        if (!force && now - lastBootstrapAttemptMs < BOOTSTRAP_REFRESH_MIN_INTERVAL_MS) {
            return bootstrapAddresses.isNotEmpty()
        }
        lastBootstrapAttemptMs = now
        return try {
            val resolved = InetAddress.getAllByName(HOST).toList()
            bootstrapAddresses = resolved
            Log.i(TAG, "DoH bootstrap resolved ${resolved.size} address(es)")
            resolved.isNotEmpty()
        } catch (e: Exception) {
            Log.e(TAG, "DoH bootstrap failed", e)
            bootstrapAddresses = emptyList()
            false
        }
    }

    fun forward(query: ByteArray): ByteArray? {
        if (!isValidQuery(query)) {
            Log.w(TAG, "Rejecting malformed DNS query")
            return null
        }
        // DNS failures can be transient during captive portal checks or network changes.
        // Retry bootstrap for each request while the VPN itself remains active.
        if (bootstrapAddresses.isEmpty() && !refreshBootstrap(force = false)) {
            Log.e(TAG, "No DoH bootstrap address available")
            return createServFailResponse(query)
        }
        return try {
            val request = Request.Builder()
                .url(ENDPOINT)
                .header("Accept", "application/dns-message")
                .post(query.toRequestBody(DNS_MEDIA_TYPE))
                .build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.e(TAG, "DoH HTTP status ${response.code}")
                    return createServFailResponse(query)
                }
                val type = response.header("Content-Type")?.substringBefore(';')?.trim()
                if (!type.equals("application/dns-message", ignoreCase = true)) {
                    Log.e(TAG, "DoH returned unexpected content type: $type")
                    return createServFailResponse(query)
                }
                val body = response.body?.bytes()
                if (body == null || !isValidResponse(query, body)) {
                    Log.e(TAG, "DoH returned invalid or mismatched DNS response")
                    return createServFailResponse(query)
                }
                if (body.size <= MAX_DNS_UDP_PAYLOAD) body else createTruncatedResponse(query)
            }
        } catch (e: Exception) {
            Log.e(TAG, "DoH request failed", e)
            createServFailResponse(query)
        }
    }

    internal fun isValidQuery(query: ByteArray): Boolean {
        if (query.size < 12 || query.size > 65535) return false
        val flags = query[2].toInt() and 0xFF
        val questionCount = readU16(query, 4)
        return (flags and 0x80) == 0 && questionCount > 0 && findQuestionEnd(query) != null
    }

    internal fun isValidResponse(query: ByteArray, response: ByteArray): Boolean {
        if (response.size < 12 || response[0] != query[0] || response[1] != query[1]) return false
        val flags = response[2].toInt() and 0xFF
        if ((flags and 0x80) == 0) return false // QR must indicate a response.
        // Require the same question section to avoid accepting a mismatched response.
        val qEnd = findQuestionEnd(query) ?: return false
        val rEnd = findQuestionEnd(response) ?: return false
        if (qEnd != rEnd) return false
        for (i in 12 until qEnd) {
            if (query[i] != response[i]) return false
        }
        return true
    }

    internal fun createServFailResponse(query: ByteArray): ByteArray? {
        val questionEnd = findQuestionEnd(query) ?: return null
        val result = query.copyOfRange(0, questionEnd)
        result[2] = (((query[2].toInt() and 0x01) or 0x80 or 0x10)).toByte() // QR, preserve RD, RA
        result[3] = 0x02.toByte() // SERVFAIL; counts were cleared below
        result[6] = 0
        result[7] = 0
        result[8] = 0
        result[9] = 0
        result[10] = 0
        result[11] = 0
        return result
    }

    internal fun createTruncatedResponse(query: ByteArray): ByteArray? {
        val questionEnd = findQuestionEnd(query) ?: return null
        val result = query.copyOfRange(0, questionEnd)
        result[2] = ((result[2].toInt() and 0x7F) or 0x80 or 0x02).toByte()
        result[3] = (result[3].toInt() or 0x80).toByte()
        for (i in 6..11) result[i] = 0
        return result
    }

    internal fun findQuestionEnd(message: ByteArray): Int? {
        if (message.size < 12) return null
        val count = readU16(message, 4)
        if (count == 0 || count > 16) return null
        var pos = 12
        repeat(count) {
            var terminated = false
            var expandedNameLength = 1
            while (pos < message.size) {
                val length = message[pos].toInt() and 0xFF
                pos++
                if (length == 0) {
                    terminated = true
                    break
                }
                // QNAME compression is not expected in a query/question section.
                if ((length and 0xC0) != 0 || length > 63 || pos + length > message.size) return null
                expandedNameLength += length + 1
                if (expandedNameLength > 255) return null
                pos += length
            }
            if (!terminated || pos + 4 > message.size) return null
            pos += 4 // QTYPE + QCLASS
        }
        return pos.takeIf { it <= message.size }
    }

    private fun readU16(data: ByteArray, index: Int): Int =
        ((data[index].toInt() and 0xFF) shl 8) or (data[index + 1].toInt() and 0xFF)

    override fun close() {
        client.dispatcher.cancelAll()
        client.connectionPool.evictAll()
        bootstrapAddresses = emptyList()
        lastBootstrapAttemptMs = 0L
    }

    private class UpstreamSocketFactory(
        private val prepareSocket: (Socket) -> Boolean
    ) : SocketFactory() {
        private fun newUpstreamSocket(): Socket = Socket().also { socket ->
            if (!prepareSocket(socket)) {
                socket.close()
                throw SocketException("Could not route DoH socket outside the VPN")
            }
        }

        override fun createSocket(): Socket = newUpstreamSocket()
        override fun createSocket(host: String, port: Int): Socket =
            newUpstreamSocket().apply { connect(InetSocketAddress(host, port)) }
        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
            newUpstreamSocket().apply {
                bind(InetSocketAddress(localHost, localPort))
                connect(InetSocketAddress(host, port))
            }
        override fun createSocket(host: InetAddress, port: Int): Socket =
            newUpstreamSocket().apply { connect(InetSocketAddress(host, port)) }
        override fun createSocket(
            address: InetAddress,
            port: Int,
            localAddress: InetAddress,
            localPort: Int
        ): Socket = newUpstreamSocket().apply {
            bind(InetSocketAddress(localAddress, localPort))
            connect(InetSocketAddress(address, port))
        }
    }
}
