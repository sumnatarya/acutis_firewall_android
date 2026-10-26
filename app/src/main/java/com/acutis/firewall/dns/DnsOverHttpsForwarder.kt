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
import java.net.SocketFactory
import java.util.concurrent.TimeUnit

/** DNS-over-HTTPS forwarder. HTTPS sockets are excluded from the VPN via protect(). */
class DnsOverHttpsForwarder(private val protectSocket: (Socket) -> Boolean) : AutoCloseable {
    companion object {
        private const val TAG = "DnsOverHttps"
        private const val HOST = "sky.rethinkdns.com"
        private const val ENDPOINT = "https://sky.rethinkdns.com/1:OPw_5Repnw_64h4AwIAGAOHRAJA="
        private val DNS_MEDIA_TYPE = "application/dns-message".toMediaType()
        private const val MAX_DNS_UDP_PAYLOAD = 1472
    }

    @Volatile private var bootstrapAddresses: List<InetAddress> = emptyList()

    private val client = OkHttpClient.Builder()
        .dns(Dns { host ->
            if (host.equals(HOST, ignoreCase = true)) {
                bootstrapAddresses.takeIf { it.isNotEmpty() }
                    ?: throw IOException("DoH bootstrap unavailable")
            } else {
                throw IOException("Unexpected DNS lookup: $host")
            }
        })
        .socketFactory(ProtectingSocketFactory(protectSocket))
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .writeTimeout(5, TimeUnit.SECONDS)
        .callTimeout(7, TimeUnit.SECONDS)
        .build()

    /** Call before establishing the VPN so resolving the endpoint cannot recurse through it. */
    fun refreshBootstrap(): Boolean = try {
        bootstrapAddresses = InetAddress.getAllByName(HOST).toList()
        bootstrapAddresses.isNotEmpty()
    } catch (e: Exception) {
        Log.e(TAG, "DoH bootstrap failed", e)
        false
    }

    fun forward(query: ByteArray): ByteArray? {
        if (query.size < 12 || bootstrapAddresses.isEmpty()) return null
        return try {
            val request = Request.Builder()
                .url(ENDPOINT)
                .header("Accept", "application/dns-message")
                .post(query.toRequestBody(DNS_MEDIA_TYPE))
                .build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.w(TAG, "DoH HTTP status ${response.code}")
                    return null
                }
                val type = response.header("Content-Type")?.substringBefore(';')?.trim()
                if (!type.equals("application/dns-message", ignoreCase = true)) {
                    Log.w(TAG, "Unexpected DoH content type: $type")
                    return null
                }
                val body = response.body?.bytes() ?: return null
                if (body.size < 12 || (body[2].toInt() and 0x80) == 0) return null
                if (body[0] != query[0] || body[1] != query[1]) return null
                if (body.size <= MAX_DNS_UDP_PAYLOAD) body else createTruncatedResponse(query)
            }
        } catch (e: Exception) {
            Log.e(TAG, "DoH request failed", e)
            null
        }
    }

    private fun createTruncatedResponse(query: ByteArray): ByteArray? {
        val questionEnd = findQuestionEnd(query) ?: return null
        val result = query.copyOfRange(0, questionEnd)
        result[2] = ((result[2].toInt() and 0x7F) or 0x80 or 0x02).toByte()
        result[3] = (result[3].toInt() or 0x80).toByte()
        for (i in 6..11) result[i] = 0
        return result
    }

    private fun findQuestionEnd(query: ByteArray): Int? {
        if (query.size < 12) return null
        val count = ((query[4].toInt() and 0xFF) shl 8) or (query[5].toInt() and 0xFF)
        var pos = 12
        repeat(count) {
            while (pos < query.size) {
                val size = query[pos].toInt() and 0xFF
                pos++
                if (size == 0) break
                if ((size and 0xC0) != 0 || pos + size > query.size) return null
                pos += size
            }
            if (pos + 4 > query.size) return null
            pos += 4
        }
        return pos.takeIf { it <= query.size }
    }

    override fun close() {
        client.dispatcher.cancelAll()
        client.connectionPool.evictAll()
        bootstrapAddresses = emptyList()
    }

    private class ProtectingSocketFactory(
        private val protectSocket: (Socket) -> Boolean
    ) : SocketFactory() {
        private fun newProtectedSocket(): Socket = Socket().also { socket ->
            if (!protectSocket(socket)) {
                socket.close()
                throw SocketException("VpnService.protect(socket) failed")
            }
        }

        override fun createSocket(): Socket = newProtectedSocket()
        override fun createSocket(host: String, port: Int): Socket =
            newProtectedSocket().apply { connect(InetSocketAddress(host, port)) }
        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
            newProtectedSocket().apply {
                bind(InetSocketAddress(localHost, localPort))
                connect(InetSocketAddress(host, port))
            }
        override fun createSocket(host: InetAddress, port: Int): Socket =
            newProtectedSocket().apply { connect(InetSocketAddress(host, port)) }
        override fun createSocket(
            address: InetAddress,
            port: Int,
            localAddress: InetAddress,
            localPort: Int
        ): Socket = newProtectedSocket().apply {
            bind(InetSocketAddress(localAddress, localPort))
            connect(InetSocketAddress(address, port))
        }
    }
}
