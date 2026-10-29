package com.acutis.firewall.blocklist

import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.dnsoverhttps.DnsOverHttps
import java.io.IOException
import java.util.concurrent.TimeUnit
import javax.inject.Inject

interface HttpFetcher {
    @Throws(IOException::class)
    fun <T> fetchLines(urlString: String, block: (Sequence<String>) -> T): T
}

// Same endpoint as FirewallVpnService.DOH_URL; change both together.
private const val DOH_URL = "https://sky.rethinkdns.com/1:OPw_5Repnw_64h4AwIAGAOHRAJA="

class DefaultHttpFetcher @Inject constructor() : HttpFetcher {
    // Resolve through Rethink DoH, not system DNS: system DNS is what times out on
    // raw.githubusercontent.com, and this also works with the firewall off.
    private val client: OkHttpClient by lazy {
        val base = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
        val doh = DnsOverHttps.Builder().client(base).url(DOH_URL.toHttpUrl()).build()
        base.newBuilder().dns(doh).build()
    }

    override fun <T> fetchLines(urlString: String, block: (Sequence<String>) -> T): T {
        client.newCall(Request.Builder().url(urlString).build()).execute().use { response ->
            if (!response.isSuccessful) {
                throw IOException("HTTP ${response.code} from $urlString")
            }
            val body = response.body ?: throw IOException("Empty body from $urlString")
            return body.charStream().buffered().useLines(block)
        }
    }
}
