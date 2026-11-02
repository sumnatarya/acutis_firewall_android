package com.acutis.firewall.blocklist

import android.content.Context
import android.content.Intent
import android.util.Log
import com.acutis.firewall.data.db.BlockedSiteDao
import com.acutis.firewall.data.db.entities.BlockCategory
import com.acutis.firewall.data.db.entities.BlockedSite
import com.acutis.firewall.service.FirewallVpnService
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class BlocklistDownloader @Inject constructor(
    @ApplicationContext private val context: Context,
    private val blockedSiteDao: BlockedSiteDao,
    private val fetcher: HttpFetcher
) {
    companion object {
        private const val TAG = "BlocklistDownloader"

        // Adult content blocklists
        val ADULT_LISTS = listOf(
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
            "https://raw.githubusercontent.com/4skinSkywalker/Anti-Porn-HOSTS-File/master/HOSTS.txt"
        )

        // Malware/phishing blocklists
        val MALWARE_LISTS = listOf(
            "https://urlhaus.abuse.ch/downloads/hostfile/",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts"
        )

        // Gambling blocklists
        val GAMBLING_LISTS = listOf(
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts"
        )

        // Social media blocklists
        val SOCIAL_MEDIA_LISTS = listOf(
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts"
        )
    }

    data class DownloadResult(
        val success: Boolean,
        val domainsAdded: Int,
        val urlsAttempted: Int = 0,
        val urlsSucceeded: Int = 0,
        val error: String? = null
    )

    suspend fun downloadAndSaveBlocklist(
        category: BlockCategory,
        urls: List<String> = getUrlsForCategory(category)
    ): DownloadResult = withContext(Dispatchers.IO) {
        var totalAdded = 0
        val allDomains = mutableSetOf<String>()
        var urlsSucceeded = 0
        val failures = mutableListOf<String>()

        for (url in urls) {
            try {
                Log.d(TAG, "Downloading from: $url")
                val domains = downloadHostsFile(url)
                Log.d(TAG, "Got ${domains.size} domains from $url")
                allDomains.addAll(domains)
                urlsSucceeded++
            } catch (e: Exception) {
                Log.e(TAG, "Error downloading $url", e)
                failures.add("${e.javaClass.simpleName}: ${e.message ?: "unknown"}")
            }
        }

        // If every source failed, don't wipe what we already have — report failure.
        if (urlsSucceeded == 0 && urls.isNotEmpty()) {
            return@withContext DownloadResult(
                success = false,
                domainsAdded = 0,
                urlsAttempted = urls.size,
                urlsSucceeded = 0,
                error = failures.firstOrNull() ?: "All ${urls.size} sources failed"
            )
        }

        try {
            blockedSiteDao.deleteByCategory(category)

            val sites = allDomains.map { domain ->
                BlockedSite(
                    domain = domain,
                    category = category,
                    isEnabled = true,
                    isCustom = false
                )
            }

            sites.chunked(1000).forEach { batch ->
                blockedSiteDao.insertAll(batch)
                totalAdded += batch.size
            }

            Log.d(TAG, "Saved $totalAdded domains for category $category")
            notifyBlocklistChanged()
            DownloadResult(
                success = true,
                domainsAdded = totalAdded,
                urlsAttempted = urls.size,
                urlsSucceeded = urlsSucceeded
            )

        } catch (e: Exception) {
            Log.e(TAG, "Error saving blocklist", e)
            DownloadResult(
                success = false,
                domainsAdded = totalAdded,
                urlsAttempted = urls.size,
                urlsSucceeded = urlsSucceeded,
                error = e.message
            )
        }
    }

    private fun downloadHostsFile(urlString: String): Set<String> {
        val domains = mutableSetOf<String>()
        fetcher.fetchLines(urlString) { lines ->
            lines.forEach { line ->
                domains.addAll(HostsFileParser.parseLine(line))
            }
        }
        return domains
    }

    private fun getUrlsForCategory(category: BlockCategory): List<String> {
        return when (category) {
            BlockCategory.ADULT -> ADULT_LISTS
            BlockCategory.MALWARE -> MALWARE_LISTS
            BlockCategory.GAMBLING -> GAMBLING_LISTS
            BlockCategory.SOCIAL_MEDIA -> SOCIAL_MEDIA_LISTS
            BlockCategory.CUSTOM -> emptyList()
        }
    }

    suspend fun downloadAllCategories(
        includeAdult: Boolean = true,
        includeMalware: Boolean = true,
        includeGambling: Boolean = false,
        includeSocialMedia: Boolean = false
    ): Map<BlockCategory, DownloadResult> {
        val results = mutableMapOf<BlockCategory, DownloadResult>()

        if (includeAdult) {
            results[BlockCategory.ADULT] = downloadAndSaveBlocklist(BlockCategory.ADULT)
        }
        if (includeMalware) {
            results[BlockCategory.MALWARE] = downloadAndSaveBlocklist(BlockCategory.MALWARE)
        }
        if (includeGambling) {
            results[BlockCategory.GAMBLING] = downloadAndSaveBlocklist(BlockCategory.GAMBLING)
        }
        if (includeSocialMedia) {
            results[BlockCategory.SOCIAL_MEDIA] = downloadAndSaveBlocklist(BlockCategory.SOCIAL_MEDIA)
        }

        notifyBlocklistChanged()
        return results
    }

    private fun notifyBlocklistChanged() {
        val intent = Intent(context, FirewallVpnService::class.java).apply {
            action = FirewallVpnService.ACTION_REFRESH_BLOCKLIST
        }
        try {
            context.startService(intent)
        } catch (e: Exception) {
            // Service might not be running, that's OK
        }
    }
}
