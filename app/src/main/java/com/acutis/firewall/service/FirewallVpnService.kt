package com.acutis.firewall.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.ConnectivityManager.NetworkCallback
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.acutis.firewall.MainActivity
import com.acutis.firewall.R
import com.acutis.firewall.data.db.BlockedSiteDao
import com.acutis.firewall.data.preferences.SettingsDataStore
import com.acutis.firewall.dns.DnsOverHttpsForwarder
import com.acutis.firewall.data.repository.TimeRuleRepository
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.Socket
import javax.inject.Inject

@AndroidEntryPoint
class FirewallVpnService : VpnService() {

    @Inject
    lateinit var blockedSiteDao: BlockedSiteDao

    @Inject
    lateinit var settingsDataStore: SettingsDataStore

    @Inject
    lateinit var timeRuleRepository: TimeRuleRepository

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile private var isRunning = false
    @Volatile private var isStarting = false
    @Volatile private var lockdownModeWarningShown = false
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var blockedDomains: Set<String> = emptySet()
    @Volatile private var activeUnderlyingNetwork: Network? = null
    private var networkCallback: NetworkCallback? = null
    private val packetWriteLock = Any()
    private val dnsForwarder = DnsOverHttpsForwarder(
        prepareSocket = { socket -> prepareDoHSocket(socket) },
        resolveBootstrap = { resolveDoHBootstrap() },
        fallbackResolver = { query -> forwardDnsOnUnderlyingNetwork(query) }
    )

    companion object {
        private const val TAG = "FirewallVPN"
        const val ACTION_START = "com.acutis.firewall.START_VPN"
        const val ACTION_STOP = "com.acutis.firewall.STOP_VPN"
        const val ACTION_REFRESH_BLOCKLIST = "com.acutis.firewall.REFRESH_BLOCKLIST"

        /**
         * Set only by the in-app path that has already verified the PIN. Absent on
         * the notification action, which is why the notification can no longer stop
         * the firewall on its own.
         */
        const val EXTRA_PIN_VERIFIED = "com.acutis.firewall.EXTRA_PIN_VERIFIED"
        private const val NOTIFICATION_ID = 1
        private const val LOCKDOWN_WARNING_NOTIFICATION_ID = 2
        private const val CHANNEL_ID = "firewall_channel"
        private const val WARNING_CHANNEL_ID = "firewall_warning_channel"
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val MTU = 1500
        private const val DNS_PORT = 53
        private const val MAX_DNS_UDP_PAYLOAD = MTU - 28
        // Use a private virtual DNS address. Routing public resolver IPs here
        // would also capture their HTTPS/DoT traffic, which this DNS-only VPN drops.
        private const val INTERCEPT_DNS = "10.0.0.1"
        private val INTERCEPT_DNS_BYTES = byteArrayOf(10, 0, 0, 1)
    }

    override fun onCreate() {
        super.onCreate()
        registerPhysicalNetworkCallback()
        createNotificationChannel()
        createWarningNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn()
            ACTION_STOP -> handleStopRequest(
                intent?.getBooleanExtra(EXTRA_PIN_VERIFIED, false) ?: false
            )
            ACTION_REFRESH_BLOCKLIST -> refreshBlocklist()
            null -> {
                // Service was restarted by the system, check if we should be running
                serviceScope.launch {
                    if (settingsDataStore.isFirewallEnabled() && !isRunning) {
                        Log.d(TAG, "Service restarted by system, restarting VPN")
                        startVpn()
                    }
                }
            }
        }
        return START_STICKY
    }

    /**
     * The notification's "Disable Firewall" action used to stop the VPN outright,
     * which let a child kill every protection with one tap and no PIN. Gating here
     * rather than in the notification's PendingIntent closes the hole for any caller.
     */
    private fun handleStopRequest(pinVerified: Boolean) {
        if (pinVerified) {
            stopVpn()
            return
        }
        serviceScope.launch {
            val pinEnabled = settingsDataStore.pinEnabled.first() && settingsDataStore.hasPin()
            if (!pinEnabled) {
                stopVpn()
            } else {
                Log.d(TAG, "Stop requested without PIN verification - prompting instead")
                val intent = Intent(this@FirewallVpnService, MainActivity::class.java).apply {
                    action = Intent.ACTION_MAIN
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    putExtra(MainActivity.EXTRA_REQUEST_DISABLE, true)
                }
                runCatching { startActivity(intent) }
                    .onFailure { Log.w(TAG, "Could not open app for PIN entry", it) }
            }
        }
    }

    @Synchronized
    private fun startVpn() {
        if (isRunning || isStarting) return
        isStarting = true

        try {
            // Promote the service synchronously before scheduling network or database work.
            startForeground(NOTIFICATION_ID, createNotification())
        } catch (e: Exception) {
            isStarting = false
            Log.e(TAG, "Could not enter foreground service state", e)
            stopSelf()
            return
        }

        serviceScope.launch {
            try {
                // Do not let a transient DNS/bootstrap failure leave a half-started VPN.
                // The first DNS packet retries bootstrap after the VPN is established.
                val bootstrapped = dnsForwarder.refreshBootstrap()
                Log.i(TAG, "Initial DoH bootstrap result=$bootstrapped")

                blockedDomains = loadBlockedDomains()
                Log.d(TAG, "Loaded ${blockedDomains.size} blocked domains")
                blockedDomains.take(10).forEach { Log.d(TAG, "  Blocked: $it") }

                val builder = Builder()
                    .setSession("Acutis Firewall")
                    .setMtu(MTU)
                    .addAddress(VPN_ADDRESS, 24)
                    .addDnsServer(INTERCEPT_DNS)
                    .addRoute(INTERCEPT_DNS, 32)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    builder.setMetered(false)
                }

                vpnInterface = builder.establish()

                if (vpnInterface != null) {
                    isRunning = true
                    findUnderlyingNetwork()?.let { network ->
                        val accepted = runCatching { setUnderlyingNetworks(arrayOf(network)) }
                            .getOrElse { error ->
                                Log.e(TAG, "Could not report DoH underlying network", error)
                                false
                            }
                        if (accepted) activeUnderlyingNetwork = network
                        Log.i(TAG, "VPN established; underlying network=$network, accepted=$accepted")
                    } ?: Log.e(TAG, "VPN established but no non-VPN internet network was found; DNS forwarding will retry when a network appears")

                    settingsDataStore.setFirewallEnabled(true)
                    Log.d(TAG, "VPN established successfully")

                    checkLockdownMode()
                    runVpnLoop()
                } else {
                    Log.e(TAG, "Failed to establish VPN")
                    settingsDataStore.setFirewallEnabled(false)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error starting VPN", e)
                isRunning = false
                runCatching { vpnInterface?.close() }
                vpnInterface = null
                runCatching { settingsDataStore.setFirewallEnabled(false) }
                    .onFailure { Log.e(TAG, "Could not clear firewall enabled state", it) }
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            } finally {
                isStarting = false
            }
        }
    }

    /**
     * DoH is control traffic for this DNS-only VPN. Prefer explicitly binding its
     * sockets to a validated physical network. This avoids a device-specific
     * VpnService.protect(socket) failure that otherwise drops every DNS lookup.
     */
    private fun prepareDoHSocket(socket: Socket): Boolean {
        // Java sockets can defer native descriptor creation until an option is queried.
        // Android's Network.bindSocket does this internally with getReuseAddress(); do
        // the same before VpnService.protect(), which otherwise may return false.
        try {
            socket.getReuseAddress()
            if (protect(socket)) {
                Log.d(TAG, "DoH socket protected from VPN routing")
                return true
            }
            Log.w(TAG, "VpnService.protect(socket) returned false after socket initialization")
        } catch (e: Exception) {
            Log.w(TAG, "Could not initialize/protect DoH socket; trying explicit network binding", e)
        }

        val network = try {
            activeUnderlyingNetwork?.takeIf { isUsablePhysicalNetwork(it) } ?: findUnderlyingNetwork()
        } catch (e: Exception) {
            Log.w(TAG, "Could not inspect available underlying networks", e)
            null
        }
        if (network != null) {
            try {
                // The socket is unconnected here; Network.bindSocket must run before connect().
                network.bindSocket(socket)
                if (activeUnderlyingNetwork != network) {
                    val accepted = runCatching { setUnderlyingNetworks(arrayOf(network)) }
                        .getOrElse { error ->
                            Log.w(TAG, "Could not update reported VPN underlying network", error)
                            false
                        }
                    if (accepted) activeUnderlyingNetwork = network
                }
                Log.i(TAG, "DoH socket bound directly to underlying network $network")
                return true
            } catch (e: Exception) {
                Log.e(TAG, "Could not bind DoH socket to underlying network $network", e)
            }
        }

        Log.e(TAG, "Unable to route DoH socket outside the VPN")
        return false
    }

    /**
     * Resolve the DoH hostname on the physical network explicitly. System DNS
     * follows the VPN's virtual DNS server after establish(), which otherwise
     * causes recursive bootstrap lookups when the bootstrap cache is empty.
     */
    private fun resolveDoHBootstrap(): List<java.net.InetAddress> {
        val network = activeUnderlyingNetwork?.takeIf { isUsablePhysicalNetwork(it) }
            ?: findUnderlyingNetwork()
            ?: throw java.net.UnknownHostException("No non-VPN network is available for DoH bootstrap")
        return network.getAllByName("sky.rethinkdns.com").toList()
    }

    /**
     * Last-resort DNS path. Requests have already passed the local blocklist and
     * time-rule checks; send them to the DNS server reported by the physical
     * network, using a socket explicitly bound to that network.
     */
    private fun forwardDnsOnUnderlyingNetwork(query: ByteArray): ByteArray? {
        val connectivityManager = getSystemService(ConnectivityManager::class.java)
        val network = activeUnderlyingNetwork?.takeIf { isUsablePhysicalNetwork(it) }
            ?: findUnderlyingNetwork()
            ?: return null
        val dnsServers = connectivityManager.getLinkProperties(network)?.dnsServers.orEmpty()
        if (dnsServers.isEmpty()) {
            Log.w(TAG, "Underlying network has no DNS servers for fallback")
            return null
        }

        for (dnsServer in dnsServers) {
            try {
                java.net.DatagramSocket(null).use { socket ->
                    socket.soTimeout = 2500
                    network.bindSocket(socket)
                    socket.connect(java.net.InetSocketAddress(dnsServer, DNS_PORT))
                    socket.send(java.net.DatagramPacket(query, query.size, java.net.InetSocketAddress(dnsServer, DNS_PORT)))

                    val responseBuffer = ByteArray(4096)
                    val responsePacket = java.net.DatagramPacket(responseBuffer, responseBuffer.size)
                    socket.receive(responsePacket)
                    val response = responseBuffer.copyOf(responsePacket.length)
                    if (dnsForwarder.isValidResponse(query, response)) {
                        Log.w(TAG, "DNS query succeeded via physical-network fallback server $dnsServer")
                        return response
                    }
                    Log.w(TAG, "Ignoring invalid fallback DNS response from $dnsServer")
                }
            } catch (e: Exception) {
                Log.w(TAG, "Physical-network DNS fallback failed via $dnsServer", e)
            }
        }
        return null
    }

    /**
     * Returns a usable non-VPN network. Prefer validated Wi-Fi, then validated
     * cellular, while keeping any internet-capable physical network as a fallback.
     */
    private fun isUsablePhysicalNetwork(network: Network): Boolean {
        val cm = getSystemService(ConnectivityManager::class.java)
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    private fun registerPhysicalNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java)
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val callback = object : NetworkCallback() {
            override fun onAvailable(network: Network) = refreshUnderlyingNetwork("available: $network")
            override fun onLost(network: Network) {
                if (activeUnderlyingNetwork == network) activeUnderlyingNetwork = null
                refreshUnderlyingNetwork("lost: $network")
            }
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    if (activeUnderlyingNetwork == network) activeUnderlyingNetwork = null
                }
                refreshUnderlyingNetwork("capabilities changed: $network")
            }
        }
        try {
            cm.registerNetworkCallback(request, callback, Handler(Looper.getMainLooper()))
            networkCallback = callback
            Log.i(TAG, "Registered physical-network callback")
        } catch (e: Exception) {
            Log.e(TAG, "Unable to register physical-network callback", e)
        }
    }

    private fun refreshUnderlyingNetwork(reason: String) {
        if (!isRunning) return
        serviceScope.launch {
            val network = runCatching { findUnderlyingNetwork() }.getOrNull()
            if (network == activeUnderlyingNetwork) return@launch
            activeUnderlyingNetwork = network
            try {
                setUnderlyingNetworks(network?.let { arrayOf(it) })
                Log.i(TAG, "Updated underlying network ($reason): $network")
            } catch (e: Exception) {
                Log.e(TAG, "Could not update underlying network ($reason)", e)
            }
            // Cached bootstrap addresses may have belonged to the prior network.
            val refreshed = dnsForwarder.refreshBootstrap()
            Log.i(TAG, "Refreshed DoH bootstrap after network change: $refreshed")
        }
    }

    private fun findUnderlyingNetwork(): Network? {
        val connectivityManager = getSystemService(ConnectivityManager::class.java)
        val candidates = connectivityManager.allNetworks.mapNotNull { network ->
            val capabilities = connectivityManager.getNetworkCapabilities(network)
                ?: return@mapNotNull null
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            ) {
                null
            } else {
                network to capabilities
            }
        }
        return candidates.sortedWith(
            compareByDescending<Pair<Network, NetworkCapabilities>> {
                it.second.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            }.thenByDescending {
                it.second.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
            }.thenByDescending {
                it.second.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
            }
        ).firstOrNull()?.first
    }

    private suspend fun loadBlockedDomains(): Set<String> {
        return blockedSiteDao.getEnabledSitesList()
            .mapNotNull { DomainMatcher.normalizePattern(it.domain) }
            .toSet()
    }

    private fun runVpnLoop() {
        serviceScope.launch {
            val fd = vpnInterface?.fileDescriptor
            if (fd == null) {
                if (isRunning) {
                    Log.e(TAG, "VPN interface disappeared before packet loop started")
                    stopVpn()
                }
                return@launch
            }

            try {
                val inputStream = FileInputStream(fd)
                val outputStream = FileOutputStream(fd)
                val buffer = ByteArray(MTU)

                Log.d(TAG, "Starting VPN packet loop")

                while (isRunning && vpnInterface != null) {
                    val length = inputStream.read(buffer)
                    if (length < 0) {
                        Log.e(TAG, "VPN packet interface reached EOF")
                        break
                    }
                    if (length > 0) {
                        handlePacket(buffer.copyOf(length), outputStream)
                    }
                }
            } catch (e: Exception) {
                if (isRunning) Log.e(TAG, "Error in VPN packet loop", e)
            } finally {
                Log.d(TAG, "VPN loop ended")
                if (isRunning) {
                    // A live flag with no packet reader would leave DNS black-holed.
                    stopVpn()
                }
            }
        }
    }

    private fun handlePacket(packetData: ByteArray, outputStream: FileOutputStream) {
        // The codec validates IPv4 lengths, UDP lengths, DNS query flags and fragmentation.
        val query = DnsPacketCodec.parseIpv4UdpQuery(packetData) ?: return
        if (!query.destinationAddress.contentEquals(INTERCEPT_DNS_BYTES)) return

        serviceScope.launch {
            try {
                val dnsResponse = processDnsQuery(query.payload) ?: return@launch
                // The VPN MTU is 1500 bytes. Keep the complete IPv4 packet below that
                // limit; signal TC rather than writing an oversized UDP datagram.
                val responsePayload = if (dnsResponse.size > MAX_DNS_UDP_PAYLOAD) {
                    DnsPacketCodec.createTruncatedDnsResponse(query.payload) ?: return@launch
                } else {
                    dnsResponse
                }

                val responsePacket = DnsPacketCodec.buildIpv4UdpPacket(
                    sourceAddress = query.destinationAddress,
                    destinationAddress = query.sourceAddress,
                    sourcePort = DNS_PORT,
                    destinationPort = query.sourcePort,
                    payload = responsePayload
                ) ?: run {
                    Log.w(TAG, "Unable to construct DNS response packet")
                    return@launch
                }

                writePacket(outputStream, responsePacket)
            } catch (e: Exception) {
                Log.e(TAG, "Error processing DNS packet", e)
            }
        }
    }

    private suspend fun processDnsQuery(dnsPayload: ByteArray): ByteArray? {
        if (dnsPayload.size < 12) return null

        val domain = extractDomainName(dnsPayload)
        Log.d(TAG, "DNS query for: $domain")

        if (domain != null) {
            // First check static blocklist
            if (shouldBlockDomain(domain)) {
                Log.d(TAG, "BLOCKING (blocklist): $domain")
                return createBlockedResponse(dnsPayload)
            }

            // Then check time rules (this also updates usage tracking)
            if (timeRuleRepository.checkAndUpdateTimeRule(domain)) {
                Log.d(TAG, "BLOCKING (time rule): $domain")
                return createBlockedResponse(dnsPayload)
            }
        }

        // Forward to upstream DNS
        Log.d(TAG, "Forwarding: $domain")
        return forwardToUpstream(dnsPayload) ?: dnsForwarder.createServFailResponse(dnsPayload)
    }

    private fun extractDomainName(dnsPayload: ByteArray): String? {
        try {
            val parts = mutableListOf<String>()
            var pos = 12 // Skip DNS header

            while (pos < dnsPayload.size) {
                val len = dnsPayload[pos].toInt() and 0xFF
                if (len == 0) break

                if ((len and 0xC0) == 0xC0) {
                    // Compression pointer - follow it
                    if (pos + 1 >= dnsPayload.size) break
                    val offset = ((len and 0x3F) shl 8) or (dnsPayload[pos + 1].toInt() and 0xFF)
                    return extractDomainFromOffset(dnsPayload, offset, parts)
                }

                pos++
                if (pos + len > dnsPayload.size) break
                parts.add(String(dnsPayload, pos, len, Charsets.US_ASCII))
                pos += len
            }

            return if (parts.isNotEmpty()) parts.joinToString(".").lowercase() else null
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing domain", e)
            return null
        }
    }

    private fun extractDomainFromOffset(data: ByteArray, startOffset: Int, existingParts: MutableList<String>): String? {
        var pos = startOffset
        while (pos < data.size) {
            val len = data[pos].toInt() and 0xFF
            if (len == 0) break
            if ((len and 0xC0) == 0xC0) break // Another pointer, stop

            pos++
            if (pos + len > data.size) break
            existingParts.add(String(data, pos, len, Charsets.US_ASCII))
            pos += len
        }
        return if (existingParts.isNotEmpty()) existingParts.joinToString(".").lowercase() else null
    }

    private fun shouldBlockDomain(domain: String): Boolean {
        val normalized = domain.lowercase().trimEnd('.')

        // Direct match
        if (blockedDomains.contains(normalized)) {
            return true
        }

        // Check parent domains and wildcards
        val parts = normalized.split(".")
        for (i in parts.indices) {
            val parent = parts.subList(i, parts.size).joinToString(".")
            if (blockedDomains.contains(parent)) {
                return true
            }
            if (blockedDomains.contains("*.$parent")) {
                return true
            }
        }

        return false
    }

    private fun createBlockedResponse(query: ByteArray): ByteArray? {
        // Use the same tested DNS response builder as the upstream SERVFAIL path.
        // Never echo a malformed request back as though it were a DNS response.
        return dnsForwarder.createBlockedResponse(query)
            ?: dnsForwarder.createServFailResponse(query)
    }

    private fun forwardToUpstream(query: ByteArray): ByteArray? = dnsForwarder.forward(query)

    private suspend fun writePacket(outputStream: FileOutputStream, packet: ByteArray) {
        withContext(Dispatchers.IO) {
            try {
                // Multiple DNS queries are handled concurrently; keep each IP packet atomic
                // when writing back to the single TUN file descriptor.
                synchronized(packetWriteLock) {
                    outputStream.write(packet)
                    outputStream.flush()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error writing packet", e)
            }
        }
    }

    private fun stopVpn() {
        Log.d(TAG, "Stopping VPN")
        isRunning = false
        // Use runBlocking to ensure DataStore writes complete before stopping service
        runBlocking {
            settingsDataStore.setFirewallEnabled(false)
            settingsDataStore.setLockdownModeDetected(false)
        }
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        dnsForwarder.close()
        super.onDestroy()
        isRunning = false
        networkCallback?.let { callback ->
            runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback) }
                .onFailure { Log.w(TAG, "Could not unregister physical-network callback", it) }
        }
        networkCallback = null
        serviceScope.cancel()
        vpnInterface?.close()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.vpn_channel_description)
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun createWarningNotificationChannel() {
        Log.d(TAG, "Creating warning notification channel")
        val channel = NotificationChannel(
            WARNING_CHANNEL_ID,
            "Firewall Warnings",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Important warnings about firewall configuration"
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun checkLockdownMode() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val lockdownEnabled = isLockdownEnabled
            val alwaysOn = isAlwaysOn
            Log.d(TAG, "VPN status - isAlwaysOn: $alwaysOn, isLockdownEnabled: $lockdownEnabled")
            if (lockdownEnabled || alwaysOn) {
                Log.w(TAG, "Always-on or lockdown is enabled for a DNS-only VPN; ordinary traffic may be blocked")
                // Save to DataStore so UI can show a dialog
                serviceScope.launch {
                    settingsDataStore.setLockdownModeDetected(true)
                }
                if (!lockdownModeWarningShown) {
                    lockdownModeWarningShown = true
                    showLockdownWarning()
                }
            } else {
                lockdownModeWarningShown = false
                // Clear the lockdown flag if not in lockdown mode
                serviceScope.launch {
                    settingsDataStore.setLockdownModeDetected(false)
                }
            }
        } else {
            Log.d(TAG, "Lockdown check skipped - requires API 29+, current: ${Build.VERSION.SDK_INT}")
        }
    }

    private fun showLockdownWarning() {
        Log.d(TAG, "Showing lockdown warning notification")
        try {
            val intent = Intent(android.provider.Settings.ACTION_VPN_SETTINGS)
            val pendingIntent = PendingIntent.getActivity(
                this, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val notification = NotificationCompat.Builder(this, WARNING_CHANNEL_ID)
                .setContentTitle("VPN Lockdown Mode Detected")
                .setContentText("Turn off VPN lockdown to restore normal internet access.")
                .setStyle(NotificationCompat.BigTextStyle()
                    .bigText("Acutis Firewall filters DNS requests; it does not tunnel all internet traffic. Android's \"Block connections without VPN\" lockdown can therefore block ordinary web traffic. Open VPN settings and turn off Always-on VPN and Block connections without VPN for Acutis Firewall, then reconnect."))
                .setSmallIcon(R.drawable.ic_shield)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .build()

            getSystemService(NotificationManager::class.java)
                .notify(LOCKDOWN_WARNING_NOTIFICATION_ID, notification)
            Log.d(TAG, "Lockdown warning notification sent")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show lockdown warning", e)
        }
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, FirewallVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.vpn_notification_text))
            .setSmallIcon(R.drawable.ic_shield)
            .setContentIntent(pendingIntent)
            .addAction(R.drawable.ic_shield, getString(R.string.disable_firewall), stopPendingIntent)
            .setOngoing(true)
            .build()
    }

    fun refreshBlocklist() {
        Log.d(TAG, "Refresh blocklist requested, isRunning=$isRunning")
        if (!isRunning) {
            Log.d(TAG, "VPN not running, skipping refresh")
            return
        }
        serviceScope.launch {
            val previousSize = blockedDomains.size
            blockedDomains = loadBlockedDomains()
            Log.d(TAG, "Refreshed blocklist: $previousSize -> ${blockedDomains.size} domains")
            // Log some newly added domains for debugging
            if (blockedDomains.size > previousSize) {
                blockedDomains.take(5).forEach { Log.d(TAG, "  Sample domain: $it") }
            }
        }
    }
}
