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
import java.nio.ByteBuffer
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
    private var isRunning = false
    private var isStarting = false
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var blockedDomains: Set<String> = emptySet()
    @Volatile private var activeUnderlyingNetwork: Network? = null
    private val dnsForwarder = DnsOverHttpsForwarder { socket -> prepareDoHSocket(socket) }

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
        // Use a private virtual DNS address. Routing public resolver IPs here
        // would also capture their HTTPS/DoT traffic, which this DNS-only VPN drops.
        private const val INTERCEPT_DNS = "10.0.0.1"
    }

    override fun onCreate() {
        super.onCreate()
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

    private fun startVpn() {
        if (isRunning || isStarting) return
        isStarting = true

        serviceScope.launch {
            try {
                check(dnsForwarder.refreshBootstrap()) { "Unable to bootstrap DoH endpoint" }
                Log.d(TAG, "Using DNS-over-HTTPS upstream endpoint")

                blockedDomains = loadBlockedDomains()
                Log.d(TAG, "Loaded ${blockedDomains.size} blocked domains")
                // Log first 10 domains for debugging
                blockedDomains.take(10).forEach { Log.d(TAG, "  Blocked: $it") }

                val builder = Builder()
                    .setSession("Acutis Firewall")
                    .setMtu(MTU)
                    .addAddress(VPN_ADDRESS, 24)
                    // This is a virtual DNS server inside the VPN subnet, not a public IP.
                    // Only packets addressed to this virtual IP enter the DNS packet handler.
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
                    } ?: Log.e(TAG, "VPN established but no non-VPN internet network was found")
                    startForeground(NOTIFICATION_ID, createNotification())
                    settingsDataStore.setFirewallEnabled(true)
                    Log.d(TAG, "VPN established successfully")

                    // Check if lockdown mode is enabled and warn user
                    checkLockdownMode()

                    runVpnLoop()
                } else {
                    Log.e(TAG, "Failed to establish VPN")
                    settingsDataStore.setFirewallEnabled(false)
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
            findUnderlyingNetwork()
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
     * Returns a usable non-VPN network. Prefer validated Wi-Fi, then validated
     * cellular, while keeping any internet-capable physical network as a fallback.
     */
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
            .map { it.domain.lowercase().trimEnd('.') }
            .toSet()
    }

    private fun runVpnLoop() {
        serviceScope.launch {
            val fd = vpnInterface?.fileDescriptor ?: return@launch
            val inputStream = FileInputStream(fd)
            val outputStream = FileOutputStream(fd)
            val buffer = ByteArray(MTU)

            Log.d(TAG, "Starting VPN packet loop")

            while (isRunning && vpnInterface != null) {
                try {
                    val length = inputStream.read(buffer)
                    if (length > 0) {
                        val packetData = buffer.copyOf(length)
                        handlePacket(packetData, outputStream)
                    }
                } catch (e: Exception) {
                    if (isRunning) {
                        Log.e(TAG, "Error in VPN loop", e)
                    }
                    break
                }
            }
            Log.d(TAG, "VPN loop ended")
        }
    }

    private fun handlePacket(packetData: ByteArray, outputStream: FileOutputStream) {
        // Validate IP header before reading UDP fields; malformed/truncated packets are ignored.
        if (packetData.size < 20) return
        val version = (packetData[0].toInt() and 0xF0) ushr 4
        if (version != 4) return // IPv4 only
        val headerLength = (packetData[0].toInt() and 0x0F) * 4
        if (headerLength < 20 || headerLength > packetData.size || packetData.size < headerLength + 8) return
        val totalLength = ((packetData[2].toInt() and 0xFF) shl 8) or (packetData[3].toInt() and 0xFF)
        if (totalLength < headerLength + 8 || totalLength > packetData.size) return
        val protocol = packetData[9].toInt() and 0xFF
        if (protocol != 17) return // UDP only

        val sourcePort = ((packetData[headerLength].toInt() and 0xFF) shl 8) or
                        (packetData[headerLength + 1].toInt() and 0xFF)
        val destPort = ((packetData[headerLength + 2].toInt() and 0xFF) shl 8) or
                      (packetData[headerLength + 3].toInt() and 0xFF)

        // Only handle DNS (port 53)
        if (destPort != DNS_PORT) return

        val udpLength = ((packetData[headerLength + 4].toInt() and 0xFF) shl 8) or
                       (packetData[headerLength + 5].toInt() and 0xFF)

        if (udpLength < 8 || headerLength + udpLength > totalLength) return
        if (destIp(packetData) != INTERCEPT_DNS) return
        if (udpLength - 8 < 12) return

        val dnsPayload = packetData.copyOfRange(headerLength + 8, headerLength + udpLength)

        // Extract source and dest IPs for response
        val sourceIp = packetData.copyOfRange(12, 16)
        val destinationIp = packetData.copyOfRange(16, 20)

        // Handle DNS query async
        serviceScope.launch(Dispatchers.IO) {
            val dnsResponse = processDnsQuery(dnsPayload)
            if (dnsResponse != null) {
                val responsePacket = buildUdpResponsePacket(
                    sourceIp = destinationIp,
                    destIp = sourceIp,
                    sourcePort = DNS_PORT,
                    destPort = sourcePort,
                    payload = dnsResponse
                )
                writePacket(outputStream, responsePacket)
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
        return forwardToUpstream(dnsPayload) ?: createServFailResponse(dnsPayload)
    }

    private fun createServFailResponse(query: ByteArray): ByteArray? {
        if (query.size < 12) return null
        val questionEnd = dnsForwarder.findQuestionEnd(query) ?: return null
        val response = query.copyOfRange(0, questionEnd)
        response[2] = ((query[2].toInt() and 0x01) or 0x80 or 0x10).toByte() // QR, preserve RD, RA
        response[3] = 0x02.toByte() // SERVFAIL, no answers/authority/additional records
        for (i in 6..11) response[i] = 0
        return response
    }

    private fun destIp(packet: ByteArray): String {
        return (16..19).joinToString(".") { (packet[it].toInt() and 0xFF).toString() }
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

    private fun createBlockedResponse(query: ByteArray): ByteArray {
        // Create NXDOMAIN response
        val questionEnd = dnsForwarder.findQuestionEnd(query) ?: return query.copyOf()
        val response = query.copyOfRange(0, questionEnd)

        // Set QR, preserve RD, set RA, return NXDOMAIN with no records.
        response[2] = (((query[2].toInt() and 0x01) or 0x80 or 0x10)).toByte()
        response[3] = 0x83.toByte()

        // ANCOUNT = 0
        response[6] = 0
        response[7] = 0

        // NSCOUNT = 0
        response[8] = 0
        response[9] = 0

        // ARCOUNT = 0
        response[10] = 0
        response[11] = 0

        return response
    }

    private fun forwardToUpstream(query: ByteArray): ByteArray? = dnsForwarder.forward(query)

    private fun buildUdpResponsePacket(
        sourceIp: ByteArray,
        destIp: ByteArray,
        sourcePort: Int,
        destPort: Int,
        payload: ByteArray
    ): ByteArray {
        val ipHeaderLen = 20
        val udpHeaderLen = 8
        val totalLen = ipHeaderLen + udpHeaderLen + payload.size

        val packet = ByteBuffer.allocate(totalLen)

        // IP Header
        packet.put(0x45.toByte())           // Version 4, IHL 5
        packet.put(0x00.toByte())           // DSCP/ECN
        packet.putShort(totalLen.toShort()) // Total length
        packet.putShort(0x0000.toShort())   // ID
        packet.putShort(0x4000.toShort())   // Flags (DF)
        packet.put(64.toByte())             // TTL
        packet.put(17.toByte())             // Protocol (UDP)
        packet.putShort(0)                  // Checksum placeholder
        packet.put(sourceIp)                // Source IP
        packet.put(destIp)                  // Dest IP

        // UDP Header
        packet.putShort(sourcePort.toShort())
        packet.putShort(destPort.toShort())
        packet.putShort((udpHeaderLen + payload.size).toShort())
        packet.putShort(0) // UDP checksum optional

        // Payload
        packet.put(payload)

        val data = packet.array()

        // Calculate the IPv4 header checksum.
        data[10] = 0
        data[11] = 0
        data[10] = (internetChecksum(data, 0, ipHeaderLen) ushr 8).toByte()
        data[11] = internetChecksum(data, 0, ipHeaderLen).toByte()

        // Calculate a non-zero UDP checksum over IPv4 pseudo-header + UDP header + DNS.
        // A zero UDP checksum is legal for IPv4, but a real checksum makes packet
        // validation reliable on Android VPN/tun interfaces.
        val pseudoHeader = ByteArray(12 + udpHeaderLen + payload.size)
        System.arraycopy(data, 12, pseudoHeader, 0, 8) // source + destination IPv4 addresses
        pseudoHeader[9] = 17
        pseudoHeader[10] = ((udpHeaderLen + payload.size) ushr 8).toByte()
        pseudoHeader[11] = (udpHeaderLen + payload.size).toByte()
        System.arraycopy(data, ipHeaderLen, pseudoHeader, 12, udpHeaderLen + payload.size)
        pseudoHeader[6] = 0
        pseudoHeader[7] = 0
        var udpChecksum = internetChecksum(pseudoHeader, 0, pseudoHeader.size)
        if (udpChecksum == 0) udpChecksum = 0xFFFF
        data[ipHeaderLen + 6] = (udpChecksum ushr 8).toByte()
        data[ipHeaderLen + 7] = udpChecksum.toByte()

        return data
    }

    private fun internetChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += (((data[index].toInt() and 0xFF) shl 8) or
                (data[index + 1].toInt() and 0xFF)).toLong()
            index += 2
        }
        if (index < end) sum += ((data[index].toInt() and 0xFF) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private suspend fun writePacket(outputStream: FileOutputStream, packet: ByteArray) {
        withContext(Dispatchers.IO) {
            try {
                outputStream.write(packet)
                outputStream.flush()
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
            if (lockdownEnabled) {
                Log.w(TAG, "VPN lockdown mode is enabled - internet may not work properly")
                // Save to DataStore so UI can show a dialog
                serviceScope.launch {
                    settingsDataStore.setLockdownModeDetected(true)
                }
                showLockdownWarning()
            } else {
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
