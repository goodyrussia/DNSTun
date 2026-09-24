package app.slipnet.data.repository

import android.os.ParcelFileDescriptor
import app.slipnet.util.AppLog as Log
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TrafficStats
import app.slipnet.domain.model.DnsResolver
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.TunnelType
import app.slipnet.domain.repository.ResolverScannerRepository
import app.slipnet.domain.repository.VpnRepository
import app.slipnet.tunnel.DnsPoolScanState
import app.slipnet.tunnel.DnsPoolScanner
import app.slipnet.tunnel.DnsttBridge
import app.slipnet.tunnel.HevSocks5Tunnel
import app.slipnet.tunnel.DnsttSocksBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VpnRepositoryImpl @Inject constructor(
    @dagger.hilt.android.qualifiers.ApplicationContext private val context: android.content.Context,
    private val preferencesDataStore: PreferencesDataStore,
    private val resolverScanner: ResolverScannerRepository,
    private val profileRepository: app.slipnet.domain.repository.ProfileRepository
) : VpnRepository {
    companion object {
        private const val TAG = "VpnRepositoryImpl"

        /**
         * Per-resolver TCP-connect budget for the preflight that filters dead
         * TCP/DoT resolvers before they reach the native bridge. Probes run in
         * parallel so this also caps total preflight time. Tuned for heavily
         * throttled networks (Iran cellular): SYN retransmit + DPI inspection
         * + lossy 4G can stack to several seconds even when the resolver is
         * actually live. 8 s leaves enough headroom to avoid false-dropping
         * working resolvers, while still bounding worst-case connect overhead.
         */
        private const val PREFLIGHT_TIMEOUT_MS = 8000

        /**
         * Resolve a hostname to a numeric IP. Go on Android cannot resolve
         * hostnames internally, so we must do it on the JVM side before
         * passing addresses to the Go bridge.
         * Returns the original [host] if it's already a numeric IP.
         *
         * @param customDnsServer If non-null, use this DNS server IP for resolution
         *   instead of the system resolver. Useful when the ISP's DNS is filtered.
         */
        private val PUBLIC_DNS_SERVERS = listOf("8.8.8.8", "1.1.1.1", "9.9.9.9")

        fun resolveHost(host: String, customDnsServer: String? = null): String {
            if (host.isBlank()) return host
            // Already numeric IPv4/IPv6 — pass through
            if (app.slipnet.tunnel.DomainRouter.isIpAddress(host)) return host

            // Try custom DNS server first (bypasses ISP DNS filtering)
            if (!customDnsServer.isNullOrBlank()) {
                try {
                    val resolved = resolveViaUdp(host, customDnsServer)
                    if (resolved != null) {
                        Log.i(TAG, "Resolved '$host' → $resolved via custom DNS $customDnsServer")
                        return resolved
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Custom DNS resolution failed for '$host' via $customDnsServer", e)
                }
            }

            // Try well-known public DNS servers (bypasses censored ISP DNS)
            for (dns in PUBLIC_DNS_SERVERS) {
                if (dns == customDnsServer) continue
                try {
                    val resolved = resolveViaUdp(host, dns)
                    if (resolved != null) {
                        Log.i(TAG, "Resolved '$host' → $resolved via public DNS $dns")
                        return resolved
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Public DNS resolution failed for '$host' via $dns", e)
                }
            }

            // Fall back to system resolver
            return try {
                java.net.InetAddress.getByName(host).hostAddress ?: host
            } catch (e: Exception) {
                Log.w(TAG, "Failed to resolve '$host' to IP, passing through", e)
                host
            }
        }

        /**
         * Resolve a hostname by sending a UDP DNS query directly to [dnsServer].
         * Returns the first A record IP, or null on failure.
         */
        private fun resolveViaUdp(hostname: String, dnsServer: String, timeoutMs: Int = 5000): String? {
            val id = (Math.random() * 65535).toInt().toShort()
            val query = buildDnsQuery(id, hostname)
            val serverAddr = java.net.InetAddress.getByName(dnsServer)
            val socket = java.net.DatagramSocket()
            try {
                socket.soTimeout = timeoutMs
                val request = java.net.DatagramPacket(query, query.size, serverAddr, 53)
                socket.send(request)
                val responseBuf = ByteArray(512)
                val response = java.net.DatagramPacket(responseBuf, responseBuf.size)
                socket.receive(response)
                return parseDnsResponse(responseBuf, response.length)
            } finally {
                socket.close()
            }
        }

        /** Build a minimal DNS A-record query packet. */
        private fun buildDnsQuery(id: Short, hostname: String): ByteArray {
            val buf = java.io.ByteArrayOutputStream()
            // Header: ID, flags (standard query, RD=1), QDCOUNT=1
            buf.write(id.toInt() shr 8 and 0xFF)
            buf.write(id.toInt() and 0xFF)
            buf.write(0x01); buf.write(0x00) // flags: RD=1
            buf.write(0x00); buf.write(0x01) // QDCOUNT=1
            buf.write(0x00); buf.write(0x00) // ANCOUNT=0
            buf.write(0x00); buf.write(0x00) // NSCOUNT=0
            buf.write(0x00); buf.write(0x00) // ARCOUNT=0
            // QNAME
            for (label in hostname.split(".")) {
                buf.write(label.length)
                buf.write(label.toByteArray(Charsets.US_ASCII))
            }
            buf.write(0x00) // root label
            // QTYPE=A (1), QCLASS=IN (1)
            buf.write(0x00); buf.write(0x01)
            buf.write(0x00); buf.write(0x01)
            return buf.toByteArray()
        }

        /** Parse a DNS response and return the first A record IP, or null. */
        private fun parseDnsResponse(data: ByteArray, length: Int): String? {
            if (length < 12) return null
            val anCount = (data[6].toInt() and 0xFF shl 8) or (data[7].toInt() and 0xFF)
            if (anCount == 0) return null
            // Skip header (12 bytes) and question section
            var offset = 12
            // Skip QNAME
            while (offset < length && data[offset].toInt() != 0) {
                if (data[offset].toInt() and 0xC0 == 0xC0) { offset += 2; break }
                offset += (data[offset].toInt() and 0xFF) + 1
            }
            if (offset < length && data[offset].toInt() == 0) offset++ // null terminator
            offset += 4 // skip QTYPE + QCLASS
            // Parse answer records
            for (i in 0 until anCount) {
                if (offset >= length) break
                // Skip NAME (may be pointer)
                if (data[offset].toInt() and 0xC0 == 0xC0) offset += 2
                else { while (offset < length && data[offset].toInt() != 0) offset += (data[offset].toInt() and 0xFF) + 1; offset++ }
                if (offset + 10 > length) break
                val rType = (data[offset].toInt() and 0xFF shl 8) or (data[offset + 1].toInt() and 0xFF)
                val rdLength = (data[offset + 8].toInt() and 0xFF shl 8) or (data[offset + 9].toInt() and 0xFF)
                offset += 10
                if (rType == 1 && rdLength == 4 && offset + 4 <= length) {
                    // A record
                    return "${data[offset].toInt() and 0xFF}.${data[offset+1].toInt() and 0xFF}.${data[offset+2].toInt() and 0xFF}.${data[offset+3].toInt() and 0xFF}"
                }
                offset += rdLength
            }
            return null
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    override val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _trafficStats = MutableStateFlow(TrafficStats.EMPTY)
    override val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

    private val _dnsPoolScanState = MutableStateFlow(DnsPoolScanState())
    /** Distilled DNS-pool scan progress, observed by the main screen. */
    val dnsPoolScanState: StateFlow<DnsPoolScanState> = _dnsPoolScanState.asStateFlow()

    /**
     * Set by [SlipNetVpnService] for connects that are part of an automatic
     * reconnect cycle (network drop, tunnel stall, kill switch). When true,
     * [applyDnsPoolIfEnabled] skips the scan and reuses the resolvers
     * already in the profile.
     */
    @Volatile private var isAutoReconnect: Boolean = false
    fun setAutoReconnect(active: Boolean) { isAutoReconnect = active }

    /**
     * Job for the in-flight DNS pool scan (if any). Tracked so the service
     * can [cancelPoolScan] when the user disconnects mid-scan — short-
     * circuiting the per-probe 8 s timeouts that
     * `testResolverE2eIsolated` would otherwise run to completion.
     */
    @Volatile private var poolScanJob: kotlinx.coroutines.Job? = null
    fun cancelPoolScan() {
        poolScanJob?.cancel()
        poolScanJob = null
        if (_dnsPoolScanState.value.isRunning) {
            _dnsPoolScanState.value = DnsPoolScanState(isRunning = false)
        }
    }

    private var prevBytesSent = 0L
    private var prevBytesReceived = 0L
    private var prevTimestamp = 0L

    private var connectedProfile: ServerProfile? = null
    private var currentTunFd: ParcelFileDescriptor? = null
    private var tunnelStartException: Exception? = null
    private var currentTunnelType: TunnelType? = null

    /**
     * Override the current tunnel type. Used by VPN service for chained startup
     * (e.g., DNSTT+SSH starts as DNSTT first, then switches to DNSTT_SSH).
     */
    fun setCurrentTunnelType(type: TunnelType) {
        currentTunnelType = type
    }

    override suspend fun connect(profile: ServerProfile): Result<Unit> {
        if (_connectionState.value is ConnectionState.Connected ||
            _connectionState.value is ConnectionState.Connecting) {
            return Result.failure(IllegalStateException("Already connected or connecting"))
        }

        _connectionState.value = ConnectionState.Connecting
        connectedProfile = profile

        return Result.success(Unit)
    }
    suspend fun startDnsttProxy(
        profile: ServerProfile,
        portOverride: Int? = null,
        hostOverride: String? = null,
        socksProxyAddr: String? = null,
        socksProxyUser: String? = null,
        socksProxyPass: String? = null,
        resolverOverride: List<DnsResolver>? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        connectedProfile = profile

        val poolResult = applyDnsPoolIfEnabled(profile, resolverOverride)
        if (poolResult.isFailure) {
            val msg = poolResult.exceptionOrNull()?.message ?: "DNS pool scan failed"
            Log.e(TAG, "Pool scan failed: $msg")
            connectedProfile = null
            return@withContext Result.failure(Exception(msg))
        }
        val effectiveOverride = poolResult.getOrNull() ?: resolverOverride

        // Format DNS server address based on transport type.
        // Resolve domain names to IPs — Go on Android cannot resolve hostnames.
        val dnsServer = formatDnsServerAddress(profile, effectiveOverride)

        val proxyPort = portOverride ?: preferencesDataStore.proxyListenPort.first()
        val proxyHost = hostOverride ?: preferencesDataStore.proxyListenAddress.first()

        val tunedPayload = if (profile.dnsAutoTune) {
            val r = app.slipnet.tunnel.DnsResolverProber.probe(
                resolvers = dnsServer,
                tunnelDomain = profile.domain,
                recordType = "txt",
                authoritative = profile.dnsttAuthoritative,
            )
            Log.i(TAG, "[Auto] DNSTT probed: qname=${r.maxQnameLen} payload=${r.maxPayload} probed=${r.probed}")
            r.maxPayload
        } else profile.dnsPayloadSize

        val result = DnsttBridge.startClient(
            dnsServer = dnsServer,
            tunnelDomain = profile.domain,
            publicKey = profile.dnsttPublicKey,
            listenPort = proxyPort,
            listenHost = proxyHost,
            authoritativeMode = profile.dnsttAuthoritative,
            maxPayload = tunedPayload,
            socksProxyAddr = socksProxyAddr,
            socksProxyUser = socksProxyUser,
            socksProxyPass = socksProxyPass,
            resolverMode = profile.resolverMode.value,
            rrSpreadCount = profile.rrSpreadCount
        )

        if (result.isSuccess) {
            Log.i(TAG, "DNSTT SOCKS5 proxy started successfully")
            currentTunnelType = TunnelType.DNSTT
            Result.success(Unit)
        } else {
            val error = result.exceptionOrNull()?.message ?: "Failed to start DNSTT proxy"
            connectedProfile = null
            Log.e(TAG, "Failed to start DNSTT proxy: $error")
            Result.failure(Exception(error))
        }
    }
    private suspend fun applyDnsPoolIfEnabled(
        profile: ServerProfile,
        explicitOverride: List<DnsResolver>?
    ): Result<List<DnsResolver>?> {
        if (explicitOverride != null) return Result.success(null)
        if (!preferencesDataStore.dnsPoolEnabled.first()) return Result.success(null)
        if (isAutoReconnect) {
            Log.i(TAG, "[Pool] auto-reconnect — reusing ${profile.resolvers.size} existing resolvers, skipping scan")
            return Result.success(null)
        }
        if (profile.dnsTransport == DnsTransport.DOT || profile.dnsTransport == DnsTransport.DOH) {
            Log.i(TAG, "[Pool] skipping pool scan — profile uses ${profile.dnsTransport.displayName}, pool scan requires UDP/TCP")
            return Result.success(null)
        }
        val poolEntries = DnsPoolScanner.parsePool(preferencesDataStore.dnsPoolText.first())
        if (poolEntries.isEmpty()) return Result.success(null)
        val fullVerification = preferencesDataStore.dnsPoolFullVerification.first()

        _dnsPoolScanState.value = DnsPoolScanState(
            isRunning = true,
            total = poolEntries.size,
        )
        return try {
            val top = DnsPoolScanner.scan(
                scanner = resolverScanner,
                profile = profile,
                entries = poolEntries,
                fullVerification = fullVerification,
                onProgress = { probed, alive, verified ->
                    _dnsPoolScanState.value = _dnsPoolScanState.value.copy(
                        probed = probed,
                        alive = alive,
                        verified = verified,
                    )
                },
                // The scanner runs probes on a detached SupervisorJob — by
                // exposing it here we let [cancelPoolScan] tear it down on
                // user disconnect even though scan() itself returns as soon
                // as the 8th success arrives. (If we don't capture it, the
                // background probe cleanup keeps running but is unreachable
                // until it finishes naturally — fine but wasteful.)
                onJobStart = { job -> poolScanJob = job }
            )
            if (top.isEmpty()) {
                Log.w(TAG, "[Pool] scan yielded no working resolvers — failing connect")
                val msg = "No working DNS resolver found in pool (${poolEntries.size} entries scanned)"
                // Push Error directly into the connection flow so the main
                // screen exits "Connecting…" the instant the scan ends — don't
                // rely on the caller's failure-path plumbing alone, which has
                // multiple variants (single connect / chain layer / SSH-wrapped)
                // and would otherwise leave the UI stuck if any one swallows
                // the Result.failure.
                _connectionState.value = ConnectionState.Error(msg)
                return Result.failure(Exception(msg))
            }
            val topResolvers = top.map { (e, _) -> DnsResolver(host = e.host, port = e.port) }
            // Persist asynchronously so the tunnel handshake doesn't wait on
            // a Room write. The connect is using `topResolvers` already, so
            // a slow/failed write doesn't affect this connect — only the
            // value shown in the editor on next open.
            scope.launch {
                try {
                    profileRepository.updateProfile(profile.copy(resolvers = topResolvers))
                    Log.i(TAG, "[Pool] persisted ${topResolvers.size} top resolvers into profile")
                } catch (e: Exception) {
                    Log.w(TAG, "[Pool] failed to persist top resolvers", e)
                }
            }
            Result.success(topResolvers)
        } catch (e: kotlinx.coroutines.CancellationException) {
            Log.i(TAG, "[Pool] scan cancelled (user disconnect)")
            Result.success(null)
        } finally {
            _dnsPoolScanState.value = DnsPoolScanState(isRunning = false)
        }
    }

    /**
     * Format the DNS server address string for the Go bridge, resolving any
     * domain names to numeric IPs (Go on Android cannot resolve hostnames).
     *
     * For TCP and DoT transports, runs a fast parallel TCP-connect preflight
     * and drops unresponsive resolvers before they reach the native bridge —
     * a single dead resolver in the list would otherwise stall connection
     * setup while the bridge times out on it.
     */
    private suspend fun formatDnsServerAddress(profile: ServerProfile, resolverOverride: List<DnsResolver>? = null): String {
        val resolvers = resolverOverride ?: profile.resolvers
        return when (profile.dnsTransport) {
            DnsTransport.UDP -> {
                resolvers.joinToString(",") { "${resolveHost(it.host)}:${it.port}" }
                    .ifBlank { "8.8.8.8:53" }
            }
            DnsTransport.DOH -> {
                profile.dohUrl.ifBlank { "https://dns.google/dns-query" }
            }
            DnsTransport.TCP -> {
                val resolved = resolvers.map { it to resolveHost(it.host) }
                val live = preflightTcp(resolved, portOf = { it.port }, timeoutMs = PREFLIGHT_TIMEOUT_MS)
                live.joinToString(",") { (resolver, ip) -> "tcp://$ip:${resolver.port}" }
                    .ifBlank { "tcp://8.8.8.8:53" }
            }
            DnsTransport.DOT -> {
                // DoT uses port 853, not 53. When global resolver override provides
                // only an IP (defaulting to port 53), use 853 instead.
                val resolved = resolvers.map { it to resolveHost(it.host) }
                val live = preflightTcp(resolved, portOf = { if (it.port == 53) 853 else it.port }, timeoutMs = PREFLIGHT_TIMEOUT_MS)
                live.joinToString(",") { (resolver, ip) ->
                    val port = if (resolver.port == 53) 853 else resolver.port
                    "tls://$ip:$port"
                }.ifBlank { "tls://8.8.8.8:853" }
            }
        }
    }

    private data class ResolverProbe(val resolver: DnsResolver, val ip: String, val ok: Boolean)

    /**
     * Probe each (resolver, resolvedIp) in parallel with a TCP connect. Returns
     * the subset that responded within [timeoutMs]. If every probe fails, returns
     * the input unchanged so the bridge can surface the real error instead of
     * silently dropping the user's entire resolver list.
     */
    private suspend fun preflightTcp(
        resolved: List<Pair<DnsResolver, String>>,
        portOf: (DnsResolver) -> Int,
        timeoutMs: Int
    ): List<Pair<DnsResolver, String>> {
        if (resolved.size <= 1) return resolved
        val probes: List<ResolverProbe> = coroutineScope {
            resolved.map { (resolver, ip) ->
                async {
                    ResolverProbe(resolver, ip, tryTcpConnect(ip, portOf(resolver), timeoutMs))
                }
            }.awaitAll()
        }
        val live = probes.filter { it.ok }.map { it.resolver to it.ip }
        if (live.isEmpty()) {
            Log.w(TAG, "Resolver preflight: none of ${resolved.size} resolvers responded within ${timeoutMs}ms — passing full list to bridge")
            return resolved
        }
        if (live.size != resolved.size) {
            val dead = probes.filter { !it.ok }
                .joinToString(",") { "${it.resolver.host}:${it.resolver.port}" }
            Log.w(TAG, "Resolver preflight: dropped unresponsive resolver(s): $dead")
        }
        return live
    }

    private fun tryTcpConnect(host: String, port: Int, timeoutMs: Int): Boolean {
        var socket: java.net.Socket? = null
        return try {
            socket = java.net.Socket()
            socket.connect(java.net.InetSocketAddress(host, port), timeoutMs)
            true
        } catch (_: Exception) {
            false
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
    }
    suspend fun startDnsttSocksBridge(
        dnsttPort: Int,
        dnsttHost: String,
        bridgePort: Int,
        bridgeHost: String,
        socksUsername: String? = null,
        socksPassword: String? = null,
        dnsServer: String? = null,
        dnsFallback: String? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val localAuthUser = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } else null
        val localAuthPass = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } else null
        val result = DnsttSocksBridge.start(
            dnsttPort = dnsttPort,
            dnsttHost = dnsttHost,
            listenPort = bridgePort,
            listenHost = bridgeHost,
            socksUsername = socksUsername,
            socksPassword = socksPassword,
            dnsServer = dnsServer,
            dnsFallback = dnsFallback,
            localAuthUsername = localAuthUser,
            localAuthPassword = localAuthPass
        )
        if (result.isSuccess) {
            Log.i(TAG, "DnsttSocksBridge started on $bridgeHost:$bridgePort -> $dnsttHost:$dnsttPort")
        } else {
            Log.e(TAG, "Failed to start DnsttSocksBridge: ${result.exceptionOrNull()?.message}")
        }
        result
    }
    suspend fun startTun2Socks(
        profile: ServerProfile,
        pfd: ParcelFileDescriptor,
        socksPortOverride: Int? = null
    ): Result<Unit> {
        currentTunFd = pfd

        val socksPort = socksPortOverride ?: preferencesDataStore.proxyListenPort.first()
        val disableQuic = preferencesDataStore.disableQuic.first()
        // Local proxy auth: hev-socks5-tunnel authenticates with the bridge
        val proxyAuthEnabled = preferencesDataStore.proxyAuthEnabled.first()
        val enableUdpTunneling = true
        val socksUsername = if (proxyAuthEnabled) preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } else null
        val socksPassword = if (proxyAuthEnabled) preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } else null

        val mtu = try { preferencesDataStore.vpnMtu.first() } catch (_: Exception) { PreferencesDataStore.DEFAULT_MTU }

        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting hev-socks5-tunnel")
        Log.i(TAG, "  SOCKS5 proxy: 127.0.0.1:$socksPort")
        Log.i(TAG, "  SOCKS auth: ${if (!socksUsername.isNullOrBlank()) "enabled" else "disabled"}")
        Log.i(TAG, "  Tunnel type: ${profile.tunnelType}")
        Log.i(TAG, "  UDP tunneling: $enableUdpTunneling")
        Log.i(TAG, "  MTU: $mtu")
        Log.i(TAG, "========================================")

        // Reject non-DNS UDP at TUN level with ICMP Port Unreachable so apps
        // (e.g. WhatsApp) fall back to TCP instantly instead of waiting for
        // silent-drop timeouts.
        val rejectNonDnsUdp = true

        val hevResult = HevSocks5Tunnel.start(
            tunFd = pfd,
            socksAddress = "127.0.0.1",
            socksPort = socksPort,
            socksUsername = socksUsername,
            socksPassword = socksPassword,
            enableUdpTunneling = enableUdpTunneling,
            mtu = mtu,
            ipv4Address = "10.255.255.1",
            ipv6Address = "fd00::1",
            disableQuic = disableQuic,
            rejectNonDnsUdp = rejectNonDnsUdp
        )

        return if (hevResult.isSuccess) {
            _connectionState.value = ConnectionState.Connected(profile)
            Log.i(TAG, "Tunnel started successfully")
            Result.success(Unit)
        } else {
            val error = hevResult.exceptionOrNull()?.message ?: "Failed to start tun2socks"
            _connectionState.value = ConnectionState.Error(error)
            connectedProfile = null
            // Stop the SOCKS5 proxy since tun2socks failed
            stopCurrentProxy()
            Log.e(TAG, "Failed to start tun2socks: $error")
            Result.failure(Exception(error))
        }
    }

    /**
     * Stop the currently running proxy.
     */
    private fun stopCurrentProxy() {
        Log.d(TAG, "Stopping DNS tunnel")
        DnsttBridge.stopClient()

        currentTunnelType = null
    }
    override fun isConnected(): Boolean {
        return _connectionState.value is ConnectionState.Connected
    }

    override fun getConnectedProfile(): ServerProfile? {
        return if (_connectionState.value is ConnectionState.Connected) connectedProfile else null
    }

    fun setProxyConnected(profile: ServerProfile) {
        _connectionState.value = ConnectionState.Connected(profile)
    }

    fun updateConnectionState(state: ConnectionState) {
        _connectionState.value = state
    }

    fun updateTrafficStats(stats: TrafficStats) {
        _trafficStats.value = stats
    }

    fun resetSpeedTracking() {
        prevBytesSent = 0L
        prevBytesReceived = 0L
        prevTimestamp = 0L
        _trafficStats.value = TrafficStats.EMPTY
    }

    fun refreshTrafficStats() {
        // For SOCKS-bridged tunnel types, use tunnel-level byte counters
        // instead of TUN-level stats (which include local retries/health checks)
        var sent = 0L
        var received = 0L
        var pktSent = 0L
        var pktReceived = 0L

        sent = DnsttSocksBridge.getTunnelTxBytes()
        received = DnsttSocksBridge.getTunnelRxBytes()
        if (sent == 0L && received == 0L) {
            // Engine not running yet — fall back to TUN-level counters.
            HevSocks5Tunnel.getStats()?.let { stats ->
                sent = stats.txBytes
                received = stats.rxBytes
                pktSent = stats.txPackets
                pktReceived = stats.rxPackets
            }
        }

        // Compute speed normalized by actual elapsed time
        val now = System.currentTimeMillis()
        val elapsedMs = now - prevTimestamp
        val upSpeed: Long
        val downSpeed: Long
        if (prevTimestamp == 0L || elapsedMs <= 0) {
            upSpeed = 0L
            downSpeed = 0L
        } else {
            upSpeed = ((sent - prevBytesSent).coerceAtLeast(0) * 1000 / elapsedMs)
            downSpeed = ((received - prevBytesReceived).coerceAtLeast(0) * 1000 / elapsedMs)
        }
        prevBytesSent = sent
        prevBytesReceived = received
        prevTimestamp = now

        _trafficStats.value = TrafficStats(
            bytesSent = sent,
            bytesReceived = received,
            packetsSent = pktSent,
            packetsReceived = pktReceived,
            uploadSpeed = upSpeed,
            downloadSpeed = downSpeed
        )
    }

    override suspend fun disconnect(): Result<Unit> {
        if (_connectionState.value is ConnectionState.Disconnected) {
            return Result.success(Unit)
        }

        _connectionState.value = ConnectionState.Disconnecting

        try {
            // Stop hev-socks5-tunnel first, then the engine behind it.
            HevSocks5Tunnel.stop()
            stopCurrentProxy()

            currentTunFd = null
            _connectionState.value = ConnectionState.Disconnected
            connectedProfile = null
            Log.i(TAG, "Tunnel stopped successfully")
            return Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping tunnel", e)
            _connectionState.value = ConnectionState.Error(e.message ?: "Unknown error")
            return Result.failure(e)
        }
    }
}
