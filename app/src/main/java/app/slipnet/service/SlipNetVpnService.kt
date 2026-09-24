package app.slipnet.service

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.ProxyInfo
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import app.slipnet.util.AppLog as Log
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.data.local.datastore.SplitTunnelingMode
import app.slipnet.data.local.datastore.SshCipher
import app.slipnet.tunnel.DomainRouter
import app.slipnet.tunnel.GeoBypassCountry
import app.slipnet.tunnel.GeoBypassData
import app.slipnet.data.repository.VpnRepositoryImpl
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.TunnelType
import app.slipnet.domain.model.isAvailable
import app.slipnet.tunnel.DnsttBridge
import app.slipnet.tunnel.DnsttSocksBridge
import app.slipnet.tunnel.HevSocks5Tunnel
import app.slipnet.tunnel.HttpProxyServer
import app.slipnet.tunnel.RateLimiter
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import javax.inject.Inject

@AndroidEntryPoint
class SlipNetVpnService : VpnService() {

    companion object {
        private const val TAG = "SlipNetVpnService"
        const val ACTION_CONNECT = "app.slipnet.CONNECT"
        const val ACTION_DISCONNECT = "app.slipnet.DISCONNECT"
        const val ACTION_RECONNECT = "app.slipnet.RECONNECT"
        const val EXTRA_PROFILE_ID = "profile_id"
        const val EXTRA_CHAIN_ID = "chain_id"
        const val EXTRA_BOOT_TRIGGERED = "boot_triggered"

        private const val VPN_MTU = 1280
        private const val VPN_ADDRESS = "10.255.255.1"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val DEFAULT_DNS = "8.8.8.8"
        private const val WAKELOCK_TIMEOUT_MS = 10 * 60 * 1000L  // 10 minutes (Chinese OEM ROMs kill indefinite WakeLocks)
        private const val WAKELOCK_RENEW_INTERVAL_MS = 9 * 60 * 1000L  // renew 1 min before expiry
        private const val HEALTH_CHECK_INTERVAL_MS = 15000L
        private const val QUIC_DOWN_THRESHOLD = 2 // Reconnect after 2 checks (~30s) with QUIC down
        private const val SSH_PROBE_INTERVAL = 2 // Probe SSH session every 2 health checks (~30s)
        private const val DNS_POOL_DEAD_THRESHOLD = 3 // Warn after 3 consecutive checks (~45s) with all workers dead
        private const val DNS_POOL_DEAD_THRESHOLD_SOCKS = 2 // Faster warning for SOCKS profiles (~30s)
        private const val TUNNEL_STALL_CHECK_INTERVAL = 4 // Check traffic flow every 4 health checks (~60s)
        private const val TUNNEL_STALL_CHECK_INTERVAL_SOCKS = 2 // Faster stall check for SOCKS profiles (~30s)
        private const val TUNNEL_STALL_THRESHOLD = 2 // Reconnect after 2 consecutive stalls
        private const val TUNNEL_STALL_THRESHOLD_SOCKS = 1 // Faster reconnect for SOCKS profiles (~30s)
        private const val ZERO_THROUGHPUT_WARNING_SECONDS = 30L // Warn after 30s of zero relayed bytes
        private const val ZERO_THROUGHPUT_DISCONNECT_SECONDS = 60L // Disconnect after 60s of zero relayed bytes

        // Persistence keys for auto-restart
        private const val PREFS_NAME = "vpn_service_state"
        private const val PREF_LAST_PROFILE_ID = "last_profile_id"
        private const val PREF_WAS_CONNECTED = "was_connected"

        // Auto-reconnect settings
        private const val AUTO_RECONNECT_MAX_RETRIES = 5
        private val AUTO_RECONNECT_DELAYS_MS = longArrayOf(3000, 3000, 3000, 3000, 3000)

        // Seamless reconnect: try restarting just the proxy (keeping TUN + tun2socks alive)
        // before escalating to kill-switch / auto-reconnect / stop.
        private const val MAX_SEAMLESS_RECONNECTS = 3
        private const val MAX_SEAMLESS_RECONNECTS_DNSTT = 4 // DNSTT is slower — give it more attempts
        private val SEAMLESS_RECONNECT_DELAYS_MS = longArrayOf(1000, 3000, 5000, 8000)

        // Boot retry settings (exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s, 30s, …)
        // 10 retries ≈ 3 minutes total before giving up
        private const val BOOT_RETRY_INITIAL_DELAY_MS = 1000L
        private const val BOOT_RETRY_MAX_DELAY_MS = 30_000L
        private const val BOOT_RETRY_MAX_ATTEMPTS = 10

        // SSH over tunnel (DNSTT/NoizDNS/Slipstream) retry count.
        // DNS tunnels can drop the first connection due to DPI or packet loss.
        private const val SSH_OVER_TUNNEL_RETRIES = 3
    }

    @Inject
    lateinit var connectionManager: VpnConnectionManager

    @Inject
    lateinit var vpnRepository: VpnRepositoryImpl

    @Inject
    lateinit var notificationHelper: NotificationHelper

    @Inject
    lateinit var preferencesDataStore: PreferencesDataStore

    @Inject
    lateinit var chainRepository: app.slipnet.domain.repository.ChainRepository

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var healthCheckJob: Job? = null
    private var currentProfileId: Long = -1
    private var currentTunnelType: TunnelType = TunnelType.DNSTT
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetworkAddresses: Set<String> = emptySet()
    private var reconnectDebounceJob: Job? = null
    private var networkLostJob: Job? = null
    private var connectJob: Job? = null
    private var disconnectJob: Job? = null
    private var stateObserverJob: Job? = null
    @Volatile
    private var isReconnecting = false
    @Volatile
    private var resetZeroThroughputCounter = false
    @Volatile
    private var isKillSwitchActive = false
    private var isProxyOnly = false
    private var isUserInitiatedDisconnect = false
    private var currentProfileName = ""
    private var currentChainId: Long = -1
    /** Tunnel types active in the current chain (outermost first), for cleanup ordering. */
    private var activeChainLayers: List<TunnelType> = emptyList()

    // Auto-reconnect state
    @Volatile
    private var isAutoReconnecting = false
    private var autoReconnectJob: Job? = null
    private var autoReconnectAttempt = 0
    private var connectionWasSuccessful = false

    // Boot-triggered retry state (network may not be ready after device boot)
    @Volatile
    private var isBootTriggered = false
    private var bootRetryJob: Job? = null
    private var bootRetryAttempt = 0
    private var bootNetworkCallback: ConnectivityManager.NetworkCallback? = null

    // Health check state
    private var quicDownChecks = 0
    private var healthCheckCount = 0
    private var dnsPoolDeadChecks = 0
    private var tunnelStallChecks = 0
    private var lastTxBytes = 0L
    private var lastRxBytes = 0L

    // Notification traffic stats polling
    private var trafficNotificationJob: Job? = null
    private var lastNotifTotalBytes = -1L  // -1 forces first update
    private var lastNotifHadSpeed = false

    // Seamless reconnect state: tracks how many times we've tried a lightweight
    // proxy-only restart before escalating to full teardown.
    private var seamlessReconnectAttempts = 0

    // Timestamp when the connection was fully established. Network change events
    // arriving within a few seconds of this are spurious (common on Chinese OEM
    // ROMs like MIUI/HyperOS that fire network callbacks when the VPN interface
    // is first created) and should be ignored.
    private var connectionEstablishedAt = 0L
    private val NETWORK_CHANGE_GRACE_MS = 5_000L

    // Persistence for service resilience
    private lateinit var prefs: SharedPreferences

    // WakeLock to prevent CPU sleep during VPN session
    private var wakeLock: PowerManager.WakeLock? = null

    // WifiLock to prevent Wi-Fi radio from entering low-power mode when screen is off
    private var wifiLock: WifiManager.WifiLock? = null
    private var wakeLockRenewJob: Job? = null

    // Doze mode receiver to detect idle state exits
    private var dozeReceiver: BroadcastReceiver? = null

    // DNS servers tracked for the current network (detects DNS changes during handoff)
    private var lastNetworkDnsServers: Set<String> = emptySet()

    override fun onCreate() {
        super.onCreate()
        connectivityManager = getSystemService(ConnectivityManager::class.java)
        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val chainId = intent.getLongExtra(EXTRA_CHAIN_ID, -1)
                val profileId = intent.getLongExtra(EXTRA_PROFILE_ID, -1)
                isBootTriggered = intent.getBooleanExtra(EXTRA_BOOT_TRIGGERED, false)
                if (isBootTriggered) {
                    Log.i(TAG, "Boot-triggered connection requested")
                    bootRetryAttempt = 0
                }
                if (chainId != -1L) {
                    // Chains belonged to the multi-engine build. When a chain is
                    // requested, connect its first layer's profile instead of
                    // failing the whole request.
                    Log.i(TAG, "Chain $chainId requested — connecting its first profile")
                    val chain = chainRepository.getChainById(chainId)
                    val firstProfileId = chain?.profileIds?.firstOrNull()
                    if (firstProfileId != null) {
                        connect(firstProfileId)
                    } else {
                        connectionManager.onVpnError("Chain $chainId has no profiles")
                        stopSelf()
                    }
                } else if (profileId != -1L) {
                    connect(profileId)
                }
            }
            ACTION_DISCONNECT -> {
                disconnect()
            }
            ACTION_RECONNECT -> {
                // Update notification immediately so user sees feedback
                val notification = notificationHelper.createVpnNotification(
                    ConnectionState.Connecting,
                    isProxyOnly = isProxyOnly
                )
                startForeground(NotificationHelper.VPN_NOTIFICATION_ID, notification)
                handleNetworkChange("manual reconnect")
            }
            null -> {
                // Service was restarted by the system after being killed
                // Try to reconnect using the last profile
                handleServiceRestart(flags)
            }
        }

        return START_STICKY
    }

    /**
     * Handle service restart after being killed by Android.
     * Attempts to reconnect using the last connected profile.
     */
    private fun handleServiceRestart(flags: Int) {
        val wasConnected = prefs.getBoolean(PREF_WAS_CONNECTED, false)
        val lastProfileId = prefs.getLong(PREF_LAST_PROFILE_ID, -1)

        Log.i(TAG, "Service restarted by system (flags=$flags, wasConnected=$wasConnected, lastProfileId=$lastProfileId)")

        if (wasConnected && lastProfileId != -1L) {
            Log.i(TAG, "Attempting to auto-reconnect with profile $lastProfileId")
            connect(lastProfileId)
        } else {
            Log.d(TAG, "No previous connection to restore, stopping service")
            stopSelf()
        }
    }

    /**
     * Save connection state for auto-restart.
     */
    private fun saveConnectionState(profileId: Long, connected: Boolean) {
        prefs.edit()
            .putLong(PREF_LAST_PROFILE_ID, profileId)
            .putBoolean(PREF_WAS_CONNECTED, connected)
            .apply()
        Log.d(TAG, "Saved connection state: profileId=$profileId, connected=$connected")
    }

    /**
     * Clear saved connection state.
     */
    private fun clearConnectionState() {
        prefs.edit()
            .putBoolean(PREF_WAS_CONNECTED, false)
            .apply()
        connectionEstablishedAt = 0
        Log.d(TAG, "Cleared connection state")
    }

    private fun connect(profileId: Long) {
        // Cancel stale state observer from a previous connection to prevent it
        // from calling stopSelf() while the new connection is starting.
        stateObserverJob?.cancel()
        stateObserverJob = null

        connectJob?.cancel()
        connectJob = serviceScope.launch {
            // Wait for any in-progress disconnect to finish releasing ports.
            // Timeout after 5s to avoid hanging forever if cleanup is stuck.
            try {
                withTimeout(5000) { disconnectJob?.join() }
            } catch (_: kotlinx.coroutines.TimeoutCancellationException) {
                Log.w(TAG, "Timed out waiting for previous disconnect — forcing cleanup")
            }

            // Always stop previous proxies to ensure ports are freed.
            // This handles the case where onDestroy() sent stop signals but
            // didn't wait for native code to release ports (e.g. abandoned Rust threads).
            withContext(Dispatchers.IO) {
                try { stopCurrentProxy() } catch (_: Exception) {}
                // Process-level singletons — a previous service instance may have left
                // listeners alive even though currentTunnelType has been reset.
                // Stop ALL bridge types to ensure ports are freed.
                try { HevSocks5Tunnel.stop() } catch (_: Exception) {}
                try { DnsttSocksBridge.stop() } catch (_: Exception) {}
                try { DnsttBridge.stopClient() } catch (_: Exception) {}
                // Give native threads extra time to fully release ports after stop.
                // Both Go (DNSTT/VayDNS) and Rust (Slipstream) may take a moment to close listeners.
                delay(300)
            }

            // Clean up previous connection resources if switching profiles
            if (currentProfileId != -1L && currentProfileId != profileId) {
                Log.i(TAG, "Switching profile: cleaning up previous connection")
                cleanupConnection()
            }

            val profile = connectionManager.getProfileById(profileId)
            if (profile == null) {
                connectionManager.onVpnError("Profile not found")
                stopSelf()
                return@launch
            }

            if (profile.isExpired) {
                connectionManager.onVpnError("This profile has expired")
                stopSelf()
                return@launch
            }
            if (profile.boundDeviceId.isNotEmpty() && profile.boundDeviceId != connectionManager.getDeviceId()) {
                connectionManager.onVpnError("This profile is bound to a different device")
                stopSelf()
                return@launch
            }

            currentProfileId = profileId
            currentProfileName = profile.name
            isUserInitiatedDisconnect = false

            // Log connection summary before enabling redaction so it's visible for locked profiles
            if (profile.isLocked) {
                val user = profile.sshUsername.ifBlank { profile.socksUsername ?: profile.naiveUsername.ifBlank { "" } }
                Log.i(TAG, "Connecting locked profile: tunnel=${profile.tunnelType.displayName}" +
                        if (user.isNotBlank()) ", user=$user" else "")
            }

            // Redact sensitive config from in-app debug log for locked profiles
            app.slipnet.util.AppLog.redactSensitive = profile.isLocked

            // Dismiss any previous reconnect/disconnect notifications
            getSystemService(NotificationManager::class.java).apply {
                cancel(NotificationHelper.RECONNECT_NOTIFICATION_ID)
                cancel(NotificationHelper.DISCONNECT_NOTIFICATION_ID)
            }

            // Show connecting notification
            val notification = notificationHelper.createVpnNotification(ConnectionState.Connecting)
            startForeground(NotificationHelper.VPN_NOTIFICATION_ID, notification)

            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager

            // Acquire WakeLock with timeout (Chinese OEM ROMs kill indefinite WakeLocks)
            if (wakeLock == null) {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SlipNet:VpnWakeLock").apply {
                    setReferenceCounted(false)
                    acquire(WAKELOCK_TIMEOUT_MS)
                }
                Log.d(TAG, "WakeLock acquired (${WAKELOCK_TIMEOUT_MS / 60000}min timeout)")
            }
            startWakeLockRenewal()

            // Acquire WifiLock to keep Wi-Fi radio active when screen is off.
            // Chinese OEMs (Xiaomi, Huawei, etc.) kill apps using WIFI_MODE_FULL_LOW_LATENCY,
            // so fall back to WIFI_MODE_FULL on those devices.
            if (wifiLock == null) {
                val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                @Suppress("DEPRECATION")
                val wifiMode = when {
                    isChineseOem() -> WifiManager.WIFI_MODE_FULL
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                    else -> WifiManager.WIFI_MODE_FULL_HIGH_PERF
                }
                wifiLock = wifiManager?.createWifiLock(wifiMode, "SlipNet:VpnWifiLock")?.apply {
                    setReferenceCounted(false)
                    acquire()
                }
                if (wifiLock != null) Log.d(TAG, "WifiLock acquired")
            }

            // Warn if battery optimization is not disabled
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                Log.w(TAG, "Battery optimization is enabled - VPN may be interrupted by Doze mode")
            }

            // Check Private DNS mode. Only "hostname" (user-set provider) is dangerous —
            // it forces DoT and bypasses VPN DNS entirely. "opportunistic" is the Android
            // default and falls back to plain DNS through the VPN when the resolver
            // doesn't support DoT (which is most ISP resolvers).
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    val privateDnsMode = android.provider.Settings.Global.getString(
                        contentResolver, "private_dns_mode"
                    )
                    when (privateDnsMode) {
                        "hostname" -> Log.w(TAG, "Private DNS is set to a custom provider - DNS queries will bypass the VPN tunnel")
                        "opportunistic" -> Log.d(TAG, "Private DNS: opportunistic (default, safe for most networks)")
                    }
                } catch (_: Exception) {}
            }

            try {
                // Read proxy-only mode setting
                isProxyOnly = preferencesDataStore.proxyOnlyMode.first()

                // Set debug logging on tunnel bridges
                val debug = preferencesDataStore.debugLogging.first()
                DnsttSocksBridge.debugLogging = debug
                HttpProxyServer.debugLogging = debug

                // Configure domain routing on bridges
                val domainRouter = buildDomainRouter()
                DnsttSocksBridge.domainRouter = domainRouter

                // Bandwidth limiting
                val ulKbps = preferencesDataStore.uploadLimitKbps.first()
                val dlKbps = preferencesDataStore.downloadLimitKbps.first()
                val ulLimiter = if (ulKbps > 0) RateLimiter(ulKbps.toLong() * 1024) else null
                val dlLimiter = if (dlKbps > 0) RateLimiter(dlKbps.toLong() * 1024) else null
                DnsttSocksBridge.uploadLimiter = ulLimiter
                DnsttSocksBridge.downloadLimiter = dlLimiter
                HttpProxyServer.uploadLimiter = ulLimiter
                HttpProxyServer.downloadLimiter = dlLimiter

                // Track the tunnel type for this connection
                currentTunnelType = profile.tunnelType
                Log.i(TAG, "Starting VPN with tunnel type: $currentTunnelType")

                // Global resolver override: replace profile resolvers with user's global list
                val globalResolverOverride: List<app.slipnet.domain.model.DnsResolver>? =
                    preferencesDataStore.parsedGlobalResolvers().takeIf { it.isNotEmpty() }
                        ?.also { Log.i(TAG, "Using global DNS resolver override: ${it.joinToString { r -> "${r.host}:${r.port}" }}") }

                // Extract global DNS IP for hostname resolution (bypasses ISP DNS filtering)
                val globalDnsIp = globalResolverOverride?.firstOrNull()?.host?.takeIf {
                    DomainRouter.isIpAddress(it)
                }

                val effectiveResolverHost = globalResolverOverride?.firstOrNull()?.host
                    ?: profile.resolvers.firstOrNull()?.host
                val dnsServer = resolveToIp(effectiveResolverHost, globalDnsIp)
                // Remote DNS: the DNS servers used on the remote side of the tunnel
                var remoteDns = preferencesDataStore.getEffectiveRemoteDns().first()
                var remoteDnsFallback = preferencesDataStore.getEffectiveRemoteDnsFallback().first()

                Log.i(TAG, "Remote DNS: $remoteDns (fallback: $remoteDnsFallback)")

                // Check if tunnel type is available in this build flavor
                if (!currentTunnelType.isAvailable()) {
                    handleTunnelFailure("${currentTunnelType.displayName} is not available in this edition")
                    return@launch
                }

                // Single tunnel engine: VPN interface first (app excluded), then the
                // in-process engine, then the hev bridge over it.
                connectDnstt(profile, dnsServer, remoteDns, remoteDnsFallback, globalResolverOverride)

            } catch (e: kotlinx.coroutines.CancellationException) {
                // Coroutine was cancelled (user disconnected, service stopped, or new connect).
                // Do NOT treat as an error — let the cancelling code handle cleanup.
                Log.d(TAG, "Connection coroutine cancelled")
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Exception during connection", e)

                // Boot-triggered retry: network may not be ready yet after device boot.
                // Retry with exponential backoff regardless of connectionWasSuccessful.
                if (isBootTriggered && !isUserInitiatedDisconnect) {
                    enterBootRetryMode(currentProfileId, "boot connect failed: ${e.message}")
                    return@launch
                }

                // If this was an auto-reconnect attempt and we can still retry, re-enter the retry loop
                val autoReconnectEnabled = try { preferencesDataStore.autoReconnect.first() } catch (_: Exception) { false }
                if (autoReconnectEnabled && connectionWasSuccessful && !isUserInitiatedDisconnect
                    && autoReconnectAttempt < AUTO_RECONNECT_MAX_RETRIES) {
                    handleTunnelFailure("reconnect failed: ${e.message}")
                } else {
                    connectionManager.onVpnError(e.message ?: "Unknown error")
                    cleanupConnection()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    // ── Chain Connection ──────────────────────────────────────────────
    private suspend fun buildDomainRouter(): DomainRouter {
        val domainRoutingEnabled = preferencesDataStore.domainRoutingEnabled.first()
        val geoBypassEnabled = preferencesDataStore.geoBypassEnabled.first()

        if (!domainRoutingEnabled && !geoBypassEnabled) return DomainRouter.DISABLED

        val mode = preferencesDataStore.domainRoutingMode.first()
        val domains = if (domainRoutingEnabled) preferencesDataStore.domainRoutingDomains.first() else emptySet()

        val geoData = if (geoBypassEnabled) {
            val countryCode = preferencesDataStore.geoBypassCountry.first()
            val country = GeoBypassCountry.fromCode(countryCode)
            Log.i(TAG, "Geo-bypass enabled: country=${country.displayName}")
            DomainRouter.loadGeoData(this, country)
        } else {
            GeoBypassData.EMPTY
        }

        if (domainRoutingEnabled) {
            Log.i(TAG, "Domain routing enabled: mode=$mode, ${domains.size} domains")
        }

        return DomainRouter(
            enabled = domainRoutingEnabled || geoBypassEnabled,
            mode = mode,
            domains = domains,
            geoBypassEnabled = geoBypassEnabled,
            geoBypass = geoData
        )
    }
    private suspend fun connectDnstt(profile: app.slipnet.domain.model.ServerProfile, dnsServer: String, remoteDns: String, remoteDnsFallback: String, globalResolverOverride: List<app.slipnet.domain.model.DnsResolver>? = null) {
        val proxyPort = preferencesDataStore.proxyListenPort.first()
        val proxyHost = preferencesDataStore.proxyListenAddress.first()
        val dnsttPort = proxyPort + 1

        // Step 1: Set VpnService reference (for potential future use)
        DnsttBridge.setVpnService(this@SlipNetVpnService)

        // Step 2: Establish VPN interface FIRST (with addDisallowedApplication for this app)
        // This ensures DNSTT's sockets bypass the VPN when created
        if (!isProxyOnly) {
            vpnInterface = establishVpnInterface(dnsServer)
            if (vpnInterface == null) {
                connectionManager.onVpnError("Failed to establish VPN interface")
                DnsttBridge.setVpnService(null)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            // Brief delay to let VPN routing settle (as reference app does)
            delay(200)
        }

        // Step 3: Start DNSTT/NoizDNS on internal port (its sockets bypass VPN due to app exclusion)
        val proxyResult = vpnRepository.startDnsttProxy(
            profile, portOverride = dnsttPort, hostOverride = "127.0.0.1", resolverOverride = globalResolverOverride
        )
        if (proxyResult.isFailure) {
            connectionManager.onVpnError(proxyResult.exceptionOrNull()?.message ?: "Failed to start tunnel engine")
            vpnInterface?.close()
            vpnInterface = null
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Read actual port — may differ from requested if preferred port was stuck
        val actualDnsttPort = DnsttBridge.getClientPort()
        if (actualDnsttPort != dnsttPort) {
            Log.i(TAG, "DNSTT bound to alternative port $actualDnsttPort (preferred $dnsttPort was stuck)")
        }

        // Step 3.5: Verify DNSTT is listening on internal port
        if (!waitForProxyReady(actualDnsttPort, maxAttempts = 20, delayMs = 100)) {
            handleProxyStartupFailure(actualDnsttPort)
            vpnInterface?.close()
            vpnInterface = null
            return
        }

        // Step 4: Start DnsttSocksBridge on proxyPort (user-facing, with auth for Dante)
        // DNS target resolved at the REMOTE server (through Dante),
        // not locally. Using local/ISP DNS would give poisoned results in censored networks.
        DnsttSocksBridge.authoritativeMode = profile.dnsttAuthoritative
        DnsttSocksBridge.proxyOnlyMode = isProxyOnly
        DnsttSocksBridge.dnsWorkerPoolSize = preferencesDataStore.dnsWorkerMode.first().poolSize
        val bridgeResult = vpnRepository.startDnsttSocksBridge(
            dnsttPort = actualDnsttPort,
            dnsttHost = "127.0.0.1",
            bridgePort = proxyPort,
            bridgeHost = proxyHost,
            socksUsername = profile.socksUsername,
            socksPassword = profile.socksPassword,
            dnsServer = remoteDns,
            dnsFallback = remoteDnsFallback
        )
        if (bridgeResult.isFailure) {
            connectionManager.onVpnError(bridgeResult.exceptionOrNull()?.message ?: "Failed to start DNSTT SOCKS5 bridge")
            stopCurrentProxy()
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Step 4.5: Verify bridge is listening
        if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 100)) {
            Log.e(TAG, "DnsttSocksBridge failed to become ready on port $proxyPort")
            connectionManager.onVpnError("DNSTT SOCKS5 bridge failed to start")
            stopCurrentProxy()
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Proxy-only mode: skip tun2socks
        if (isProxyOnly) {
            vpnRepository.setProxyConnected(profile)
            Log.i(TAG, "Proxy-only mode: DNSTT SOCKS5 bridge ready on $proxyHost:$proxyPort")
            finishConnection()
            return
        }

        // Step 5: Start tun2socks pointing at bridge on proxyPort
        val tun2socksResult = vpnRepository.startTun2Socks(profile, vpnInterface!!)
        if (tun2socksResult.isFailure) {
            connectionManager.onVpnError(tun2socksResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            vpnInterface?.close()
            vpnInterface = null
            DnsttBridge.setVpnService(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Give DNSTT a moment to establish the connection
        delay(500)
        Log.d(TAG, "DNSTT tunnel started with bridge")

        finishConnection()
    }
    private suspend fun handleProxyStartupFailure(port: Int) {
        val nativeRunning = try { DnsttBridge.isRunning() } catch (e: Exception) { false }
        Log.e(TAG, "Proxy failed to become ready on port $port, nativeRunning=$nativeRunning")

        val errorMsg = if (!nativeRunning) {
            "Proxy failed to start - client crashed"
        } else {
            "Proxy failed to start - port not listening"
        }
        connectionManager.onVpnError(errorMsg)
        stopCurrentProxy()
        clearVpnServiceRef()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /**
     * Finish connection setup - common to all tunnel types.
     */
    private fun finishConnection() {
        // Mark connection as successful for auto-reconnect eligibility
        connectionWasSuccessful = true
        autoReconnectAttempt = 0
        vpnRepository.setAutoReconnect(false)
        connectionEstablishedAt = System.currentTimeMillis()

        // Clear boot-triggered state — connection succeeded, normal auto-reconnect takes over
        isBootTriggered = false
        bootRetryAttempt = 0
        bootRetryJob?.cancel()
        bootRetryJob = null
        unregisterBootNetworkCallback()

        // Notify connection manager for bookkeeping (profile preferences, etc.)
        connectionManager.onVpnEstablished()

        // Tag the Connected state with chain info so the UI can highlight the chain
        if (currentChainId > 0) {
            val current = vpnRepository.connectionState.value
            if (current is ConnectionState.Connected) {
                vpnRepository.updateConnectionState(
                    current.copy(chainId = currentChainId, chainName = currentProfileName)
                )
            }
        }

        // Save connection state for auto-restart if killed by system
        saveConnectionState(currentProfileId, connected = true)

        // Start HTTP proxy if enabled (chains through existing SOCKS5 proxy).
        // Skip if already running (started earlier by establishVpnInterface for VPN append).
        serviceScope.launch {
            try {
                if (!HttpProxyServer.isRunning()) {
                    val httpEnabled = preferencesDataStore.httpProxyEnabled.first()
                    if (httpEnabled) {
                        val httpPort = preferencesDataStore.httpProxyPort.first()
                        val listenHost = preferencesDataStore.proxyListenAddress.first()
                        val socksPort = preferencesDataStore.proxyListenPort.first()
                        val authUser = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } else null
                        val authPass = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } else null
                        val result = HttpProxyServer.start(
                            socksHost = "127.0.0.1",
                            socksPort = socksPort,
                            listenHost = listenHost,
                            listenPort = httpPort,
                            socksAuthUsername = authUser,
                            socksAuthPassword = authPass
                        )
                        if (result.isFailure) {
                            Log.w(TAG, "HTTP proxy failed to start: ${result.exceptionOrNull()?.message}")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error starting HTTP proxy: ${e.message}")
            }
        }

        // Start health monitoring and network change detection
        startHealthCheck()
        registerNetworkCallback()
        registerDozeReceiver()

        // Tell Android which physical networks the VPN uses for seamless failover
        updateUnderlyingNetworks()

        // Update notification to connected state
        observeConnectionState()

        // Warm up the tunnel with a few DNS queries so the KCP session is active
        // before apps like Telegram try to connect. Without this, the first
        // connections through a cold tunnel are slow and apps with aggressive
        // timeouts may fail and enter exponential backoff.
        if (!isProxyOnly) {
            serviceScope.launch(Dispatchers.IO) {
                try {
                    val proxyPort = preferencesDataStore.proxyListenPort.first()
                    repeat(3) {
                        try {
                            java.net.Socket().use { s ->
                                s.connect(java.net.InetSocketAddress("127.0.0.1", proxyPort), 3000)
                                val out = s.getOutputStream()
                                // SOCKS5 handshake + CONNECT to 8.8.8.8:53 to prime the tunnel
                                out.write(byteArrayOf(0x05, 0x01, 0x00)) // SOCKS5 no-auth
                                out.flush()
                                s.getInputStream().read(ByteArray(2)) // auth response
                                out.write(byteArrayOf(
                                    0x05, 0x01, 0x00, 0x01,        // SOCKS5 CONNECT IPv4
                                    0x08, 0x08, 0x08, 0x08,        // 8.8.8.8
                                    0x00, 0x35                      // port 53
                                ))
                                out.flush()
                                s.getInputStream().read(ByteArray(10)) // connect response
                            }
                        } catch (_: Exception) {}
                        delay(100)
                    }
                    Log.d(TAG, "Tunnel warm-up complete")
                } catch (_: Exception) {}
            }
        }
    }
    private suspend fun waitForProxyReady(port: Int, maxAttempts: Int, delayMs: Long): Boolean {
        Log.d(TAG, "Waiting for proxy to be ready on port $port (max ${maxAttempts * delayMs}ms, type=$currentTunnelType)")

        return kotlinx.coroutines.withContext(Dispatchers.IO) {
            repeat(maxAttempts) { attempt ->
                val nativeRunning = try {
                    DnsttBridge.isRunning()
                } catch (e: Exception) {
                    Log.e(TAG, "Error checking tunnel engine state: ${e.message}")
                    true // Assume it's running if we can't check
                }

                if (!nativeRunning) {
                    Log.e(TAG, "Native client stopped during startup (attempt ${attempt + 1}, type=$currentTunnelType)")
                    return@withContext false
                }

                try {
                    java.net.Socket().use { socket ->
                        socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 200)
                        Log.i(TAG, "Proxy ready on port $port after ${attempt + 1} attempts (${(attempt + 1) * delayMs}ms)")
                        return@withContext true
                    }
                } catch (e: java.net.ConnectException) {
                    // Connection refused - port not listening yet
                    if (attempt % 10 == 0) {
                        Log.d(TAG, "Proxy not ready yet (attempt ${attempt + 1}): connection refused")
                    }
                } catch (e: java.net.SocketTimeoutException) {
                    // Timeout - port might be in weird state
                    Log.d(TAG, "Proxy not ready yet (attempt ${attempt + 1}): timeout")
                } catch (e: Exception) {
                    Log.d(TAG, "Proxy not ready yet (attempt ${attempt + 1}): ${e.javaClass.simpleName} - ${e.message}")
                }

                if (attempt < maxAttempts - 1) {
                    Thread.sleep(delayMs)
                }
            }

            Log.e(TAG, "Proxy failed to become ready after $maxAttempts attempts (${maxAttempts * delayMs}ms)")
            false
        }
    }


    /**
     * Start periodic health check to detect if the Rust client has crashed
     * or if the connection has become stale.
     */
    private fun startHealthCheck() {
        healthCheckJob?.cancel()
        quicDownChecks = 0
        healthCheckCount = 0
        dnsPoolDeadChecks = 0
        tunnelStallChecks = 0
        lastTxBytes = 0L
        lastRxBytes = 0L
        seamlessReconnectAttempts = 0  // Reset on successful reconnection

        // Event-driven DNS pool death: react in ~8s instead of waiting 3 polls (45s).
        // The polled check in the loop below remains as a safety net.
        run {
            DnsttSocksBridge.onDnsPoolDead = {
                serviceScope.launch(Dispatchers.Main) {
                    if (healthCheckJob?.isActive == true) {
                        handleTunnelFailure("DNS workers dead")
                    }
                }
            }
        }

        healthCheckJob = serviceScope.launch(Dispatchers.IO) {
            // Give the connection time to establish before monitoring
            delay(10_000L)

            while (isActive) {
                delay(HEALTH_CHECK_INTERVAL_MS)
                healthCheckCount++

                // Check if both native clients are still running and healthy
                val proxyHealthy = isCurrentProxyHealthy()
                val tunnelRunning = if (isProxyOnly) true else HevSocks5Tunnel.isRunning()

                if (!proxyHealthy || !tunnelRunning) {
                    Log.e(TAG, "Health check failed: proxy=$proxyHealthy (type=$currentTunnelType), tunnel=$tunnelRunning")
                    launch(Dispatchers.Main) {
                        handleTunnelFailure("health check failed")
                    }
                    break
                }

                // For tunnels with DNS worker pools: warn when all workers are dead.
                val dnsPoolDead = DnsttSocksBridge.isDnsPoolDead()
                if (dnsPoolDead) {
                    dnsPoolDeadChecks++
                    val threshold = DNS_POOL_DEAD_THRESHOLD
                    if (dnsPoolDeadChecks >= threshold) {
                        Log.e(TAG, "All DNS workers dead for ${dnsPoolDeadChecks * HEALTH_CHECK_INTERVAL_MS / 1000}s, triggering reconnect")
                        launch(Dispatchers.Main) {
                            handleTunnelFailure("DNS workers dead")
                        }
                        break
                    }
                } else {
                    dnsPoolDeadChecks = 0
                }

                // Traffic stall detection: if VPN is forwarding outgoing packets but
                // getting nothing back, the tunnel is dead (connected but can't transfer data).
                val stallCheckInterval = TUNNEL_STALL_CHECK_INTERVAL
                val stallThreshold = TUNNEL_STALL_THRESHOLD
                if (!isProxyOnly && healthCheckCount % stallCheckInterval == 0) {
                    val stats = HevSocks5Tunnel.getStats()
                    if (stats != null) {
                        val txIncreased = stats.txBytes > lastTxBytes
                        val rxIncreased = stats.rxBytes > lastRxBytes

                        if (txIncreased && !rxIncreased) {
                            tunnelStallChecks++
                            Log.w(TAG, "Tunnel stall detected ($tunnelStallChecks/$stallThreshold): tx flowing but no rx")
                            if (tunnelStallChecks >= stallThreshold) {
                                Log.e(TAG, "Tunnel stalled — data sent but no response for ~${tunnelStallChecks * stallCheckInterval * HEALTH_CHECK_INTERVAL_MS / 1000}s")
                                tunnelStallChecks = 0
                                launch(Dispatchers.Main) {
                                    handleTunnelFailure("tunnel not responding")
                                }
                                break
                            }
                        } else {
                            if (tunnelStallChecks > 0) {
                                Log.i(TAG, "Tunnel stall recovered after $tunnelStallChecks checks")
                            }
                            tunnelStallChecks = 0
                        }

                        lastTxBytes = stats.txBytes
                        lastRxBytes = stats.rxBytes
                    }
                }

                // Capacity exhaustion: all CONNECT semaphore slots stuck for >60s.
                // This happens when the transport dies (e.g. QUIC) but localhost TCP
                // sockets stay open, causing handshake reads to hang indefinitely.
                val capacityExhausted = DnsttSocksBridge.isCapacityExhausted()
                if (capacityExhausted) {
                    Log.e(TAG, "Bridge capacity exhausted — all CONNECT slots stuck, triggering reconnect")
                    launch(Dispatchers.Main) {
                        handleTunnelFailure("bridge capacity exhausted")
                    }
                    break
                }

            }
        }
    }

    /**
     * Update the VPN's underlying networks for seamless handover.
     * Tells Android which physical networks the VPN uses, enabling
     * automatic failover during WiFi↔cellular switches without full reconnection.
     */
    @Suppress("DEPRECATION")
    private fun updateUnderlyingNetworks() {
        try {
            val cm = connectivityManager ?: return
            val networks = cm.allNetworks
                .mapNotNull { network ->
                    val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
                    if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                        network
                    } else null
                }
                .sortedByDescending { network ->
                    val caps = cm.getNetworkCapabilities(network)
                    when {
                        caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> 3
                        caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> 2
                        caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> 1
                        else -> 0
                    }
                }
                .toTypedArray()

            setUnderlyingNetworks(if (networks.isNotEmpty()) networks else null)
            Log.d(TAG, "Updated underlying networks: ${networks.size} available")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to update underlying networks", e)
        }
    }

    /**
     * Register a BroadcastReceiver to detect when the device exits Doze mode.
     * Doze suspends network access — when it lifts, connections may be stale
     * and need immediate refresh.
     */
    private fun registerDozeReceiver() {
        if (dozeReceiver != null) return
        dozeReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
                if (pm.isDeviceIdleMode) {
                    Log.d(TAG, "Device entered Doze mode")
                } else {
                    Log.i(TAG, "Device exited Doze mode — checking connection health")
                    // Update underlying networks immediately (network state may have changed in Doze)
                    updateUnderlyingNetworks()
                    // Only reconnect if the proxy is actually unhealthy.
                    // Unconditional reconnect kills working DNSTT/SSH connections
                    // and causes unnecessary downtime on every Doze cycle.
                    if (!isCurrentProxyHealthy()) {
                        Log.i(TAG, "Proxy unhealthy after Doze — reconnecting")
                        debouncedReconnect("doze mode exit")
                    } else {
                        Log.d(TAG, "Proxy healthy after Doze — no reconnect needed")
                    }
                }
            }
        }
        @Suppress("UnspecifiedRegisterReceiverFlag")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(dozeReceiver, IntentFilter(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED), Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(dozeReceiver, IntentFilter(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED))
        }
        Log.d(TAG, "Doze mode receiver registered")
    }

    private fun unregisterDozeReceiver() {
        dozeReceiver?.let {
            try {
                unregisterReceiver(it)
                Log.d(TAG, "Doze mode receiver unregistered")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to unregister Doze receiver", e)
            }
        }
        dozeReceiver = null
    }

    /**
     * Register for network connectivity changes to detect when we need to reconnect.
     */
    private fun registerNetworkCallback() {
        unregisterNetworkCallback() // Clean up any existing callback

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            private var currentNetwork: Network? = null
            // Ignore onAvailable calls for 2s after registration to let all
            // initial callbacks settle (WiFi + cellular fire back-to-back)
            private val registeredAt = System.currentTimeMillis()
            private val quietPeriodMs = 2000L

            override fun onAvailable(network: Network) {
                Log.d(TAG, "Network available: $network")
                // A network arrived — cancel any pending "no network" disconnect
                networkLostJob?.cancel()
                networkLostJob = null

                // Always update underlying networks so the VPN can use the new network
                updateUnderlyingNetworks()

                if (System.currentTimeMillis() - registeredAt < quietPeriodMs) {
                    Log.d(TAG, "Initial network detected: $network (quiet period, no reconnection)")
                    currentNetwork = network
                    updateTrackedAddresses(network)
                    return
                }
                if (currentNetwork == null) {
                    Log.i(TAG, "Network restored: $network, triggering reconnection")
                    debouncedReconnect("network restored")
                } else if (currentNetwork != network) {
                    Log.i(TAG, "Network changed from $currentNetwork to $network, triggering reconnection")
                    debouncedReconnect("network change")
                }
                currentNetwork = network
                // Update tracked addresses for new network
                updateTrackedAddresses(network)
            }

            override fun onLost(network: Network) {
                Log.d(TAG, "Network lost: $network")
                // Update underlying networks to remove the lost network
                updateUnderlyingNetworks()

                if (network == currentNetwork) {
                    currentNetwork = null
                    lastNetworkAddresses = emptySet()
                    lastNetworkDnsServers = emptySet()

                    // Wait briefly for a replacement network (e.g. WiFi → cellular handoff).
                    // If no network arrives within the window, treat as full connectivity loss.
                    networkLostJob?.cancel()
                    networkLostJob = serviceScope.launch {
                        delay(3000)
                        Log.w(TAG, "No network available after loss of $network — reporting tunnel failure")
                        handleTunnelFailure("network lost")
                    }
                }
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                // Network capabilities changed - check if we still have internet
                val hasInternet = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                Log.d(TAG, "Network capabilities changed: $network, hasInternet=$hasInternet")
                // Refresh underlying networks (capabilities like VALIDATED may have changed)
                updateUnderlyingNetworks()
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                // Link properties changed - check for IP address and DNS server changes
                val newAddresses = linkProperties.linkAddresses
                    .mapNotNull { it.address?.hostAddress }
                    .toSet()

                val newDnsServers = linkProperties.dnsServers
                    .mapNotNull { it.hostAddress }
                    .toSet()

                Log.d(TAG, "Link properties changed: $network, addresses=$newAddresses, dns=$newDnsServers")

                // Skip change detection during quiet period
                if (System.currentTimeMillis() - registeredAt < quietPeriodMs) {
                    lastNetworkAddresses = newAddresses
                    lastNetworkDnsServers = newDnsServers
                    return
                }

                // If IP addresses changed, we need to reconnect
                if (lastNetworkAddresses.isNotEmpty() && newAddresses != lastNetworkAddresses) {
                    val added = newAddresses - lastNetworkAddresses
                    val removed = lastNetworkAddresses - newAddresses
                    Log.i(TAG, "IP addresses changed: added=$added, removed=$removed")
                    debouncedReconnect("IP address change")
                }
                // If DNS servers changed (common during WiFi↔cellular handoff), reconnect
                else if (lastNetworkDnsServers.isNotEmpty() && newDnsServers != lastNetworkDnsServers) {
                    Log.i(TAG, "DNS servers changed: ${lastNetworkDnsServers} → $newDnsServers")
                    debouncedReconnect("DNS server change")
                }
                lastNetworkAddresses = newAddresses
                lastNetworkDnsServers = newDnsServers
            }

            private fun updateTrackedAddresses(network: Network) {
                try {
                    val linkProps = connectivityManager?.getLinkProperties(network)
                    lastNetworkAddresses = linkProps?.linkAddresses
                        ?.mapNotNull { it.address?.hostAddress }
                        ?.toSet() ?: emptySet()
                    lastNetworkDnsServers = linkProps?.dnsServers
                        ?.mapNotNull { it.hostAddress }
                        ?.toSet() ?: emptySet()
                    Log.d(TAG, "Updated tracked addresses: $lastNetworkAddresses, dns: $lastNetworkDnsServers")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get link properties", e)
                }
            }
        }

        try {
            connectivityManager?.registerNetworkCallback(request, networkCallback!!)
            Log.d(TAG, "Network callback registered")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register network callback", e)
        }
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let { callback ->
            try {
                connectivityManager?.unregisterNetworkCallback(callback)
                Log.d(TAG, "Network callback unregistered")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to unregister network callback", e)
            }
        }
        networkCallback = null
    }

    /**
     * Debounced reconnection to avoid thrashing on rapid network changes.
     * Waits 2s before triggering reconnection in case more changes come in.
     */
    private fun debouncedReconnect(reason: String) {
        // A reconnect supersedes any pending "network lost" disconnect
        networkLostJob?.cancel()
        networkLostJob = null
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = serviceScope.launch {
            Log.d(TAG, "Debouncing reconnect for: $reason")
            delay(2000) // Wait 2s for network to stabilize
            handleNetworkChange(reason)
        }
    }

    /**
     * Handle network change by restarting the tunnel connection.
     * Keeps HevSocks5Tunnel (tun2socks) running during the proxy restart to minimize
     * the traffic gap. The TUN interface stays alive and tun2socks buffers/retries
     * connections until the new proxy is ready.
     */
    private fun handleNetworkChange(reason: String = "unknown") {
        serviceScope.launch {
            // Ignore spurious network changes fired shortly after connection.
            // Chinese OEM ROMs (MIUI/HyperOS, EMUI) trigger network callbacks
            // when the VPN interface is first created, causing the proxy to be
            // torn down before any data flows. Skip unless this is a tunnel
            // recovery (seamless reconnect), which must always proceed.
            if (!reason.startsWith("tunnel recovery") && connectionEstablishedAt > 0) {
                val elapsed = System.currentTimeMillis() - connectionEstablishedAt
                if (elapsed < NETWORK_CHANGE_GRACE_MS) {
                    Log.d(TAG, "Ignoring network change '$reason' — ${elapsed}ms after connection (grace period ${NETWORK_CHANGE_GRACE_MS}ms)")
                    return@launch
                }
            }

            // Prevent concurrent reconnection attempts
            if (isReconnecting) {
                Log.d(TAG, "Skipping reconnection for '$reason' - already reconnecting")
                return@launch
            }
            isReconnecting = true

            try {
                Log.i(TAG, "Handling network change ($reason) - restarting connection")

                // Update underlying networks immediately for the new network
                updateUnderlyingNetworks()

                // Stop health check during reconnection
                healthCheckJob?.cancel()

                // Get the current profile
                val profile = connectionManager.getProfileById(currentProfileId)
                if (profile == null) {
                    Log.e(TAG, "Cannot reconnect: profile not found")
                    return@launch
                }

                // Save chain state before stopCurrentProxy clears it
                val savedChainId = currentChainId
                val wasChain = activeChainLayers.isNotEmpty()

                // Stop proxy on IO but keep HevSocks5Tunnel (tun2socks) running.
                // The TUN interface stays alive and tun2socks will retry connections
                // once the new proxy is ready, minimizing the traffic interruption gap.
                withContext(Dispatchers.IO) {
                    stopCurrentProxy()
                }

                // For DNSTT-based tunnels, explicitly wait for the Go runtime to
                // fully release the port.  stopCurrentProxy() already waits inside
                // DnsttBridge.stopClient(), but we add an extra coroutine-friendly
                // check here to be safe — this avoids spawning a second DNSTT
                // instance on a fallback port (which caused massive upload leaks).
                DnsttBridge.stopClientBlocking()  // no-op if already stopped, but ensures port is released

                val proxyPort = preferencesDataStore.proxyListenPort.first()
                val proxyHost = preferencesDataStore.proxyListenAddress.first()
                var remoteDns = preferencesDataStore.getEffectiveRemoteDns().first()
                var remoteDnsFallback = preferencesDataStore.getEffectiveRemoteDnsFallback().first()

                // Restart the tunnel + bridge on their ports
                val dnsttPort = proxyPort + 1

                val dnsttResult = vpnRepository.startDnsttProxy(profile, portOverride = dnsttPort, hostOverride = "127.0.0.1")
                if (dnsttResult.isFailure) {
                    Log.e(TAG, "Failed to restart tunnel after network change", dnsttResult.exceptionOrNull())
                    handleTunnelFailure("failed to reconnect after network change")
                    return@launch
                }

                val actualDnsttPort = DnsttBridge.getClientPort()

                if (!waitForProxyReady(actualDnsttPort, maxAttempts = 20, delayMs = 50)) {
                    Log.e(TAG, "Tunnel engine failed to restart on port $actualDnsttPort")
                    handleTunnelFailure("failed to reconnect after network change")
                    return@launch
                }

                DnsttSocksBridge.authoritativeMode = profile.dnsttAuthoritative
                DnsttSocksBridge.proxyOnlyMode = isProxyOnly
                DnsttSocksBridge.dnsWorkerPoolSize = preferencesDataStore.dnsWorkerMode.first().poolSize
                val bridgeResult = vpnRepository.startDnsttSocksBridge(
                    dnsttPort = actualDnsttPort,
                    dnsttHost = "127.0.0.1",
                    bridgePort = proxyPort,
                    bridgeHost = proxyHost,
                    socksUsername = profile.socksUsername,
                    socksPassword = profile.socksPassword,
                    dnsServer = remoteDns,
                    dnsFallback = remoteDnsFallback
                )
                if (bridgeResult.isFailure) {
                    Log.e(TAG, "Failed to restart bridge after network change")
                    handleTunnelFailure("failed to reconnect after network change")
                    return@launch
                }

                if (!waitForProxyReady(proxyPort, maxAttempts = 20, delayMs = 50)) {
                    Log.e(TAG, "Bridge failed to restart on port $proxyPort")
                    handleTunnelFailure("failed to reconnect after network change")
                    return@launch
                }

                // Wait for tunnel to be re-established
                // Give the tunnel a moment to re-establish
                delay(500)

                // Restart HTTP proxy if it was running before (stopped by stopCurrentProxy)
                if (!HttpProxyServer.isRunning()) {
                    val appendProxy = preferencesDataStore.appendHttpProxyToVpn.first()
                    val httpEnabled = preferencesDataStore.httpProxyEnabled.first()
                    if (appendProxy || httpEnabled) {
                        val httpPort = preferencesDataStore.httpProxyPort.first()
                        val socksPort = preferencesDataStore.proxyListenPort.first()
                        // Use proxyListenAddress when HTTP proxy (LAN sharing) is enabled so other
                        // devices can reach it. Use 127.0.0.1 only when appendProxy is the sole
                        // reason (local VPN use only, no LAN sharing needed).
                        val listenHost = if (httpEnabled) preferencesDataStore.proxyListenAddress.first() else "127.0.0.1"
                        val authUser = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } else null
                        val authPass = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } else null
                        val result = HttpProxyServer.start(
                            socksHost = "127.0.0.1",
                            socksPort = socksPort,
                            listenHost = listenHost,
                            listenPort = httpPort,
                            socksAuthUsername = authUser,
                            socksAuthPassword = authPass
                        )
                        if (result.isFailure) {
                            Log.w(TAG, "HTTP proxy failed to restart after reconnect: ${result.exceptionOrNull()?.message}")
                        } else {
                            Log.i(TAG, "HTTP proxy restarted on $listenHost:$httpPort after reconnect")
                        }
                    }
                }

                // Restart health check
                startHealthCheck()

                // Refresh underlying networks after successful reconnection
                updateUnderlyingNetworks()

                // Clear kill switch state and restore connected notification
                if (isKillSwitchActive) {
                    isKillSwitchActive = false
                    val state = vpnRepository.connectionState.first()
                    val notification = notificationHelper.createVpnNotification(state, isProxyOnly)
                    val notificationManager = getSystemService(NotificationManager::class.java)
                    notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)
                }

                Log.i(TAG, "Successfully reconnected after network change (tunnel type: $currentTunnelType)")
                resetZeroThroughputCounter = true
            } finally {
                isReconnecting = false
                vpnRepository.setAutoReconnect(false)
            }
        }
    }

    /**
     * Stop the currently running proxy based on tunnel type.
     * Stops SSH first if enabled, then the DNS tunnel.
     * Synchronized to prevent double-stop from onDestroy + coroutine cleanup.
     */
    @Synchronized
    private fun stopCurrentProxy() {
        // Always stop HTTP proxy (it chains through whatever SOCKS5 proxy is running)
        HttpProxyServer.stop()

        Log.d(TAG, "Stopping tunnel engine and bridge")
        DnsttSocksBridge.onDnsPoolDead = null
        DnsttSocksBridge.stop()
        DnsttBridge.stopClient()
    }

    /**
     * Clear VPN service reference from the current bridge.
     */
    private fun clearVpnServiceRef() {
        DnsttBridge.setVpnService(null)
    }

    /**
     * Check if the current proxy is healthy.
     * When SSH is enabled, also checks SSH tunnel health.
     */
    private fun isCurrentProxyHealthy(): Boolean {
        // If HTTP proxy is running, it must also be healthy
        if (HttpProxyServer.isRunning() && !HttpProxyServer.isHealthy()) {
            return false
        }

        return DnsttBridge.isClientHealthy() && DnsttSocksBridge.isClientHealthy()
    }


    /**
     * Resolve a resolver host to a numeric IP for [Builder.addDnsServer].
     * Falls back to [DEFAULT_DNS] if resolution fails or host is null.
     */
    private suspend fun resolveToIp(host: String?, customDnsServer: String? = null): String = withContext(Dispatchers.IO) {
        if (host.isNullOrBlank()) return@withContext DEFAULT_DNS
        val resolved = VpnRepositoryImpl.resolveHost(host, customDnsServer)
        if (DomainRouter.isIpAddress(resolved)) resolved else DEFAULT_DNS
    }

    private suspend fun establishVpnInterface(dnsServer: String): ParcelFileDescriptor? {
        val mtu = try { preferencesDataStore.vpnMtu.first() } catch (_: Exception) { VPN_MTU }
        val builder = Builder()
            .setSession("SlipNet VPN")
            .setMtu(mtu)
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(dnsServer)
            .setBlocking(false)

        builder.addRoute(VPN_ROUTE, 0)


        // The engine's resolver queries must never be captured by our own TUN.
        val needsSelfExclusion = true

        val splitEnabled = preferencesDataStore.splitTunnelingEnabled.first()
        val splitMode = preferencesDataStore.splitTunnelingMode.first()
        val splitApps = preferencesDataStore.splitTunnelingApps.first()

        if (splitEnabled && splitApps.isNotEmpty()) {
            when (splitMode) {
                SplitTunnelingMode.DISALLOW -> {
                    // Selected apps bypass VPN. Always include self if tunnel type needs it.
                    if (needsSelfExclusion) {
                        try {
                            builder.addDisallowedApplication(packageName)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to exclude self from VPN", e)
                        }
                    }
                    for (pkg in splitApps) {
                        if (pkg == packageName) continue // already handled above
                        try {
                            builder.addDisallowedApplication(pkg)
                        } catch (_: Exception) { }
                    }
                    Log.d(TAG, "Split tunneling: disallow mode, ${splitApps.size} apps bypass VPN")
                }
                SplitTunnelingMode.ALLOW -> {
                    // Only selected apps use VPN. Self is automatically excluded
                    // (not in the allowed list) — which is what tunnel types need.
                    for (pkg in splitApps) {
                        if (pkg == packageName) continue // don't route our own traffic through VPN
                        try {
                            builder.addAllowedApplication(pkg)
                        } catch (_: Exception) { }
                    }
                    Log.d(TAG, "Split tunneling: allow mode, ${splitApps.size} apps use VPN")
                }
            }
        } else {
            // Original behavior: exclude self for tunnel types that need it
            if (needsSelfExclusion) {
                try {
                    builder.addDisallowedApplication(packageName)
                    Log.d(TAG, "Excluded app from VPN: $packageName")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to exclude app from VPN", e)
                }
            }
        }

        // Append HTTP proxy to VPN so apps route HTTP/HTTPS through it directly,
        // bypassing TUN/tun2socks overhead. Requires API 29+.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val appendProxy = preferencesDataStore.appendHttpProxyToVpn.first()
            if (appendProxy) {
                val httpPort = preferencesDataStore.httpProxyPort.first()
                val socksPort = preferencesDataStore.proxyListenPort.first()

                // Start HTTP proxy now (before VPN) so it's ready when apps connect.
                // If "HTTP proxy" (LAN sharing) is also enabled, bind to proxyListenAddress
                // (e.g. 0.0.0.0) so other devices can reach it. setHttpProxy still uses
                // 127.0.0.1 which is reachable on a 0.0.0.0-bound socket.
                // If only appendProxy is active (no LAN sharing), 127.0.0.1 is sufficient.
                if (!HttpProxyServer.isRunning()) {
                    val httpEnabled = preferencesDataStore.httpProxyEnabled.first()
                    val httpListenHost = if (httpEnabled) preferencesDataStore.proxyListenAddress.first() else "127.0.0.1"
                    val authUser = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthUsername.first().ifEmpty { null } else null
                    val authPass = if (preferencesDataStore.proxyAuthEnabled.first()) preferencesDataStore.proxyAuthPassword.first().ifEmpty { null } else null
                    val result = HttpProxyServer.start(
                        socksHost = "127.0.0.1",
                        socksPort = socksPort,
                        listenHost = httpListenHost,
                        listenPort = httpPort,
                        socksAuthUsername = authUser,
                        socksAuthPassword = authPass
                    )
                    if (result.isFailure) {
                        Log.w(TAG, "HTTP proxy failed to start for VPN append: ${result.exceptionOrNull()?.message}")
                    }
                }

                if (HttpProxyServer.isRunning()) {
                    builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", httpPort))
                    Log.i(TAG, "HTTP proxy appended to VPN on 127.0.0.1:$httpPort")
                }
            }
        }

        return builder.establish()
    }

    private fun observeConnectionState() {
        stateObserverJob?.cancel()
        stateObserverJob = serviceScope.launch {
            vpnRepository.connectionState.collect { state ->
                val notification = notificationHelper.createVpnNotification(state, isProxyOnly)
                val notificationManager = getSystemService(NotificationManager::class.java)
                notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)

                when (state) {
                    is ConnectionState.Connected -> {
                        startTrafficNotificationPolling()
                    }
                    is ConnectionState.Error -> {
                        stopTrafficNotificationPolling()
                        // Don't stop service during kill switch — we're blocking traffic and reconnecting
                        if (isKillSwitchActive) return@collect
                        // Already handling reconnection — don't interfere
                        if (isAutoReconnecting || isReconnecting) return@collect

                        // If connection was previously successful, route through
                        // handleTunnelFailure so auto-reconnect / kill-switch can trigger.
                        if (connectionWasSuccessful && !isUserInitiatedDisconnect) {
                            handleTunnelFailure("connection error: ${state.message}")
                            return@collect
                        }

                        // Startup failure — show reconnect notification and stop
                        if (currentProfileId != -1L) {
                            val reconnectNotification = notificationHelper.createReconnectNotification(
                                message = state.message,
                                profileId = currentProfileId
                            )
                            notificationManager.notify(NotificationHelper.RECONNECT_NOTIFICATION_ID, reconnectNotification)
                        }
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                    // Disconnected is handled by the disconnect() coroutine which already
                    // calls stopForeground/stopSelf. Do NOT call stopSelf() here — if the
                    // user reconnects quickly on the same service instance, this observer
                    // may still be processing the old Disconnected state and would kill
                    // the new connection.
                    else -> {
                        stopTrafficNotificationPolling()
                    }
                }
            }
        }
    }

    private fun startTrafficNotificationPolling() {
        trafficNotificationJob?.cancel()
        vpnRepository.resetSpeedTracking()
        trafficNotificationJob = serviceScope.launch {
            val showTrafficInNotification = preferencesDataStore.showNotificationTraffic.first()
            var idleCount = 0
            var zeroThroughputSeconds = 0L
            var tunnelHealthWarningShown = false
            while (isActive) {
                // Adaptive interval: 1s when active, 5s when idle, 10s when screen off.
                val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                val screenOn = pm.isInteractive
                val interval = when {
                    !screenOn -> 10_000L
                    idleCount >= 3 -> 5_000L // 3+ consecutive idle ticks → slow down
                    else -> 1_000L
                }
                delay(interval)

                vpnRepository.refreshTrafficStats()
                val current = vpnRepository.trafficStats.value
                val upSpeed = current.uploadSpeed
                val downSpeed = current.downloadSpeed

                // Track idle: no bytes transferred in this tick.
                if (upSpeed == 0L && downSpeed == 0L) {
                    idleCount++
                } else {
                    idleCount = 0
                }

                // After a reconnect, bridge byte counters are reset to 0.
                // Reset the watchdog so an idle phone doesn't get disconnected.
                if (resetZeroThroughputCounter) {
                    resetZeroThroughputCounter = false
                    zeroThroughputSeconds = 0L
                    tunnelHealthWarningShown = false
                    connectionManager.setDnsWarning(null)
                    vpnRepository.resetSpeedTracking()
                }

                // Tunnel health: warn if zero cumulative throughput for too long.
                // This detects broken tunnels that show "Connected" but relay no data
                // (e.g. overloaded servers, wrong auth) while DNS overhead drains SIM data.
                // Skip in proxy-only mode: no TUN = no DNS overhead, and apps may be idle.
                // Skip for DoH: only DNS is routed through VPN (/32 route), so idle
                // periods with zero tun2socks traffic are normal (especially on TV).
                if (!isProxyOnly && current.totalBytes == 0L) {
                    zeroThroughputSeconds += interval / 1000
                    if (!tunnelHealthWarningShown && zeroThroughputSeconds >= ZERO_THROUGHPUT_WARNING_SECONDS) {
                        tunnelHealthWarningShown = true
                        connectionManager.setDnsWarning("No data flowing — server may be unreachable or overloaded")
                    }
                    if (zeroThroughputSeconds >= ZERO_THROUGHPUT_DISCONNECT_SECONDS) {
                        Log.w(TAG, "Zero throughput for ${zeroThroughputSeconds}s — disconnecting")
                        connectionManager.onVpnError("Disconnected — no data received from server")
                        disconnect()
                        return@launch
                    }
                } else if (tunnelHealthWarningShown) {
                    // Data started flowing — clear the warning
                    tunnelHealthWarningShown = false
                    zeroThroughputSeconds = 0L
                    connectionManager.setDnsWarning(null)
                }

                // Skip notification updates while screen is off — nobody can see them,
                // and they waste IPC / cause MIUI reordering issues.
                // Health checks above still run regardless.
                if (screenOn) {
                    val state = vpnRepository.connectionState.first()
                    if (state is ConnectionState.Connected) {
                        // Only update notification when displayed values change.
                        // Redundant updates cause notification reordering on MIUI/HyperOS.
                        val newTotal = current.totalBytes
                        val newSpeed = upSpeed + downSpeed
                        if (showTrafficInNotification && (newTotal != lastNotifTotalBytes || (newSpeed > 0) != (lastNotifHadSpeed))) {
                            lastNotifTotalBytes = newTotal
                            lastNotifHadSpeed = newSpeed > 0
                            val notification = notificationHelper.createVpnNotification(
                                state = state,
                                isProxyOnly = isProxyOnly,
                                trafficStats = if (showTrafficInNotification) current else null,
                                uploadSpeed = if (showTrafficInNotification) upSpeed else 0,
                                downloadSpeed = if (showTrafficInNotification) downSpeed else 0
                            )
                            val notificationManager = getSystemService(NotificationManager::class.java)
                            notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)
                        }
                    }
                } else {
                    // Force refresh on next screen-on by invalidating cached state
                    lastNotifTotalBytes = -1L
                }
            }
        }
    }

    private fun stopTrafficNotificationPolling() {
        trafficNotificationJob?.cancel()
        trafficNotificationJob = null
        vpnRepository.resetSpeedTracking()
        lastNotifTotalBytes = -1L
        lastNotifHadSpeed = false
    }

    private fun disconnect() {
        // Mark as user-initiated so onDestroy() doesn't show disconnect notification
        isUserInitiatedDisconnect = true

        // Stop traffic stats polling
        stopTrafficNotificationPolling()

        // Clear kill switch so teardown proceeds normally
        isKillSwitchActive = false

        // Cancel auto-reconnect
        autoReconnectJob?.cancel()
        autoReconnectJob = null
        isAutoReconnecting = false
        autoReconnectAttempt = 0
        connectionWasSuccessful = false
        vpnRepository.setAutoReconnect(false)

        // Cancel boot retry
        bootRetryJob?.cancel()
        bootRetryJob = null
        isBootTriggered = false
        bootRetryAttempt = 0
        unregisterBootNetworkCallback()

        // Cancel any in-progress DNS pool scan so it stops immediately
        // instead of running each probe to its 8 s timeout.
        vpnRepository.cancelPoolScan()

        // Cancel any in-progress connection attempt
        connectJob?.cancel()
        connectJob = null

        // Cancel any in-progress reconnection immediately — before the coroutine.
        // This prevents a race where the reconnect coroutine is mid-flight in native
        // code (e.g., starting Slipstream on port 1081) while disconnect also tries
        // to stop/start, leading to "port already in use" on the next connect.
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
        networkLostJob?.cancel()
        networkLostJob = null
        isReconnecting = false
        resetZeroThroughputCounter = false

        // Cancel state observer to prevent stale stopSelf() calls
        stateObserverJob?.cancel()
        stateObserverJob = null

        // Reset accumulated traffic stats so next connection starts fresh
        DnsttSocksBridge.resetTrafficStats()

        disconnectJob = serviceScope.launch {
            Log.i(TAG, "Disconnecting VPN")
            // Clear saved state so we don't auto-reconnect on restart
            clearConnectionState()
            cleanupConnection()
            connectionManager.onVpnDisconnected()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    /**
     * Handle tunnel failure with seamless reconnect, kill switch, and auto-reconnect support.
     *
     * First tries a lightweight "seamless reconnect": restarts only the proxy while keeping
     * the TUN interface and tun2socks alive. This handles transient failures such as QUIC
     * idle timeouts on devices where the OS throttles background network (e.g. Chinese OEM
     * phones like Honor/Huawei), causing keepalive pings to fail and the transport connection
     * to drop. Seamless reconnect minimizes the traffic gap — tun2socks buffers/retries
     * connections until the new proxy is ready.
     *
     * If seamless reconnect is not possible (tun2socks crashed) or has been exhausted
     * (MAX_SEAMLESS_RECONNECTS attempts), escalates to kill switch or auto-reconnect.
     */
    private suspend fun handleTunnelFailure(reason: String) {
        // Try seamless proxy restart first if tun2socks is still alive.
        // Skip if: tun2socks is dead, already in kill-switch/auto-reconnect,
        // or we've exhausted seamless attempts (prevents infinite loop).
        val tunnelAlive = if (isProxyOnly) true else HevSocks5Tunnel.isRunning()
        val maxSeamless = MAX_SEAMLESS_RECONNECTS_DNSTT
        if (tunnelAlive && seamlessReconnectAttempts < maxSeamless
            && !isKillSwitchActive && !isAutoReconnecting) {
            seamlessReconnectAttempts++
            // Wait before retrying so the network has time to recover.
            // Without this delay, back-to-back attempts on a flaky network
            // burn through the budget instantly and escalate to full disconnect.
            val delayIdx = (seamlessReconnectAttempts - 1).coerceAtMost(SEAMLESS_RECONNECT_DELAYS_MS.size - 1)
            val delayMs = SEAMLESS_RECONNECT_DELAYS_MS[delayIdx]
            Log.i(TAG, "Attempting seamless reconnect ($seamlessReconnectAttempts/$maxSeamless) in ${delayMs}ms: $reason")
            delay(delayMs)
            // Skip the DNS pool scan during seamless reconnect — the resolvers
            // are already validated and saved from the initial connect.
            vpnRepository.setAutoReconnect(true)
            handleNetworkChange("tunnel recovery: $reason")
            return
        }

        // Seamless reconnect exhausted or not possible — reset counter and escalate.
        Log.i(TAG, "Escalating tunnel failure (seamless attempts=$seamlessReconnectAttempts): $reason")
        seamlessReconnectAttempts = 0

        val killSwitchEnabled = preferencesDataStore.killSwitch.first()
        if (killSwitchEnabled && !isProxyOnly && vpnInterface != null) {
            enterKillSwitchMode(reason)
        } else {
            val autoReconnectEnabled = preferencesDataStore.autoReconnect.first()
            if (autoReconnectEnabled && connectionWasSuccessful && !isUserInitiatedDisconnect
                && autoReconnectAttempt < AUTO_RECONNECT_MAX_RETRIES) {
                enterAutoReconnectMode(reason)
            } else {
                connectionManager.onVpnError("VPN connection lost - $reason")
                cleanupConnection()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    /**
     * Enter kill switch mode: keep VPN interface alive (blocking all traffic),
     * stop proxy/tunnel, show kill switch notification, and attempt reconnection.
     */
    private suspend fun enterKillSwitchMode(reason: String) {
        Log.i(TAG, "Kill switch activated: $reason")
        isKillSwitchActive = true

        // Stop health check during kill switch
        healthCheckJob?.cancel()
        healthCheckJob = null

        // Stop proxy/tunnel but NOT vpnInterface — TUN stays alive to block traffic
        withContext(Dispatchers.IO) {
            if (!isProxyOnly) {
                try { HevSocks5Tunnel.stop() } catch (_: Exception) {}
            }
            try { stopCurrentProxy() } catch (_: Exception) {}
        }

        // Update foreground notification to kill switch notification
        val profile = connectionManager.getProfileById(currentProfileId)
        val profileName = profile?.name ?: "VPN"
        val notification = notificationHelper.createKillSwitchNotification(profileName)
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)

        // Attempt reconnection after a brief delay
        serviceScope.launch {
            delay(2000)
            if (isKillSwitchActive) {
                handleNetworkChange("kill switch reconnect")
            }
        }
    }

    /**
     * Enter auto-reconnect mode: tear down VPN (traffic flows directly during retry),
     * show reconnecting notification, and attempt reconnection with exponential backoff.
     */
    private suspend fun enterAutoReconnectMode(reason: String) {
        autoReconnectAttempt++
        isAutoReconnecting = true
        Log.i(TAG, "Auto-reconnect attempt $autoReconnectAttempt/$AUTO_RECONNECT_MAX_RETRIES: $reason")

        // Capture profile info BEFORE cleanup resets currentProfileId
        val profileId = currentProfileId
        val profileName = currentProfileName

        // Tear down the connection (VPN goes down, traffic flows directly)
        cleanupConnection()

        // Show auto-reconnect foreground notification to keep service alive
        val notification = notificationHelper.createAutoReconnectNotification(
            profileName, autoReconnectAttempt, AUTO_RECONNECT_MAX_RETRIES
        )
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)

        // Schedule reconnect with exponential backoff
        val delayMs = AUTO_RECONNECT_DELAYS_MS[
            (autoReconnectAttempt - 1).coerceAtMost(AUTO_RECONNECT_DELAYS_MS.size - 1)
        ]
        autoReconnectJob = serviceScope.launch {
            Log.d(TAG, "Auto-reconnect: waiting ${delayMs}ms before attempt $autoReconnectAttempt")
            delay(delayMs)
            if (isUserInitiatedDisconnect) {
                Log.i(TAG, "Auto-reconnect cancelled: user-initiated disconnect")
                return@launch
            }
            isAutoReconnecting = false
            // Tell the repo this is an auto-reconnect so the DNS-pool feature
            // reuses the resolvers already on the profile instead of running
            // a fresh E2E scan on every network blip.
            vpnRepository.setAutoReconnect(true)
            connect(profileId)
        }
    }

    /**
     * Boot-triggered retry: wait for network with exponential backoff.
     * Also registers a one-shot network callback for instant retry when network arrives.
     *
     * @param needsCleanup true on first entry (failed connect), false on subsequent timer retries
     */
    private suspend fun enterBootRetryMode(profileId: Long, reason: String, needsCleanup: Boolean = true) {
        bootRetryAttempt++

        if (bootRetryAttempt > BOOT_RETRY_MAX_ATTEMPTS) {
            Log.w(TAG, "Boot retry exhausted ($BOOT_RETRY_MAX_ATTEMPTS attempts): $reason")
            isBootTriggered = false
            unregisterBootNetworkCallback()
            connectionManager.onVpnError("Auto-connect failed \u2014 no network after boot")
            if (needsCleanup) cleanupConnection()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val delayMs = (BOOT_RETRY_INITIAL_DELAY_MS shl (bootRetryAttempt - 1).coerceAtMost(14))
            .coerceAtMost(BOOT_RETRY_MAX_DELAY_MS)

        Log.i(TAG, "Boot retry attempt $bootRetryAttempt/$BOOT_RETRY_MAX_ATTEMPTS (delay ${delayMs}ms): $reason")

        val profileName = currentProfileName

        // Only clean up on first entry (after a failed connect attempt).
        // Subsequent timer-driven retries have nothing to clean up.
        if (needsCleanup) {
            cleanupConnection()
        }

        val notification = notificationHelper.createBootRetryNotification(
            profileName, bootRetryAttempt, BOOT_RETRY_MAX_ATTEMPTS
        )
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NotificationHelper.VPN_NOTIFICATION_ID, notification)

        // Register a one-shot network callback to connect immediately when network arrives.
        // Supplements the timer — whichever fires first wins.
        if (bootNetworkCallback == null) {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()

            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    Log.i(TAG, "Boot retry: network became available, triggering immediate connect")
                    bootRetryJob?.cancel()
                    unregisterBootNetworkCallback()
                    serviceScope.launch {
                        if (!isUserInitiatedDisconnect) {
                            connect(profileId)
                        }
                    }
                }
            }
            try {
                connectivityManager?.registerNetworkCallback(request, callback)
                bootNetworkCallback = callback
                Log.d(TAG, "Boot retry network callback registered")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to register boot retry network callback", e)
            }
        }

        bootRetryJob = serviceScope.launch {
            delay(delayMs)

            if (isUserInitiatedDisconnect) {
                Log.i(TAG, "Boot retry cancelled: user-initiated disconnect")
                unregisterBootNetworkCallback()
                return@launch
            }

            // Check if network is now available before attempting connection
            val cm = connectivityManager
            val capabilities = cm?.activeNetwork?.let { cm.getNetworkCapabilities(it) }
            val hasInternet = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true

            if (hasInternet) {
                Log.i(TAG, "Network available after boot retry delay, attempting connection")
                unregisterBootNetworkCallback()
                connect(profileId)
            } else {
                Log.i(TAG, "Network still unavailable, scheduling next boot retry")
                enterBootRetryMode(profileId, "network still unavailable", needsCleanup = false)
            }
        }
    }

    private fun unregisterBootNetworkCallback() {
        bootNetworkCallback?.let { callback ->
            try {
                connectivityManager?.unregisterNetworkCallback(callback)
                Log.d(TAG, "Boot retry network callback unregistered")
            } catch (_: Exception) {}
        }
        bootNetworkCallback = null
    }

    /** Release WakeLock and WifiLock if held. */
    private fun releaseLocks() {
        wakeLockRenewJob?.cancel()
        wakeLockRenewJob = null
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
                Log.d(TAG, "WakeLock released")
            }
        }
        wakeLock = null
        wifiLock?.let {
            if (it.isHeld) {
                it.release()
                Log.d(TAG, "WifiLock released")
            }
        }
        wifiLock = null
    }

    /** Periodically re-acquires the WakeLock before it expires. */
    private fun startWakeLockRenewal() {
        wakeLockRenewJob?.cancel()
        wakeLockRenewJob = serviceScope.launch(Dispatchers.IO) {
            while (isActive) {
                kotlinx.coroutines.delay(WAKELOCK_RENEW_INTERVAL_MS)
                wakeLock?.let {
                    if (it.isHeld) {
                        it.acquire(WAKELOCK_TIMEOUT_MS)
                        Log.d(TAG, "WakeLock renewed")
                    }
                }
            }
        }
    }

    /** Chinese OEM ROMs aggressively kill apps using high-power WifiLock modes. */
    private fun isChineseOem(): Boolean {
        val manufacturer = Build.MANUFACTURER.lowercase()
        return manufacturer in listOf(
            "xiaomi", "redmi", "poco", "huawei", "honor",
            "oppo", "vivo", "realme", "oneplus", "meizu", "zte", "lenovo"
        )
    }

    /**
     * Clean up all resources - must be called before stopping service.
     * This is a suspend function to run blocking operations on IO dispatcher.
     */
    private suspend fun cleanupConnection() {
        app.slipnet.util.AppLog.redactSensitive = false
        Log.d(TAG, "Cleaning up connection resources")

        releaseLocks()

        // Stop health monitoring
        healthCheckJob?.cancel()
        healthCheckJob = null

        // Cancel any pending reconnect / network-loss timer
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
        networkLostJob?.cancel()
        networkLostJob = null
        isReconnecting = false

        // Unregister network callback and Doze receiver
        unregisterNetworkCallback()
        unregisterBootNetworkCallback()
        unregisterDozeReceiver()
        lastNetworkAddresses = emptySet()
        lastNetworkDnsServers = emptySet()

        // Stop native tunnels on IO thread to avoid ANR.
        // Timeout after 8s — if a bridge hangs, don't block the entire disconnect.
        try {
            withTimeout(8000) {
                withContext(Dispatchers.IO) {
                    if (!isProxyOnly) {
                        try {
                            HevSocks5Tunnel.stop()
                        } catch (e: Exception) {
                            Log.e(TAG, "Error stopping HevSocks5Tunnel", e)
                        }
                    }

                    try {
                        stopCurrentProxy()
                    } catch (e: Exception) {
                        Log.e(TAG, "Error stopping proxy", e)
                    }
                }
            }
        } catch (_: kotlinx.coroutines.TimeoutCancellationException) {
            Log.w(TAG, "Cleanup timed out after 8s — bridge may be stuck, proceeding with disconnect")
        }

        // Clear VPN service reference AFTER native code has stopped (or timed out).
        // Must come after stopCurrentProxy() to avoid crashing native protectSocket() calls.
        clearVpnServiceRef()

        // Close VPN interface
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        currentProfileId = -1
    }

    override fun onRevoke() {
        super.onRevoke()
        Log.i(TAG, "VPN permission revoked (another VPN took over)")
        // Do NOT mark as user-initiated — onRevoke means another VPN took over,
        // so onDestroy() should show the disconnect notification.
        // We still need to clean up, but skip setting isUserInitiatedDisconnect.
        isKillSwitchActive = false
        // Cancel auto-reconnect — another VPN took over, don't fight it
        autoReconnectJob?.cancel()
        autoReconnectJob = null
        isAutoReconnecting = false
        autoReconnectAttempt = 0
        connectionWasSuccessful = false
        vpnRepository.setAutoReconnect(false)
        vpnRepository.cancelPoolScan()
        connectJob?.cancel()
        connectJob = null
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
        networkLostJob?.cancel()
        networkLostJob = null
        isReconnecting = false
        stateObserverJob?.cancel()
        stateObserverJob = null
        disconnectJob = serviceScope.launch {
            Log.i(TAG, "Disconnecting VPN (revoked)")
            clearConnectionState()
            cleanupConnection()
            connectionManager.onVpnDisconnected()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.i(TAG, "Task removed (app swiped from recents)")

        // If VPN is active, save state and re-deliver start intent to keep running
        if (currentProfileId != -1L) {
            saveConnectionState(currentProfileId, true)
            val restartIntent = Intent(this, SlipNetVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_PROFILE_ID, currentProfileId)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(restartIntent)
            } else {
                startService(restartIntent)
            }
            Log.i(TAG, "Re-delivered start intent for profile $currentProfileId")
        }
    }

    override fun onDestroy() {
        Log.i(TAG, "Service onDestroy")

        // Capture state before cleanup resets currentProfileId to -1
        val wasActive = currentProfileId != -1L
        val profileName = currentProfileName
        val profileId = currentProfileId

        // Quick non-blocking cleanup for onDestroy
        // Don't wait for native threads - they'll clean up themselves
        cleanupConnectionSync()

        // Ensure connection state is always reset when the service dies.
        // This is critical for onRevoke() (another VPN app takes over):
        // disconnect() runs cleanup in a coroutine on serviceScope, but onDestroy()
        // cancels serviceScope before the coroutine reaches onVpnDisconnected().
        // Without this, the UI would still show "Connected" after another VPN connects.
        clearConnectionState()
        connectionManager.onVpnDisconnected()

        // Show disconnect notification if the connection was active and not user-initiated.
        // Skip if kill switch is active (it has its own notification) or if reconnecting
        // (the reconnect/kill-switch flow handles notifications).
        if (wasActive && !isUserInitiatedDisconnect && !isKillSwitchActive && !isReconnecting && !isAutoReconnecting) {
            Log.i(TAG, "Unexpected disconnect detected, showing notification")
            val notification = notificationHelper.createDisconnectedNotification(profileName, profileId)
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.notify(NotificationHelper.DISCONNECT_NOTIFICATION_ID, notification)
        }

        serviceScope.cancel()
        super.onDestroy()
    }

    /**
     * Synchronous cleanup that doesn't wait for native threads.
     * Used in onDestroy where we can't suspend.
     */
    private fun cleanupConnectionSync() {
        app.slipnet.util.AppLog.redactSensitive = false
        Log.d(TAG, "Quick cleanup (sync)")

        releaseLocks()

        // Stop health monitoring
        healthCheckJob?.cancel()
        healthCheckJob = null

        // Cancel auto-reconnect
        autoReconnectJob?.cancel()
        autoReconnectJob = null
        isAutoReconnecting = false
        vpnRepository.setAutoReconnect(false)

        // Cancel any in-progress DNS pool scan
        vpnRepository.cancelPoolScan()

        // Cancel any pending reconnect / network-loss timer
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = null
        networkLostJob?.cancel()
        networkLostJob = null
        isReconnecting = false

        // Unregister network callback and Doze receiver
        unregisterNetworkCallback()
        unregisterDozeReceiver()
        lastNetworkAddresses = emptySet()
        lastNetworkDnsServers = emptySet()

        // Stop HTTP proxy
        try {
            HttpProxyServer.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping HTTP proxy", e)
        }

        // Request native tunnels to stop (non-blocking)
        // The native code will handle the actual shutdown
        if (!isProxyOnly) {
            try {
                HevSocks5Tunnel.stop()
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping HevSocks5Tunnel", e)
            }
        }

        try {
            // Just send stop signal, don't wait
            stopCurrentProxy()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping proxy", e)
        }

        // Clear VPN service reference
        clearVpnServiceRef()

        // Close VPN interface
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        currentProfileId = -1
    }
}
