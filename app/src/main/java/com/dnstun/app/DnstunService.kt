package com.dnstun.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import hev.htproxy.TProxyService
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The tunnel, assembled the way shipping DNS-tunnel VPNs do it.
 *
 *   VpnService TUN fd
 *     -> libhev-socks5-tunnel  (C bridge: owns ALL tun/TCP/UDP work)
 *       -> SOCKS5 on 127.0.0.1:<socksPort>
 *         -> libdnstun.so      (our own stream engine: SOCKS5 -> DNS tunnel)
 *           -> DNS tunnel -> our dnstund server on the VPS -> internet
 *
 * No hand-rolled packet code: the bridge owns the TUN, we only supply a SOCKS5
 * upstream. Two details that matter:
 *  - TUN is non-blocking and we exclude ourselves with addDisallowedApplication,
 *    so the engine's own DNS queries ride the real network instead of looping
 *    back into our own VPN (this is why no protect() call is needed).
 *  - The engine ships as jniLibs/arm64-v8a/libdnstun.so because Android 10+
 *    forbids executing files from the app data dir; nativeLibraryDir is
 *    executable.
 */
class DnstunService : VpnService() {

    companion object {
        private const val TAG = "DNSTun"
        const val ACTION_START = "com.dnstun.app.START"
        const val ACTION_STOP = "com.dnstun.app.STOP"
        const val EXTRA_STATS = "stats"
        const val CHANNEL_ID = "dnstun"
        private const val NOTIF_ID = 1

        const val TUN_ADDR = "10.111.0.2"
        const val TUN_PREFIX = 32
        const val TUN_MTU = 1500
        const val TUN_DNS = "1.1.1.1"

        @Volatile var running = false
            private set

        @Volatile var lastStats: TunnelStats = TunnelStats()
            private set
    }

    private var pfd: ParcelFileDescriptor? = null
    @Volatile private var engine: Process? = null
    private val stopping = AtomicBoolean(false)
    private var statsThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForeground(NOTIF_ID, buildNotification(Config.load(this)))
                Thread { startTunnel() }.start()
            }
        }
        return START_STICKY
    }

    private fun startTunnel() {
        if (running) return
        val cfg = Config.load(this)
        Log.i(TAG, "start: resolver=${cfg.resolver}:${cfg.port} zone=${cfg.zone} sid=${cfg.sid} chunk=${cfg.maxChunk} depth=${cfg.startDepth}")

        // ---- 1. TUN ----------------------------------------------------------
        val builder = Builder()
            .setSession("DNSTun")
            .setMtu(TUN_MTU)
            .addAddress(TUN_ADDR, TUN_PREFIX)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(TUN_DNS)
        runCatching { builder.setBlocking(false) }
        runCatching { builder.addDisallowedApplication(packageName) }
        val fd = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "establish failed: ${e.message}")
            null
        }
        if (fd == null) {
            fail("VPN permission missing (establish returned null)")
            return
        }
        pfd = fd

        // ---- 2. engine binary ------------------------------------------------
        val enginePath = File(applicationInfo.nativeLibraryDir, "libdnstun.so").absolutePath
        if (!File(enginePath).exists()) {
            fail("engine missing: $enginePath")
            return
        }
        // ---- 3. start the engine --------------------------------------------
        // Our own engine. No pubkey: this protocol has no crypto on purpose
        // (speed only), and it authenticates by sid.
        val cmd = listOf(
            enginePath,
            "-resolver", "${cfg.resolver}:${cfg.port}",
            "-zone", cfg.zone,
            "-sid", cfg.sid,
            "-listen", "127.0.0.1:${cfg.socksPort}",
            "-chunk", cfg.maxChunk.toString(),
            "-depth", cfg.startDepth.toString(),
            "-edns", cfg.edns.toString(),
        )
        Log.i(TAG, "engine: ${cmd.joinToString(" ")}")
        val p = try {
            ProcessBuilder(cmd).redirectErrorStream(true).start()
        } catch (e: Exception) {
            fail("cannot start engine: ${e.message}")
            return
        }
        engine = p
        Thread {
            runCatching {
                p.inputStream.bufferedReader().forEachLine { Log.i(TAG, "engine: $it") }
            }
        }.start()

        // ---- 4. wait for the SOCKS5 listener --------------------------------
        var up = false
        for (i in 0 until 120) {
            if (stopping.get()) return
            if (portOpen(cfg.socksPort)) { up = true; break }
            if (!p.isAlive) break
            Thread.sleep(100)
        }
        if (!up) {
            fail("engine never opened 127.0.0.1:${cfg.socksPort}")
            return
        }

        // ---- 5. hev-socks5-tunnel config ------------------------------------
        val cfgPath = File(filesDir, "hev.yml").absolutePath
        File(cfgPath).writeText(
            """
            tunnel:
              mtu: $TUN_MTU
            socks5:
              port: ${cfg.socksPort}
              address: 127.0.0.1
              udp: 'udp'
            misc:
              task-stack-size: 65536
              connect-timeout: 10000
              read-write-timeout: 0
              log-level: warn
              log-file: stderr
            """.trimIndent() + "\n"
        )

        // ---- 6. bridge ------------------------------------------------------
        val ok = try {
            TProxyService.TProxyStartService(cfgPath, fd.fd)
        } catch (e: Throwable) {
            Log.e(TAG, "TProxyStartService threw", e)
            false
        }
        if (!ok) {
            fail("TProxyStartService failed")
            return
        }

        running = true
        lastStats = TunnelStats(state = "connected", text = "tunnel up")
        startStatsLoop()
        Log.i(TAG, "tunnel running")
    }

    private fun startStatsLoop() {
        statsThread = Thread {
            while (running && !stopping.get()) {
                val st = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
                val tx = if (st != null && st.size >= 2) st[0] else 0L
                val rx = if (st != null && st.size >= 2) st[1] else 0L
                val alive = engine?.isAlive == true
                lastStats = TunnelStats(
                    state = if (alive) "connected" else "engine stopped",
                    text = "engine ${if (alive) "running" else "dead"}",
                    txBytes = tx,
                    rxBytes = rx,
                    upMB = tx / 1048576.0,
                    downMB = rx / 1048576.0,
                )
                Thread.sleep(2000)
            }
        }.also { it.start() }
    }

    private fun portOpen(port: Int): Boolean = try {
        Socket().use {
            it.connect(InetSocketAddress("127.0.0.1", port), 200)
            true
        }
    } catch (e: Exception) {
        false
    }

    private fun fail(msg: String) {
        Log.e(TAG, msg)
        lastStats = TunnelStats(state = "error", text = msg)
        stopTunnel()
        stopSelf()
    }

    private fun stopTunnel() {
        stopping.set(true)
        runCatching { TProxyService.TProxyStopService() }
        runCatching { engine?.destroy() }
        engine = null
        runCatching { pfd?.close() }
        pfd = null
        running = false
        if (lastStats.state != "error") {
            lastStats = TunnelStats(state = "disconnected", text = "stopped")
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
            else @Suppress("DEPRECATION") stopForeground(true)
        }
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    private fun buildNotification(cfg: Config): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "DNSTun", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, DnstunService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("DNSTun")
            .setContentText("resolver ${cfg.resolver} - ${cfg.zone}")
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .setOngoing(true)
            .build()
    }
}
