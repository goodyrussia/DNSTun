package com.dnstun.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Hamara-style path:
 *   VpnService TUN -> libtun2socks.so (BadVPN 1.999.127)
 *     --dnsgw 127.0.0.1:5353  (DNS never through SOCKS UDP)
 *     --socks 127.0.0.1:7300  (TCP only)
 *       -> libdnstun.so -> unique-qname DNS tunnel -> dnsfast on the VPS
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
        const val TUN_GW = "10.111.0.1"
        const val TUN_MASK = "255.255.255.0"
        const val TUN_PREFIX = 24
        const val TUN_MTU = 512
        const val TUN_DNS = "10.111.0.1"

        @Volatile var running = false
            private set

        @Volatile var lastStats: TunnelStats = TunnelStats()
            private set
    }

    private var pfd: ParcelFileDescriptor? = null
    @Volatile private var engine: Process? = null
    @Volatile private var t2s: Process? = null
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
        Log.i(TAG, "start tun2socks: resolver=${cfg.resolver} zone=${cfg.zone} sid=${cfg.sid} depth=${cfg.startDepth}")

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

        val enginePath = File(applicationInfo.nativeLibraryDir, "libdnstun.so").absolutePath
        if (!File(enginePath).exists()) {
            fail("engine missing: $enginePath")
            return
        }
        val t2sPath = File(applicationInfo.nativeLibraryDir, "libtun2socks.so").absolutePath
        if (!File(t2sPath).exists()) {
            fail("tun2socks missing: $t2sPath")
            return
        }

        val cmd = listOf(
            enginePath,
            "-resolver", "${cfg.resolver}:${cfg.port}",
            "-zone", cfg.zone,
            "-sid", cfg.sid,
            "-listen", "127.0.0.1:${cfg.socksPort}",
            "-chunk", cfg.maxChunk.toString(),
            "-depth", cfg.startDepth.toString(),
            "-edns", cfg.edns.toString(),
            "-dns", "127.0.0.1:5353",
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

        val sockFile = File(filesDir, "t2s.sock")
        runCatching { sockFile.delete() }

        val t2sCmd = listOf(
            t2sPath,
            "--netif-ipaddr", TUN_GW,
            "--netif-netmask", TUN_MASK,
            "--socks-server-addr", "127.0.0.1:${cfg.socksPort}",
            "--tunmtu", TUN_MTU.toString(),
            "--sock", sockFile.absolutePath,
            "--loglevel", "3",
            "--dnsgw", "127.0.0.1:5353",
        )
        Log.i(TAG, "tun2socks: ${t2sCmd.joinToString(" ")}")
        val tp = try {
            ProcessBuilder(t2sCmd).redirectErrorStream(true).start()
        } catch (e: Exception) {
            fail("cannot start tun2socks: ${e.message}")
            return
        }
        t2s = tp
        Thread {
            runCatching {
                tp.inputStream.bufferedReader().forEachLine { Log.i(TAG, "t2s: $it") }
            }
        }.start()

        if (!sendFd(fd, sockFile)) {
            fail("failed to pass TUN fd to tun2socks")
            return
        }

        running = true
        lastStats = TunnelStats(state = "connected", text = "tun2socks + engine")
        startStatsLoop()
        Log.i(TAG, "tunnel running")
    }

    private fun sendFd(pfd: ParcelFileDescriptor, sockPath: File): Boolean {
        repeat(25) {
            try {
                if (!sockPath.exists()) {
                    Thread.sleep(200)
                    return@repeat
                }
                val ls = LocalSocket()
                ls.connect(
                    LocalSocketAddress(sockPath.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM)
                )
                ls.setFileDescriptorsForSend(arrayOf(pfd.fileDescriptor))
                ls.outputStream.write(42)
                ls.shutdownOutput()
                ls.close()
                Log.i(TAG, "tun fd sent")
                return true
            } catch (e: Exception) {
                Thread.sleep(200)
            }
        }
        return false
    }

    private fun startStatsLoop() {
        statsThread = Thread {
            while (running && !stopping.get()) {
                val alive = engine?.isAlive == true && t2s?.isAlive == true
                lastStats = TunnelStats(
                    state = if (alive) "connected" else "engine stopped",
                    text = if (alive) "tun2socks + engine" else "process dead",
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
        runCatching { t2s?.destroy() }
        t2s = null
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
            .setContentText("tun2socks ${cfg.resolver}")
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .setOngoing(true)
            .build()
    }
}
