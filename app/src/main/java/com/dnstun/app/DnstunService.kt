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
 * Wiring taken 1:1 from the two apps proven on this device class:
 *
 *   SocksDroid (bndeff/socksdroid) and Hamara Tunnel. Both run this exact
 *   BadVPN tun2socks 1.999.127 fork (it reports "net.typeblog.socks" in its
 *   strings) behind a VpnService with these numbers:
 *
 *     TUN            10.111.0.1/24     dns stub 8.8.8.8     mtu 1500
 *     tun2socks      --netif-ipaddr 10.111.0.2 --netif-netmask 255.255.255.0
 *                    --socks-server-addr 127.0.0.1:7300
 *                    --sock <unix path>   <- ANDROID build takes the TUN fd
 *                                            ONLY over this unix socket
 *                    --dnsgw 10.111.0.1:8091   <- engine's DNS listener
 *     engine         SOCKS5 on 127.0.0.1:7300 + DNS on 10.111.0.1:8091
 *
 * Why the 2.x builds could never work:
 *   tun2socks rewrites every UDP :53 packet (dst = dnsgw) and writes it back
 *   into the TUN; the kernel only delivers such a packet to a socket bound on
 *   the TUN's own address. 2.x pointed dnsgw at 127.0.0.1 (never deliverable
 *   from a tun device) and the hev-based builds never set dnsgw at all, so
 *   DNS never resolved and no page ever loaded even though the tunnel ran.
 */
class DnstunService : VpnService() {

    companion object {
        private const val TAG = "DNSTun"
        const val ACTION_START = "com.dnstun.app.START"
        const val ACTION_STOP = "com.dnstun.app.STOP"
        const val CHANNEL_ID = "dnstun"
        private const val NOTIF_ID = 1

        // SocksDroid / Hamara numbers. Do not invent others.
        const val TUN_ADDR = "10.111.0.1"
        const val TUN_PREFIX = 24
        const val T2S_GW = "10.111.0.2"
        const val T2S_MASK = "255.255.255.0"
        const val TUN_MTU = 1500
        const val STUB_DNS = "8.8.8.8"
        const val DNS_PORT = 8091

        @Volatile var running = false
            private set

        @Volatile var lastStats: TunnelStats = TunnelStats()
            private set
    }

    private var pfd: ParcelFileDescriptor? = null
    @Volatile private var engine: Process? = null
    @Volatile private var t2s: Process? = null
    private val stopping = AtomicBoolean(false)
    @Volatile private var statsText: String? = null

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
        Log.i(TAG, "start: resolver=${cfg.resolver} zone=${cfg.zone} sid=${cfg.sid}")

        val builder = Builder()
            .setMtu(TUN_MTU)
            .setSession("DNSTun")
            .addAddress(TUN_ADDR, TUN_PREFIX)
            .addRoute("0.0.0.0", 0)
            .addRoute(STUB_DNS, 32)
            .addDnsServer(STUB_DNS)
        runCatching { builder.setBlocking(false) }
        runCatching { builder.addDisallowedApplication(packageName) }
        val fd = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "establish: ${e.message}")
            null
        }
        if (fd == null) {
            fail("VPN permission missing")
            return
        }
        pfd = fd
        Log.i(TAG, "tun up ${TUN_ADDR}/$TUN_PREFIX mtu=$TUN_MTU dns=$STUB_DNS")

        val libDir = applicationInfo.nativeLibraryDir
        val enginePath = File(libDir, "libdnstun.so")
        val t2sPath = File(libDir, "libtun2socks.so")
        if (!enginePath.exists()) {
            fail("engine missing: ${enginePath.absolutePath}")
            return
        }
        if (!t2sPath.exists()) {
            fail("tun2socks missing: ${t2sPath.absolutePath}")
            return
        }

        // 1. engine first: SOCKS5 + DNS listener on the TUN address
        val cmd = listOf(
            enginePath.absolutePath,
            "-resolver", "${cfg.resolver}:${cfg.port}",
            "-zone", cfg.zone,
            "-sid", cfg.sid,
            "-listen", "127.0.0.1:${cfg.socksPort}",
            "-chunk", cfg.maxChunk.toString(),
            "-depth", cfg.startDepth.toString(),
            "-edns", cfg.edns.toString(),
            "-dns", "$TUN_ADDR:$DNS_PORT",
        )
        Log.i(TAG, "engine: ${cmd.joinToString(" ")}")
        val p = try {
            ProcessBuilder(cmd).redirectErrorStream(true).start()
        } catch (e: Exception) {
            fail("engine start: ${e.message}")
            return
        }
        engine = p
        Thread {
            runCatching {
                p.inputStream.bufferedReader().forEachLine { line ->
                    Log.i(TAG, "engine: $line")
                    if (line.startsWith("STATS ")) {
                        statsText = line.removePrefix("STATS ")
                        lastStats = TunnelStats(state = "connected", text = statsText!!)
                    }
                }
            }
        }.start()

        var up = false
        for (i in 0 until 100) {
            if (stopping.get()) return
            if (portOpen("127.0.0.1", cfg.socksPort) && portOpen(TUN_ADDR, DNS_PORT)) {
                up = true
                break
            }
            if (!p.isAlive) break
            Thread.sleep(100)
        }
        if (!up) {
            fail("engine ports not up (socks 127.0.0.1:${cfg.socksPort} dns $TUN_ADDR:$DNS_PORT)")
            return
        }
        Log.i(TAG, "engine up: socks + dns listening")

        // 2. tun2socks, then hand it the TUN fd over the unix socket
        val sockFile = File(filesDir, "t2s.sock")
        runCatching { sockFile.delete() }

        val t2sCmd = listOf(
            t2sPath.absolutePath,
            "--netif-ipaddr", T2S_GW,
            "--netif-netmask", T2S_MASK,
            "--socks-server-addr", "127.0.0.1:${cfg.socksPort}",
            "--tunfd", fd.fd.toString(),
            "--tunmtu", TUN_MTU.toString(),
            "--loglevel", "3",
            "--pid", File(filesDir, "tun2socks.pid").absolutePath,
            "--sock", sockFile.absolutePath,
            "--dnsgw", "$TUN_ADDR:$DNS_PORT",
        )
        Log.i(TAG, "tun2socks: ${t2sCmd.joinToString(" ")}")
        val tp = try {
            ProcessBuilder(t2sCmd).redirectErrorStream(true).start()
        } catch (e: Exception) {
            fail("tun2socks start: ${e.message}")
            return
        }
        t2s = tp
        Thread {
            runCatching {
                tp.inputStream.bufferedReader().forEachLine { Log.i(TAG, "t2s: $it") }
            }
        }.start()

        if (!sendFd(fd, sockFile)) {
            fail("TUN fd was not accepted by tun2socks")
            return
        }
        Log.i(TAG, "tun fd delivered")

        running = true
        lastStats = TunnelStats(state = "connected", text = "tun2socks + engine")
        Thread {
            while (running && !stopping.get()) {
                val alive = engine?.isAlive == true && t2s?.isAlive == true
                lastStats = TunnelStats(
                    state = if (alive) "connected" else "stopped",
                    text = statsText ?: if (alive) "tun2socks + engine" else "process dead",
                )
                Thread.sleep(2000)
            }
        }.start()
        Log.i(TAG, "tunnel running")
    }

    /**
     * The ANDROID build of this tun2socks fork always receives its TUN fd as
     * SCM_RIGHTS ancillary data on the unix socket given to --sock; it never
     * reads --tunfd. This is the same fd pass Hamara and SocksDroid do.
     */
    private fun sendFd(pfd: ParcelFileDescriptor, sockPath: File): Boolean {
        repeat(25) {
            if (stopping.get()) return false
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
                return true
            } catch (e: Exception) {
                Thread.sleep(200)
            }
        }
        return false
    }

    private fun portOpen(host: String, port: Int): Boolean = try {
        Socket().use {
            it.connect(InetSocketAddress(host, port), 200)
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
        statsText = null
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
            .setContentText(cfg.resolver)
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .setOngoing(true)
            .build()
    }
}
