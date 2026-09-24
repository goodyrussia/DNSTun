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
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * SlipNet's proven on-device recipe, wired to our engine and our server:
 *
 *   1. establish the VPN FIRST -- 10.255.255.1/32, MTU 1280, DNS = carrier
 *      resolver, route 0.0.0.0/0 -- with this app excluded from it
 *      (addDisallowedApplication), so the engine's own queries to the
 *      carrier resolver leave the phone directly and never loop;
 *   2. start the engine (libdnstun.so): SOCKS5 CONNECT for TCP + FWD_UDP
 *      (cmd 0x05) for DNS, both riding our DNS tunnel to our server;
 *   3. start hev-socks5-tunnel with udp:'tcp': it owns the TUN and sends
 *      every UDP datagram (all of Android's DNS) to the engine as FWD_UDP
 *      frames on a TCP connection, and every TCP stream as a CONNECT.
 *
 * No kernel tricks anywhere: no iptables, no dnsgw rewriting, no writing
 * packets back into the TUN, no fd passing over unix sockets. The DNS path
 * is exactly the one SlipNet's working builds use.
 */
class DnstunService : VpnService() {

    companion object {
        private const val TAG = "DNSTun"
        const val ACTION_START = "com.dnstun.app.START"
        const val ACTION_STOP = "com.dnstun.app.STOP"
        const val CHANNEL_ID = "dnstun"
        private const val NOTIF_ID = 1

        // SlipNet's numbers, verbatim.
        const val TUN_ADDR = "10.255.255.1"
        const val TUN_PREFIX = 32
        const val TUN_MTU = 1280

        @Volatile var running = false
            private set

        @Volatile var lastStats: TunnelStats = TunnelStats()
            private set
    }

    private var pfd: ParcelFileDescriptor? = null
    @Volatile private var engine: Process? = null
    private val stopping = AtomicBoolean(false)
    @Volatile private var statsText: String? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                Thread { stopTunnel() }.start()
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
        Log.i(TAG, "start: resolver=${cfg.resolver}:${cfg.port} zone=${cfg.zone} sid=${cfg.sid}")

        if (!HevTunnel.isLoaded()) {
            fail("hev native libs missing")
            return
        }

        // 1. VPN first (SlipNet order): the engine's own sockets must be
        //    created outside the VPN, so the app is excluded here.
        val builder = Builder()
            .setMtu(TUN_MTU)
            .setSession("DNSTun")
            .addAddress(TUN_ADDR, TUN_PREFIX)
            .addDnsServer(cfg.resolver)
            .addRoute("0.0.0.0", 0)
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
        Log.i(TAG, "tun up $TUN_ADDR/$TUN_PREFIX mtu=$TUN_MTU dns=${cfg.resolver}")

        // 2. engine: SOCKS5 CONNECT + FWD_UDP over our DNS tunnel.
        val enginePath = File(applicationInfo.nativeLibraryDir, "libdnstun.so")
        if (!enginePath.exists()) {
            fail("engine missing: ${enginePath.absolutePath}")
            return
        }
        val cmd = listOf(
            enginePath.absolutePath,
            "-resolver", "${cfg.resolver}:${cfg.port}",
            "-zone", cfg.zone,
            "-sid", cfg.sid,
            "-listen", "127.0.0.1:${cfg.socksPort}",
            "-chunk", cfg.maxChunk.toString(),
            "-depth", cfg.startDepth.toString(),
            "-edns", cfg.edns.toString(),
            "-dns", "127.0.0.1:5353",
            "-dnsdirect=true",
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
                    }
                }
            }
        }.start()

        var up = false
        for (i in 0 until 100) {
            if (stopping.get()) return
            if (portOpen("127.0.0.1", cfg.socksPort)) {
                up = true
                break
            }
            if (!p.isAlive) break
            Thread.sleep(100)
        }
        if (!up) {
            fail("engine SOCKS5 not up on 127.0.0.1:${cfg.socksPort}")
            return
        }
        Log.i(TAG, "engine up: socks5 listening")

        // 3. hev-socks5-tunnel: TUN -> engine (udp:'tcp' -> FWD_UDP for DNS).
        if (!HevTunnel.start(fd, cfg.socksPort, TUN_MTU, TUN_ADDR)) {
            fail("hev start failed")
            return
        }
        Log.i(TAG, "hev running")

        running = true
        lastStats = TunnelStats(state = "connected", text = "hev + engine")

        Thread {
            while (running && !stopping.get()) {
                val alive = engine?.isAlive == true && HevTunnel.isRunning()
                val st = HevTunnel.getStats()
                lastStats = TunnelStats(
                    state = if (alive) "connected" else "stopped",
                    text = statsText ?: if (alive) "hev + engine" else "process dead",
                    txBytes = st?.getOrNull(1) ?: 0L,
                    rxBytes = st?.getOrNull(3) ?: 0L,
                    upMB = (st?.getOrNull(1) ?: 0L) / 1_000_000.0,
                    downMB = (st?.getOrNull(3) ?: 0L) / 1_000_000.0,
                )
                Thread.sleep(1000)
            }
        }.start()
        Log.i(TAG, "tunnel running")
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
        runCatching { HevTunnel.stop() }
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
        Thread { stopTunnel() }.start()
        super.onDestroy()
    }

    override fun onRevoke() {
        Thread { stopTunnel() }.start()
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
