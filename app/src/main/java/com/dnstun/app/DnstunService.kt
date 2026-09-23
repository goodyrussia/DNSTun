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

class DnstunService : VpnService() {

    companion object {
        const val ACTION_START = "com.dnstun.app.START"
        const val ACTION_STOP = "com.dnstun.app.STOP"
        const val EXTRA_STATS = "stats"
        const val CHANNEL_ID = "dnstun"

        @Volatile
        var running = false
            private set

        /** last stats, polled by the UI */
        @Volatile
        var lastStats: TunnelStats = TunnelStats()
            private set
    }

    private var pfd: ParcelFileDescriptor? = null
    private var tunnel: Tunnel? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> startTunnel()
        }
        return START_STICKY
    }

    private fun startTunnel() {
        if (running) return
        val cfg = Config.load(this)
        Log.i("DNSTun", "starting: resolver=${cfg.resolver}:${cfg.port} zone=${cfg.zone} sid=${cfg.sid} mtu=${cfg.mtu} depth=${cfg.startDepth}")

        val builder = Builder()
            .setSession("DNSTun")
            .setMtu(cfg.mtu)
            .addAddress(cfg.vip, 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .setBlocking(true)
        runCatching { builder.addDisallowedApplication(packageName) }

        val fd = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e("DNSTun", "establish failed: ${e.message}")
            null
        }
        if (fd == null) {
            Log.e("DNSTun", "VPN permission missing or establish() returned null")
            stopSelf()
            return
        }
        pfd = fd

        val t = Tunnel(cfg, fd, { protect(it) }) { st -> lastStats = st }
        tunnel = t
        running = true
        t.start()

        startForeground(1, buildNotification(cfg))
    }

    private fun stopTunnel() {
        tunnel?.stop()
        tunnel = null
        runCatching { pfd?.close() }
        pfd = null
        running = false
        lastStats = TunnelStats()
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
            .setContentTitle("DNSTun connected")
            .setContentText("resolver ${cfg.resolver} - zone ${cfg.zone}")
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .setOngoing(true)
            .build()
    }
}
