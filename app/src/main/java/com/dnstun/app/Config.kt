package com.dnstun.app

import android.content.Context

/**
 * Everything the tunnel needs. Flat and boring on purpose - no profiles, no
 * encryption, no routing rules. Speed only.
 */
data class Config(
    val resolver: String = "188.31.250.128",
    val port: Int = 53,
    val zone: String = "v.techychi.com",
    val sid: String = "g7x2k9",
    val vip: String = "10.78.0.2",
    val mtu: Int = 600,
    val edns: Int = 1300,
    val startDepth: Int = 128,
    val minDepth: Int = 16,
    val maxDepth: Int = 256,
) {
    companion object {
        private const val PREFS = "dnstun"

        fun load(ctx: Context): Config {
            val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val d = Config()
            return Config(
                resolver = p.getString("resolver", d.resolver) ?: d.resolver,
                port = p.getInt("port", d.port),
                zone = p.getString("zone", d.zone) ?: d.zone,
                sid = p.getString("sid", d.sid) ?: d.sid,
                vip = p.getString("vip", d.vip) ?: d.vip,
                mtu = p.getInt("mtu", d.mtu),
                edns = p.getInt("edns", d.edns),
                startDepth = p.getInt("depth", d.startDepth),
                minDepth = d.minDepth,
                maxDepth = d.maxDepth,
            )
        }

        fun save(ctx: Context, c: Config) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("resolver", c.resolver)
                .putInt("port", c.port)
                .putString("zone", c.zone)
                .putString("sid", c.sid)
                .putString("vip", c.vip)
                .putInt("mtu", c.mtu)
                .putInt("edns", c.edns)
                .putInt("depth", c.startDepth)
                .apply()
        }
    }
}

data class TunnelStats(
    val queriesPerSec: Double = 0.0,
    val downKBps: Double = 0.0,
    val upKBps: Double = 0.0,
    val lossPercent: Double = 0.0,
    val depth: Int = 0,
    val upBytes: Long = 0,
    val downBytes: Long = 0,
    val sent: Long = 0,
    val recv: Long = 0,
    /** ms since the last reply arrived; -1 = never */
    val lastReplyAgoMs: Long = -1,
    val protectOk: Boolean = false,
    val sendErrors: Long = 0,
    val recvErrors: Long = 0,
    val lastError: String = "",
    val ownLoopDropped: Long = 0,
)
