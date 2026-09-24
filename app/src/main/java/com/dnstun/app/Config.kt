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
    val mtu: Int = 1500,
    val edns: Int = 1300,
    /** Start depth: the Smarty climb peaked at ~12k in-flight queries
     *  (6.6 MB/s sustained, 7.6 MB/s burst). 8192 is the sweet spot. */
    val startDepth: Int = 8192,
    val minDepth: Int = 16,
    val maxDepth: Int = 12288,
    /** Upstream bytes per query. Probes: 60-byte payload (127-char name) is
     *  always accepted; 80+ is what the carrier drops. 80 stays as the cap. */
    val maxChunk: Int = 80,
    /** Local SOCKS5 port the engine opens; tun2socks dials it. */
    val socksPort: Int = 7300,
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
    val state: String = "disconnected",
    val text: String = "",
    val txBytes: Long = 0,
    val rxBytes: Long = 0,
    val upMB: Double = 0.0,
    val downMB: Double = 0.0,
)
