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
    /** Sweep-proven: 128 gives 440 replies/s, 192 drops to 118/s with
     *  21% loss, 256 collapses to 7/s. Never climb past 160. */
    val maxDepth: Int = 160,
    /** Upstream bytes per query. Sweep-proven on the Smarty resolver:
     *  120 bytes -> 224-char dotted name / 226 wire, accepted.
     *  140 bytes -> 258 wire, EXCEEDS the 255-byte DNS wire limit and is
     *  rejected as malformed. 120 is the practical maximum. */
    val maxChunk: Int = 120,
    /** Local SOCKS5 port our engine opens; hev-socks5-tunnel dials it. */
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
