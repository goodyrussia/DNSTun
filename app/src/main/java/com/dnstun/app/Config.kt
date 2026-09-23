package com.dnstun.app

import android.content.Context

/**
 * Everything the tunnel needs. Flat and boring on purpose.
 *
 * pubkey is the vaydns-server public key printed at server setup
 * (`./vaydns-server -gen-key`); the client authenticates the server with it.
 */
data class Config(
    val resolver: String = "188.31.250.128",
    val port: Int = 53,
    val zone: String = "v.techychi.com",
    /** public key of the vaydns-server; not a secret, safe to ship as default */
    val pubkey: String = "580cd814cbd65bd8e5b2613213ffab5827433e5fdc34990727df5c8d68cd7545",
    val socksPort: Int = 7300,
    /** max DNS query-name length; the carrier resolver here allows ~253 */
    val maxQnameLen: Int = 250,
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
                pubkey = p.getString("pubkey", d.pubkey) ?: d.pubkey,
                socksPort = p.getInt("socksPort", d.socksPort),
                maxQnameLen = p.getInt("maxQnameLen", d.maxQnameLen),
            )
        }

        fun save(ctx: Context, c: Config) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("resolver", c.resolver)
                .putInt("port", c.port)
                .putString("zone", c.zone)
                .putString("pubkey", c.pubkey)
                .putInt("socksPort", c.socksPort)
                .putInt("maxQnameLen", c.maxQnameLen)
                .apply()
        }
    }
}

/**
 * What the UI shows. The byte counters come straight from the C bridge
 * (TProxyGetStats), so they are real tunnel throughput.
 */
data class TunnelStats(
    val state: String = "disconnected",
    val text: String = "",
    val txBytes: Long = 0,
    val rxBytes: Long = 0,
    val upMB: Double = 0.0,
    val downMB: Double = 0.0,
)
