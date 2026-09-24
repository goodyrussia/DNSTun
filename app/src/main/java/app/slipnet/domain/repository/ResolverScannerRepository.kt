package app.slipnet.domain.repository

import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.E2eTestResult
import app.slipnet.domain.model.ServerProfile

/**
 * Probing operations kept from the upstream project's scanner: the resolver
 * pool ranks candidates with them, and the profile ping uses the E2E probe.
 *
 * Both are implemented on top of the app's own engine — a probe is a real,
 * isolated tunnel instance that is started, exercised and stopped.
 */
interface ResolverScannerRepository {

    /**
     * Send a plain DNS query straight at [host] and report whether a matching
     * response came back. Used as the cheap phase-1 filter of the pool scan.
     */
    suspend fun isResolverAlive(
        host: String,
        port: Int = 53,
        testDomain: String,
        timeoutMs: Long = 3000,
        transport: DnsTransport = DnsTransport.UDP
    ): Boolean

    /**
     * Start an isolated tunnel instance against [resolverHost]:[resolverPort],
     * then (unless [fullVerification] is false) fetch [testUrl] through it.
     *
     * `fullVerification = false` still proves bidirectional data flow: the
     * SOCKS5 CONNECT only completes once the remote side of the tunnel has
     * opened the TCP connection.
     */
    suspend fun testResolverE2eIsolated(
        resolverHost: String,
        resolverPort: Int,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
        fullVerification: Boolean = false,
        onPhaseUpdate: (String) -> Unit
    ): E2eTestResult

    /** How many isolated tunnels may be probed in parallel. */
    fun maxE2eConcurrency(profile: ServerProfile): Int
}
