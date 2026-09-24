package app.slipnet.data.repository

import android.os.SystemClock
import app.slipnet.domain.model.DnsTransport
import app.slipnet.domain.model.E2eTestPhase
import app.slipnet.domain.model.E2eTestResult
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.repository.ResolverScannerRepository
import app.slipnet.util.AppLog as Log
import mobile.DnsttClient
import mobile.Mobile
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The app's probe engine: a throwaway tunnel instance per candidate resolver.
 *
 * Unlike the live session (which owns the process-wide bridge), every probe is
 * an independent engine on its own loopback port and its own session id, so
 * probes never disturb a running tunnel and can run in parallel.
 */
@Singleton
class EngineProbeRepositoryImpl @Inject constructor() : ResolverScannerRepository {

    override fun maxE2eConcurrency(profile: ServerProfile): Int = PROBE_CONCURRENCY

    override suspend fun isResolverAlive(
        host: String,
        port: Int,
        testDomain: String,
        timeoutMs: Long,
        transport: DnsTransport
    ): Boolean = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val name = testDomain.ifBlank { "example.com" }
        val query = buildDnsQuery(nextQueryId(), name)
        try {
            when (transport) {
                DnsTransport.TCP, DnsTransport.DOT -> tcpProbe(host, port, query, timeoutMs)
                else -> udpProbe(host, port, query, timeoutMs)
            }
        } catch (e: Exception) {
            Log.d(TAG, "isResolverAlive($host:$port) failed: ${e.message}")
            false
        }
    }

    override suspend fun testResolverE2eIsolated(
        resolverHost: String,
        resolverPort: Int,
        profile: ServerProfile,
        testUrl: String,
        timeoutMs: Long,
        fullVerification: Boolean,
        onPhaseUpdate: (String) -> Unit
    ): E2eTestResult = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val started = SystemClock.elapsedRealtime()
        var engine: DnsttClient? = null
        val port = freePort()
        try {
            onPhaseUpdate("Tunnel setup")
            engine = Mobile.newClient(
                "$resolverHost:$resolverPort",
                profile.domain,
                probeSessionId(profile),
                "127.0.0.1:$port"
            )
            engine.setAuthoritativeMode(profile.dnsttAuthoritative)
            engine.start()
            val setupMs = SystemClock.elapsedRealtime() - started

            val url = URL(testUrl)
            val targetPort = if (url.port > 0) url.port else if (url.protocol == "https") 443 else 80

            onPhaseUpdate(if (fullVerification) "HTTP request" else "Handshake")
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", port), timeoutMs.toInt())
                socket.soTimeout = timeoutMs.toInt()
                if (!socks5Connect(socket, url.host, targetPort)) {
                    return@withContext fail(started, "SOCKS5 CONNECT refused", setupMs)
                }
                val handshakeMs = SystemClock.elapsedRealtime() - started

                if (!fullVerification) {
                    return@withContext E2eTestResult(
                        tunnelSetupMs = setupMs,
                        httpLatencyMs = handshakeMs - setupMs,
                        totalMs = handshakeMs,
                        httpStatusCode = 0,
                        success = true,
                        phase = E2eTestPhase.COMPLETED
                    )
                }

                val path = url.file?.takeIf { it.isNotEmpty() } ?: "/"
                val request = "GET $path HTTP/1.1\r\nHost: ${url.host}\r\n" +
                        "User-Agent: dnstun-probe\r\nConnection: close\r\n\r\n"
                socket.getOutputStream().write(request.toByteArray())
                socket.getOutputStream().flush()

                val statusLine = readLine(socket.getInputStream(), 64)
                val code = statusLine?.split(' ')?.getOrNull(1)?.toIntOrNull() ?: 0
                val total = SystemClock.elapsedRealtime() - started
                return@withContext E2eTestResult(
                    tunnelSetupMs = setupMs,
                    httpLatencyMs = total - handshakeMs,
                    totalMs = total,
                    httpStatusCode = code,
                    success = code in 200..399,
                    errorMessage = if (code in 200..399) null else "HTTP ${if (code == 0) "no response" else code}",
                    phase = E2eTestPhase.COMPLETED
                )
            }
        } catch (e: Exception) {
            fail(started, e.message ?: e.javaClass.simpleName, 0)
        } finally {
            try { engine?.stop() } catch (_: Exception) {}
        }
    }

    private fun fail(startedAt: Long, message: String, setupMs: Long): E2eTestResult =
        E2eTestResult(
            tunnelSetupMs = setupMs,
            totalMs = SystemClock.elapsedRealtime() - startedAt,
            success = false,
            errorMessage = message.take(60),
            phase = E2eTestPhase.COMPLETED
        )

    // ── SOCKS5 client ───────────────────────────────────────────────────

    /** Greeting + CONNECT; true when the proxy replies with rep=0x00. */
    private fun socks5Connect(socket: Socket, host: String, port: Int): Boolean {
        val out = socket.getOutputStream()
        val input = socket.getInputStream()

        out.write(byteArrayOf(5, 1, 0))
        out.flush()
        val greeting = ByteArray(2)
        if (!readFully(input, greeting)) return false
        if (greeting[0].toInt() != 5 || greeting[1].toInt() != 0) return false

        val request = ByteArrayOutputStream()
        request.write(5)
        request.write(1)  // CONNECT
        request.write(0)
        val hostBytes = host.toByteArray()
        request.write(3)  // domain name
        request.write(hostBytes.size)
        request.write(hostBytes)
        request.write(port shr 8)
        request.write(port and 0xFF)
        out.write(request.toByteArray())
        out.flush()

        val head = ByteArray(4)
        if (!readFully(input, head)) return false
        if (head[0].toInt() != 5 || head[1].toInt() != 0) return false
        // Drain the bound address that follows.
        val addrLen = when (head[3].toInt()) {
            1 -> 4
            4 -> 16
            3 -> {
                val len = ByteArray(1)
                if (!readFully(input, len)) return false
                len[0].toInt() and 0xFF
            }
            else -> return false
        }
        return readFully(input, ByteArray(addrLen + 2))
    }

    private fun readFully(input: InputStream, buffer: ByteArray): Boolean {
        var offset = 0
        while (offset < buffer.size) {
            val read = input.read(buffer, offset, buffer.size - offset)
            if (read < 0) return false
            offset += read
        }
        return true
    }

    private fun readLine(input: InputStream, max: Int): String? {
        val line = StringBuilder()
        while (line.length < max) {
            val c = input.read()
            if (c < 0) break
            if (c == '\n'.code) return line.toString().trim()
            if (c != '\r'.code) line.append(c.toChar())
        }
        return line.takeIf { it.isNotEmpty() }?.toString()
    }

    // ── Plain DNS probes ────────────────────────────────────────────────

    private fun udpProbe(host: String, port: Int, query: ByteArray, timeoutMs: Long): Boolean {
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMs.toInt()
            socket.send(DatagramPacket(query, query.size, InetSocketAddress(host, port)))
            val response = ByteArray(4096)
            val packet = DatagramPacket(response, response.size)
            socket.receive(packet)
            return packet.length >= 12 && response[0] == query[0] && response[1] == query[1]
        }
    }

    private fun tcpProbe(host: String, port: Int, query: ByteArray, timeoutMs: Long): Boolean {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), timeoutMs.toInt())
            socket.soTimeout = timeoutMs.toInt()
            val framed = ByteArray(query.size + 2)
            framed[0] = (query.size shr 8).toByte()
            framed[1] = (query.size and 0xFF).toByte()
            query.copyInto(framed, 2)
            socket.getOutputStream().write(framed)
            socket.getOutputStream().flush()
            val length = ByteArray(2)
            if (!readFully(socket.getInputStream(), length)) return false
            val size = ((length[0].toInt() and 0xFF) shl 8) or (length[1].toInt() and 0xFF)
            if (size < 12) return false
            return readFully(socket.getInputStream(), ByteArray(size))
        }
    }

    private fun buildDnsQuery(id: Int, name: String): ByteArray {
        val out = ByteArrayOutputStream()
        fun u16(value: Int) {
            out.write((value shr 8) and 0xFF)
            out.write(value and 0xFF)
        }
        u16(id)
        u16(0x0100)  // standard query, recursion desired
        u16(1)       // QDCOUNT
        u16(0); u16(0); u16(0)
        for (label in name.split('.')) {
            val bytes = label.toByteArray()
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        u16(2)  // NS
        u16(1)  // IN
        return out.toByteArray()
    }

    private fun nextQueryId(): Int = QUERY_ID.getAndIncrement() and 0x7FFF

    private fun freePort(): Int = ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1")).use { it.localPort }

    /**
     * Isolated probes must not share the live session: two engines on one
     * session id would interleave fragments in the server's stream table.
     */
    private fun probeSessionId(profile: ServerProfile): String {
        val key = profile.dnsttPublicKey.trim()
        val base = if (key.isNotEmpty() && key.length <= 12 && key.all { it.isLetterOrDigit() }) {
            key
        } else {
            DEFAULT_SESSION_ID
        }
        return base + "-p" + (PROBE_COUNT.getAndIncrement() and 0xFFFF).toString(16)
    }

    companion object {
        private const val TAG = "EngineProbe"
        private const val PROBE_CONCURRENCY = 6
        private const val DEFAULT_SESSION_ID = "g7x2k9"
        private val QUERY_ID = AtomicInteger(0x2000)
        private val PROBE_COUNT = AtomicInteger(1)
    }
}
