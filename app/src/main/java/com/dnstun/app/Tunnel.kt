package com.dnstun.app

import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketTimeoutException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread
import kotlin.math.max
import kotlin.math.min
import kotlin.random.Random

private const val TAG = "DNSTun"

/** Max payload bytes we can pack into one query name (253 char DNS limit). */
// Upstream payload per query. The carrier resolver DROPS long query names
// (measured: ~246-char names get no answer, ~110 is the safe ceiling).
// 48 bytes -> b32(52) = 84 chars + sid(6) + zone(13) + dots ~= 106 chars.
// This only limits UPLOAD; download speed is driven by short polls and is
// unaffected.
private const val MAX_CHUNK = 48

/** Poll queries carry 4 unique bytes so a resolver can never serve a cached reply. */
private val POLL_RND = java.util.Random(System.nanoTime())

private const val FLAG_MORE = 1

/**
 * The whole tunnel. Upstream IP packets are fragmented into query names, the
 * server streams replies back as TXT records carrying raw IP packets.
 *
 * No crypto, no compression, no framing beyond a 3 byte header - every byte of
 * overhead is bandwidth we do not get back.
 */
class Tunnel(
    private val cfg: Config,
    private val tun: ParcelFileDescriptor,
    private val protectSocket: (DatagramSocket) -> Boolean,
    private val bindUnderlying: (DatagramSocket) -> Boolean,
    private val onStats: (TunnelStats) -> Unit,
) {
    private val running = AtomicBoolean(false)

    private val sent = AtomicLong()
    private val recv = AtomicLong()
    private val lost = AtomicLong()
    private val upBytes = AtomicLong()
    private val downBytes = AtomicLong()

    private var channel: DatagramChannel? = null
    /** fragments waiting to go out; the sender thread drains this */
    private val upQueue = ArrayDeque<ByteArray>()
    private val upLock = Object()
    private val upDropped = AtomicLong()
    private val inflight = java.util.concurrent.ConcurrentHashMap<Int, Long>()
    @Volatile private var depth = 128
    @Volatile private var sendStalled = 0L
    @Volatile private var recvStalled = 0L
    private var sockRef: DatagramSocket? = null
    @Volatile private var protectOk = false
    @Volatile private var bindOk = false
    private val sendErrors = AtomicLong()
    private val recvErrors = AtomicLong()
    @Volatile private var lastError = ""
    private var resolverIp = 0
    @Volatile private var lastRecvAt = 0L
    private val probeLock = Object()
    @Volatile private var rcvBufSize = -1
    @Volatile private var socketEpoch = 0
    private var sendEpoch = -1
    @Volatile private var sndBufSize = -1
    private val ownLoopDropped = AtomicLong()
    private val tunIdleReads = AtomicLong()
    private val tunReads = AtomicLong()
    private val tunWriteDropped = AtomicLong()
    private val tunWriteQueue = ArrayDeque<ByteArray>()
    private val tunWriteLock = Object()
    /** the call we are currently inside - the only way to see a stall from outside */
    @Volatile private var op = "starting"
    @Volatile private var stalledFor = 0L
    private var lastSendAt = 0L
    // built-in path self-test: 60 queries on distinct qids, count how many come back
    private val probeQids = HashSet<Int>()
    @Volatile private var probeUntil = 0L
    @Volatile private var probeSent = 0
    @Volatile private var probeRecv = 0
    private var tunOut: FileOutputStream? = null
    private var fragCounter = 0

    @Volatile
    private var lastLoss = 0.0

    fun start() {
        if (!running.compareAndSet(false, true)) return
        depth = cfg.startDepth
        // Every blocking call gets its own thread. A blocked send, a blocked
        // receive or a blocked tun write can then no longer freeze the tunnel -
        // which is exactly how they all used to fail.
        thread(name = "dnstun-tun") { tunReader() }
        thread(name = "dnstun-tunw") { tunWriter() }
        thread(name = "dnstun-send") { senderLoop() }
        thread(name = "dnstun-recv") { receiverLoop() }
        thread(name = "dnstun-stat") { statsLoop() }
    }

    /** Called when the device's underlying network changes: the tunnel socket is
     *  bound to a specific network, so it has to be rebuilt on the new one. */
    fun onNetworkChanged() {
        socketEpoch++
    }

    fun stop() {
        running.set(false)
        runCatching { sockRef?.close() }
        runCatching { channel?.close() }
        channel = null
        sockRef = null
    }

    private fun setError(msg: String) {
        lastError = msg
        Log.w(TAG, msg)
    }

    // ------------------------------------------------------------------ tun

    /**
     * Reads IP packets out of the tun.
     *
     * Android hands out a NON-BLOCKING tun fd (AOSP: "By default, the file
     * descriptor returned by establish() is non-blocking") and ToyVpn polls it
     * for exactly this reason. FileChannel.read() is the robust way to read such
     * an fd: an empty queue returns 0 rather than throwing EAGAIN, and a blocking
     * fd simply blocks. Reading the raw stream with FileInputStream.read(byte[])
     * throws IOException("Try again") instead - which used to kill this thread.
     */
    private fun tunReader() {
        val ch = FileInputStream(tun.fileDescriptor).channel
        val bb = ByteBuffer.allocate(max(1500, cfg.mtu))
        val buf = ByteArray(max(1500, cfg.mtu))
        while (running.get()) {
            bb.clear()
            val n = try {
                ch.read(bb)
            } catch (e: Exception) {
                // Android 14+ hands out a NON-BLOCKING tun fd (setBlocking(true) is
                // ignored), so an idle read throws EAGAIN / "Try again". That is the
                // normal empty-queue case, not an error - treating it as fatal kills
                // the reader thread on the first idle moment and the tunnel then
                // never carries a single upstream packet.
                val msg = e.message ?: ""
                if (e is java.io.InterruptedIOException || msg.contains("Try again") ||
                    msg.contains("EAGAIN") || msg.contains("would block")
                ) {
                    tunIdleReads.incrementAndGet()
                    Thread.sleep(1)
                    continue
                }
                if (running.get()) setError("tun read: $msg")
                break
            }
            if (n <= 0) {
                tunIdleReads.incrementAndGet()
                Thread.sleep(1)
                continue
            }
            tunReads.incrementAndGet()
            bb.flip()
            bb.get(buf, 0, n)
            // Safety net: if protect() ever fails, our own queries would be routed
            // back into our own VPN and loop forever. Never re-tunnel them.
            if (isOwnTunnelPacket(buf, n)) {
                ownLoopDropped.incrementAndGet()
                continue
            }
            upBytes.addAndGet(n.toLong())
            fragment(buf, n)
        }
    }

    private fun ipToInt(a: InetAddress): Int {
        val b = a.address
        return ((b[0].toInt() and 0xFF) shl 24) or ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or (b[3].toInt() and 0xFF)
    }

    /** true if this TUN packet is our own UDP query heading for the resolver */
    private fun isOwnTunnelPacket(p: ByteArray, n: Int): Boolean {
        if (resolverIp == 0 || n < 28) return false
        if ((p[0].toInt() and 0xF0) != 0x40) return false
        if ((p[9].toInt() and 0xFF) != 17) return false
        val dst = ((p[16].toInt() and 0xFF) shl 24) or ((p[17].toInt() and 0xFF) shl 16) or
            ((p[18].toInt() and 0xFF) shl 8) or (p[19].toInt() and 0xFF)
        if (dst != resolverIp) return false
        val dport = ((p[22].toInt() and 0xFF) shl 8) or (p[23].toInt() and 0xFF)
        return dport == cfg.port
    }

    private fun fragment(pkt: ByteArray, n: Int) {
        val id = fragCounter++ and 0xFFFF
        var off = 0
        var idx = 0
        while (off < n) {
            val len = min(cfg.maxChunk, n - off)
            val chunk = ByteArray(4 + len)
            chunk[0] = (id ushr 8).toByte()
            chunk[1] = (id and 0xFF).toByte()
            chunk[2] = idx.toByte()
            chunk[3] = if (off + len < n) FLAG_MORE.toByte() else 0
            System.arraycopy(pkt, off, chunk, 4, len)
            synchronized(upLock) {
                if (upQueue.size < 8192) upQueue.addLast(chunk)
                else upDropped.incrementAndGet()
            }
            off += len
            idx++
        }
    }

    /**
     * Writing to the tun can block when the queue is full (which happens exactly
     * when the phone is NOT consuming packets). Doing that on the udp thread
     * froze the whole tunnel, so writes are queued and drained by their own
     * thread - the tunnel keeps running even if the device stops reading.
     */
    private fun queueTunWrite(pkt: ByteArray, off: Int, len: Int) {
        val copy = pkt.copyOfRange(off, off + len)
        synchronized(tunWriteLock) {
            if (tunWriteQueue.size < 4096) tunWriteQueue.addLast(copy)
            else tunWriteDropped.incrementAndGet()
        }
    }

    private fun tunWriter() {
        val out = try {
            FileOutputStream(tun.fileDescriptor)
        } catch (e: Exception) {
            setError("tun writer: ${e.message}")
            return
        }
        while (running.get()) {
            val pkt = synchronized(tunWriteLock) { tunWriteQueue.removeFirstOrNull() }
            if (pkt == null) {
                Thread.sleep(1)
                continue
            }
            op = "tun-write"
            try {
                out.write(pkt)
            } catch (e: Exception) {
                if (running.get()) setError("tun write: ${e.message}")
            }
        }
    }

    private fun writeToTun(pkt: ByteArray, off: Int, len: Int) = queueTunWrite(pkt, off, len)

    // ------------------------------------------------------------------ udp

    /**
     * Opens the tunnel socket. A plain DatagramSocket is used because
     * VpnService.protect() genuinely works on it (it returns false on
     * channel-derived sockets on some devices).
     */
    private fun openSocket(): DatagramChannel? {
        val ch = try {
            DatagramChannel.open()
        } catch (e: Exception) {
            setError("socket: ${e.message}")
            return null
        }
        // Non-blocking is the whole point: a full kernel send buffer must never
        // freeze the sender thread. Blocking send() on a black-holed network
        // never returns, which silently killed the tunnel before.
        runCatching { ch.configureBlocking(false) }
        // Big buffers: replies arrive in bursts of `depth` packets and a small
        // receive buffer discards most of them.
        runCatching { ch.socket().receiveBufferSize = 4 shl 20 }
        runCatching { ch.socket().sendBufferSize = 4 shl 20 }
        rcvBufSize = runCatching { ch.socket().receiveBufferSize }.getOrDefault(-1)
        sndBufSize = runCatching { ch.socket().sendBufferSize }.getOrDefault(-1)
        // No protect() and no bind. The app excludes itself from its own VPN with
        // addDisallowedApplication(), so its sockets follow the device's CURRENT
        // network. protect() instead pins the socket to whatever network was
        // default at connect time: move networks, or sit on a DNS-only bearer,
        // and the socket black-holes while send() blocks forever.
        protectOk = true
        bindOk = true
        channel = ch
        return ch
    }

    private fun senderLoop() {
        var ch = openSocket() ?: return
        sendEpoch = socketEpoch
        val resolver = try {
            InetSocketAddress(InetAddress.getByName(cfg.resolver), cfg.port)
        } catch (e: Exception) {
            setError("resolver ${cfg.resolver}: ${e.message}")
            onStats(TunnelStats(protectOk = protectOk, bindOk = bindOk, lastError = lastError))
            return
        }
        resolverIp = ipToInt(resolver.address)
        onStats(TunnelStats(protectOk = protectOk, bindOk = bindOk, depth = depth, lastError = lastError))
        val rnd = Random(System.nanoTime())
        val startedAt = System.currentTimeMillis()
        lastSendAt = startedAt
        var probeDone = false

        while (running.get()) {
            val now = System.currentTimeMillis()

            // network changed underneath us: rebuild the socket on the new one
            if (socketEpoch != sendEpoch) {
                sendEpoch = socketEpoch
                runCatching { ch.close() }
                val fresh = openSocket()
                if (fresh != null) {
                    ch = fresh
                    inflight.clear()
                    setError("network changed - tunnel socket rebuilt")
                }
            }

            // one-shot path self-test: 60 fresh queries, count the replies
            if (!probeDone && now - startedAt > 1500) {
                probeDone = true
                probeSent = 0
                probeRecv = 0
                synchronized(probeLock) { probeQids.clear() }
                var ok = 0
                for (i in 0 until 60) {
                    val qid = 60000 + i
                    val q = buildQuery(pollName(), qid)
                    val n = try {
                        op = "send"
                        ch.send(ByteBuffer.wrap(q), resolver)
                    } catch (e: Exception) {
                        sendErrors.incrementAndGet()
                        break
                    }
                    if (n == 0) break
                    inflight[qid] = now
                    synchronized(probeLock) { probeQids.add(qid) }
                    ok++
                }
                probeSent = ok
                sent.addAndGet(ok.toLong())
                probeUntil = now + 5000
            }

            // keep `depth` queries in flight: real data first, polls to fill
            var sentThisRound = 0
            while (inflight.size < depth && sentThisRound < 1024) {
                val chunk = synchronized(upLock) { upQueue.removeFirstOrNull() }
                val name = if (chunk != null) encodeName(chunk) else pollName()
                val qid = rnd.nextInt(1, 65536)
                if (inflight.containsKey(qid)) continue
                val q = buildQuery(name, qid)
                op = "send"
                val n = try {
                    ch.send(ByteBuffer.wrap(q), resolver)
                } catch (e: Exception) {
                    sendErrors.incrementAndGet()
                    if (running.get()) setError("send: ${e.message}")
                    break
                }
                if (n == 0) break // kernel buffer full: retry next round, never block
                inflight[qid] = System.currentTimeMillis()
                lastSendAt = System.currentTimeMillis()
                sent.incrementAndGet()
                sentThisRound++
            }

            val idle = System.currentTimeMillis() - lastSendAt
            sendStalled = if (idle > 3000) idle / 1000 else 0
            if (sentThisRound == 0) Thread.sleep(1)
        }
    }

    private fun receiverLoop() {
        val rcv = ByteBuffer.allocate(4096)
        var ch = channel ?: return
        var epoch = socketEpoch
        while (running.get()) {
            if (epoch != socketEpoch) {
                epoch = socketEpoch
                Thread.sleep(50)
                ch = channel ?: continue
            }
            rcv.clear()
            op = "recv"
            val src = try {
                ch.receive(rcv)
            } catch (e: Exception) {
                if (running.get()) {
                    recvErrors.incrementAndGet()
                    setError("recv: ${e.message}")
                }
                Thread.sleep(5)
                continue
            }
            if (src == null) {
                recvStalled = if (System.currentTimeMillis() - lastRecvAt > 3000) 1 else 0
                Thread.sleep(1)
                continue
            }
            val len = rcv.position()
            val data = rcv.array()
            lastRecvAt = System.currentTimeMillis()
            lastReplyAt.set(lastRecvAt)
            recv.incrementAndGet()
            if (len >= 2) {
                val rqid = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
                if (probeUntil > 0) {
                    synchronized(probeLock) {
                        if (probeQids.remove(rqid)) probeRecv++
                    }
                }
            }
            handleResponse(data, len, inflight)
        }
    }

    private fun statsLoop() {
        var lastStat = System.currentTimeMillis()
        var lastAdapt = lastStat
        var statSent = sent.get()
        var statRecv = recv.get()
        var statDown = downBytes.get()
        var statUp = upBytes.get()
        var statLost = lost.get()
        while (running.get()) {
            Thread.sleep(500)
            val now = System.currentTimeMillis()
            if (now - lastStat < 1000) continue

            // drop queries that never came back
            val stale = ArrayList<Int>()
            for ((qid, at) in inflight) if (now - at > 3000) stale.add(qid)
            for (qid in stale) {
                inflight.remove(qid)
                lost.incrementAndGet()
                if (probeUntil > 0) {
                    synchronized(probeLock) { probeQids.remove(qid) }
                }
            }

            val dt = (now - lastStat) / 1000.0
            val qps = (recv.get() - statRecv) / dt
            val down = (downBytes.get() - statDown) / dt
            val up = (upBytes.get() - statUp) / dt
            val dSent = sent.get() - statSent
            val dLost = lost.get() - statLost
            lastLoss = if (dSent > 0) min(100.0, 100.0 * dLost / dSent) else 0.0

            // depth tuning: climb while the path is healthy, back off when it is not
            if (now - lastAdapt > 3000) {
                lastAdapt = now
                val q = synchronized(upLock) { upQueue.size }
                when {
                    lastLoss > 8.0 || (q == 0 && qps < 5.0) -> depth = max(cfg.minDepth, depth - 16)
                    lastLoss < 4.0 && depth < cfg.maxDepth && q > 0 -> depth = min(cfg.maxDepth, depth + 16)
                    lastLoss < 4.0 && depth < cfg.maxDepth && qps > depth * 2.0 -> depth = min(cfg.maxDepth, depth + 16)
                }
            }

            onStats(
                TunnelStats(
                    queriesPerSec = qps,
                    downKBps = down / 1024.0,
                    upKBps = up / 1024.0,
                    lossPercent = lastLoss,
                    depth = depth,
                    upBytes = upBytes.get(),
                    downBytes = downBytes.get(),
                    sent = sent.get(),
                    recv = recv.get(),
                    lastReplyAgoMs = if (lastReplyAt.get() == 0L) -1L else now - lastReplyAt.get(),
                    protectOk = protectOk,
                    bindOk = bindOk,
                    sendErrors = sendErrors.get(),
                    recvErrors = recvErrors.get(),
                    lastError = lastError,
                    ownLoopDropped = ownLoopDropped.get(),
                    tunIdleReads = tunIdleReads.get(),
                    tunReads = tunReads.get(),
                    tunWriteDropped = tunWriteDropped.get(),
                    op = op,
                    stalledFor = max(sendStalled, recvStalled),
                    probeSent = probeSent,
                    probeRecv = probeRecv,
                    upQueued = synchronized(upLock) { upQueue.size },
                    inflight = inflight.size,
                )
            )
            statSent = sent.get()
            statRecv = recv.get()
            statDown = downBytes.get()
            statUp = upBytes.get()
            statLost = lost.get()
        }
    }


    private fun nowMs() = System.currentTimeMillis()

    private fun pollName(): String {
        val b = ByteArray(4)
        POLL_RND.nextBytes(b)
        b[3] = 0
        return encodeName(b)
    }

    /** 4 byte header (fragId, idx, flags) + payload, base32, split into labels. */
    private fun encodeName(chunk: ByteArray): String {
        val b32 = base32(chunk)
        val sb = StringBuilder(b32.length + cfg.sid.length + cfg.zone.length + 8)
        var i = 0
        while (i < b32.length) {
            val end = min(i + 63, b32.length)
            sb.append(b32, i, end).append('.')
            i = end
        }
        sb.append(cfg.sid).append('.').append(cfg.zone)
        return sb.toString()
    }

    private fun buildQuery(name: String, qid: Int): ByteArray {
        val out = ByteBuffer.allocate(512)
        out.putShort(qid.toShort())
        out.putShort(0x0100.toShort())   // RD
        out.putShort(1)                  // qdcount
        out.putShort(0)                  // ancount
        out.putShort(0)                  // nscount
        out.putShort(1)                  // arcount (OPT)
        for (label in name.split('.')) {
            if (label.isEmpty()) continue
            out.put(label.length.toByte())
            out.put(label.toByteArray(Charsets.US_ASCII))
        }
        out.put(0)
        out.putShort(16)                 // TXT
        out.putShort(1)                  // IN
        out.put(0)                       // root name for OPT
        out.putShort(41)                 // OPT
        out.putShort(cfg.edns.toShort())
        out.putInt(0)
        out.putShort(0)
        return out.array().copyOf(out.position())
    }

    /**
     * A reply is: 3 byte header (seq, flags) + zero or more raw IP packets,
     * wrapped in one TXT record. We only care about the payload.
     */
    private fun handleResponse(msg: ByteArray, len: Int, inflight: MutableMap<Int, Long>) {
        if (len < 12) return
        val qid = ((msg[0].toInt() and 0xFF) shl 8) or (msg[1].toInt() and 0xFF)
        if (inflight.remove(qid) != null) recvOk++ else badQid++

        val payload = parseTxt(msg, len) ?: return
        if (payload.size <= 3) return

        downBytes.addAndGet((payload.size - 3).toLong())
        var off = 3
        while (off + 20 <= payload.size) {
            if ((payload[off].toInt() and 0xF0) != 0x40) break
            val total = ((payload[off + 2].toInt() and 0xFF) shl 8) or (payload[off + 3].toInt() and 0xFF)
            if (total <= 0 || off + total > payload.size) break
            writeToTun(payload, off, total)
            off += total
        }
    }

    /** wall clock of the last reply we processed (0 = none yet) */
    private val lastReplyAt = java.util.concurrent.atomic.AtomicLong(0)

    private var recvOk = 0L
    private var badQid = 0L

    private fun parseTxt(msg: ByteArray, len: Int): ByteArray? {
        var off = 12
        val qd = ((msg[4].toInt() and 0xFF) shl 8) or (msg[5].toInt() and 0xFF)
        val an = ((msg[6].toInt() and 0xFF) shl 8) or (msg[7].toInt() and 0xFF)
        for (i in 0 until qd) {
            while (off < len && msg[off].toInt() != 0) off += 1 + (msg[off].toInt() and 0xFF)
            off += 5
        }
        for (i in 0 until an) {
            if (off + 2 > len) return null
            if ((msg[off].toInt() and 0xC0) == 0xC0) {
                off += 2
            } else {
                while (off < len && msg[off].toInt() != 0) off += 1 + (msg[off].toInt() and 0xFF)
                off += 1
            }
            if (off + 10 > len) return null
            val rtype = ((msg[off].toInt() and 0xFF) shl 8) or (msg[off + 1].toInt() and 0xFF)
            val rdlen = ((msg[off + 8].toInt() and 0xFF) shl 8) or (msg[off + 9].toInt() and 0xFF)
            off += 10
            if (off + rdlen > len) return null
            if (rtype == 16) {
                val out = ByteArray(rdlen)
                var n = 0
                var i2 = off
                val end = off + rdlen
                while (i2 < end) {
                    val sl = msg[i2].toInt() and 0xFF
                    i2++
                    val take = min(sl, end - i2)
                    System.arraycopy(msg, i2, out, n, take)
                    n += take
                    i2 += take
                }
                return out.copyOf(n)
            }
            off += rdlen
        }
        return null
    }

    // ------------------------------------------------------------- base32

    private val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray()

    private fun base32(data: ByteArray): String {
        val sb = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                sb.append(ALPHABET[(buffer ushr (bits - 5)) and 0x1F])
                bits -= 5
            }
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 0x1F])
        return sb.toString()
    }
}
