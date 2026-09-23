package com.dnstun.app

import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket
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
private const val MAX_CHUNK = 140

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
    private val onStats: (TunnelStats) -> Unit,
) {
    private val running = AtomicBoolean(false)
    private val queue = ArrayDeque<ByteArray>()
    private val queueLock = Object()

    private val sent = AtomicLong()
    private val recv = AtomicLong()
    private val lost = AtomicLong()
    private val upBytes = AtomicLong()
    private val downBytes = AtomicLong()

    private var channel: DatagramChannel? = null
    private var tunOut: FileOutputStream? = null
    private var fragCounter = 0
    private var depth = cfg.startDepth

    @Volatile
    private var lastLoss = 0.0

    fun start() {
        if (!running.compareAndSet(false, true)) return
        depth = cfg.startDepth
        thread(name = "dnstun-tun") { tunReader() }
        thread(name = "dnstun-udp") { udpLoop() }
    }

    fun stop() {
        running.set(false)
        runCatching { channel?.close() }
        channel = null
    }

    // ------------------------------------------------------------------ tun

    private fun tunReader() {
        val input = FileInputStream(tun.fileDescriptor)
        val buf = ByteArray(max(1500, cfg.mtu))
        while (running.get()) {
            val n = try {
                input.read(buf)
            } catch (e: Exception) {
                if (running.get()) Log.w(TAG, "tun read: ${e.message}")
                break
            }
            if (n <= 0) continue
            upBytes.addAndGet(n.toLong())
            fragment(buf, n)
        }
    }

    private fun fragment(pkt: ByteArray, n: Int) {
        val id = fragCounter++ and 0xFFFF
        var off = 0
        var idx = 0
        while (off < n) {
            val len = min(MAX_CHUNK, n - off)
            val chunk = ByteArray(4 + len)
            chunk[0] = (id ushr 8).toByte()
            chunk[1] = (id and 0xFF).toByte()
            chunk[2] = idx.toByte()
            chunk[3] = if (off + len < n) FLAG_MORE.toByte() else 0
            System.arraycopy(pkt, off, chunk, 4, len)
            synchronized(queueLock) {
                if (queue.size < 8192) queue.addLast(chunk)
            }
            off += len
            idx++
        }
    }

    private fun writeToTun(pkt: ByteArray, off: Int, len: Int) {
        val out = tunOut ?: FileOutputStream(tun.fileDescriptor).also { tunOut = it }
        try {
            out.write(pkt, off, len)
        } catch (e: Exception) {
            if (running.get()) Log.w(TAG, "tun write: ${e.message}")
            runCatching { out.close() }
            tunOut = null
        }
    }

    // ------------------------------------------------------------------ udp

    private fun udpLoop() {
        val ch = try {
            DatagramChannel.open()
        } catch (e: Exception) {
            Log.e(TAG, "channel: ${e.message}")
            return
        }
        ch.configureBlocking(false)
        protectSocket(ch.socket())
        channel = ch
        val resolver = InetSocketAddress(InetAddress.getByName(cfg.resolver), cfg.port)
        val rnd = Random(System.nanoTime())
        val inflight = HashMap<Int, Long>()
        val rcv = ByteBuffer.allocate(4096)

        var lastStat = System.currentTimeMillis()
        var lastAdapt = lastStat
        var statSent = 0L
        var statRecv = 0L
        var statDown = 0L
        var statUp = 0L
        var statLost = 0L
        var lastStatTime = lastStat

        while (running.get()) {
            // ---- keep `depth` queries in flight ----
            var guard = 0
            while (inflight.size < depth && guard++ < 512) {
                val chunk = synchronized(queueLock) { queue.removeFirstOrNull() }
                val name = if (chunk != null) encodeName(chunk) else pollName()
                val qid = rnd.nextInt(1, 65536)
                val q = buildQuery(name, qid)
                try {
                    ch.send(ByteBuffer.wrap(q), resolver)
                } catch (e: Exception) {
                    if (running.get()) Log.w(TAG, "send: ${e.message}")
                    break
                }
                inflight[qid] = System.currentTimeMillis()
                sent.incrementAndGet()
            }

            // ---- drain everything that is waiting ----
            var got = false
            while (true) {
                rcv.clear()
                val from = try {
                    ch.receive(rcv)
                } catch (e: Exception) {
                    break
                } ?: break
                got = true
                recv.incrementAndGet()
                lastReplyAt.set(nowMs())
                rcv.flip()
                val len = rcv.remaining()
                val data = ByteArray(len)
                rcv.get(data)
                handleResponse(data, len, inflight)
            }

            // ---- drop queries that never came back ----
            val now = System.currentTimeMillis()
            val stale = ArrayList<Int>()
            for ((qid, at) in inflight) if (now - at > 3000) stale.add(qid)
            for (qid in stale) {
                inflight.remove(qid)
                lost.incrementAndGet()
            }

            // ---- stats + depth tuning every second ----
            if (now - lastStat >= 1000) {
                val dt = (now - lastStatTime) / 1000.0
                val qps = (recv.get() - statRecv) / dt
                val down = (downBytes.get() - statDown) / dt
                val up = (upBytes.get() - statUp) / dt
                val dSent = sent.get() - statSent
                val dLost = lost.get() - statLost
                lastLoss = if (dSent > 0) 100.0 * dLost / dSent else 0.0
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
                    )
                )
                statSent = sent.get()
                statRecv = recv.get()
                statDown = downBytes.get()
                statUp = upBytes.get()
                statLost = lost.get()
                lastStat = now
                lastStatTime = now

                if (now - lastAdapt >= 2000) {
                    lastAdapt = now
                    when {
                        lastLoss < 4.0 && depth < cfg.maxDepth -> depth += 16
                        lastLoss > 8.0 && depth > cfg.minDepth -> depth -= 16
                    }
                    if (depth < cfg.minDepth) depth = cfg.minDepth
                    if (depth > cfg.maxDepth) depth = cfg.maxDepth
                }
            }

            if (!got) Thread.sleep(1)
        }
    }

    // ------------------------------------------------------- wire format

    /**
     * Poll query with fresh random bytes. Resolvers cache answers to repeated
     * names - even TTL=0 ones - so a constant poll name would make every reply
     * after the first come back empty.
     */
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
    private fun handleResponse(msg: ByteArray, len: Int, inflight: HashMap<Int, Long>) {
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
