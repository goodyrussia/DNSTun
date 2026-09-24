package com.dnstun.app

import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * JNI bridge to the patched hev-socks5-tunnel that SlipNet ships (same
 * sources, same udp:'tcp' mode). Native libs: libhev-socks5-tunnel.so +
 * libhev-tunnel-jni.so, both built from app/src/main/cpp.
 *
 * With `udp: 'tcp'` every UDP datagram the TUN sees (i.e. all of Android's
 * DNS) is forwarded to our engine's SOCKS5 listener as FWD_UDP (cmd 0x05)
 * frames on a TCP connection -- no kernel delivery tricks, no dnsgw, no
 * packet rewriting. TCP streams become plain SOCKS5 CONNECTs.
 */
object HevTunnel {
    private const val TAG = "HevTunnel"

    private var loaded = false

    init {
        try {
            System.loadLibrary("hev-socks5-tunnel")
            System.loadLibrary("hev-tunnel-jni")
            loaded = true
            Log.i(TAG, "native libraries loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "native libraries: ${e.message}")
            loaded = false
        }
    }

    fun isLoaded(): Boolean = loaded

    fun start(
        tunFd: ParcelFileDescriptor,
        socksPort: Int,
        mtu: Int,
        ipv4Address: String,
        disableQuic: Boolean = true,
        rejectNonDnsUdp: Boolean = true,
    ): Boolean {
        if (!loaded) return false
        if (isRunning()) {
            Log.w(TAG, "already running, stopping first")
            stop()
        }

        val config = buildString {
            append("tunnel:\n")
            append("  mtu: $mtu\n")
            append("  ipv4: $ipv4Address\n")
            append("  ipv6: fd00::1\n\n")
            append("socks5:\n")
            append("  address: 127.0.0.1\n")
            append("  port: $socksPort\n")
            append("  udp: 'tcp'\n\n")
            append("misc:\n")
            append("  task-stack-size: 32768\n")
            append("  connect-timeout: 8000\n")
            append("  tcp-read-write-timeout: 120000\n")
            append("  udp-read-write-timeout: 60000\n")
            append("  log-level: warning\n")
        }

        Log.i(TAG, "hev start socks5=127.0.0.1:$socksPort mtu=$mtu ipv4=$ipv4Address")
        Log.i(TAG, "config:\n$config")

        return try {
            nativeSetRejectQuic(disableQuic)
            nativeSetRejectNonDnsUdp(rejectNonDnsUdp)
            val r = nativeStart(config, tunFd.fd)
            Log.i(TAG, "nativeStart -> $r")
            r == 0
        } catch (e: Exception) {
            Log.e(TAG, "start: ${e.message}")
            false
        }
    }

    fun stop() {
        if (!loaded) return
        try {
            nativeStop()
        } catch (e: Exception) {
            Log.e(TAG, "stop: ${e.message}")
        }
    }

    fun isRunning(): Boolean =
        loaded && try {
            nativeIsRunning()
        } catch (e: Exception) {
            false
        }

    /** tx = TUN -> tunnel (upload), rx = tunnel -> TUN (download). */
    fun getStats(): LongArray? =
        if (!loaded || !isRunning()) null
        else try {
            nativeGetStats()
        } catch (e: Exception) {
            null
        }

    private external fun nativeStart(config: String, tunFd: Int): Int
    private external fun nativeStop()
    private external fun nativeSetRejectQuic(enabled: Boolean)
    private external fun nativeSetRejectNonDnsUdp(enabled: Boolean)
    private external fun nativeIsRunning(): Boolean
    private external fun nativeGetStats(): LongArray?
}
