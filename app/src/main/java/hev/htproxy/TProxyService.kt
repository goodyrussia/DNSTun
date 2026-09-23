package hev.htproxy

/**
 * JNI binding for libhev-socks5-tunnel.
 *
 * The library registers its natives in JNI_OnLoad against exactly this class
 * (PKGNAME/CLSNAME default to hev/htproxy + TProxyService), so the package and
 * class name must not change. The natives are registered as STATIC methods,
 * which is why they carry @JvmStatic.
 *
 * Signatures registered by src/hev-jni.c:
 *   TProxyStartService  (Ljava/lang/String;I)Z
 *   TProxyStopService   ()Z
 *   TProxyIsRunning     ()Z
 *   TProxyGetStats      ()[J
 */
object TProxyService {
    init {
        System.loadLibrary("hev-socks5-tunnel")
    }

    /** configPath points at the YAML config; fd is the VpnService tun fd. */
    @JvmStatic
    external fun TProxyStartService(configPath: String, fd: Int): Boolean

    @JvmStatic
    external fun TProxyStopService(): Boolean

    @JvmStatic
    external fun TProxyIsRunning(): Boolean

    /** returns [txBytes, rxBytes, ...] as reported by the C bridge */
    @JvmStatic
    external fun TProxyGetStats(): LongArray
}
