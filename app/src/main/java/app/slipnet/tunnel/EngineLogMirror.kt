package app.slipnet.tunnel

import java.io.File
import java.io.RandomAccessFile
import app.slipnet.util.AppLog as Log

/**
 * Follows the engine log file and mirrors new lines into the app log, so an
 * in-process engine failure is visible in the app instead of vanishing into
 * stderr (which Android discards for apps).
 */
object EngineLogMirror {
    private const val TAG = "EngineLog"

    @Volatile private var thread: Thread? = null
    @Volatile private var running = false

    fun start(path: String?) {
        if (path.isNullOrEmpty()) return
        stop()
        running = true
        thread = Thread {
            var raf: RandomAccessFile? = null
            try {
                raf = RandomAccessFile(File(path), "r")
                while (running) {
                    val line = raf.readLine()
                    if (line == null) {
                        Thread.sleep(400)
                    } else {
                        Log.i(TAG, line)
                    }
                }
            } catch (_: Throwable) {
            } finally {
                try { raf?.close() } catch (_: Throwable) {}
            }
        }.apply { isDaemon = true; name = "engine-log"; start() }
    }

    fun stop() {
        running = false
        thread?.interrupt()
        thread = null
    }
}
