package com.dnstun.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {

    private lateinit var status: TextView
    private lateinit var button: Button
    private lateinit var resolver: EditText
    private lateinit var zone: EditText
    private lateinit var sid: EditText
    private lateinit var mtu: EditText
    private lateinit var depth: EditText

    private val handler = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() {
            render()
            handler.postDelayed(this, 500)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        status = findViewById(R.id.status)
        button = findViewById(R.id.connect)
        resolver = findViewById(R.id.resolver)
        zone = findViewById(R.id.zone)
        sid = findViewById(R.id.sid)
        mtu = findViewById(R.id.mtu)
        depth = findViewById(R.id.depth)

        val cfg = Config.load(this)
        resolver.setText(cfg.resolver)
        zone.setText(cfg.zone)
        sid.setText(cfg.sid)
        mtu.setText(cfg.mtu.toString())
        depth.setText(cfg.startDepth.toString())

        button.setOnClickListener {
            if (DnstunService.running) stop() else start()
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(ticker)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }

    private fun currentConfig(): Config {
        val d = Config()
        return Config(
            resolver = resolver.text.toString().trim().ifEmpty { d.resolver },
            zone = zone.text.toString().trim().ifEmpty { d.zone },
            sid = sid.text.toString().trim().ifEmpty { d.sid },
            mtu = mtu.text.toString().trim().toIntOrNull() ?: d.mtu,
            startDepth = depth.text.toString().trim().toIntOrNull() ?: d.startDepth,
        )
    }

    private fun start() {
        Config.save(this, currentConfig())
        val prep = VpnService.prepare(this)
        if (prep != null) {
            startActivityForResult(prep, 1)
            return
        }
        go()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == RESULT_OK) go()
        else if (requestCode == 1) Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
    }

    private fun go() {
        startForegroundServiceCompat(Intent(this, DnstunService::class.java).setAction(DnstunService.ACTION_START))
    }

    private fun stop() {
        startService(Intent(this, DnstunService::class.java).setAction(DnstunService.ACTION_STOP))
    }

    private fun startForegroundServiceCompat(i: Intent) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) startForegroundService(i)
        else startService(i)
    }

    private fun render() {
        val s = DnstunService.lastStats
        if (DnstunService.running) {
            button.text = "Disconnect"
            status.text = String.format(
                "connected\ndepth %d   %.0f q/s   loss %.1f%%\n%.1f KB/s down   %.1f KB/s up\ntotal %.1f MB down / %.1f MB up",
                s.depth, s.queriesPerSec, s.lossPercent,
                s.downKBps, s.upKBps,
                s.downBytes / 1048576.0, s.upBytes / 1048576.0
            )
        } else {
            button.text = "Connect"
            status.text = "disconnected"
        }
    }
}
