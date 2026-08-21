package org.derooms.app.wifi

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.WpsInfo
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.content.ContextCompat
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Best-effort Wi‑Fi Direct bulk path for **already-sealed** payloads
 * (BandwidthClass::High / media-sized). Wire format matches
 * `rooms_sync::WifiDirectSealedFrame` (`DRWD`).
 *
 * Reliability hardening (Gate 2 residual):
 * - Receive stance creates a local P2P group (GO) so the socket is ready
 * - Periodic rediscovery + connect retries with cancelConnect
 * - Prefer AVAILABLE peers; transfer-in-flight guard; SO_REUSEADDR
 *
 * OEM honesty: some devices still flake on P2P. Host simulation in
 * `rooms-sync` covers CI. See `docs/wifi-direct.md`.
 */
class WifiDirectBulkController(
    private val context: Context,
    private val onStatus: (String) -> Unit,
    private val onSealedDelivered: (sealed: ByteArray) -> Unit = {},
) {
    private val executor = Executors.newSingleThreadExecutor()
    private val scheduler: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val manager = context.applicationContext.getSystemService(Context.WIFI_P2P_SERVICE)
        as? WifiP2pManager
    private var channel: WifiP2pManager.Channel? = null
    private val running = AtomicBoolean(false)
    private val receiveStance = AtomicBoolean(false)
    private val transferBusy = AtomicBoolean(false)
    private val connectAttempts = AtomicInteger(0)
    private val outbound = AtomicReference<ByteArray?>(null)
    private val tipHex = AtomicReference("bulk")
    private val peers = AtomicReference<List<WifiP2pDevice>>(emptyList())
    private var receiver: BroadcastReceiver? = null
    private var rediscoverFuture: java.util.concurrent.ScheduledFuture<*>? = null
    private var connectRetryFuture: java.util.concurrent.ScheduledFuture<*>? = null

    fun hasPermissions(): Boolean {
        val fine = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_FINE_LOCATION,
        ) == PackageManager.PERMISSION_GRANTED
        if (Build.VERSION.SDK_INT >= 33) {
            val near = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.NEARBY_WIFI_DEVICES,
            ) == PackageManager.PERMISSION_GRANTED
            return fine || near
        }
        return fine
    }

    /** Queue sealed payload (≤ [MAX_SEALED] B). Tip is an opaque hex / label. */
    fun queueSealedPayload(sealed: ByteArray, tip: String = "bulk") {
        if (sealed.isEmpty() || sealed.size > MAX_SEALED) {
            onStatus("Wi‑Fi Direct payload out of range (1..$MAX_SEALED B).")
            return
        }
        tipHex.set(tip.take(64).ifEmpty { "bulk" })
        outbound.set(sealed.copyOf())
        onStatus("Queued ${sealed.size} B sealed for Wi‑Fi Direct bulk.")
        Log.i(TAG, "E2E_WD_QUEUED bytes=${sealed.size}")
    }

    /**
     * Start discovery. When [asReceiver] is true (default for “Start WD”),
     * also create a local group so this device becomes GO and can accept.
     */
    fun start(asReceiver: Boolean = true) {
        if (manager == null) {
            onStatus("Wi‑Fi Direct unavailable on this device.")
            Log.i(TAG, "E2E_WD_UNAVAILABLE")
            return
        }
        if (!hasPermissions()) {
            onStatus("Wi‑Fi Direct needs location / Nearby Wi‑Fi permission.")
            return
        }
        if (!running.compareAndSet(false, true)) {
            // Already running — refresh discover / group if needed.
            if (asReceiver) ensureGroupOwner()
            discover()
            return
        }
        receiveStance.set(asReceiver)
        channel = manager.initialize(context.applicationContext, Looper.getMainLooper(), null)
        registerReceiver()
        discover()
        if (asReceiver) {
            ensureGroupOwner()
        }
        scheduleRediscover()
        onStatus(
            if (asReceiver) {
                "Wi‑Fi Direct ready (group owner stance) — peer should Start WD then Send."
            } else {
                "Wi‑Fi Direct discovery started (sender stance)."
            },
        )
        Log.i(TAG, "E2E_WD_START receiver=$asReceiver")
    }

    /** Explicit receive stance (lab `wd_recv` / UI Start WD). */
    fun startReceive() = start(asReceiver = true)

    fun stop() {
        running.set(false)
        receiveStance.set(false)
        transferBusy.set(false)
        connectAttempts.set(0)
        rediscoverFuture?.cancel(false)
        rediscoverFuture = null
        connectRetryFuture?.cancel(false)
        connectRetryFuture = null
        try {
            channel?.let { ch ->
                manager?.stopPeerDiscovery(ch, null)
                manager?.cancelConnect(ch, null)
                manager?.removeGroup(ch, null)
            }
        } catch (_: Exception) {
        }
        unregisterReceiver()
        channel = null
        onStatus("Wi‑Fi Direct stopped.")
    }

    /**
     * Connect to a discovered peer and transfer queued sealed bytes.
     * Retries up to [MAX_CONNECT_ATTEMPTS] with cancelConnect between tries.
     */
    fun connectAndSend() {
        executor.execute {
            val sealed = outbound.get()
            if (sealed == null) {
                onStatus("Queue a sealed payload first.")
                return@execute
            }
            if (!running.get()) {
                onStatus("Start Wi‑Fi Direct first.")
                return@execute
            }
            receiveStance.set(false)
            connectAttempts.set(0)
            attemptConnect()
            scheduleConnectRetries()
        }
    }

    private fun scheduleConnectRetries() {
        connectRetryFuture?.cancel(false)
        connectRetryFuture = scheduler.scheduleAtFixedRate({
            if (!running.get() || outbound.get() == null || transferBusy.get()) {
                connectRetryFuture?.cancel(false)
                return@scheduleAtFixedRate
            }
            if (connectAttempts.get() >= MAX_CONNECT_ATTEMPTS) {
                onStatus("Wi‑Fi Direct connect budget exhausted — OEM flake residual.")
                Log.i(TAG, "E2E_WD_CONNECT_EXHAUSTED")
                connectRetryFuture?.cancel(false)
                return@scheduleAtFixedRate
            }
            attemptConnect()
        }, 4, 5, TimeUnit.SECONDS)
    }

    private fun attemptConnect() {
        val peer = pickPeer()
        if (peer == null) {
            onStatus("No Wi‑Fi Direct peer yet — keep devices close / Wi‑Fi on.")
            Log.i(TAG, "E2E_WD_NO_PEER")
            discover()
            return
        }
        val ch = channel ?: run {
            onStatus("Start Wi‑Fi Direct first.")
            return
        }
        val attempt = connectAttempts.incrementAndGet()
        val config = WifiP2pConfig().apply {
            deviceAddress = peer.deviceAddress
            wps.setup = WpsInfo.PBC
            // Prefer joining peer's group when they hold receive stance.
            groupOwnerIntent = 0
        }
        onStatus("Connecting Wi‑Fi Direct to ${peer.deviceName} (try $attempt)…")
        Log.i(TAG, "E2E_WD_CONNECT_TRY attempt=$attempt peer=${peer.deviceName}")
        try {
            manager?.cancelConnect(ch, null)
        } catch (_: Exception) {
        }
        manager?.connect(
            ch,
            config,
            object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    onStatus("P2P connect requested — waiting group…")
                    Log.i(TAG, "E2E_WD_CONNECT_OK attempt=$attempt")
                }

                override fun onFailure(reason: Int) {
                    onStatus("Wi‑Fi Direct connect failed (reason=$reason). Retrying…")
                    Log.i(TAG, "E2E_WD_CONNECT_FAIL reason=$reason attempt=$attempt")
                    discover()
                }
            },
        )
    }

    private fun pickPeer(): WifiP2pDevice? {
        val list = peers.get()
        return list.firstOrNull { it.status == WifiP2pDevice.AVAILABLE }
            ?: list.firstOrNull { it.status == WifiP2pDevice.INVITED }
            ?: list.firstOrNull { it.status == WifiP2pDevice.CONNECTED }
            ?: list.firstOrNull { it.status != WifiP2pDevice.UNAVAILABLE }
    }

    private fun ensureGroupOwner() {
        val ch = channel ?: return
        manager?.createGroup(
            ch,
            object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    onStatus("Wi‑Fi Direct group created (waiting peer)…")
                    Log.i(TAG, "E2E_WD_CREATE_GROUP_OK")
                }

                override fun onFailure(reason: Int) {
                    // BUSY often means a group already exists — still OK.
                    onStatus("createGroup note (reason=$reason) — rediscovering.")
                    Log.i(TAG, "E2E_WD_CREATE_GROUP_FAIL reason=$reason")
                    discover()
                }
            },
        )
    }

    /** Listen as group owner / client once connection info arrives. */
    private fun onConnectionInfo(info: WifiP2pInfo) {
        if (!transferBusy.compareAndSet(false, true)) {
            Log.i(TAG, "E2E_WD_TRANSFER_SKIP busy")
            return
        }
        executor.execute {
            try {
                if (!info.groupFormed) {
                    onStatus("P2P group not formed.")
                    transferBusy.set(false)
                    return@execute
                }
                Log.i(TAG, "E2E_WD_GROUP_FORMED go=${info.isGroupOwner}")
                onStatus(
                    if (info.isGroupOwner) {
                        "P2P group formed — we are owner."
                    } else {
                        "P2P group formed — joining owner."
                    },
                )
                val sealed = outbound.get()
                if (info.isGroupOwner) {
                    serveAsOwner(sealed)
                } else {
                    val host = info.groupOwnerAddress?.hostAddress
                    if (host.isNullOrBlank()) {
                        onStatus("No group owner address.")
                        return@execute
                    }
                    // Client: retry dial to GO — GO may still be binding.
                    if (sealed != null) {
                        clientSendWithRetry(host, sealed)
                    } else {
                        clientRecvWithRetry(host)
                    }
                }
            } catch (e: Exception) {
                onStatus("Wi‑Fi Direct transfer error: ${e.message}")
                Log.i(TAG, "E2E_WD_ERR ${e.message}")
            } finally {
                transferBusy.set(false)
            }
        }
    }

    private fun serveAsOwner(outboundSealed: ByteArray?) {
        ServerSocket().use { server ->
            server.reuseAddress = true
            server.soTimeout = 60_000
            server.bind(InetSocketAddress(PORT))
            onStatus("Wi‑Fi Direct GO listening on $PORT…")
            Log.i(TAG, "E2E_WD_GO_LISTEN port=$PORT")
            val sock = server.accept()
            sock.soTimeout = 60_000
            sock.use { s ->
                if (outboundSealed != null) {
                    writeFrame(s, tipHex.get(), outboundSealed)
                    outbound.compareAndSet(outboundSealed, null)
                    Log.i(TAG, "E2E_WD_SEND_OK bytes=${outboundSealed.size}")
                    onStatus("Wi‑Fi Direct sent ${outboundSealed.size} B sealed.")
                    connectRetryFuture?.cancel(false)
                    tryReadIncoming(s)
                } else {
                    tryReadIncoming(s)
                }
            }
        }
    }

    private fun clientSendWithRetry(host: String, sealed: ByteArray) {
        var last: Exception? = null
        repeat(CLIENT_DIAL_ATTEMPTS) { i ->
            try {
                Socket().use { sock ->
                    sock.soTimeout = 45_000
                    sock.connect(InetSocketAddress(host, PORT), 12_000)
                    writeFrame(sock, tipHex.get(), sealed)
                    outbound.compareAndSet(sealed, null)
                    Log.i(TAG, "E2E_WD_SEND_OK bytes=${sealed.size}")
                    onStatus("Wi‑Fi Direct sent ${sealed.size} B sealed.")
                    connectRetryFuture?.cancel(false)
                    return
                }
            } catch (e: Exception) {
                last = e
                Log.i(TAG, "E2E_WD_CLIENT_DIAL_FAIL attempt=${i + 1} ${e.message}")
                Thread.sleep(1_200L * (i + 1))
            }
        }
        onStatus("Wi‑Fi Direct client send failed: ${last?.message}")
        Log.i(TAG, "E2E_WD_ERR ${last?.message}")
    }

    private fun clientRecvWithRetry(host: String) {
        var last: Exception? = null
        repeat(CLIENT_DIAL_ATTEMPTS) { i ->
            try {
                Socket().use { sock ->
                    sock.soTimeout = 45_000
                    sock.connect(InetSocketAddress(host, PORT), 12_000)
                    tryReadIncoming(sock)
                    return
                }
            } catch (e: Exception) {
                last = e
                Log.i(TAG, "E2E_WD_CLIENT_DIAL_FAIL attempt=${i + 1} ${e.message}")
                Thread.sleep(1_200L * (i + 1))
            }
        }
        onStatus("Wi‑Fi Direct client recv failed: ${last?.message}")
        Log.i(TAG, "E2E_WD_ERR ${last?.message}")
    }

    private fun tryReadIncoming(sock: Socket) {
        try {
            val frame = readFrame(sock) ?: return
            onSealedDelivered(frame.second)
            Log.i(TAG, "E2E_WD_RECV_OK bytes=${frame.second.size} tip=${frame.first}")
            onStatus("Wi‑Fi Direct received ${frame.second.size} B sealed.")
            connectRetryFuture?.cancel(false)
        } catch (_: Exception) {
            // Peer may not send — OK for one-way lab.
        }
    }

    private fun discover() {
        val ch = channel ?: return
        manager?.discoverPeers(
            ch,
            object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    onStatus("Peer discovery active.")
                    Log.i(TAG, "E2E_WD_DISCOVER_OK")
                }

                override fun onFailure(reason: Int) {
                    onStatus("Discover failed (reason=$reason). Try Wi‑Fi on + location.")
                    Log.i(TAG, "E2E_WD_DISCOVER_FAIL reason=$reason")
                }
            },
        )
    }

    private fun scheduleRediscover() {
        rediscoverFuture?.cancel(false)
        rediscoverFuture = scheduler.scheduleAtFixedRate({
            if (!running.get()) return@scheduleAtFixedRate
            mainHandler.post {
                if (!running.get()) return@post
                discover()
                // Receive stance: re-assert GO if OEM dropped the group.
                if (receiveStance.get() && outbound.get() == null) {
                    ensureGroupOwner()
                }
            }
        }, 8, 12, TimeUnit.SECONDS)
    }

    private fun registerReceiver() {
        if (receiver != null) return
        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
        }
        receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                when (intent.action) {
                    WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                        val state = intent.getIntExtra(
                            WifiP2pManager.EXTRA_WIFI_STATE,
                            WifiP2pManager.WIFI_P2P_STATE_DISABLED,
                        )
                        if (state != WifiP2pManager.WIFI_P2P_STATE_ENABLED) {
                            onStatus("Wi‑Fi P2P disabled — turn Wi‑Fi on.")
                            Log.i(TAG, "E2E_WD_P2P_DISABLED")
                        }
                    }
                    WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                        val ch = channel ?: return
                        manager?.requestPeers(ch) { list ->
                            peers.set(list.deviceList.toList())
                            val n = list.deviceList.size
                            if (n > 0) {
                                val names = list.deviceList.joinToString(",") { it.deviceName }
                                onStatus("Wi‑Fi Direct peers: $n ($names)")
                                Log.i(TAG, "E2E_WD_PEER_SEEN count=$n")
                            }
                        }
                    }
                    WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                        val ch = channel ?: return
                        @Suppress("DEPRECATION")
                        val networkInfo =
                            intent.getParcelableExtra<android.net.NetworkInfo>(
                                WifiP2pManager.EXTRA_NETWORK_INFO,
                            )
                        if (networkInfo != null && !networkInfo.isConnected) {
                            Log.i(TAG, "E2E_WD_DISCONNECTED")
                            return
                        }
                        manager?.requestConnectionInfo(ch) { info ->
                            if (info != null && info.groupFormed) {
                                onConnectionInfo(info)
                            }
                        }
                    }
                }
            }
        }
        ContextCompat.registerReceiver(
            context,
            receiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    private fun unregisterReceiver() {
        receiver?.let {
            try {
                context.unregisterReceiver(it)
            } catch (_: Exception) {
            }
        }
        receiver = null
    }

    companion object {
        const val TAG = "DEROOMS_WD"
        const val PORT = 45455
        /** Matches `rooms_sync::WD_MAX_SEALED_PAYLOAD`. */
        const val MAX_SEALED = 256 * 1024
        private const val MAX_CONNECT_ATTEMPTS = 6
        private const val CLIENT_DIAL_ATTEMPTS = 5
        private val MAGIC = byteArrayOf('D'.code.toByte(), 'R'.code.toByte(), 'W'.code.toByte(), 'D'.code.toByte())

        /** Encode DRWD frame (tip + sealed). */
        fun encodeFrame(tip: String, sealed: ByteArray): ByteArray {
            val tipBytes = tip.toByteArray(Charsets.US_ASCII).take(64).toByteArray()
            val out = ByteArray(4 + 1 + 1 + tipBytes.size + 4 + sealed.size)
            System.arraycopy(MAGIC, 0, out, 0, 4)
            out[4] = 1
            out[5] = tipBytes.size.toByte()
            System.arraycopy(tipBytes, 0, out, 6, tipBytes.size)
            val lenOff = 6 + tipBytes.size
            val len = sealed.size
            out[lenOff] = (len and 0xff).toByte()
            out[lenOff + 1] = ((len shr 8) and 0xff).toByte()
            out[lenOff + 2] = ((len shr 16) and 0xff).toByte()
            out[lenOff + 3] = ((len shr 24) and 0xff).toByte()
            System.arraycopy(sealed, 0, out, lenOff + 4, sealed.size)
            return out
        }

        fun writeFrame(sock: Socket, tip: String, sealed: ByteArray) {
            val dos = DataOutputStream(sock.getOutputStream())
            val frame = encodeFrame(tip, sealed)
            dos.writeInt(frame.size)
            dos.write(frame)
            dos.flush()
        }

        fun readFrame(sock: Socket): Pair<String, ByteArray>? {
            val dis = DataInputStream(sock.getInputStream())
            val n = dis.readInt()
            if (n <= 0 || n > MAX_SEALED + 128) return null
            val buf = ByteArray(n)
            dis.readFully(buf)
            return decodeFrame(buf)
        }

        fun decodeFrame(bytes: ByteArray): Pair<String, ByteArray>? {
            if (bytes.size < 4 + 1 + 1 + 4) return null
            if (bytes[0] != MAGIC[0] || bytes[1] != MAGIC[1] ||
                bytes[2] != MAGIC[2] || bytes[3] != MAGIC[3]
            ) {
                return null
            }
            if (bytes[4].toInt() != 1) return null
            val tipLen = bytes[5].toInt() and 0xff
            if (tipLen == 0 || tipLen > 64 || 6 + tipLen + 4 > bytes.size) return null
            val tip = String(bytes, 6, tipLen, Charsets.US_ASCII)
            val lenOff = 6 + tipLen
            val sealedLen = (bytes[lenOff].toInt() and 0xff) or
                ((bytes[lenOff + 1].toInt() and 0xff) shl 8) or
                ((bytes[lenOff + 2].toInt() and 0xff) shl 16) or
                ((bytes[lenOff + 3].toInt() and 0xff) shl 24)
            val start = lenOff + 4
            if (sealedLen < 0 || sealedLen > MAX_SEALED || start + sealedLen > bytes.size) {
                return null
            }
            return tip to bytes.copyOfRange(start, start + sealedLen)
        }
    }
}
