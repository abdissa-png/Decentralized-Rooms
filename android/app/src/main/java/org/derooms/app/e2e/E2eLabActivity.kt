package org.derooms.app.e2e

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.ScrollView
import android.widget.TextView
import java.io.File
import java.util.concurrent.Executors

/**
 * secureDebug lab Activity driven by adb intents (API 26+ / API 28 Lenovo OK).
 *
 * `--es cmd consumer|provider|bootstrap|listen|serve|send`
 */
class E2eLabActivity : Activity() {
    private val executor = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private lateinit var logView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        logView = TextView(this).apply {
            textSize = 12f
            setPadding(24, 24, 24, 24)
            setTextIsSelectable(true)
        }
        setContentView(ScrollView(this).apply { addView(logView) })
        E2eLabHarness.log("E2E_ACTIVITY_ONCREATE")
        handle(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent?) {
        val cmd = intent?.getStringExtra(EXTRA_CMD)?.trim().orEmpty()
        E2eLabHarness.log("E2E_CMD_RECV cmd=$cmd")
        if (cmd.isEmpty()) {
            append("missing cmd extra")
            E2eLabHarness.log("E2E_FAIL missing_cmd")
            return
        }
        append("cmd=$cmd")
        executor.execute {
            try {
                runCmd(cmd, intent!!)
            } catch (e: Exception) {
                E2eLabHarness.log(
                    "E2E_FAIL exception:${e.javaClass.name}:${e.message}",
                )
                append("fail: ${e.message}")
            }
        }
    }

    private fun runCmd(cmd: String, intent: Intent) {
        val files = filesDir
        E2eLabHarness.initExchange(files)
        val ex = E2eLabHarness.exchangeDir()
        when (cmd) {
            "bootstrap" -> {
                val role = intent.getStringExtra(EXTRA_ROLE) ?: "lab"
                val ok = E2eLabHarness.bootstrap(files, role)
                append(if (ok) "bootstrap ok" else "bootstrap fail")
            }
            "listen" -> {
                val ip = intent.getStringExtra(EXTRA_ADVERTISE_IP) ?: "127.0.0.1"
                val port = intent.getIntExtra(EXTRA_PORT, E2eLabHarness.LISTEN_PORT)
                val addr = E2eLabHarness.listen(ip, port)
                append(if (addr != null) "listen $addr" else "listen fail")
            }
            "serve" -> {
                val vk = intent.getStringExtra(EXTRA_AUTHOR_VK)
                    ?: File(ex, "peer_device_pubkey.hex").takeIf { it.exists() }?.readText()?.trim()
                    ?: ""
                val ok = E2eLabHarness.servePull(vk)
                append(if (ok) "serve decrypt ok" else "serve fail")
            }
            "send" -> {
                val prekey = intent.getStringExtra(EXTRA_PEER_PREKEY)
                    ?: File(ex, "peer_prekey.b64").takeIf { it.exists() }?.readText()?.trim()
                    ?: ""
                val addr = intent.getStringExtra(EXTRA_PEER_ADDR)
                    ?: File(ex, "peer_listen_addr.txt").takeIf { it.exists() }?.readText()?.trim()
                    ?: ""
                val ok = E2eLabHarness.sendPush(prekey, addr)
                append(if (ok) "send ok" else "send fail")
            }
            "consumer" -> {
                val ip = intent.getStringExtra(EXTRA_ADVERTISE_IP) ?: "127.0.0.1"
                val port = intent.getIntExtra(EXTRA_PORT, E2eLabHarness.LISTEN_PORT)
                if (!E2eLabHarness.bootstrap(files, "bob")) {
                    append("consumer bootstrap fail")
                    return
                }
                val addr = E2eLabHarness.listen(ip, port)
                if (addr == null) {
                    append("consumer listen fail")
                    return
                }
                E2eLabHarness.log("E2E_CONSUMER_READY")
                append("consumer ready; waiting author vk + pull")
                val vkExtra = intent.getStringExtra(EXTRA_AUTHOR_VK).orEmpty()
                val authorVk = waitForText(
                    initial = vkExtra,
                    file = File(ex, "peer_device_pubkey.hex"),
                    timeoutMs = 90_000,
                )
                if (authorVk.isEmpty()) {
                    E2eLabHarness.log("E2E_FAIL no_author_vk")
                    append("no author vk")
                    return
                }
                val ok = E2eLabHarness.servePull(authorVk)
                append(if (ok) "consumer PASS" else "consumer FAIL")
            }
            "provider" -> {
                if (!E2eLabHarness.bootstrap(files, "alice")) {
                    append("provider bootstrap fail")
                    return
                }
                E2eLabHarness.log(
                    "E2E_PROVIDER_READY vk=${E2eLabHarness.exportDevicePubkeyHex().take(16)}",
                )
                append("provider ready; waiting peer materials")
                val prekey = waitForText("", File(ex, "peer_prekey.b64"), 90_000)
                val peerAddr = waitForText("", File(ex, "peer_listen_addr.txt"), 90_000)
                if (prekey.isEmpty() || peerAddr.isEmpty()) {
                    E2eLabHarness.log("E2E_FAIL missing_peer_material")
                    append("missing peer material")
                    return
                }
                val ok = E2eLabHarness.sendPush(prekey, peerAddr)
                append(if (ok) "provider PASS" else "provider FAIL")
            }
            "peer_recv" -> runPeerRecv(intent, files, ex)
            "peer_send" -> runPeerSend(files, ex)
            "ble_recv" -> runBleRecv(intent)
            "ble_send" -> runBleSend(intent)
            "wd_recv" -> runWdRecv(intent)
            "wd_send" -> runWdSend(intent)
            "sync_now" -> {
                org.derooms.app.sync.OpportunisticSyncWorker.enqueueNow(this)
                E2eLabHarness.log("E2E_SYNC_NOW")
                append("sync_now enqueued")
            }
            "fgs_start" -> {
                org.derooms.app.sync.SyncForegroundService.start(this)
                E2eLabHarness.log("E2E_SYNC_FGS_START")
                append("fgs_start")
            }
            "fgs_stop" -> {
                org.derooms.app.sync.SyncForegroundService.stop(this)
                E2eLabHarness.log("E2E_SYNC_FGS_STOP")
                append("fgs_stop")
            }
            "sync_status" -> {
                val prefs = getSharedPreferences(
                    org.derooms.app.sync.OpportunisticSyncWorker.PREFS,
                    MODE_PRIVATE,
                )
                val fgs = prefs.getLong(
                    org.derooms.app.sync.SyncForegroundService.PREF_FGS_STARTED,
                    0L,
                )
                val beat = prefs.getLong(
                    org.derooms.app.sync.SyncForegroundService.PREF_FGS_HEARTBEAT,
                    0L,
                )
                val opp = prefs.getLong(
                    org.derooms.app.sync.OpportunisticSyncWorker.PREF_LAST_OPPORTUNISTIC,
                    0L,
                )
                val syncNow = prefs.getLong("last_sync_now_ms", 0L)
                E2eLabHarness.log(
                    "E2E_SYNC_STATUS fgs_started_ms=$fgs fgs_beat_ms=$beat " +
                        "opp_ms=$opp sync_now_ms=$syncNow",
                )
                append("sync_status ok")
            }
            else -> {
                E2eLabHarness.log("E2E_FAIL unknown_cmd:$cmd")
                append("unknown cmd")
            }
        }
    }

    /** Start BLE mesh + wait for sealed GATT frame (receiver role). */
    private fun runBleRecv(intent: Intent) {
        val timeoutSec = intent.getIntExtra(EXTRA_TIMEOUT_SEC, 90)
        val latch = java.util.concurrent.CountDownLatch(1)
        val got = java.util.concurrent.atomic.AtomicBoolean(false)
        val ble = org.derooms.app.ble.BleMeshController(
            context = this,
            onStatus = { E2eLabHarness.log("E2E_BLE_STATUS $it") },
            onPeerSeen = { id -> E2eLabHarness.log("E2E_BLE_PEER_SEEN id=${id.take(16)}") },
            onSealedDelivered = { sealed ->
                E2eLabHarness.log("E2E_BLE_RECV_OK bytes=${sealed.size}")
                got.set(true)
                latch.countDown()
            },
        )
        ble.start()
        E2eLabHarness.log("E2E_BLE_RECV_READY")
        append("ble_recv waiting ${timeoutSec}s")
        val ok = latch.await(timeoutSec.toLong(), java.util.concurrent.TimeUnit.SECONDS) && got.get()
        append(if (ok) "ble_recv PASS" else "ble_recv FAIL")
        if (!ok) E2eLabHarness.log("E2E_FAIL ble_recv_timeout")
        // Keep GATT server up briefly so the sender can finish write callbacks.
        if (ok) Thread.sleep(3_000)
        ble.stop()
    }

    /** Start BLE mesh, queue sealed payload, wait for GATT send marker. */
    private fun runBleSend(intent: Intent) {
        val timeoutSec = intent.getIntExtra(EXTRA_TIMEOUT_SEC, 90)
        val payloadHex = intent.getStringExtra(EXTRA_BLE_PAYLOAD_HEX)
        val sealed = if (!payloadHex.isNullOrBlank()) {
            hexToBytes(payloadHex)
        } else {
            // Lab opaque sealed stub (ciphertext-shaped bytes — no plaintext on air).
            ByteArray(32) { (0xB0 + (it % 16)).toByte() }
        }
        if (sealed.isEmpty() || sealed.size > org.derooms.app.ble.BleMeshController.MAX_SEALED) {
            E2eLabHarness.log("E2E_FAIL ble_payload")
            append("ble_send bad payload")
            return
        }
        val ble = org.derooms.app.ble.BleMeshController(
            context = this,
            onStatus = { msg ->
                E2eLabHarness.log("E2E_BLE_STATUS $msg")
            },
            onPeerSeen = { id -> E2eLabHarness.log("E2E_BLE_PEER_SEEN id=${id.take(16)}") },
            onSealedDelivered = { s ->
                E2eLabHarness.log("E2E_BLE_RECV_OK bytes=${s.size}")
            },
        )
        ble.start()
        // Give advertise/scan a moment, then queue so handoff can fire on peer seen.
        Thread.sleep(2_000)
        ble.queueSealedPayload(sealed)
        E2eLabHarness.log("E2E_BLE_SEND_QUEUED bytes=${sealed.size}")
        append("ble_send queued; waiting handoff ${timeoutSec}s")
        // Success is logged from BleMeshController as E2E_BLE_SEND_OK; wait window for RF.
        Thread.sleep(timeoutSec * 1000L)
        append("ble_send done")
        ble.stop()
    }

    /** Best-effort Wi‑Fi Direct bulk receive (OEM may flake — markers still useful). */
    private fun runWdRecv(intent: Intent) {
        val timeoutSec = intent.getIntExtra(EXTRA_TIMEOUT_SEC, 90)
        val latch = java.util.concurrent.CountDownLatch(1)
        val got = java.util.concurrent.atomic.AtomicBoolean(false)
        val wd = org.derooms.app.wifi.WifiDirectBulkController(
            context = this,
            onStatus = { E2eLabHarness.log("E2E_WD_STATUS $it") },
            onSealedDelivered = { sealed ->
                E2eLabHarness.log("E2E_WD_RECV_OK bytes=${sealed.size}")
                got.set(true)
                latch.countDown()
            },
        )
        // GO stance first so ServerSocket is ready when sender joins.
        wd.startReceive()
        E2eLabHarness.log("E2E_WD_RECV_READY")
        append("wd_recv waiting ${timeoutSec}s")
        val ok = latch.await(timeoutSec.toLong(), java.util.concurrent.TimeUnit.SECONDS) && got.get()
        append(if (ok) "wd_recv PASS" else "wd_recv FAIL (OEM flake residual OK)")
        if (!ok) E2eLabHarness.log("E2E_WD_RECV_TIMEOUT")
        wd.stop()
    }

    /** Best-effort Wi‑Fi Direct bulk send of opaque sealed stub (>BLE Low size). */
    private fun runWdSend(intent: Intent) {
        val timeoutSec = intent.getIntExtra(EXTRA_TIMEOUT_SEC, 90)
        val sealed = ByteArray(2048) { (0xC0 + (it % 16)).toByte() }
        val sendOk = java.util.concurrent.atomic.AtomicBoolean(false)
        val wd = org.derooms.app.wifi.WifiDirectBulkController(
            context = this,
            onStatus = { msg ->
                E2eLabHarness.log("E2E_WD_STATUS $msg")
                if (msg.contains("sent ") && msg.contains("sealed")) {
                    sendOk.set(true)
                }
            },
            onSealedDelivered = { s ->
                E2eLabHarness.log("E2E_WD_RECV_OK bytes=${s.size}")
            },
        )
        // Sender stance: discover + connect (do not create competing GO).
        wd.start(asReceiver = false)
        Thread.sleep(5_000)
        wd.queueSealedPayload(sealed, tip = "lab-bulk")
        wd.connectAndSend()
        E2eLabHarness.log("E2E_WD_SEND_QUEUED bytes=${sealed.size}")
        append("wd_send queued; waiting ${timeoutSec}s")
        val deadline = System.currentTimeMillis() + timeoutSec * 1000L
        while (System.currentTimeMillis() < deadline && !sendOk.get()) {
            Thread.sleep(1_000)
        }
        append(if (sendOk.get()) "wd_send PASS" else "wd_send done (markers may still arrive)")
        wd.stop()
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        if (clean.length % 2 != 0) return ByteArray(0)
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    /** Product-path smoke: PeerChatController listen → sender card → decrypt. */
    private fun runPeerRecv(intent: Intent, files: File, ex: File) {
        val ip = intent.getStringExtra(EXTRA_ADVERTISE_IP) ?: "127.0.0.1"
        val port = intent.getIntExtra(EXTRA_PORT, E2eLabHarness.LISTEN_PORT)
        if (!E2eLabHarness.bootstrap(files, "bob")) {
            append("peer_recv bootstrap fail")
            return
        }
        val latch = java.util.concurrent.CountDownLatch(1)
        val got = java.util.concurrent.atomic.AtomicBoolean(false)
        val controller = org.derooms.app.peer.PeerChatController(
            context = this,
            onMessage = { line ->
                if (!line.outbound) {
                    E2eLabHarness.log("E2E_PEER_UI_DECRYPT_OK text=${line.text.take(32)}")
                    got.set(true)
                    latch.countDown()
                }
            },
            onStatus = { E2eLabHarness.log("E2E_PEER_UI_STATUS $it") },
            onInviteReady = { inv ->
                File(ex, "peer_invite.txt").writeText(inv)
                E2eLabHarness.log("E2E_PEER_UI_RECV_READY")
            },
        )
        controller.setDeviceVkHex(E2eLabHarness.exportDevicePubkeyHex())
        controller.startListening(port, advertiseIp = ip)
        // Wait until invite file exists (listen finished).
        if (waitForText("", File(ex, "peer_invite.txt"), 30_000).isEmpty()) {
            E2eLabHarness.log("E2E_FAIL peer_invite_missing")
            append("peer_recv no invite")
            return
        }
        val card = waitForText("", File(ex, "peer_sender_card.txt"), 90_000)
        if (card.isEmpty()) {
            E2eLabHarness.log("E2E_FAIL no_sender_card")
            append("peer_recv no sender card")
            return
        }
        controller.pasteSenderCard(card)
        val ok = latch.await(90, java.util.concurrent.TimeUnit.SECONDS) && got.get()
        append(if (ok) "peer_recv PASS" else "peer_recv FAIL")
        if (!ok) E2eLabHarness.log("E2E_FAIL peer_ui_decrypt")
    }

    /** Product-path smoke: PeerChatController connect + send. */
    private fun runPeerSend(files: File, ex: File) {
        if (!E2eLabHarness.bootstrap(files, "alice")) {
            append("peer_send bootstrap fail")
            return
        }
        val sent = java.util.concurrent.atomic.AtomicBoolean(false)
        val latch = java.util.concurrent.CountDownLatch(1)
        val controller = org.derooms.app.peer.PeerChatController(
            context = this,
            onMessage = { line ->
                if (line.outbound) {
                    E2eLabHarness.log("E2E_PEER_UI_SEND_OK")
                    sent.set(true)
                    latch.countDown()
                }
            },
            onStatus = { E2eLabHarness.log("E2E_PEER_UI_STATUS $it") },
        )
        controller.setDeviceVkHex(E2eLabHarness.exportDevicePubkeyHex())
        E2eLabHarness.log("E2E_PEER_UI_SEND_READY")
        val invite = waitForText("", File(ex, "peer_invite.txt"), 90_000)
        if (invite.isEmpty()) {
            E2eLabHarness.log("E2E_FAIL no_peer_invite")
            append("peer_send no invite")
            return
        }
        controller.pastePeerInvite(invite)
        // Wait until establish finishes on controller executor.
        val deadline = System.currentTimeMillis() + 15_000
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(200)
        }
        val card = controller.mySenderCardText()
        File(ex, "peer_sender_card.txt").writeText(card)
        E2eLabHarness.log("E2E_PEER_UI_CARD_WRITTEN")
        // Host script copies card to Bob; wait for go-ahead before push.
        val go = waitForText("", File(ex, "peer_go_send.txt"), 90_000)
        if (go.isEmpty()) {
            E2eLabHarness.log("E2E_FAIL no_go_send")
            append("peer_send no go")
            return
        }
        controller.sendMessage("peer-ui-e2e-1")
        val ok = latch.await(90, java.util.concurrent.TimeUnit.SECONDS) && sent.get()
        append(if (ok) "peer_send PASS" else "peer_send FAIL")
        if (!ok) E2eLabHarness.log("E2E_FAIL peer_ui_send")
    }

    private fun waitForText(initial: String, file: File, timeoutMs: Long): String {
        if (initial.isNotBlank()) return initial.trim()
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (file.exists()) {
                val t = file.readText().trim()
                if (t.isNotEmpty()) return t
            }
            Thread.sleep(250)
        }
        return ""
    }

    private fun append(line: String) {
        main.post { logView.append(line + "\n") }
    }

    companion object {
        const val EXTRA_CMD = "cmd"
        const val EXTRA_ROLE = "role"
        const val EXTRA_ADVERTISE_IP = "advertise_ip"
        const val EXTRA_PORT = "port"
        const val EXTRA_AUTHOR_VK = "author_vk_hex"
        const val EXTRA_PEER_PREKEY = "peer_prekey_b64"
        const val EXTRA_PEER_ADDR = "peer_addr"
        const val EXTRA_BLE_PAYLOAD_HEX = "ble_payload_hex"
        const val EXTRA_TIMEOUT_SEC = "timeout_sec"
    }
}
