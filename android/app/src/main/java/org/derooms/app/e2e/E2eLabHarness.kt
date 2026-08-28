package org.derooms.app.e2e

import android.util.Base64
import android.util.Log
import org.derooms.app.core.CreatedIdentityBundle
import org.derooms.app.core.RoomsCoreBridge
import org.derooms.app.crypto.IdentityKeystore
import org.derooms.app.signal.LibsignalSession
import uniffi.rooms.SyncLabNode
import java.io.File
import java.util.concurrent.atomic.AtomicReference

/**
 * In-process Gate 1 lab harness. Exchange files under `filesDir/derooms-e2e`
 * (adb: `run-as org.derooms.app`). Never logs secret blobs.
 */
object E2eLabHarness {
    const val TAG = "DEROOMS_E2E"
    val ROOM_ID: ByteArray = ByteArray(32) { 0xE2.toByte() }
    const val PLAINTEXT = "cross-device-e2e-1"
    const val LISTEN_PORT = 44001

    private val identityBundle = AtomicReference<CreatedIdentityBundle?>(null)
    private val secretPlain = AtomicReference<ByteArray?>(null)
    private val signalSession = AtomicReference<LibsignalSession?>(null)
    private val syncNode = AtomicReference<SyncLabNode?>(null)
    private val exchangeRoot = AtomicReference<File?>(null)

    fun initExchange(filesDir: File): File {
        val dir = File(filesDir, "derooms-e2e")
        dir.mkdirs()
        exchangeRoot.set(dir)
        log("E2E_EXCHANGE_DIR ${dir.absolutePath}")
        return dir
    }

    fun exchangeDir(): File =
        exchangeRoot.get() ?: error("exchange dir not initialized")

    fun ensureNative(): Boolean {
        log("E2E_NATIVE_LOAD_BEGIN")
        RoomsCoreBridge.tryLoadNative()
        val uniffi = RoomsCoreBridge.isNativeUsable()
        val sig = LibsignalSession.isNativeAvailable()
        log("E2E_NATIVE_LOAD uniffi=$uniffi libsignal=$sig")
        return uniffi && sig
    }

    fun bootstrap(filesDir: File, role: String): Boolean {
        initExchange(filesDir)
        if (!ensureNative()) {
            log("E2E_FAIL native missing")
            return false
        }
        log("E2E_BOOTSTRAP_BEGIN role=$role")
        val bundle = RoomsCoreBridge.createIdentityBundle()
        val wrapped = IdentityKeystore.wrap(bundle.secretBlob)
        File(filesDir, "identity.wrap").writeBytes(wrapped.blob)
        secretPlain.set(bundle.secretBlob.copyOf())
        identityBundle.set(bundle)

        log("E2E_SIGNAL_CREATE")
        val session = LibsignalSession.create(role)
        signalSession.set(session)

        val ex = exchangeDir()
        File(ex, "device_pubkey.hex").writeText(bundle.publicIdentity.devicePubkeyHex)
        File(ex, "identity_id.hex").writeText(bundle.publicIdentity.identityIdHex)
        val prekeyB64 = Base64.encodeToString(session.exportPreKeyBundle(), Base64.NO_WRAP)
        File(ex, "prekey.b64").writeText(prekeyB64)
        log("E2E_BOOTSTRAP_OK role=$role id=${bundle.publicIdentity.identityIdHex.take(16)}")
        return true
    }

    fun listen(advertiseIp: String, port: Int = LISTEN_PORT): String? {
        if (!ensureNative()) return null
        log("E2E_LISTEN_BEGIN ip=$advertiseIp port=$port")
        val node = syncNode.get() ?: SyncLabNode().also { syncNode.set(it) }
        val bind = "/ip4/0.0.0.0/tcp/$port"
        val dial = node.listenTcp(bind, advertiseIp, 15_000u)
        if (dial.startsWith("ERROR:")) {
            log("E2E_FAIL listen $dial")
            return null
        }
        File(exchangeDir(), "listen_addr.txt").writeText(dial)
        log("E2E_LISTEN_OK $dial")
        log("E2E_PEER_ID ${node.localPeerId()}")
        return dial
    }

    fun servePull(authorDevicePubkeyHex: String, timeoutMs: UInt = 90_000u): Boolean {
        val node = syncNode.get()
        val session = signalSession.get()
        if (node == null || session == null) {
            log("E2E_FAIL serve_not_ready")
            return false
        }
        val vk = hexToBytes(authorDevicePubkeyHex)
        if (vk.size != 32) {
            log("E2E_FAIL bad_author_vk len=${authorDevicePubkeyHex.length}")
            return false
        }
        session.acceptIncomingFrom("alice", 1)
        log("E2E_SESSION_OK inbound_accept alice")
        log("E2E_PULL_WAIT")
        val sealed = node.syncPullOneEvent(ROOM_ID, vk, timeoutMs)
        val asText = sealed.toString(Charsets.UTF_8)
        if (sealed.isEmpty() || asText.startsWith("ERR:")) {
            log("E2E_FAIL pull $asText")
            return false
        }
        log("E2E_SYNC_RECV_OK bytes=${sealed.size}")
        return try {
            val opened = session.decrypt(sealed)
            val text = opened.toString(Charsets.UTF_8)
            if (text == PLAINTEXT) {
                log("E2E_DECRYPT_OK")
                true
            } else {
                log("E2E_FAIL decrypt_mismatch len=${text.length}")
                false
            }
        } catch (e: Exception) {
            log("E2E_FAIL decrypt ${e.javaClass.simpleName}:${e.message}")
            false
        }
    }

    fun sendPush(peerPrekeyB64: String, peerMultiaddr: String, timeoutMs: UInt = 90_000u): Boolean {
        val session = signalSession.get()
        val secret = secretPlain.get()
        if (session == null || secret == null) {
            log("E2E_FAIL send_not_ready")
            return false
        }
        if (!ensureNative()) return false
        val prekey = Base64.decode(peerPrekeyB64, Base64.DEFAULT)
        return try {
            session.establish(ByteArray(0), prekey)
            log("E2E_SESSION_OK establish")
            val sealed = session.encrypt(PLAINTEXT.toByteArray(Charsets.UTF_8))
            val wire = RoomsCoreBridge.createSignedTextEvent(secret, ROOM_ID, sealed, emptyList())
            if (wire.wireEnvelope.isEmpty()) {
                log("E2E_FAIL sign_empty")
                return false
            }
            val node = syncNode.get() ?: SyncLabNode().also { syncNode.set(it) }
            log("E2E_PUSH_BEGIN addr=$peerMultiaddr")
            val tip = node.syncPushSignedEvent(
                secret,
                ROOM_ID,
                wire.wireEnvelope,
                peerMultiaddr,
                timeoutMs,
            )
            if (tip.startsWith("ERROR:") || tip.length != 64) {
                log("E2E_FAIL push $tip")
                return false
            }
            log("E2E_SYNC_SEND_OK tip=${tip.take(16)}")
            true
        } catch (e: Exception) {
            log("E2E_FAIL send ${e.javaClass.simpleName}:${e.message}")
            false
        }
    }

    fun exportDevicePubkeyHex(): String =
        identityBundle.get()?.publicIdentity?.devicePubkeyHex.orEmpty()

    fun log(msg: String) {
        Log.println(Log.INFO, TAG, msg)
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        if (clean.length % 2 != 0) return ByteArray(0)
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
