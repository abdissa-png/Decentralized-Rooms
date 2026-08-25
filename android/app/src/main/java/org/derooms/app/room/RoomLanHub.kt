package org.derooms.app.room

import android.content.Context
import org.derooms.app.core.RoomsCoreBridge
import org.derooms.app.crypto.IdentityKeystore
import org.derooms.app.onMainUi
import org.derooms.app.peer.PeerChatController
import uniffi.rooms.SyncLabNode
import java.io.File
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Process-scoped room LAN listener + inbox.
 *
 * RoomScreen used to bind/release TCP on every enter/leave. Leaving dropped the
 * socket, so the peer’s saved `/tcp/44002` got Connection refused. Ephemeral
 * fallback made that worse: we advertised a random port the peer never learned.
 */
class RoomLanHub(
    private val context: Context,
    private val roomStore: RoomStore,
) {
    private val nodeHolder = AtomicSyncNode()
    private val inboxExecutor = Executors.newSingleThreadExecutor()
    private val handlers = ConcurrentHashMap<String, (ByteArray, String) -> Unit>()
    private val activeRoomId = AtomicReference("")
    private val activePeerVk = AtomicReference("")
    private val inboxStarted = AtomicBoolean(false)

    @Volatile
    var listenDialAddr: String = ""
        private set

    fun node(): SyncLabNode = nodeHolder.getOrCreate()

    fun ensureListen(): String {
        listenDialAddr.takeIf { it.isNotEmpty() && !it.startsWith("ERROR:") }?.let { return it }
        synchronized(this) {
            listenDialAddr.takeIf { it.isNotEmpty() && !it.startsWith("ERROR:") }?.let { return it }
            val existing = try {
                node().listenDialAddr()
            } catch (_: Throwable) {
                ""
            }
            if (existing.isNotEmpty() && !existing.startsWith("ERROR:")) {
                listenDialAddr = existing
                return existing
            }
            if (!RoomsCoreBridge.isNativeUsable()) return "ERROR:uniffi"
            val ip = discoverLocalIpv4() ?: return "ERROR:no_lan_ip"
            val node = node()
            var dial = node.listenTcp("/ip4/0.0.0.0/tcp/$LISTEN_PORT", ip, 15_000u)
            if (dial.contains("Address already in use", ignoreCase = true) ||
                dial.contains("os error 98", ignoreCase = true)
            ) {
                try {
                    Thread.sleep(250)
                } catch (_: InterruptedException) {
                }
                dial = node.listenTcp("/ip4/0.0.0.0/tcp/$LISTEN_PORT", ip, 15_000u)
            }
            if (!dial.startsWith("ERROR:")) {
                listenDialAddr = dial
            }
            return dial
        }
    }

    fun startInbox(
        roomIdHex: String,
        peerVkHex: String,
        onEvent: ((ByteArray, String) -> Unit)? = null,
    ) {
        val roomId = roomIdHex.trim().lowercase()
        val vk = peerVkHex.trim().lowercase()
        if (roomId.length != 64) return
        if (onEvent != null) handlers[roomId] = onEvent
        if (vk.length == 64) {
            activeRoomId.set(roomId)
            activePeerVk.set(vk)
        } else if (activeRoomId.get().isEmpty()) {
            activeRoomId.set(roomId)
        }
        ensureListen()
        if (!inboxStarted.compareAndSet(false, true)) return
        inboxExecutor.execute { pullLoop() }
    }

    fun clearUiHandler(roomIdHex: String) {
        handlers.remove(roomIdHex.trim().lowercase())
    }

    fun warmInboxes() {
        ensureListen()
        val first = roomStore.listRooms().firstOrNull { it.peerDeviceVkHex.trim().length == 64 }
        if (first != null) {
            startInbox(first.roomIdHex, first.peerDeviceVkHex, onEvent = null)
        }
    }

    fun rememberPeerVk(vkHex: String) {
        val vk = vkHex.trim()
        if (vk.length != 64) return
        try {
            node().rememberPeerDeviceVk(PeerChatController.hexToBytes(vk))
        } catch (_: Throwable) {
        }
    }

    fun pushWithRetry(
        secret: ByteArray,
        roomBytes: ByteArray,
        wire: ByteArray,
        peerAddr: String,
    ): String {
        val addrs = linkedSetOf(peerAddr.trim())
        val stable = withTcpPort(peerAddr, LISTEN_PORT)
        if (stable.isNotEmpty()) addrs.add(stable)
        var last = "ERROR:connect"
        repeat(3) { attempt ->
            for (addr in addrs) {
                if (addr.isEmpty()) continue
                last = node().syncPushSignedEvent(secret, roomBytes, wire, addr, 90_000u)
                if (!last.startsWith("ERROR:") && last.length >= 64) return last
                if (!last.contains("connect") && !last.contains("want_timeout") &&
                    !last.contains("ack_timeout")
                ) {
                    return last
                }
            }
            try {
                Thread.sleep(300L * (attempt + 1))
            } catch (_: InterruptedException) {
                return last
            }
        }
        return last
    }

    private fun pullLoop() {
        while (!Thread.currentThread().isInterrupted) {
            val roomId = activeRoomId.get().trim()
            val vkHex = activePeerVk.get().trim()
            if (roomId.length != 64 || vkHex.length != 64) {
                try {
                    Thread.sleep(400)
                } catch (_: InterruptedException) {
                    break
                }
                continue
            }
            try {
                val node = node()
                rememberPeerVk(vkHex)
                ensureListen()
                val ct = node.syncPullOneEvent(
                    PeerChatController.hexToBytes(roomId),
                    PeerChatController.hexToBytes(vkHex),
                    15_000u,
                )
                val asText = ct.toString(Charsets.UTF_8)
                if (ct.isEmpty() || asText.startsWith("ERR:")) {
                    continue
                }
                val tip = node.lastTipHex()
                val handler = handlers[roomId]
                onMainUi {
                    if (handler != null) {
                        handler(ct, tip)
                    } else {
                        applyWithoutUi(roomId, ct, tip)
                    }
                }
            } catch (_: InterruptedException) {
                break
            } catch (_: Exception) {
                try {
                    Thread.sleep(400)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }
        inboxStarted.set(false)
    }

    private fun applyWithoutUi(roomId: String, ct: ByteArray, eventIdHex: String) {
        val asText = ct.toString(Charsets.UTF_8)
        val handle = restoreRoom(roomId)
        when {
            asText.startsWith(RoomSyncTags.ACCEPT) -> {
                val receipt = asText.removePrefix(RoomSyncTags.ACCEPT)
                if (handle?.applyAcceptReceiptHex(receipt) == true) {
                    persistRoom(handle)
                }
            }
            asText.startsWith(RoomSyncTags.MEMBERSHIP) -> {
                val hex = asText.removePrefix(RoomSyncTags.MEMBERSHIP)
                if (handle != null &&
                    (handle.applyMembershipEventHex(hex) || handle.applyAcceptReceiptHex(hex))
                ) {
                    persistRoom(handle)
                }
            }
            asText.startsWith(RoomSyncTags.WELCOME) ||
                asText.startsWith(RoomSyncTags.COMMIT) ||
                asText.startsWith(RoomSyncTags.MLS_SEALED) -> {
                // Needs the MLS session on the room screen.
            }
            else -> {
                roomStore.appendLine(
                    roomId,
                    RoomStore.RoomLine(
                        outbound = false,
                        text = asText,
                        meta = "Peer · LAN",
                        eventIdHex = eventIdHex,
                        atMs = System.currentTimeMillis(),
                    ),
                )
            }
        }
    }

    private fun restoreRoom(roomId: String): org.derooms.app.core.LocalRoomHandle? {
        RoomSessionCache.getRoom(roomId)?.let { return it }
        val state = roomStore.roomStateFile(roomId)
        if (!state.exists()) return null
        val wrap = File(context.filesDir, "identity.wrap")
        if (!wrap.exists()) return null
        val secret = try {
            IdentityKeystore.unwrap(IdentityKeystore.WrappedSecret(wrap.readBytes()))
        } catch (_: Exception) {
            return null
        }
        val restored = RoomsCoreBridge.localRoomSessionFromStateBlob(secret, state.readBytes())
        if (!restored.roomIdHex().equals(roomId, ignoreCase = true)) return null
        RoomSessionCache.putRoom(roomId, restored)
        return restored
    }

    private fun persistRoom(handle: org.derooms.app.core.LocalRoomHandle) {
        val blob = handle.exportStateBlob()
        if (blob.isEmpty()) return
        val file = roomStore.roomStateFile(handle.roomIdHex())
        file.parentFile?.mkdirs()
        file.writeBytes(blob)
    }

    companion object {
        const val LISTEN_PORT = 44002

        fun withTcpPort(multiaddr: String, port: Int): String {
            val parts = multiaddr.split('/').filter { it.isNotEmpty() }.toMutableList()
            val tcpIdx = parts.indexOfFirst { it.equals("tcp", ignoreCase = true) }
            if (tcpIdx < 0 || tcpIdx + 1 >= parts.size) return ""
            parts[tcpIdx + 1] = port.toString()
            return "/" + parts.joinToString("/")
        }
    }
}

internal class AtomicSyncNode {
    @Volatile
    private var node: SyncLabNode? = null

    fun getOrCreate(): SyncLabNode {
        node?.let { return it }
        synchronized(this) {
            node?.let { return it }
            return SyncLabNode().also { node = it }
        }
    }
}

internal fun discoverLocalIpv4(): String? {
    try {
        val ifaces = java.util.Collections.list(NetworkInterface.getNetworkInterfaces())
        for (ni in ifaces) {
            if (!ni.isUp || ni.isLoopback) continue
            for (addr in java.util.Collections.list(ni.inetAddresses)) {
                if (addr is Inet4Address && !addr.isLoopbackAddress) {
                    return addr.hostAddress
                }
            }
        }
    } catch (_: Exception) {
    }
    return null
}
