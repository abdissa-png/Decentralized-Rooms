package org.derooms.app.peer

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import org.derooms.app.core.RoomsCoreBridge
import org.derooms.app.crypto.IdentityKeystore
import org.derooms.app.signal.LibsignalSession
import org.derooms.app.signal.PreKeyBundleCodec
import org.derooms.app.signal.SignalNotAvailableException
import uniffi.rooms.SyncLabNode
import java.io.File
import java.net.Inet4Address
import java.net.NetworkInterface
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Product 1:1 peer chat over the same LAN SyncLab + libsignal path as
 * [org.derooms.app.e2e.E2eLabHarness].
 *
 * Bidirectional MVP: one QR scan on LAN uploads the scanner's prekey on the
 * Kyber fetch socket so **both** Signal sessions exist. Either side can send
 * without a second QR. Legacy sender-card path remains for older scripts.
 */
class PeerChatController(
    private val context: Context,
    private var onMessage: (ChatLine) -> Unit,
    private var onStatus: (String) -> Unit,
    private var onInviteReady: (String) -> Unit = {},
    private var onConnectedChanged: (Boolean) -> Unit = {},
) {
    data class ChatLine(
        val peerKey: String,
        val outbound: Boolean,
        val text: String,
        val meta: String,
        val via: String = "",
        val deviceShort: String = "",
    )

    data class PeerInvite(
        val signalName: String,
        val deviceVkHex: String,
        val prekeyB64: String,
        val listenAddr: String,
        /** Optional `host:port` for TCP rooms-relay (invite auto-discovery). */
        val relayHostPort: String = "",
        val identityIdHex: String = "",
        val displayLabel: String = "",
    )

    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "derooms-peer-cmd").also { it.isDaemon = true }
    }
    private val receiveExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "derooms-peer-inbox").also { it.isDaemon = true }
    }
    private val listening = AtomicBoolean(false)
    private val receiving = AtomicBoolean(false)
    private val sessionRef = AtomicReference<LibsignalSession?>(null)
    private val syncRef = AtomicReference<SyncLabNode?>(null)
    private val secretRef = AtomicReference<ByteArray?>(null)
    private val deviceVkHexRef = AtomicReference<String>("")
    private val myInviteRef = AtomicReference<PeerInvite?>(null)
    private val peerInviteRef = AtomicReference<PeerInvite?>(null)
    private val peerDeviceVkHexRef = AtomicReference<String>("")
    private val establishedOutbound = AtomicBoolean(false)
    private val connected = AtomicBoolean(false)
    private val seenSealedTips = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
    private val relayHostPortRef = AtomicReference(loadPersistedRelay(context))
    /** `set` / `connecting` / `used` for Manage status. */
    private val relayPathRef = AtomicReference(
        if (relayHostPortRef.get().isNotBlank()) "set" else "",
    )
    private val kyberBootstrapRef = AtomicReference<InviteKyberBootstrap?>(null)
    private val pendingDeferredInvite = AtomicReference<PeerInvite?>(null)
    /** Full local invite (Kyber included) to ferry over BLE after handshake QR. */
    private val pendingBleHandshakeOffer = AtomicReference<ByteArray?>(null)
    private data class PendingSealed(val bytes: ByteArray, val via: String)
    private val pendingSealedUntilHandshake = ConcurrentLinkedQueue<PendingSealed>()
    /** A process restart creates a new in-memory Signal identity. */
    private val localSignalInviteRegenerated = AtomicBoolean(false)
    private val signalRepairInFlight = AtomicBoolean(false)
    private val conversations = ConversationStore(context)
    private val inboxEpoch = AtomicLong(0L)
    private val activeThreadKey = AtomicReference("")
    /** Detect identity.wrap rotation without process restart (Create identity). */
    private var identityWrapMtimeMs: Long = -1L
    /** Last advertised path key: Wi‑Fi IPv4 or `ble` — drives invite refresh. */
    private val lastAdvertiseKey = AtomicReference("")
    private val networkRefreshAtMs = AtomicLong(0L)
    private val mainHandler = Handler(Looper.getMainLooper())
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    fun listConversations(): List<ConversationStore.Contact> = conversations.list()

    fun inboxEpoch(): Long = inboxEpoch.get()

    fun contactDisplayName(): String {
        val key = lastPeerKey()
        return conversations.get(key)?.displayName
            ?: peerInviteRef.get()?.displayLabel?.takeIf { it.isNotBlank() }
            ?: ConversationStore.defaultName(peerDeviceVkHexRef.get(), peerInviteRef.get()?.identityIdHex.orEmpty())
    }

    fun setContactDisplayName(name: String) {
        val key = lastPeerKey()
        if (key.isBlank()) return
        conversations.setDisplayName(key, name)
        inboxEpoch.incrementAndGet()
    }

    fun openConversation(threadKey: String): Boolean {
        val contact = conversations.get(threadKey) ?: return false
        activeThreadKey.set(contact.threadKey)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(PREF_PEER_KEY, contact.threadKey)
            .apply()
        if (contact.inviteText.isNotBlank()) {
            pastePeerInvite(contact.inviteText)
        }
        return true
    }

    fun needsContactName(): Boolean = conversations.needsName(lastPeerKey())

    fun localDisplayName(): String = conversations.localDisplayName()

    fun setLocalDisplayName(name: String) {
        conversations.setLocalDisplayName(name)
        refreshInviteRelayLine()
    }

    fun localIdentityIdHex(): String {
        secretRef.get()?.let { s ->
            val id = RoomsCoreBridge.identityIdHexFromSecretBlob(s).trim()
            if (id.length == 64) return id
        }
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString("identity_id", "")
            .orEmpty()
    }

    fun noteLocalLine(text: String, outbound: Boolean, via: String) {
        val key = lastPeerKey()
        if (key.isBlank()) return
        val device = if (outbound) {
            ConversationStore.deviceShort(deviceVkHex())
        } else {
            ConversationStore.deviceShort(peerDeviceVkHexRef.get())
        }
        val line = ChatLine(
            peerKey = key,
            outbound = outbound,
            text = text,
            meta = ConversationStore.pathLabel(via),
            via = via,
            deviceShort = device,
        )
        appendTranscript(line)
    }

    fun isConnected(): Boolean = connected.get()

    /**
     * Rebind UI callbacks after leaving/re-entering Direct message. The
     * controller is Activity-scoped so Signal + invites survive Back.
     */
    fun attach(
        onMessage: (ChatLine) -> Unit,
        onStatus: (String) -> Unit,
        onInviteReady: (String) -> Unit,
        onConnectedChanged: (Boolean) -> Unit,
    ) {
        this.onMessage = onMessage
        this.onStatus = onStatus
        this.onInviteReady = onInviteReady
        this.onConnectedChanged = onConnectedChanged
        onConnectedChanged(connected.get())
        myInviteRef.get()?.let { publishInvite(it) }
    }

    fun signalReady(): Boolean = canSealMessages()

    fun isListening(): Boolean = listening.get()

    fun lastPeerKey(): String {
        val active = activeThreadKey.get()
        if (active.isNotBlank()) return active
        val inv = peerInviteRef.get()
        if (inv != null) return peerKey(inv)
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(PREF_PEER_KEY, "")
            .orEmpty()
    }

    /** True when peer invite has no LAN listen address (BLE / nearby only). */
    fun isBleOnlyPeer(): Boolean {
        val peer = peerInviteRef.get() ?: return false
        return isBleListenAddr(peer.listenAddr)
    }

    fun hasRelay(): Boolean = relayHostPortRef.get().isNotBlank()

    /**
     * True when the device has a validated (or at least INTERNET-capable) network.
     * Offline / airplane → false so nearby BLE can win over a configured relay.
     */
    fun hasUsableInternet(): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        return try {
            val network = cm.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(network) ?: return false
            val hasInternet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            // VALIDATED can lag right after radio up; INTERNET alone is enough to try relay.
            hasInternet && (validated || caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Nearby sealed BLE when the peer is BLE-only **and** either no rooms-relay
     * is set **or** this phone has no usable internet (relay would hang/fail).
     * With data/Wi‑Fi + relay, Send prefers rooms-relay for far-away peers.
     */
    fun shouldSendViaBle(): Boolean {
        if (!isBleOnlyPeer()) return false
        if (!hasRelay()) return true
        return !hasUsableInternet()
    }

    fun relayUiStatus(): String {
        val host = relayHostPortRef.get().trim()
        return when {
            host.isBlank() ->
                "Relay not set — needs a public rooms-relay for Wi‑Fi↔mobile or far-away phones."
            !hasUsableInternet() ->
                "Relay saved ($host) but no internet — nearby Send uses BLE until data/Wi‑Fi returns."
            relayPathRef.get() == "connecting" -> "Connecting via relay $host…"
            relayPathRef.get() == "used" -> "Last send used relay $host"
            else -> "Relay set: $host (ciphertext only; relay sees who connected, not plaintext)."
        }
    }

    /** True when libsignal outbound session can encrypt (invite Connect succeeded). */
    fun canSealMessages(): Boolean {
        if (!ensureReady()) return false
        val session = sessionRef.get() ?: return false
        return session.isEstablished()
    }

    /** TCP rooms-relay `host:port` (empty disables). Persisted in SharedPreferences. */
    fun relayHostPort(): String = relayHostPortRef.get()

    fun setRelayHostPort(hostPort: String) {
        val raw = hostPort.trim()
        val normalized = normalizeRelayHostPort(raw)
        if (raw.isNotEmpty() && normalized.isEmpty()) {
            onStatus("Relay address should look like host:44099 — clearing.")
        }
        relayHostPortRef.set(normalized)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(PREF_RELAY, normalized)
            .apply()
        relayPathRef.set(if (normalized.isNotBlank()) "set" else "")
        applyRelayConfig()
        if (normalized.isNotBlank()) {
            ensureRelayTransport()
        }
        // Refresh invite so `relay=` is present for the peer's auto-fallback.
        refreshInviteRelayLine()
    }

    fun applyDefaultPublicRelay(): Boolean {
        val baked = normalizeRelayHostPort(DEFAULT_PUBLIC_RELAY)
        if (baked.isEmpty()) {
            onStatus(
                "No public DeRooms relay is baked in. Self-host rooms-relay " +
                    "(TCP DRRL) and paste host:port. STUN/TURN, ngrok, and bore.pub " +
                    "are not drop-in replacements.",
            )
            return false
        }
        setRelayHostPort(baked)
        return true
    }

    private fun refreshInviteRelayLine() {
        val prev = myInviteRef.get() ?: return
        val refreshed = prev.copy(
            relayHostPort = relayHostPortRef.get().trim(),
            identityIdHex = localIdentityIdHex(),
            displayLabel = conversations.localDisplayName(),
        )
        myInviteRef.set(refreshed)
        persistSessionFiles()
        publishInvite(refreshed)
    }

    /**
     * BLE-only listen still stands up SyncLab + relay inbox so far-away /
     * mobile-data peers can Send after QR + handshake (no LAN Kyber fetch).
     */
    private fun ensureRelayTransport() {
        if (!hasRelay()) return
        if (!ensureReady()) return
        val node = syncLab()
        applyRelayConfig(node)
        listening.set(true)
        if (peerDeviceVkHexRef.get().length == 64) {
            startReceiveLoop()
        }
    }

    private fun shouldOpenInbox(): Boolean {
        if (peerDeviceVkHexRef.get().length != 64) return false
        if (hasRelay()) return true
        val mine = myInviteRef.get()?.listenAddr.orEmpty()
        return listening.get() && mine.isNotEmpty() && !isBleListenAddr(mine)
    }

    private fun publishInvite(inv: PeerInvite) {
        val text = encodeInvite(inv)
        val uri = PeerInviteUri.encode(text)
        val n = uri.toByteArray(Charsets.UTF_8).size
        Log.i(
            TAG,
            "E2E_INVITE_URI_LEN utf8=$n phoneQr=${n <= PeerInviteUri.PHONE_QR_MAX_BYTES}",
        )
        onInviteReady(text)
    }

    fun ensureReady(): Boolean {
        RoomsCoreBridge.tryLoadNative()
        if (!RoomsCoreBridge.isNativeUsable()) {
            onStatus("UniFFI native missing — rebuild FFI.")
            return false
        }
        if (!LibsignalSession.isNativeAvailable()) {
            onStatus("libsignal JNI missing — cannot seal.")
            return false
        }
        val wrap = File(context.filesDir, "identity.wrap")
        if (!wrap.exists()) {
            secretRef.set(null)
            identityWrapMtimeMs = -1L
            onStatus("Create identity first.")
            return false
        }
        val wrapMtime = wrap.lastModified()
        if (secretRef.get() == null || wrapMtime != identityWrapMtimeMs) {
            val rotated = identityWrapMtimeMs >= 0L && wrapMtime != identityWrapMtimeMs
            val secret = IdentityKeystore.unwrap(
                IdentityKeystore.WrappedSecret(wrap.readBytes()),
            )
            secretRef.set(secret)
            identityWrapMtimeMs = wrapMtime
            if (rotated) {
                // Invite QR uses device_vk from disk; stale secretRef caused applied0 /
                // ack_tips_mismatch after Create identity without killing the app.
                sessionRef.set(null)
                establishedOutbound.set(false)
                connected.set(false)
                Log.w(TAG, "E2E_IDENTITY_ROTATED reload secret + reset Signal session")
            }
            // Always derive device_vk from the signing secret — prefs/file can drift
            // and cause peer applied0 / ack_tips_mismatch on sync.
            syncDeviceVkFromSecret(secret)
        } else {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            deviceVkHexRef.set(prefs.getString("device_pubkey", "").orEmpty())
            val vkFile = File(context.filesDir, "device_pubkey.hex")
            if (vkFile.exists()) {
                deviceVkHexRef.set(vkFile.readText().trim())
            }
            secretRef.get()?.let { syncDeviceVkFromSecret(it) }
        }
        if (sessionRef.get() == null) {
            // Unique Signal address name per device — both using "local" caused
            // UntrustedIdentityException / Sealed-frame UI on BLE decrypt.
            val vk = deviceVkHexRef.get()
            val signalName = if (vk.length >= 16) "d${vk.take(16)}" else "d${System.nanoTime()}"
            val session = LibsignalSession.create(signalName)
            sessionRef.set(session)
        }
        // attach() can create the Signal session before restoreAfterEnter() loads
        // the persisted invite. Validate on every readiness pass, not only at
        // session construction time.
        val session = sessionRef.get() ?: return false
        val persisted = myInviteRef.get()
        val persistedPrekey = persisted?.prekeyB64?.let {
            try {
                Base64.decode(it, Base64.DEFAULT)
            } catch (_: Exception) {
                null
            }
        }
        if (persisted != null &&
            (persistedPrekey == null || !session.ownsPreKeyBundle(persistedPrekey))
        ) {
            // Never publish a prekey generated by a previous process: the
            // current in-memory Signal identity cannot decrypt messages for it.
            myInviteRef.set(null)
            File(context.filesDir, "peer_chat/my_invite.txt").delete()
            lastAdvertiseKey.set("")
            localSignalInviteRegenerated.set(true)
            connected.set(false)
            Log.w(
                TAG,
                "E2E_SIGNAL_INVITE_STALE regenerated local=${session.localIdentityFingerprint()}",
            )
        }
        return true
    }

    fun deviceVkHex(): String = deviceVkHexRef.get()

    fun setDeviceVkHex(hex: String) {
        deviceVkHexRef.set(hex.trim())
        File(context.filesDir, "device_pubkey.hex").writeText(hex.trim())
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString("device_pubkey", hex.trim())
            .apply()
    }

    /**
     * Invite `device_vk` must match the ed25519 key inside [secret], or peers
     * reject sync (`applied0` / `ack_tips_mismatch`).
     */
    private fun syncDeviceVkFromSecret(secret: ByteArray) {
        if (!RoomsCoreBridge.isNativeUsable() && !RoomsCoreBridge.tryLoadNative()) return
        val derived = RoomsCoreBridge.devicePubkeyHexFromSecretBlob(secret).trim()
        if (derived.length != 64) return
        val prev = deviceVkHexRef.get().trim()
        if (!prev.equals(derived, ignoreCase = true)) {
            Log.w(
                TAG,
                "E2E_DEVICE_VK_SYNC old=${prev.take(16)} new=${derived.take(16)} — rewriting invite key",
            )
            setDeviceVkHex(derived)
            // Stale my_invite would advertise the old vk; force rebuild on next listen.
            val mine = myInviteRef.get()
            if (mine != null && !mine.deviceVkHex.equals(derived, ignoreCase = true)) {
                myInviteRef.set(mine.copy(deviceVkHex = derived))
                persistSessionFiles()
                publishInvite(myInviteRef.get()!!)
            }
        } else if (prev.isEmpty()) {
            setDeviceVkHex(derived)
        }
    }

    fun localIpv4(): String? {
        val candidates = mutableListOf<LanAdvertise.Candidate>()
        try {
            val ifaces = Collections.list(NetworkInterface.getNetworkInterfaces())
            for (ni in ifaces) {
                if (!ni.isUp || ni.isLoopback) continue
                for (addr in Collections.list(ni.inetAddresses)) {
                    if (addr is Inet4Address && !addr.isLoopbackAddress) {
                        val host = addr.hostAddress ?: continue
                        candidates += LanAdvertise.Candidate(ni.name, host)
                    }
                }
            }
        } catch (_: Exception) {
        }
        val picked = LanAdvertise.pick(candidates)
        Log.i(
            TAG,
            "E2E_ADVERTISE_IP pick=$picked candidates=${candidates.joinToString { "${it.iface}=${it.host}" }}",
        )
        return picked
    }

    /** Start TCP listen and build a shareable invite (either role).
     * Without Wi‑Fi, still exports a BLE-capable invite (prekey + device_vk).
     * Re-entering / network changes rebind LAN vs relay-only cleanly. */
    fun startListening(port: Int = DEFAULT_PORT, advertiseIp: String? = null) {
        executor.execute {
            try {
                startNetworkWatch()
                doStartOrRefreshListening(port, advertiseIp, force = true, reason = "start_listening")
            } catch (e: Exception) {
                onStatus("Listen error: ${e.message}")
            }
        }
    }

    /**
     * Rebuild invite + QR for the **current** network (Wi‑Fi LAN vs mobile/relay).
     * Does not wipe identity or Signal session — only listen path + invite text.
     */
    fun refreshInviteForCurrentNetwork() {
        executor.execute {
            try {
                startNetworkWatch()
                doStartOrRefreshListening(DEFAULT_PORT, null, force = true, reason = "manual_refresh")
            } catch (e: Exception) {
                onStatus("Invite refresh failed: ${e.message}")
            }
        }
    }

    private fun scheduleNetworkInviteRefresh(reason: String) {
        mainHandler.post {
            val now = System.currentTimeMillis()
            val prev = networkRefreshAtMs.get()
            if (now - prev < 2_000L) return@post
            networkRefreshAtMs.set(now)
            executor.execute {
                try {
                    if (!ensureReady()) return@execute
                    // Only auto-refresh while the user is in a listen / Direct-message session.
                    if (!listening.get() && myInviteRef.get() == null) return@execute
                    doStartOrRefreshListening(DEFAULT_PORT, null, force = false, reason = reason)
                } catch (e: Exception) {
                    Log.w(TAG, "E2E_NET_REFRESH_FAIL $reason ${e.message}")
                }
            }
        }
    }

    private fun startNetworkWatch() {
        if (networkCallback != null) return
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                scheduleNetworkInviteRefresh("net_available")
            }

            override fun onLost(network: Network) {
                scheduleNetworkInviteRefresh("net_lost")
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                scheduleNetworkInviteRefresh("net_caps")
            }
        }
        try {
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            cm.registerNetworkCallback(req, cb)
            networkCallback = cb
            Log.i(TAG, "E2E_NET_WATCH on")
        } catch (e: Exception) {
            Log.w(TAG, "E2E_NET_WATCH_FAIL ${e.message}")
        }
    }

    private fun stopNetworkWatch() {
        val cb = networkCallback ?: return
        networkCallback = null
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            cm?.unregisterNetworkCallback(cb)
            Log.i(TAG, "E2E_NET_WATCH off")
        } catch (_: Exception) {
        }
    }

    private fun advertiseKey(ip: String?): String = ip?.trim().orEmpty().ifEmpty { "ble" }

    /**
     * Core listen / invite refresh. Must run on [executor].
     * @param force always rebuild invite UI even if path key unchanged
     */
    private fun doStartOrRefreshListening(
        port: Int,
        advertiseIp: String?,
        force: Boolean,
        reason: String,
    ) {
        if (!ensureReady()) return
        val session = sessionRef.get() ?: return
        val ip = advertiseIp?.takeIf { it.isNotBlank() } ?: localIpv4()
        val key = advertiseKey(ip)
        val existing = myInviteRef.get()
        val hadLan = existing?.listenAddr?.startsWith("/ip4/") == true
        val wantLan = ip != null
        val sameKey = key == lastAdvertiseKey.get() && existing != null

        if (existing != null && sameKey && listening.get()) {
            // Path unchanged: never rotate prekey / listen port / QR.
            val relay = relayHostPortRef.get().trim()
            if (existing.relayHostPort != relay ||
                existing.identityIdHex != localIdentityIdHex() ||
                existing.displayLabel != conversations.localDisplayName()
            ) {
                val refreshed = existing.copy(
                    relayHostPort = relay,
                    identityIdHex = localIdentityIdHex(),
                    displayLabel = conversations.localDisplayName(),
                )
                myInviteRef.set(refreshed)
                persistSessionFiles()
                publishInvite(refreshed)
                Log.i(TAG, "E2E_INVITE_STABLE_FIELDS reason=$reason")
            } else if (force) {
                publishInvite(existing)
                onStatus("Invite unchanged ($reason): ${existing.listenAddr}. Same QR.")
            }
            if (hasRelay()) ensureRelayTransport()
            maybeMarkConnected()
            return
        }

        // Path changed (Wi‑Fi ↔ mobile) or first listen — drop old LAN socket.
        if (hadLan && (!wantLan || !sameKey)) {
            stopKyberBootstrap()
            syncRef.get()?.let { node ->
                val r = node.releaseListen()
                Log.i(TAG, "E2E_LISTEN_RELEASE_FOR_NET $reason $r")
            }
        }

        lastAdvertiseKey.set(key)
        val prekey = existing
            ?.takeIf { it.signalName == session.name && it.prekeyB64.isNotBlank() }
            ?.prekeyB64
            ?: Base64.encodeToString(session.exportPreKeyBundle(), Base64.NO_WRAP)
        val vk = deviceVkHex()
        val identityId = localIdentityIdHex()
        val label = conversations.localDisplayName()

        if (!wantLan) {
            val invite = PeerInvite(
                signalName = session.name,
                deviceVkHex = vk,
                prekeyB64 = prekey,
                listenAddr = BLE_LISTEN_PLACEHOLDER,
                relayHostPort = relayHostPortRef.get().trim(),
                identityIdHex = identityId,
                displayLabel = label,
            )
            myInviteRef.set(invite)
            persistSessionFiles()
            publishInvite(invite)
            repairPeerAfterLocalSignalRegeneration()
            if (hasRelay()) {
                ensureRelayTransport()
                maybeMarkConnected()
                onStatus(
                    "Invite updated ($reason): no Wi‑Fi — relay ${relayHostPort()}. " +
                        "QR refreshed; Bluetooth off is OK for Send.",
                )
            } else {
                onStatus(
                    "Invite updated ($reason): no Wi‑Fi — ble://offline. " +
                        "Nearby: Start BLE. Far-away: Save a rooms-relay under Manage.",
                )
            }
            Log.i(TAG, "E2E_INVITE_REFRESH reason=$reason path=ble relay=${hasRelay()}")
            return
        }

        // Want LAN: bind (or rebind) TCP and publish /ip4/… invite.
        val node = syncLab()
        var dial = ""
        var boundPort = port
        for (p in port until port + 10) {
            val bind = "/ip4/0.0.0.0/tcp/$p"
            dial = node.listenTcp(bind, ip!!, 15_000u)
            if (!dial.startsWith("ERROR:")) {
                boundPort = p
                break
            }
            if (dial.contains("addr") || dial.contains("in use") || dial.contains("os error 98") ||
                dial.contains("Address already in use")
            ) {
                continue
            }
            onStatus("Listen failed: $dial")
            return
        }
        if (dial.startsWith("ERROR:") || dial.isEmpty()) {
            syncRef.getAndSet(null)
            val fresh = syncLab()
            dial = fresh.listenTcp("/ip4/0.0.0.0/tcp/$port", ip!!, 15_000u)
            if (dial.startsWith("ERROR:")) {
                onStatus("Listen failed: $dial — leave Direct message, wait a moment, retry.")
                return
            }
            boundPort = port
        }
        listening.set(true)
        val invite = PeerInvite(
            signalName = session.name,
            deviceVkHex = vk,
            prekeyB64 = prekey,
            listenAddr = dial,
            relayHostPort = relayHostPortRef.get().trim(),
            identityIdHex = identityId,
            displayLabel = label,
        )
        myInviteRef.set(invite)
        persistSessionFiles()
        applyRelayConfig()
        maybeStartKyberBootstrap(invite, boundPort)
        publishInvite(invite)
        repairPeerAfterLocalSignalRegeneration()
        if (shouldOpenInbox()) {
            startReceiveLoop()
        }
        maybeMarkConnected()
        val relay = relayHostPortRef.get()
        onStatus(
            if (relay.isNotBlank()) {
                "Invite updated ($reason): LAN $dial + relay $relay. QR refreshed."
            } else {
                "Invite updated ($reason): LAN $dial. QR refreshed."
            },
        )
        Log.i(TAG, "E2E_INVITE_REFRESH reason=$reason path=lan dial=$dial")
    }

    private fun repairPeerAfterLocalSignalRegeneration() {
        if (!localSignalInviteRegenerated.compareAndSet(true, false)) return
        val peer = peerInviteRef.get() ?: return
        Log.i(TAG, "E2E_SIGNAL_REPAIR_OFFER peer=${peer.signalName}")
        notifyPeerOfOurInvite(peer)
    }

    /**
     * Release the TCP listen port only. Does **not** delete `identity.wrap`,
     * the conversation transcript, Signal session, or sled event store.
     */
    fun releaseTransport() {
        stopNetworkWatch()
        receiving.set(false)
        listening.set(false)
        // Keep lastAdvertiseKey so a same-path restore does not invent a new QR.
        persistSessionFiles()
        stopKyberBootstrap()
        val node = syncRef.get()
        if (node != null) {
            val r = node.releaseListen()
            Log.i(TAG, "E2E_LISTEN_RELEASE $r")
        }
        onConnectedChanged(false)
    }

    /**
     * Same as [releaseTransport]. Identity and transcript are never wiped.
     */
    fun shutdown() {
        releaseTransport()
        // Keep sessionRef / secretRef / invites / SyncLabNode (sled). Do not
        // recreate identity.wrap. Callers leaving Direct message must use this
        // instead of deleting files.
    }

    /**
     * After re-entering Direct message: restore invites + transcript key, rebind
     * TCP if we had a listen, and reopen inbox when Signal is still established.
     */
    fun restoreAfterEnter() {
        loadPersistedInvites()
        if (hasRelay() && relayPathRef.get().isEmpty()) {
            relayPathRef.set("set")
        }
        startNetworkWatch()
        myInviteRef.get()?.let { publishInvite(it) }
        if (!ensureReady()) return
        rememberPeerVk()
        peerInviteRef.get()?.let { inv ->
            (sessionRef.get() as? LibsignalSession)?.acceptIncomingFrom(inv.signalName, 1)
        }
        // Re-evaluate LAN vs relay without rotating a live invite QR.
        executor.execute {
            try {
                startNetworkWatch()
                doStartOrRefreshListening(DEFAULT_PORT, null, force = false, reason = "restore")
            } catch (e: Exception) {
                Log.w(TAG, "E2E_RESTORE_LISTEN ${e.message}")
            }
        }
    }

    fun myInviteText(): String {
        val inv = myInviteRef.get() ?: return ""
        return encodeInvite(inv)
    }

    /**
     * Paste peer invite: establish outbound Signal session, wire peer vk for
     * verify, accept incoming from peer name, and start inbox if listening.
     * No separate sender card required when invite includes device_vk.
     */
    fun pastePeerInvite(raw: String) {
        executor.execute { doPastePeerInvite(raw) }
    }

    /**
     * Second QR (Kyber continuation) after a compact identity scan when LAN
     * fetch is unavailable (BLE-only / offline).
     */
    fun applyKyberQr(raw: String) {
        executor.execute {
            val base = pendingDeferredInvite.get()?.let { encodeInvite(it) }
                ?: peerInviteRef.get()?.let { encodeInvite(it) }
            if (base == null) {
                onStatus("Scan the identity QR first, then the handshake QR.")
                return@execute
            }
            val merged = PeerInviteUri.mergeKyberContinuation(base, raw)
            if (merged == null) {
                onStatus("Handshake QR did not match the identity invite.")
                return@execute
            }
            doPastePeerInvite(merged)
            // Handshake QR completes Kyber locally — DRKY2 never ran, so the
            // listener still has no session. Push our full invite (LAN retry + BLE).
            peerInviteRef.get()?.let { notifyPeerOfOurInvite(it) }
        }
    }

    /**
     * Paste peer invite: establish outbound Signal session, wire peer vk for
     * verify, accept incoming from peer name, and start inbox if listening.
     * No separate sender card required when invite includes device_vk.
     */
    private fun doPastePeerInvite(raw: String) {
        try {
            if (!ensureReady()) return
            val inv = decodeInvite(raw)
                ?: run {
                    onStatus("Could not parse peer invite.")
                    return
                }
            peerInviteRef.set(inv)
            persistSessionFiles()
            // Auto-fallback: peer invite `relay=` applies when local relay empty,
            // or when the invite carries a different reachable relay (NAT labs).
            val inviteRelay = normalizeRelayHostPort(inv.relayHostPort)
            if (inviteRelay.isNotBlank()) {
                val local = relayHostPortRef.get().trim()
                if (local.isBlank() || isLoopbackRelay(local)) {
                    setRelayHostPort(inviteRelay)
                    onStatus("Relay from invite: $inviteRelay")
                } else if (local != inviteRelay) {
                    // Keep local preference but surface the invite hint.
                    onStatus(
                        "Invite suggests relay $inviteRelay (local $local kept). " +
                            "Save relay address to switch.",
                    )
                }
            }
            val session = sessionRef.get() as LibsignalSession
            val prekey = resolvePrekeyForEstablish(inv)
                ?: return
            session.establish(ByteArray(0), prekey)
            if (!session.isEstablished()) {
                establishedOutbound.set(false)
                onStatus("Connect failed — invite prekey did not create a session. Get a fresh invite.")
                return
            }
            pendingDeferredInvite.set(null)
            establishedOutbound.set(true)
            if (inv.deviceVkHex.length == 64) {
                val prevVk = peerDeviceVkHexRef.get()
                peerDeviceVkHexRef.set(inv.deviceVkHex)
                rememberPeerVk(inv.deviceVkHex)
                if (prevVk.length == 64 && !prevVk.equals(inv.deviceVkHex, ignoreCase = true)) {
                    Log.w(TAG, "E2E_PEER_VK_CHANGED old=${prevVk.take(16)} new=${inv.deviceVkHex.take(16)}")
                }
                Log.i(TAG, "E2E_PEER_VK_SET vk=${inv.deviceVkHex.take(16)} name=${inv.signalName}")
                // Only sets inbound address if no outbound session yet.
                session.acceptIncomingFrom(inv.signalName, 1)
                applyRelayConfig()
                ensureRelayTransport()
                if (shouldOpenInbox()) {
                    startReceiveLoop()
                }
            }
            maybeMarkConnected()
            rememberContact(inv)
            val peerLabel = conversations.get(peerKey(inv))?.displayName
                ?: inv.displayLabel.takeIf { it.isNotBlank() }
                ?: session.remoteSignalName()
                ?: inv.signalName
            val both = session.isEstablished() && connected.get()
            val ble = isBleListenAddr(inv.listenAddr)
            onStatus(
                when {
                    ble && hasRelay() ->
                        "Signal ready with $peerLabel. Handshake QR is enough — " +
                            "Send uses relay ${relayHostPort()} (no shared Wi-Fi)."
                    ble ->
                        "Signal ready with $peerLabel. Nearby: Start BLE then Send. " +
                            "Far-away: Save a rooms-relay under Manage."
                    both -> "Signal ready with $peerLabel. Either side can send."
                    else ->
                        "Connected toward $peerLabel. They can decrypt after they receive our handshake (Start listening on this phone)."
                },
            )
            Log.i(TAG, "E2E_PEER_ESTABLISHED peer=$peerLabel bleOnly=$ble both=$both relay=${hasRelay()}")
            if (ble) {
                notifyPeerOfOurInvite(inv)
            }
        } catch (e: Exception) {
            establishedOutbound.set(false)
            onStatus("Establish failed: ${e.message}")
        }
    }

    private fun resolvePrekeyForEstablish(inv: PeerInvite): ByteArray? {
        val prekey = Base64.decode(inv.prekeyB64, Base64.DEFAULT)
        if (!PreKeyBundleCodec.isDeferred(prekey)) return prekey
        val wire = PreKeyBundleCodec.parseWire(prekey)
        val fetched = fetchKyberPk(inv)
        if (fetched != null) {
            return try {
                PreKeyBundleCodec.completeDeferred(wire, fetched)
            } catch (e: Exception) {
                onStatus("Handshake key from LAN did not match the QR. Scan handshake QR.")
                pendingDeferredInvite.set(inv)
                null
            }
        }
        pendingDeferredInvite.set(inv)
        onStatus(
            if (isBleListenAddr(inv.listenAddr) || hasRelay()) {
                "Identity QR ok — scan handshake QR (2 of 2). LAN Kyber fetch is not used across NAT."
            } else {
                "Identity QR ok — waiting for handshake key on LAN (peer must be listening). " +
                    "Or scan handshake QR."
            },
        )
        return null
    }

    private fun fetchKyberPk(inv: PeerInvite): ByteArray? {
        val hp = PeerInviteUri.listenHostPort(inv.listenAddr) ?: return null
        val offer = localHandshakeOffer()
        val blob = InviteKyberBootstrap.fetch(
            hp.first,
            hp.second + InviteKyberBootstrap.PORT_OFFSET,
            timeoutMs = if (hasRelay()) 1_500 else 5_000,
            offer = offer,
        ) ?: return null
        Log.i(TAG, "E2E_KYBER_FETCH_OK host=${hp.first} offered=${offer.isNotEmpty()}")
        return PeerInviteUri.decodeKyberBlob(blob)?.second
    }

    /** Full local invite (with Kyber) so the listener can establish without scanning us. */
    private fun localHandshakeOffer(): ByteArray {
        val existing = myInviteRef.get()
        if (existing != null) {
            return encodeInvite(existing).toByteArray(Charsets.UTF_8)
        }
        val session = sessionRef.get() as? LibsignalSession ?: return ByteArray(0)
        val ip = localIpv4()
        val listen = if (ip.isNullOrBlank()) {
            BLE_LISTEN_PLACEHOLDER
        } else {
            "/ip4/$ip/tcp/$DEFAULT_PORT"
        }
        val inv = PeerInvite(
            signalName = session.name,
            deviceVkHex = deviceVkHex(),
            prekeyB64 = Base64.encodeToString(session.exportPreKeyBundle(), Base64.NO_WRAP),
            listenAddr = listen,
            relayHostPort = relayHostPortRef.get().trim(),
            identityIdHex = localIdentityIdHex(),
            displayLabel = conversations.localDisplayName(),
        )
        return encodeInvite(inv).toByteArray(Charsets.UTF_8)
    }

    /**
     * After one-way handshake QR (or BLE-only paste), the listener never saw our
     * prekey. Retry DRKY2 offer upload; if LAN is unreachable, queue the invite
     * for BLE GATT so they can `establish()` too.
     */
    private fun notifyPeerOfOurInvite(peer: PeerInvite) {
        val offered = localHandshakeOffer()
        if (offered.isEmpty()) return
        val hp = PeerInviteUri.listenHostPort(peer.listenAddr)
        if (hp != null) {
            val blob = InviteKyberBootstrap.fetch(
                hp.first,
                hp.second + InviteKyberBootstrap.PORT_OFFSET,
                offer = offered,
            )
            if (blob != null) {
                Log.i(TAG, "E2E_HANDSHAKE_OFFER_PUSHED host=${hp.first}")
                return
            }
            Log.i(TAG, "E2E_HANDSHAKE_OFFER_LAN_FAIL host=${hp.first}")
        }
        // The invite contains public prekey material. Carry it as a signed
        // control event so LAN/relay path changes can repair Signal without
        // requiring another QR scan. The receiver verifies the outer event
        // with our stable app device_vk before applying this payload.
        if (pushHandshakeOfferViaSync(peer, offered)) {
            onStatus("Signal handshake refreshed with peer over the active sync path.")
            return
        }
        if (offered.size > org.derooms.app.ble.BleMeshController.MAX_SEALED) {
            onStatus(
                "Handshake applied here — they still need our invite. " +
                    "Show our QR (Manage) and have them scan it, or Start BLE.",
            )
            Log.w(TAG, "E2E_HANDSHAKE_OFFER_TOO_BIG bytes=${offered.size}")
            return
        }
        pendingBleHandshakeOffer.set(offered)
        Log.i(TAG, "E2E_HANDSHAKE_OFFER_BLE_QUEUED bytes=${offered.size}")
        onStatus(
            "Handshake key applied. Start BLE on both (stay close) so they get our session — " +
                "or let them scan our invite QR. Then Send.",
        )
    }

    private fun pushHandshakeOfferViaSync(peer: PeerInvite, offered: ByteArray): Boolean {
        val secret = secretRef.get() ?: return false
        if (peerDeviceVkHexRef.get().length != 64) return false
        return try {
            val wire = RoomsCoreBridge.createSignedTextEvent(
                secret,
                ROOM_ID,
                offered,
                loadTips(),
            )
            if (wire.wireEnvelope.isEmpty()) return false
            val node = syncLab()
            applyRelayConfig(node)
            rememberPeerVk()
            val raw = node.syncPushSignedEvent(
                secret,
                ROOM_ID,
                wire.wireEnvelope,
                peer.listenAddr,
                12_000u,
            )
            val (tip, viaRelay) = parsePushTip(raw)
            val ok = !raw.startsWith("ERROR:") && tip.length == 64
            Log.i(TAG, "E2E_HANDSHAKE_OFFER_SYNC ok=$ok relay=$viaRelay result=$raw")
            ok
        } catch (e: Exception) {
            Log.w(TAG, "E2E_HANDSHAKE_OFFER_SYNC_FAIL ${e.message}")
            false
        }
    }

    /** Drain one pending BLE handshake-offer frame (full invite, not sealed). */
    fun takePendingBleHandshakeOffer(): ByteArray? = pendingBleHandshakeOffer.getAndSet(null)

    fun hasPendingBleHandshakeOffer(): Boolean = pendingBleHandshakeOffer.get() != null

    private fun maybeStartKyberBootstrap(inv: PeerInvite, boundPort: Int? = null) {
        val port = boundPort
            ?: PeerInviteUri.listenHostPort(inv.listenAddr)?.second
            ?: return
        val raw = try {
            Base64.decode(inv.prekeyB64, Base64.DEFAULT)
        } catch (_: Exception) {
            return
        }
        val wire = try {
            PreKeyBundleCodec.parseWire(raw)
        } catch (_: Exception) {
            return
        }
        if (wire.deferred || wire.kyberPreKey.size < 64) return
        val blob = PeerInviteUri.encodeKyberBlob(
            wire.kyberPreKeyId,
            wire.kyberPreKey,
            wire.kyberSig,
        )
        stopKyberBootstrap()
        try {
            val boot = InviteKyberBootstrap(
                port + InviteKyberBootstrap.PORT_OFFSET,
                blob,
            ) { offer -> applyHandshakeOfferBlocking(offer) }
            boot.start()
            kyberBootstrapRef.set(boot)
        } catch (e: Exception) {
            Log.w(TAG, "kyber bootstrap bind failed: ${e.message}")
        }
    }

    /**
     * Called on the bootstrap thread. Hops to the Signal executor and waits so
     * the scanner does not get Kyber until we can decrypt their first send.
     */
    private fun applyHandshakeOfferBlocking(offer: ByteArray): String? {
        val future = CompletableFuture<String?>()
        executor.execute {
            try {
                applyHandshakeOffer(offer)
                future.complete(null)
            } catch (e: Exception) {
                Log.w(TAG, "handshake offer failed: ${e.message}")
                future.complete(e.message ?: "handshake failed")
            }
        }
        return try {
            future.get(8, TimeUnit.SECONDS)
        } catch (e: Exception) {
            e.message ?: "handshake timeout"
        }
    }

    private fun applyHandshakeOffer(offer: ByteArray) {
        val text = offer.toString(Charsets.UTF_8)
        val inv = decodeInvite(text)
            ?: throw IllegalArgumentException("bad handshake offer")
        if (!ensureReady()) {
            throw IllegalStateException("not ready for handshake")
        }
        val session = sessionRef.get() as LibsignalSession
        if (inv.deviceVkHex.isNotEmpty() &&
            inv.deviceVkHex.equals(deviceVkHex(), ignoreCase = true)
        ) {
            Log.i(TAG, "E2E_HANDSHAKE_OFFER_SKIP_SELF vk")
            return
        }
        if (inv.signalName == session.name) {
            Log.i(TAG, "E2E_HANDSHAKE_OFFER_SKIP_SELF name")
            return
        }
        val prekey = Base64.decode(inv.prekeyB64, Base64.DEFAULT)
        if (PreKeyBundleCodec.isDeferred(prekey)) {
            throw IllegalArgumentException("handshake offer missing Kyber")
        }
        // LibsignalSession deduplicates an identical bundle and replaces the
        // session when the same stable device name presents a new Signal identity.
        session.establish(ByteArray(0), prekey)
        if (!session.isEstablished()) {
            throw IllegalStateException("handshake offer did not create a session")
        }
        peerInviteRef.set(inv)
        persistSessionFiles()
        rememberContact(inv)
        pendingDeferredInvite.set(null)
        establishedOutbound.set(true)
        if (inv.deviceVkHex.length == 64) {
            peerDeviceVkHexRef.set(inv.deviceVkHex)
            rememberPeerVk(inv.deviceVkHex)
            session.acceptIncomingFrom(inv.signalName, 1)
            applyRelayConfig()
            ensureRelayTransport()
            if (shouldOpenInbox()) {
                startReceiveLoop()
            }
        }
        maybeMarkConnected()
        drainPendingSealedAfterHandshake()
        onStatus("Peer handshake from ${inv.signalName} — Signal ready, either side can send.")
        Log.i(TAG, "E2E_HANDSHAKE_OFFER_OK peer=${inv.signalName}")
    }

    private fun stopKyberBootstrap() {
        kyberBootstrapRef.getAndSet(null)?.stop()
    }

    /** Legacy sender card (still accepted by lab scripts / older peers). */
    fun mySenderCardText(): String {
        val session = sessionRef.get() ?: return ""
        val vk = deviceVkHex()
        return buildString {
            appendLine(SENDER_MAGIC)
            appendLine("name=${session.name}")
            appendLine("device_vk=$vk")
        }.trim()
    }

    fun pasteSenderCard(raw: String) {
        executor.execute {
            try {
                if (!ensureReady()) return@execute
                val lines = raw.lines().map { it.trim() }.filter { it.isNotEmpty() }
                if (lines.isEmpty() || lines[0] != SENDER_MAGIC) {
                    onStatus("Not a sender card.")
                    return@execute
                }
                var name = "peer"
                var vk = ""
                for (line in lines.drop(1)) {
                    val eq = line.indexOf('=')
                    if (eq <= 0) continue
                    val k = line.substring(0, eq)
                    val v = line.substring(eq + 1)
                    when (k) {
                        "name" -> name = v
                        "device_vk" -> vk = v
                    }
                }
                if (vk.length != 64) {
                    onStatus("Sender card missing device_vk.")
                    return@execute
                }
                peerDeviceVkHexRef.set(vk)
                rememberPeerVk(vk)
                val session = sessionRef.get() ?: return@execute
                session.acceptIncomingFrom(name, 1)
                maybeMarkConnected()
                onStatus("Ready to receive from $name.")
                startReceiveLoop()
            } catch (e: Exception) {
                onStatus("Sender card failed: ${e.message}")
            }
        }
    }

    private fun maybeMarkConnected() {
        val peer = peerInviteRef.get()
        val sessionOk = sessionRef.get()?.isEstablished() == true
        val bleOnly = isBleListenAddr(peer?.listenAddr.orEmpty()) ||
            isBleListenAddr(myInviteRef.get()?.listenAddr.orEmpty())
        val ok = if (bleOnly || hasRelay()) {
            sessionOk && peerDeviceVkHexRef.get().length == 64
        } else {
            sessionOk &&
                peerDeviceVkHexRef.get().length == 64 &&
                peer != null &&
                (listening.get() || establishedOutbound.get())
        }
        if (connected.getAndSet(ok) != ok) {
            onConnectedChanged(ok)
        }
    }

    fun sendMessage(text: String) {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return
        onStatus("Sending…")
        executor.execute {
            try {
                if (!ensureReady()) return@execute
                val session = sessionRef.get()
                    ?: run {
                        onStatus("Session missing — tap Manage → Connect again.")
                        return@execute
                    }
                val secret = secretRef.get()
                    ?: run {
                        onStatus("Create identity first.")
                        return@execute
                    }
                val peer = peerInviteRef.get()
                    ?: run {
                        onStatus("Paste peer invite first (Manage → Connect).")
                        return@execute
                    }
                if (isBleListenAddr(peer.listenAddr) && (!hasRelay() || !hasUsableInternet())) {
                    // UI should route to BLE; keep a clear status if called directly.
                    onStatus("BLE_ONLY_SEND")
                    Log.i(
                        TAG,
                        "E2E_SEND_BLE_ROUTE relay=${hasRelay()} internet=${hasUsableInternet()}",
                    )
                    return@execute
                }
                if (!establishedOutbound.get() && !session.isEstablished()) {
                    onStatus("Session not established — Connect with peer invite.")
                    return@execute
                }
                val sealed = session.encrypt(trimmed.toByteArray(Charsets.UTF_8))
                secretRef.get()?.let { syncDeviceVkFromSecret(it) }
                val parents = loadTips()
                val wire = RoomsCoreBridge.createSignedTextEvent(secret, ROOM_ID, sealed, parents)
                if (wire.wireEnvelope.isEmpty()) {
                    onStatus("Sign failed (UniFFI).")
                    return@execute
                }
                Log.i(
                    TAG,
                    "E2E_SIGN_VK self=${deviceVkHex().take(16)} peer=${peerDeviceVkHexRef.get().take(16)} tip=${wire.eventIdHex.take(16)}",
                )
                if (wire.eventIdHex.length == 64) {
                    recordTip(wire.eventIdHex)
                }
                val node = syncLab()
                applyRelayConfig(node)
                rememberPeerVk()
                if (hasRelay()) {
                    relayPathRef.set("connecting")
                    onStatus("Sending via LAN, then relay ${relayHostPort()} if needed…")
                }
                val tipRaw = node.syncPushSignedEvent(
                    secret,
                    ROOM_ID,
                    wire.wireEnvelope,
                    peer.listenAddr,
                    25_000u,
                )
                val (tip, viaRelayMarker) = parsePushTip(tipRaw)
                if (tipRaw.startsWith("ERROR:") || tip.length != 64) {
                    if (hasRelay()) relayPathRef.set("set")
                    // Offline / unreachable relay + BLE-only peer → hand back to UI BLE path.
                    if (isBleListenAddr(peer.listenAddr) &&
                        (tipRaw.contains("connect") || tipRaw.contains("relay") || tipRaw.contains("timeout"))
                    ) {
                        Log.w(TAG, "E2E_RELAY_FAIL_BLE_FALLBACK $tipRaw")
                        onStatus("BLE_ONLY_SEND")
                        return@execute
                    }
                    val hint = when {
                        tipRaw.contains("want_timeout") ->
                            "Peer inbox not answering — both stay on Direct message. " +
                                if (hasRelay()) {
                                    "Relay is set; peer must also have this rooms-relay and an open inbox. " +
                                        "Nearby with no data: Start BLE on both, then Send."
                                } else {
                                    "Same Wi‑Fi, or Save a rooms-relay for different networks."
                                }
                        tipRaw.contains("connect") || tipRaw.contains("relay_not_configured") ->
                            if (hasRelay()) {
                                "Cannot reach peer over LAN or relay ${relayHostPort()}. " +
                                    "If you are nearby with no data, Start BLE on both then Send. " +
                                    "Otherwise the rooms-relay must be reachable (TCP DRRL)."
                            } else {
                                "Cannot reach peer LAN address — join the same Wi-Fi " +
                                    "(mobile data will not reach a listen address). " +
                                    "For Wi‑Fi↔mobile or far-away, Save a rooms-relay under Manage."
                            }
                        tipRaw.contains("ack_tips_mismatch") ->
                            "Peer did not apply this send (relay path busy or signature mismatch). " +
                                "Retry Send — do not recreate identity. If it keeps failing, " +
                                "have the other phone send once, then try again."
                        tipRaw.contains("ack") && tipRaw.contains("eof") ->
                            "Peer closed sync before ACK — both Start listening and stay on Direct message, then retry."
                        tipRaw.contains("ack") && tipRaw.contains("mismatch") ->
                            "Peer did not confirm the message — re-scan QR on both phones, then retry Send."
                        else -> tipRaw
                    }
                    onStatus("Sync send failed: $hint")
                    Log.i(TAG, "E2E_RELAY_FALLBACK_RESULT $tipRaw")
                    return@execute
                }
                val viaRelay = viaRelayMarker ||
                    (hasRelay() && isBleListenAddr(peer.listenAddr))
                if (viaRelay) {
                    relayPathRef.set("used")
                    Log.i(TAG, "E2E_RELAY_USED host=${relayHostPort()}")
                }
                val via = if (viaRelay) "relay" else "lan"
                val line = ChatLine(
                    peerKey(peer),
                    true,
                    trimmed,
                    ConversationStore.pathLabel(via),
                    via = via,
                    deviceShort = ConversationStore.deviceShort(deviceVkHex()),
                )
                appendTranscript(line)
                onMessage(line)
                onStatus(
                    if (viaRelay) {
                        "Sent via relay ${relayHostPort()} (${sealed.size} B sealed)."
                    } else {
                        "Sent to peer (${sealed.size} B sealed)."
                    },
                )
                Log.i(TAG, "E2E_SYNC_SEND_OK tip=${tip.take(16)} relay=$viaRelay")
            } catch (_: SignalNotAvailableException) {
                onStatus("libsignal unavailable — message not sent.")
            } catch (e: Exception) {
                onStatus("Send failed: ${e.message}")
            }
        }
    }

    /**
     * Seal text with libsignal and return ciphertext for BLE GATT handoff
     * (no LAN sync). Null on failure.
     */
    fun sealForBle(text: String): ByteArray? {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return null
        if (!ensureReady()) return null
        val session = sessionRef.get() ?: return null
        if (!session.isEstablished()) {
            establishedOutbound.set(false)
            onStatus(
                "Signal not connected — Manage → paste peer invite → Connect. " +
                    "(Seeing a BLE peer is not enough.)",
            )
            return null
        }
        return try {
                val sealed = session.encrypt(trimmed.toByteArray(Charsets.UTF_8))
                val max = org.derooms.app.ble.BleMeshController.MAX_SEALED
                if (sealed.size > max) {
                    onStatus(
                        "Sealed payload ${sealed.size} B exceeds BLE cap ($max). " +
                            "Send a shorter message.",
                    )
                    null
                } else {
                    seenSealedTips.add(sealedTip(sealed))
                    Log.i(TAG, "E2E_BLE_SEAL_OK bytes=${sealed.size}")
                    sealed
                }
        } catch (e: Exception) {
            establishedOutbound.set(false)
            onStatus(
                "BLE seal failed: ${e.message}. " +
                    "Manage → Start listening → exchange fresh invites → Connect, then retry.",
            )
            null
        }
    }

    /**
     * Seal text for Wi‑Fi Direct bulk (High bandwidth). Allows larger sealed
     * blobs than BLE Low (≤256 KiB). Null on failure.
     */
    fun sealForWifiDirect(text: String): ByteArray? {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return null
        if (!ensureReady()) return null
        val session = sessionRef.get() ?: return null
        if (!establishedOutbound.get() && !session.isEstablished()) {
            onStatus("Paste peer invite before Wi‑Fi Direct sealed send.")
            return null
        }
        return try {
            val sealed = session.encrypt(trimmed.toByteArray(Charsets.UTF_8))
            if (sealed.size > 256 * 1024) {
                onStatus("Sealed payload ${sealed.size} B exceeds Wi‑Fi Direct High cap.")
                null
            } else {
                sealed
            }
        } catch (e: Exception) {
            onStatus("Wi‑Fi Direct seal failed: ${e.message}")
            null
        }
    }

    /** Decrypt a sealed BLE / Wi‑Fi Direct frame (libsignal). */
    fun openBleSealed(sealed: ByteArray, via: String = "ble"): String? {
        if (!ensureReady()) return null
        if (isHandshakeOfferPayload(sealed)) {
            Log.i(TAG, "E2E_BLE_HANDSHAKE_OFFER_IN bytes=${sealed.size}")
            val copy = sealed.copyOf()
            executor.execute {
                try {
                    applyHandshakeOffer(copy)
                } catch (e: Exception) {
                    Log.w(TAG, "BLE handshake offer failed: ${e.message}")
                    onStatus("BLE handshake from peer failed: ${e.message}")
                }
            }
            return ""
        }
        val session = sessionRef.get() ?: return null
        // Drop exact duplicates from GATT retries (empty string = UI ignores).
        val tip = sealedTip(sealed)
        if (!seenSealedTips.add(tip)) {
            Log.i(TAG, "E2E_BLE_DECRYPT_DUP tip=${tip.take(16)}")
            return ""
        }
        return try {
            val text = String(session.decrypt(sealed), Charsets.UTF_8)
            refreshLocalPrekeyInvite(session)
            Log.i(TAG, "E2E_BLE_DECRYPT_OK tip=${tip.take(16)} chars=${text.length}")
            onStatus("Message received over ${ConversationStore.pathLabel(via)}.")
            text
        } catch (e: Exception) {
            val msg = e.message.orEmpty()
            if (msg.contains("stale prekey", ignoreCase = true) ||
                (msg.contains("prekeyrecord", ignoreCase = true) &&
                    session.isEstablished()) ||
                msg.contains("old counter", ignoreCase = true)
            ) {
                Log.i(TAG, "E2E_BLE_STALE_PREKEY ignoring duplicate PQXDH")
                return ""
            }
            seenSealedTips.remove(tip)
            Log.w(TAG, "BLE decrypt failed: ${e.message}")
            if (isRecoverableSignalFailure(e)) {
                queueUntilHandshake(sealed, via)
                requestSignalRepair("sealed_${via}_${e.message}")
            }
            val hint = when {
                e.message?.contains("not established", ignoreCase = true) == true ->
                    "Signal session not established on this phone — they must send their handshake " +
                        "(Start BLE so we receive it, or scan their QR). BLE seen is not enough."
                e.message?.contains("untrusted", ignoreCase = true) == true ||
                    e.message?.contains("invalid message", ignoreCase = true) == true ->
                    "Signal state changed — refreshing the signed handshake automatically. " +
                        "Keep both phones on this chat, then retry if this message cannot be recovered."
                else ->
                    "${e.message}. Re-exchange invites (both Start listening → Connect)."
            }
            onStatus("BLE decrypt failed: $hint")
            null
        }
    }

    private fun isRecoverableSignalFailure(e: Exception): Boolean {
        val msg = e.message.orEmpty()
        return msg.contains("untrusted", ignoreCase = true) ||
            msg.contains("invalid message", ignoreCase = true) ||
            msg.contains("not established", ignoreCase = true) ||
            msg.contains("no session", ignoreCase = true)
    }

    private fun queueUntilHandshake(sealed: ByteArray, via: String) {
        while (pendingSealedUntilHandshake.size >= 8) {
            pendingSealedUntilHandshake.poll()
        }
        pendingSealedUntilHandshake.offer(PendingSealed(sealed.copyOf(), via))
    }

    private fun requestSignalRepair(reason: String) {
        if (!signalRepairInFlight.compareAndSet(false, true)) return
        executor.execute {
            try {
                val session = sessionRef.get() ?: return@execute
                refreshLocalPrekeyInvite(session)
                peerInviteRef.get()?.let { notifyPeerOfOurInvite(it) }
                Log.i(TAG, "E2E_SIGNAL_REPAIR_SENT reason=$reason")
            } catch (e: Exception) {
                Log.w(TAG, "E2E_SIGNAL_REPAIR_FAIL reason=$reason ${e.message}")
            } finally {
                signalRepairInFlight.set(false)
            }
        }
    }

    private fun drainPendingSealedAfterHandshake() {
        val session = sessionRef.get() ?: return
        while (true) {
            val pending = pendingSealedUntilHandshake.poll() ?: break
            val tip = sealedTip(pending.bytes)
            try {
                val text = String(session.decrypt(pending.bytes), Charsets.UTF_8)
                refreshLocalPrekeyInvite(session)
                seenSealedTips.add(tip)
                val line = ChatLine(
                    peerKey = lastPeerKey().ifBlank { peerDeviceVkHexRef.get() },
                    outbound = false,
                    text = text,
                    meta = ConversationStore.pathLabel(pending.via),
                    via = pending.via,
                    deviceShort = ConversationStore.deviceShort(peerDeviceVkHexRef.get()),
                )
                appendTranscript(line)
                onMessage(line)
                Log.i(TAG, "E2E_SIGNAL_REPAIR_DECRYPT_OK via=${pending.via} tip=${tip.take(16)}")
            } catch (e: Exception) {
                Log.w(TAG, "E2E_SIGNAL_REPAIR_DECRYPT_DROP via=${pending.via} ${e.message}")
            }
        }
    }

    /**
     * A successful inbound PreKey consumes the advertised one-time/Kyber keys.
     * Refresh the pairing QR once, while preserving identity and all path hints.
     */
    private fun refreshLocalPrekeyInvite(session: LibsignalSession) {
        val mine = myInviteRef.get() ?: return
        val full = session.exportPreKeyBundle()
        val b64 = Base64.encodeToString(full, Base64.NO_WRAP)
        if (mine.prekeyB64 == b64) return
        val refreshed = mine.copy(prekeyB64 = b64)
        myInviteRef.set(refreshed)
        persistSessionFiles()
        maybeStartKyberBootstrap(refreshed)
        publishInvite(refreshed)
        Log.i(TAG, "E2E_INVITE_PREKEY_REFRESH signal=${session.localIdentityFingerprint()}")
    }

    private fun isHandshakeOfferPayload(bytes: ByteArray): Boolean {
        if (bytes.size < INVITE_MAGIC.length) return false
        val prefix = INVITE_MAGIC.toByteArray(Charsets.UTF_8)
        if (bytes.size < prefix.size) return false
        return bytes.copyOfRange(0, prefix.size).contentEquals(prefix)
    }

    private fun sealedTip(sealed: ByteArray): String {
        val dig = MessageDigest.getInstance("SHA-256").digest(sealed)
        return dig.joinToString("") { "%02x".format(it) }.take(32)
    }

    private fun applyRelayConfig(node: SyncLabNode? = syncRef.get()) {
        val n = node ?: return
        val host = relayHostPortRef.get().trim()
        if (host.isEmpty()) {
            n.configureRelay("", "")
            return
        }
        val tokenHex = relayTokenHex()
        if (tokenHex.isEmpty()) {
            // Token needs both device vks; configure host now, re-apply after peer paste.
            return
        }
        val cfg = n.configureRelay(host, tokenHex)
        Log.i(TAG, "E2E_RELAY_CFG host=$host result=$cfg")
        if (cfg != "ok") {
            onStatus("Relay config: $cfg")
        }
    }

    private fun relayTokenHex(): String {
        val a = deviceVkHex().lowercase()
        val b = peerDeviceVkHexRef.get().lowercase()
        if (a.length != 64 || b.length != 64) return ""
        // Directional tokens: push SHA256(self|peer), pull SHA256(peer|self) so
        // our inbox cannot splice with our own Send on the relay.
        val push = sha256Hex("$a|$b").take(32)
        val pull = sha256Hex("$b|$a").take(32)
        return "$push:$pull"
    }

    private fun sha256Hex(s: String): String {
        val dig = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
        return dig.joinToString("") { "%02x".format(it) }
    }

    private fun rememberPeerVk(hex: String = peerDeviceVkHexRef.get()) {
        if (hex.length != 64) return
        if (!RoomsCoreBridge.isNativeUsable()) return
        try {
            val node = syncRef.get() ?: syncLab()
            node.rememberPeerDeviceVk(hexToBytes(hex))
        } catch (_: Exception) {
        }
    }

    private fun startReceiveLoop() {
        if (!receiving.compareAndSet(false, true)) return
        receiveExecutor.execute {
            try {
                val node = syncRef.get() ?: syncLab()
                val session = sessionRef.get()
                if (session == null) {
                    onStatus("Receive not ready (peer invite with device_vk).")
                    receiving.set(false)
                    return@execute
                }
                peerInviteRef.get()?.let { session.acceptIncomingFrom(it.signalName, 1) }
                onStatus(
                    if (listening.get()) {
                        "Inbox open — waiting for peer…"
                    } else {
                        "Inbox open for replies on this connection — Start listening if they send first."
                    },
                )
                while (receiving.get()) {
                    val authorVkHex = peerDeviceVkHexRef.get()
                    if (authorVkHex.length != 64) {
                        Log.i(TAG, "pull skip no peer vk")
                        Thread.sleep(250)
                        continue
                    }
                    rememberPeerVk(authorVkHex)
                    val vk = hexToBytes(authorVkHex)
                    // Short pulls so a stuck accept does not starve other work at the
                    // Kotlin layer; SyncLab Push/Pull also overlap now.
                    val sealed = node.syncPullOneEvent(ROOM_ID, vk, 8_000u)
                    val asText = sealed.toString(Charsets.UTF_8)
                    if (sealed.isEmpty() || asText.startsWith("ERR:")) {
                        if (asText.contains("accept_timeout") || asText.contains("timeout")) {
                            continue
                        }
                        Log.i(TAG, "pull skip $asText")
                        continue
                    }
                    // Decrypt on the command executor so libsignal stays single-threaded.
                    val payload = sealed.copyOf()
                    executor.execute {
                        try {
                            if (isHandshakeOfferPayload(payload)) {
                                applyHandshakeOffer(payload)
                                Log.i(TAG, "E2E_HANDSHAKE_OFFER_SYNC_IN bytes=${payload.size}")
                                return@execute
                            }
                            val sessionNow = sessionRef.get() ?: return@execute
                            if (!sessionNow.hasRemote()) {
                                peerInviteRef.get()?.let { inv ->
                                    sessionNow.acceptIncomingFrom(inv.signalName, 1)
                                }
                            }
                            if (!sessionNow.hasRemote()) {
                                Log.w(TAG, "E2E_DECRYPT_NO_SESSION")
                                onStatus(
                                    "Decrypt failed: Signal session not established — " +
                                        "peer must scan your QR (or handshake on LAN).",
                                )
                                return@execute
                            }
                            val opened = sessionNow.decrypt(payload)
                            refreshLocalPrekeyInvite(sessionNow)
                            val text = opened.toString(Charsets.UTF_8)
                            val via = when {
                                hasRelay() && isBleListenAddr(peerInviteRef.get()?.listenAddr.orEmpty()) -> "relay"
                                hasRelay() -> "lan"
                                else -> "lan"
                            }
                            val line = ChatLine(
                                peerKey = lastPeerKey().ifBlank { peerDeviceVkHexRef.get() },
                                outbound = false,
                                text = text,
                                meta = ConversationStore.pathLabel(via),
                                via = via,
                                deviceShort = ConversationStore.deviceShort(peerDeviceVkHexRef.get()),
                            )
                            val pulledTip = node.lastTipHex()
                            if (pulledTip.length == 64) {
                                recordTip(pulledTip)
                            }
                            appendTranscript(line)
                            onMessage(line)
                            onStatus("Message received.")
                        } catch (e: Exception) {
                            onStatus("Decrypt failed: ${e.message}")
                            Log.w(TAG, "E2E_DECRYPT_FAIL ${e.message}")
                            if (isRecoverableSignalFailure(e)) {
                                requestSignalRepair("sync_${e.message}")
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                onStatus("Receive loop: ${e.message}")
                receiving.set(false)
            }
        }
    }

    fun stopReceiving() {
        receiving.set(false)
        // Do not shut down executors — screen may restart inbox after Manage.
    }

    /**
     * Manual sync burst (FR-UX-006): re-apply relay, nudge inbox loop, and
     * attempt a no-op push readiness check. Works with BLE (separate mesh),
     * LAN SyncLab, and TCP relay when configured.
     */
    fun syncNow() {
        executor.execute {
            try {
                if (!ensureReady()) return@execute
                applyRelayConfig()
                ensureRelayTransport()
                if (shouldOpenInbox()) {
                    startReceiveLoop()
                }
                val relay = relayHostPortRef.get()
                val peer = peerInviteRef.get()
                context.getSharedPreferences(
                    org.derooms.app.sync.OpportunisticSyncWorker.PREFS,
                    Context.MODE_PRIVATE,
                ).edit()
                    .putLong("last_sync_now_ms", System.currentTimeMillis())
                    .apply()
                onStatus(
                    buildString {
                        append("Sync now — ")
                        append(if (listening.get()) "LAN listen" else "no listen")
                        append(if (relay.isNotBlank()) " + relay $relay" else " (no relay)")
                        append(if (peer != null) " + peer wired" else " (no peer)")
                        append(". BLE/Wi‑Fi Direct are separate radios.")
                    },
                )
                Log.i(TAG, "E2E_SYNC_NOW relay=${relay.isNotBlank()} peer=${peer != null}")
            } catch (e: Exception) {
                onStatus("Sync now failed: ${e.message}")
            }
        }
    }

    fun loadTranscript(peerKey: String): List<ChatLine> {
        val key = peerKey.ifBlank { lastPeerKey() }
        return conversations.loadLines(key).map { line ->
            ChatLine(
                peerKey = key,
                outbound = line.outbound,
                text = line.text,
                meta = line.meta,
                via = line.via,
                deviceShort = line.deviceShort,
            )
        }
    }

    private fun rememberContact(inv: PeerInvite) {
        val contact = conversations.upsertFromInvite(
            identityIdHex = inv.identityIdHex,
            deviceVkHex = inv.deviceVkHex,
            suggestedName = inv.displayLabel,
            inviteText = encodeInvite(inv),
        )
        activeThreadKey.set(contact.threadKey)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(PREF_PEER_KEY, contact.threadKey)
            .apply()
        inboxEpoch.incrementAndGet()
    }

    private fun peerKey(inv: PeerInvite): String =
        ConversationStore.threadKey(inv.identityIdHex, inv.deviceVkHex)

    private fun appendTranscript(line: ChatLine) {
        conversations.append(
            line.peerKey,
            ConversationStore.Line(
                outbound = line.outbound,
                text = line.text,
                meta = line.meta,
                via = line.via,
                deviceShort = line.deviceShort,
                atMs = System.currentTimeMillis(),
            ),
        )
        inboxEpoch.incrementAndGet()
    }

    fun persistSessionFiles() {
        val dir = File(context.filesDir, "peer_chat")
        dir.mkdirs()
        myInviteRef.get()?.let { File(dir, "my_invite.txt").writeText(encodeInvite(it)) }
        peerInviteRef.get()?.let { inv ->
            File(dir, "peer_invite.txt").writeText(encodeInvite(inv))
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putString(PREF_PEER_KEY, peerKey(inv))
                .putBoolean(PREF_ESTABLISHED, establishedOutbound.get())
                .apply()
        }
    }

    private fun loadPersistedInvites() {
        val dir = File(context.filesDir, "peer_chat")
        val peerFile = File(dir, "peer_invite.txt")
        if (peerInviteRef.get() == null && peerFile.exists()) {
            decodeInvite(peerFile.readText())?.let { inv ->
                peerInviteRef.set(inv)
                if (inv.deviceVkHex.length == 64) {
                    peerDeviceVkHexRef.set(inv.deviceVkHex)
                }
                rememberContact(inv)
            }
        }
        val myFile = File(dir, "my_invite.txt")
        if (myInviteRef.get() == null && myFile.exists()) {
            decodeInvite(myFile.readText())?.let { myInviteRef.set(it) }
        }
        if (context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getBoolean(PREF_ESTABLISHED, false)
        ) {
            establishedOutbound.set(sessionRef.get()?.isEstablished() == true)
        }
    }

    private fun loadTips(): List<String> {
        val f = File(context.filesDir, "peer_chat/tips.txt")
        if (!f.exists()) return emptyList()
        return f.readLines().map { it.trim() }.filter { it.length == 64 }
    }

    private fun recordTip(hex: String) {
        if (hex.length != 64) return
        val dir = File(context.filesDir, "peer_chat")
        dir.mkdirs()
        File(dir, "tips.txt").writeText("$hex\n")
    }

    private fun syncLab(): SyncLabNode {
        syncRef.get()?.let { return it }
        val dir = File(context.filesDir, "synclab")
        dir.mkdirs()
        val node = try {
            SyncLabNode.withStoreDir(dir.absolutePath)
        } catch (t: Throwable) {
            Log.w(TAG, "sled EventStore/Outbox open failed; memory only (won’t survive process death)", t)
            onStatus("Event store failed — messages won’t persist across restarts.")
            SyncLabNode()
        }
        syncRef.set(node)
        return node
    }

    companion object {
        const val TAG = "DEROOMS_PEER"
        const val INVITE_MAGIC = "DEROOMS_PEER_V1"
        const val SENDER_MAGIC = "DEROOMS_SENDER_V1"
        const val DEFAULT_PORT = 44001
        /** Placeholder listen addr when Wi‑Fi is off — BLE/nearby only. */
        const val BLE_LISTEN_PLACEHOLDER = "ble://offline"
        const val PREFS = "derooms_gate1"
        const val PREF_RELAY = "relay_host_port"
        const val PREF_PEER_KEY = "peer_chat_key"
        const val PREF_ESTABLISHED = "peer_established"
        /**
         * Baked-in public `rooms-relay` `host:port`. Empty on purpose: there is
         * no public DeRooms DRRL fleet. Do **not** put bore.pub or 127.0.0.1 here.
         * When a hosted relay exists, set this and the app auto-fills on first run.
         */
        const val DEFAULT_PUBLIC_RELAY = ""
        /** Placeholder shown in the address field (not a live endpoint). */
        const val DEFAULT_RELAY_HINT = "host:44099"
        val ROOM_ID: ByteArray = ByteArray(32) { 0xE2.toByte() }

        fun isBleListenAddr(addr: String): Boolean =
            addr == BLE_LISTEN_PLACEHOLDER || addr.startsWith("ble://")

        fun isLoopbackRelay(hostPort: String): Boolean {
            val s = hostPort.trim().lowercase()
            return s.startsWith("127.0.0.1:") || s.startsWith("localhost:")
        }

        /** Best-effort normalize `host:port` (strip schemes / whitespace). */
        fun normalizeRelayHostPort(raw: String): String {
            var s = raw.trim()
            if (s.isEmpty()) return ""
            s = s.removePrefix("relay://").removePrefix("tcp://").removePrefix("http://")
                .removePrefix("https://")
            if (s.startsWith("relay=", ignoreCase = true)) {
                s = s.substringAfter('=').trim()
            }
            s = s.substringBefore('/').substringBefore('?').trim()
            val colon = s.lastIndexOf(':')
            if (colon <= 0 || colon == s.lastIndex) return ""
            val port = s.substring(colon + 1).toIntOrNull() ?: return ""
            if (port !in 1..65535) return ""
            return s
        }

        fun resolveInitialRelay(saved: String?, hasPref: Boolean): String {
            if (hasPref) return normalizeRelayHostPort(saved.orEmpty())
            return normalizeRelayHostPort(DEFAULT_PUBLIC_RELAY)
        }

        fun loadPersistedRelay(context: Context): String {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val hasPref = prefs.contains(PREF_RELAY)
            val saved = if (hasPref) prefs.getString(PREF_RELAY, "") else null
            val resolved = resolveInitialRelay(saved, hasPref)
            if (!hasPref && resolved.isNotBlank()) {
                prefs.edit().putString(PREF_RELAY, resolved).apply()
            }
            return resolved
        }

        fun parsePushTip(raw: String): Pair<String, Boolean> {
            val via = raw.endsWith("+relay")
            val hex = raw.removeSuffix("+relay")
            return hex to via
        }

        fun encodeInvite(inv: PeerInvite): String = buildString {
            appendLine(INVITE_MAGIC)
            appendLine("name=${inv.signalName}")
            appendLine("device_vk=${inv.deviceVkHex}")
            appendLine("prekey=${inv.prekeyB64}")
            appendLine("listen=${inv.listenAddr}")
            if (inv.relayHostPort.isNotBlank()) {
                appendLine("relay=${inv.relayHostPort}")
            }
            if (inv.identityIdHex.isNotBlank()) {
                appendLine("identity=${inv.identityIdHex}")
            }
            if (inv.displayLabel.isNotBlank()) {
                appendLine("label=${inv.displayLabel}")
            }
        }.trim()

        fun decodeInvite(raw: String): PeerInvite? {
            val lines = raw.lines().map { it.trim() }.filter { it.isNotEmpty() }
            if (lines.isEmpty() || lines[0] != INVITE_MAGIC) return null
            var name = "peer"
            var vk = ""
            var prekey = ""
            var listen = ""
            var relay = ""
            var identity = ""
            var label = ""
            for (line in lines.drop(1)) {
                val eq = line.indexOf('=')
                if (eq <= 0) continue
                val k = line.substring(0, eq)
                val v = line.substring(eq + 1)
                when (k) {
                    "name" -> name = v
                    "device_vk" -> vk = v
                    "prekey" -> prekey = v
                    "listen" -> listen = v
                    "relay" -> relay = v
                    "identity" -> identity = v
                    "label" -> label = v
                }
            }
            if (prekey.isEmpty()) return null
            // listen may be ble://offline when peer has no Wi‑Fi.
            if (listen.isEmpty()) return null
            return PeerInvite(name, vk, prekey, listen, relay, identity, label)
        }

        fun hexToBytes(hex: String): ByteArray {
            val clean = hex.trim()
            if (clean.length % 2 != 0) return ByteArray(0)
            return ByteArray(clean.length / 2) { i ->
                clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        }
    }
}
