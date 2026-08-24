package org.derooms.app.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.derooms.app.core.CreatedIdentity
import org.derooms.app.core.LocalRoomHandle
import org.derooms.app.core.RoomsCoreBridge
import org.derooms.app.crypto.IdentityKeystore
import org.derooms.app.onMainUi
import org.derooms.app.peer.InviteQr
import org.derooms.app.peer.PeerChatController
import org.derooms.app.room.RoomAcceptUri
import org.derooms.app.room.RoomIdentityUri
import org.derooms.app.room.RoomInviteUri
import org.derooms.app.room.RoomSessionCache
import org.derooms.app.room.RoomLanHub
import org.derooms.app.room.RoomStore
import org.derooms.app.room.RoomSyncPathUri
import org.derooms.app.room.RoomSyncTags
import org.derooms.app.ui.components.ChatBubbleModel
import org.derooms.app.ui.components.CopyBlock
import org.derooms.app.ui.components.EmptyState
import org.derooms.app.ui.components.MessageBubble
import org.derooms.app.ui.components.PrimaryButton
import org.derooms.app.ui.components.QuietHint
import org.derooms.app.ui.components.SectionLabel
import org.derooms.app.ui.components.StatusChip
import org.derooms.app.ui.theme.DeroomsColors
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private enum class RoomTab { Messages, Members }
private enum class RoomScanMode { Invite, Accept, Identity, SyncPath }

/**
 * Room detail: Messages + Members tabs. QR-first invite; MLS paste under Advanced.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RoomScreen(
    context: Context,
    identity: CreatedIdentity?,
    roomStore: RoomStore,
    lanHub: RoomLanHub,
    roomIdHexArg: String,
    status: String,
    onStatus: (String) -> Unit,
    onBack: () -> Unit,
) {
    val entry = remember(roomIdHexArg) { roomStore.get(roomIdHexArg) }
    var roomIdHex by remember { mutableStateOf(roomIdHexArg.trim().lowercase()) }
    var displayName by remember {
        mutableStateOf(entry?.displayName ?: RoomStore.defaultName(roomIdHexArg))
    }
    var tab by remember { mutableStateOf(RoomTab.Messages) }
    var members by remember { mutableStateOf<List<String>>(emptyList()) }
    var inviteMaterial by remember { mutableStateOf("") }
    var inviteUri by remember { mutableStateOf("") }
    var inviteQr by remember { mutableStateOf<Bitmap?>(null) }
    var inviteeIdPaste by remember { mutableStateOf("") }
    var joinMaterialPaste by remember { mutableStateOf("") }
    var acceptReceipt by remember {
        mutableStateOf(entry?.pendingAcceptReceiptHex.orEmpty())
    }
    var acceptReceiptPaste by remember { mutableStateOf("") }
    var acceptQr by remember { mutableStateOf<Bitmap?>(null) }
    var acceptUri by remember { mutableStateOf("") }
    var showAccept by remember { mutableStateOf(false) }
    var showIdentityCard by remember { mutableStateOf(false) }
    var showSyncPath by remember { mutableStateOf(false) }
    var identityCardQr by remember { mutableStateOf<Bitmap?>(null) }
    var identityCardUri by remember { mutableStateOf("") }
    var syncPathQr by remember { mutableStateOf<Bitmap?>(null) }
    var syncPathUri by remember { mutableStateOf("") }
    var listenStarted by remember { mutableStateOf(false) }
    var scanMode by remember { mutableStateOf(RoomScanMode.Invite) }
    var draft by remember { mutableStateOf("") }
    var peerListenPaste by remember {
        mutableStateOf(entry?.peerListenMultiaddr.orEmpty())
    }
    var myListenAddr by remember { mutableStateOf("") }
    var peerAuthorVkPaste by remember {
        mutableStateOf(entry?.peerDeviceVkHex.orEmpty())
    }
    val messages = remember { mutableStateListOf<ChatBubbleModel>() }
    var roomHandle by remember {
        mutableStateOf(RoomSessionCache.getRoom(roomIdHexArg))
    }
    var mlsHandle by remember {
        mutableStateOf(RoomSessionCache.getMls(roomIdHexArg))
    }
    var mlsKeyPackage by remember { mutableStateOf("") }
    var mlsWelcomePaste by remember { mutableStateOf("") }
    var mlsCommitPaste by remember { mutableStateOf("") }
    var mlsKpPaste by remember { mutableStateOf("") }
    var mlsSealedPaste by remember { mutableStateOf("") }
    var mlsDraft by remember { mutableStateOf("") }
    var mlsEpoch by remember { mutableStateOf(0uL) }
    var mlsMembers by remember { mutableStateOf(0u) }
    var showAdvanced by remember { mutableStateOf(false) }
    var showInvite by remember { mutableStateOf(false) }
    var transcriptLoaded by remember { mutableStateOf(false) }
    val roomExecutor = remember { Executors.newSingleThreadExecutor() }
    val acceptSyncAttempted = remember { AtomicBoolean(false) }
    val pullRoomIdRef = remember { AtomicReference(roomIdHex) }
    val pullPeerVkRef = remember { AtomicReference(peerAuthorVkPaste.trim()) }
    val listState = rememberLazyListState()
    val advancedSheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val inviteSheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val acceptSheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val identitySheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val syncPathSheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    DisposableEffect(Unit) {
        onDispose {
            lanHub.clearUiHandler(roomIdHexArg)
            roomExecutor.shutdownNow()
        }
    }

    fun loadSecret(): ByteArray? {
        val wrapFile = File(context.filesDir, "identity.wrap")
        if (!wrapFile.exists()) {
            onStatus("No Keystore-wrapped identity — create identity first.")
            return null
        }
        return IdentityKeystore.unwrap(IdentityKeystore.WrappedSecret(wrapFile.readBytes()))
    }

    fun refreshMls(handle: org.derooms.app.core.MlsGroupHandle) {
        mlsEpoch = handle.epoch()
        mlsMembers = handle.memberCount()
        mlsKeyPackage = handle.exportKeyPackageHex()
    }

    fun roomStateFile(): File =
        roomStore.roomStateFile(roomIdHex.ifBlank { roomIdHexArg })

    fun persistRoom(handle: LocalRoomHandle) {
        val blob = handle.exportStateBlob()
        if (blob.isEmpty()) return
        val file = roomStateFile()
        file.parentFile?.mkdirs()
        file.writeBytes(blob)
    }

    fun refreshMembers(handle: LocalRoomHandle) {
        roomIdHex = handle.roomIdHex().trim().lowercase()
        pullRoomIdRef.set(roomIdHex)
        members = handle.activeMemberIdHexes()
        RoomSessionCache.putRoom(roomIdHex, handle)
        persistRoom(handle)
    }

    fun mlsStateFile(): File {
        val path = entry?.mlsStatePath
        if (!path.isNullOrBlank()) return File(path)
        return roomStore.mlsStateFile(roomIdHex.ifBlank { roomIdHexArg })
    }

    fun persistMls(handle: org.derooms.app.core.MlsGroupHandle) {
        val blob = handle.exportStateBlob()
        val f = mlsStateFile()
        if (blob.isNotEmpty()) {
            f.parentFile?.mkdirs()
            f.writeBytes(blob)
        }
        mlsEpoch = handle.epoch()
        mlsMembers = handle.memberCount()
        if (roomIdHex.isNotEmpty()) {
            RoomSessionCache.putMls(roomIdHex, handle)
            roomStore.upsert(roomIdHex, mlsStatePath = f.absolutePath)
        }
    }

    fun setAcceptReceipt(hex: String, showSheet: Boolean = true) {
        acceptReceipt = hex
        if (hex.isEmpty()) {
            acceptUri = ""
            acceptQr = null
            return
        }
        val uri = RoomAcceptUri.encode(hex)
        acceptUri = uri
        acceptQr = when {
            uri.isNotEmpty() -> InviteQr.bitmap(uri)
            InviteQr.fitsPhoneCamera(hex) -> InviteQr.bitmap(hex)
            else -> null
        }
        if (roomIdHex.isNotEmpty()) {
            roomStore.upsert(roomIdHex, pendingAcceptReceiptHex = hex)
        }
        if (showSheet) showAccept = true
    }

    fun rememberPeerVkOnNode() {
        lanHub.rememberPeerVk(pullPeerVkRef.get().trim().ifEmpty { peerAuthorVkPaste.trim() })
    }

    fun applyPulledCiphertext(ct: ByteArray, eventIdHex: String = "") {
        val asText = ct.toString(Charsets.UTF_8)
        when {
            asText.startsWith(RoomSyncTags.ACCEPT) -> {
                val receipt = asText.removePrefix(RoomSyncTags.ACCEPT)
                val handle = roomHandle
                if (handle == null) {
                    onStatus("Open room session to apply peer Accept.")
                    return
                }
                if (handle.applyAcceptReceiptHex(receipt)) {
                    refreshMembers(handle)
                    persistRoom(handle)
                    onStatus("Roster synced · ${handle.activeMemberCount()} member(s).")
                } else {
                    onStatus("Peer Accept not applied — generate invite first, then retry.")
                }
            }
            asText.startsWith(RoomSyncTags.MEMBERSHIP) -> {
                val hex = asText.removePrefix(RoomSyncTags.MEMBERSHIP)
                val handle = roomHandle
                if (handle == null) {
                    onStatus("Open room session to apply membership event.")
                    return
                }
                val ok = handle.applyMembershipEventHex(hex) || handle.applyAcceptReceiptHex(hex)
                if (ok) {
                    refreshMembers(handle)
                    persistRoom(handle)
                    onStatus("Roster synced · ${handle.activeMemberCount()} member(s).")
                } else {
                    onStatus("Membership event from peer not applied.")
                }
            }
            asText.startsWith(RoomSyncTags.WELCOME) -> {
                val welcome = asText.removePrefix(RoomSyncTags.WELCOME)
                val h = mlsHandle
                if (h == null || !h.isReady()) {
                    onStatus("Create MLS joiner session first, then Wait again.")
                    return
                }
                if (!h.joinFromWelcomeHex(welcome)) {
                    onStatus("MLS Welcome from sync failed.")
                    return
                }
                persistMls(h)
                refreshMls(h)
                onStatus("MLS Welcome applied from sync · epoch ${h.epoch()}")
            }
            asText.startsWith(RoomSyncTags.COMMIT) -> {
                val commit = asText.removePrefix(RoomSyncTags.COMMIT)
                val h = mlsHandle
                if (h == null || !h.hasGroup()) {
                    onStatus("Need MLS group before applying Commit.")
                    return
                }
                if (!h.processCommitHex(commit)) {
                    onStatus("MLS Commit from sync failed.")
                    return
                }
                persistMls(h)
                refreshMls(h)
                onStatus("MLS Commit applied from sync · epoch ${h.epoch()}")
            }
            asText.startsWith(RoomSyncTags.MLS_SEALED) -> {
                val sealed = asText.removePrefix(RoomSyncTags.MLS_SEALED)
                val h = mlsHandle
                if (h == null || !h.hasGroup()) {
                    onStatus("Need MLS group to open sealed message.")
                    return
                }
                val pt = h.openMessageHex(sealed)
                if (pt.isEmpty()) {
                    onStatus("MLS open from sync failed (epoch?).")
                    return
                }
                persistMls(h)
                val meta = "Peer · MLS · sync"
                messages.add(ChatBubbleModel(pt, outbound = false, meta = meta))
                if (roomIdHex.isNotEmpty()) {
                    roomStore.appendLine(
                        roomIdHex,
                        RoomStore.RoomLine(
                            outbound = false,
                            text = pt,
                            meta = meta,
                            eventIdHex = eventIdHex,
                            atMs = System.currentTimeMillis(),
                        ),
                    )
                }
                onStatus("MLS message from sync decrypted.")
            }
            else -> {
                val meta = "Peer · LAN"
                messages.add(ChatBubbleModel(asText, outbound = false, meta = meta))
                if (roomIdHex.isNotEmpty()) {
                    roomStore.appendLine(
                        roomIdHex,
                        RoomStore.RoomLine(
                            outbound = false,
                            text = asText,
                            meta = meta,
                            eventIdHex = eventIdHex,
                            atMs = System.currentTimeMillis(),
                        ),
                    )
                }
                onStatus("Room message received.")
            }
        }
    }

    fun startReceiveLoop() {
        val roomId = pullRoomIdRef.get().trim().ifEmpty { roomIdHex.trim() }
        val vkHex = pullPeerVkRef.get().trim()
        if (roomId.length != 64) return
        lanHub.startInbox(roomId, vkHex) { ct, tip ->
            applyPulledCiphertext(ct, tip)
        }
        if (lanHub.listenDialAddr.isNotEmpty() && !lanHub.listenDialAddr.startsWith("ERROR:")) {
            myListenAddr = lanHub.listenDialAddr
            listenStarted = true
        }
    }

    fun savePeerPath() {
        if (roomIdHex.isEmpty()) return
        val vk = peerAuthorVkPaste.trim()
        pullPeerVkRef.set(vk)
        if (roomIdHex.isNotEmpty()) {
            pullRoomIdRef.set(roomIdHex)
        }
        roomStore.upsert(
            roomIdHex,
            peerListenMultiaddr = peerListenPaste.trim(),
            peerDeviceVkHex = vk,
        )
        rememberPeerVkOnNode()
        startReceiveLoop()
    }

    fun pushSignedEvent(secret: ByteArray, roomBytes: ByteArray, wire: ByteArray, peerAddr: String): String {
        rememberPeerVkOnNode()
        return lanHub.pushWithRetry(secret, roomBytes, wire, peerAddr)
    }

    fun refreshIdentityCard() {
        val id = identity?.identityIdHex.orEmpty()
        val vk = identity?.devicePubkeyHex.orEmpty()
        val uri = RoomIdentityUri.encode(id, vk)
        identityCardUri = uri
        identityCardQr = if (uri.isNotEmpty()) InviteQr.bitmap(uri) else null
    }

    fun refreshSyncPathQr() {
        val vk = identity?.devicePubkeyHex.orEmpty()
        val uri = RoomSyncPathUri.encode(roomIdHex, myListenAddr, vk)
        syncPathUri = uri
        syncPathQr = if (uri.isNotEmpty()) InviteQr.bitmap(uri) else null
    }

    fun ensureRoomListen(showQrAfter: Boolean = false) {
        if (roomHandle == null) {
            onStatus("Open room session first.")
            return
        }
        val cached = lanHub.listenDialAddr
        if (cached.isNotEmpty() && !cached.startsWith("ERROR:")) {
            myListenAddr = cached
            listenStarted = true
            refreshSyncPathQr()
            startReceiveLoop()
            if (showQrAfter) showSyncPath = true
            return
        }
        roomExecutor.execute {
            try {
                val dial = lanHub.ensureListen()
                onMainUi {
                    if (dial.startsWith("ERROR:")) {
                        onStatus("Room listen failed: $dial")
                    } else {
                        myListenAddr = dial
                        listenStarted = true
                        refreshSyncPathQr()
                        onStatus("Listening for room sync.")
                        startReceiveLoop()
                        if (showQrAfter) showSyncPath = true
                    }
                }
            } catch (e: Exception) {
                onMainUi { onStatus("Room listen: ${e.message}") }
            }
        }
    }

    fun pushOpaqueCiphertext(
        label: String,
        opaqueUtf8: String,
        onOk: (() -> Unit)? = null,
        onFail: (() -> Unit)? = null,
    ) {
        val handle = roomHandle ?: run {
            onStatus("Open room session first.")
            onFail?.invoke()
            return
        }
        val peerAddr = peerListenPaste.trim()
        if (peerAddr.isEmpty()) {
            onStatus("Set peer listen multiaddr under Advanced → Sync, then Save peer path.")
            onFail?.invoke()
            return
        }
        roomExecutor.execute {
            try {
                val parents = roomStore.lastTipHexes(handle.roomIdHex())
                val signed = handle.signTextEvent(opaqueUtf8.toByteArray(Charsets.UTF_8), parents)
                if (signed.wireEnvelope.isEmpty()) {
                    onMainUi {
                        onStatus("sign_text_event failed for $label.")
                        onFail?.invoke()
                    }
                    return@execute
                }
                val secret = loadSecret() ?: run {
                    onMainUi { onFail?.invoke() }
                    return@execute
                }
                val roomBytes = PeerChatController.hexToBytes(handle.roomIdHex())
                val tip = pushSignedEvent(
                    secret,
                    roomBytes,
                    signed.wireEnvelope,
                    peerAddr,
                )
                if (tip.startsWith("ERROR:") || tip.length != 64) {
                    onMainUi {
                        onStatus("$label sync push failed: $tip")
                        onFail?.invoke()
                    }
                    return@execute
                }
                onMainUi {
                    savePeerPath()
                    onStatus("$label synced · tip ${tip.take(8)}…")
                    onOk?.invoke()
                }
            } catch (e: Exception) {
                onMainUi {
                    onStatus("$label push failed: ${e.message}")
                    onFail?.invoke()
                }
            }
        }
    }

    fun maybePushPendingAccept() {
        val handle = roomHandle ?: return
        val self = identity?.identityIdHex.orEmpty()
        if (self.isNotEmpty() &&
            self.equals(handle.creatorIdentityIdHex(), ignoreCase = true)
        ) {
            return
        }
        val receipt = acceptReceipt.trim().ifEmpty {
            roomStore.get(roomIdHex.ifBlank { roomIdHexArg })?.pendingAcceptReceiptHex.orEmpty()
        }
        if (receipt.isEmpty()) return
        if (peerListenPaste.trim().isEmpty()) return
        if (!acceptSyncAttempted.compareAndSet(false, true)) return
        pushOpaqueCiphertext(
            label = "Accept",
            opaqueUtf8 = RoomSyncTags.ACCEPT + receipt,
            onOk = {
                onStatus("Accept sent — founder roster should update.")
            },
            onFail = { acceptSyncAttempted.set(false) },
        )
    }

    fun setInviteMaterial(mat: String) {
        inviteMaterial = mat
        val uri = RoomInviteUri.encode(mat)
        inviteUri = uri
        inviteQr = when {
            uri.isNotEmpty() -> InviteQr.bitmap(uri)
            mat.isNotEmpty() && InviteQr.fitsPhoneCamera(mat) -> InviteQr.bitmap(mat)
            else -> null
        }
    }

    fun generateInvite(inviteeId: String) {
        val handle = roomHandle ?: return
        val welcomeHint = handle.welcomeCidHex()
        val mat = handle.inviteMaterialWithWelcomeHex(
            inviteeId.trim(),
            welcomeHint,
            "",
        ).ifBlank {
            handle.inviteMaterialHex(inviteeId.trim())
        }
        if (mat.isEmpty()) {
            onStatus("Invite material failed (need 64-char identity_id).")
        } else {
            setInviteMaterial(mat)
            refreshMembers(handle)
            onStatus("Invite ready — show QR or share link.")
            showInvite = true
        }
    }

    LaunchedEffect(roomIdHexArg) {
        if (roomHandle == null) {
            val state = roomStore.roomStateFile(roomIdHexArg)
            if (state.exists()) {
                val secret = loadSecret()
                if (secret != null) {
                    val restored =
                        RoomsCoreBridge.localRoomSessionFromStateBlob(secret, state.readBytes())
                    if (restored.roomIdHex().equals(roomIdHexArg, ignoreCase = true)) {
                        roomHandle = restored
                        RoomSessionCache.putRoom(roomIdHexArg, restored)
                    }
                }
            } else if (roomIdHexArg.isNotBlank()) {
                onStatus(
                    "This legacy cached room has no restorable session state. " +
                        "Rejoin it once; new rooms now survive app restarts.",
                )
            }
        }
        roomHandle?.let { refreshMembers(it) }
        mlsHandle?.let { refreshMls(it) }
        if (mlsHandle == null) {
            val f = mlsStateFile()
            if (f.exists()) {
                val h = RoomsCoreBridge.mlsSessionFromStateBlob(f.readBytes())
                if (h.hasGroup()) {
                    mlsHandle = h
                    refreshMls(h)
                    RoomSessionCache.putMls(roomIdHexArg, h)
                }
            }
        }
        if (!transcriptLoaded) {
            transcriptLoaded = true
            val lines = roomStore.loadLines(roomIdHexArg)
            if (lines.isNotEmpty() && messages.isEmpty()) {
                lines.forEach { line ->
                    messages.add(
                        ChatBubbleModel(
                            text = line.text,
                            outbound = line.outbound,
                            meta = line.meta,
                        ),
                    )
                }
            }
        }
        val pending = roomStore.get(roomIdHexArg)?.pendingAcceptReceiptHex.orEmpty()
        if (pending.isNotEmpty() && acceptReceipt.isEmpty()) {
            setAcceptReceipt(pending, showSheet = true)
        } else if (pending.isNotEmpty() && acceptReceipt.isNotEmpty() && acceptQr == null) {
            setAcceptReceipt(pending, showSheet = false)
        }
        if (roomHandle != null && !listenStarted) {
            ensureRoomListen(showQrAfter = false)
        }
        pullRoomIdRef.set(roomIdHex.ifBlank { roomIdHexArg.trim().lowercase() })
        pullPeerVkRef.set(peerAuthorVkPaste.trim())
        startReceiveLoop()
        maybePushPendingAccept()
    }

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty() && tab == RoomTab.Messages) {
            listState.animateScrollToItem(messages.lastIndex)
        }
    }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val contents = result.contents ?: return@rememberLauncherForActivityResult
        when (scanMode) {
            RoomScanMode.Accept -> {
                val receipt = RoomAcceptUri.decode(contents)
                if (receipt == null) {
                    onStatus("QR was not an Accept receipt. Founder must scan the joiner’s Accept QR.")
                    return@rememberLauncherForActivityResult
                }
                val handle = roomHandle
                if (handle == null) {
                    onStatus("Open the founded room session first, then scan Accept.")
                    return@rememberLauncherForActivityResult
                }
                val ok = handle.applyAcceptReceiptHex(receipt)
                if (ok) {
                    refreshMembers(handle)
                    onStatus("Accept applied · ${handle.activeMemberCount()} member(s) on roster.")
                } else {
                    onStatus("Accept apply failed — wrong room or already applied.")
                }
            }
            RoomScanMode.Identity -> {
                val card = RoomIdentityUri.decode(contents)
                if (card == null) {
                    onStatus("QR was not an identity card (derooms://id/v1/).")
                    return@rememberLauncherForActivityResult
                }
                inviteeIdPaste = card.identityIdHex
                peerAuthorVkPaste = card.deviceVkHex
                savePeerPath()
                generateInvite(card.identityIdHex)
                onStatus("Scanned identity — invite QR ready. Peer device_vk saved for sync.")
            }
            RoomScanMode.SyncPath -> {
                val path = RoomSyncPathUri.decode(contents)
                if (path == null) {
                    onStatus("QR was not a room sync path.")
                    return@rememberLauncherForActivityResult
                }
                if (roomIdHex.isNotEmpty() &&
                    !path.roomIdHex.equals(roomIdHex, ignoreCase = true)
                ) {
                    onStatus("Sync QR is for a different room.")
                    return@rememberLauncherForActivityResult
                }
                peerListenPaste = path.listenMultiaddr
                peerAuthorVkPaste = path.deviceVkHex
                savePeerPath()
                ensureRoomListen(showQrAfter = false)
                maybePushPendingAccept()
                onStatus("Peer sync path saved — membership and messages can sync.")
            }
            RoomScanMode.Invite -> {
                val material = RoomInviteUri.decode(contents)
                if (material == null) {
                    // Convenient: scanning an identity card from Invite mode still works.
                    val card = RoomIdentityUri.decode(contents)
                    if (card != null) {
                        inviteeIdPaste = card.identityIdHex
                        peerAuthorVkPaste = card.deviceVkHex
                        savePeerPath()
                        generateInvite(card.identityIdHex)
                        onStatus("Scanned identity — invite QR ready.")
                        return@rememberLauncherForActivityResult
                    }
                    onStatus("QR was not a room invite.")
                    return@rememberLauncherForActivityResult
                }
                try {
                    val secret = loadSecret() ?: return@rememberLauncherForActivityResult
                    val handle = RoomsCoreBridge.joinRoomFromInvite(secret, material)
                    roomHandle = handle
                    refreshMembers(handle)
                    val receipt = handle.acceptReceiptHex()
                    if (roomIdHex.isEmpty()) {
                        onStatus("Join failed — invite must target your identity_id.")
                    } else {
                        roomStore.upsert(
                            roomIdHex = roomIdHex,
                            displayName = displayName,
                            mlsStatePath = mlsStateFile().absolutePath,
                            pendingAcceptReceiptHex = receipt,
                        )
                        setAcceptReceipt(receipt, showSheet = true)
                        ensureRoomListen(showQrAfter = false)
                        maybePushPendingAccept()
                        onStatus(
                            "Joined · Accept will sync once the founder’s sync QR is scanned " +
                                "(${handle.activeMemberCount()} local member(s)).",
                        )
                    }
                } catch (e: Exception) {
                    onStatus("Join failed: ${e.message}")
                }
            }
        }
    }
    val cameraPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            val prompt = when (scanMode) {
                RoomScanMode.Accept -> "Scan joiner Accept QR"
                RoomScanMode.Invite -> "Scan room invite QR"
                RoomScanMode.Identity -> "Scan their identity QR"
                RoomScanMode.SyncPath -> "Scan their sync path QR"
            }
            scanLauncher.launch(
                ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setPrompt(prompt)
                    .setBeepEnabled(false),
            )
        } else {
            onStatus("Camera denied — use Advanced paste.")
        }
    }

    fun launchRoomScan(mode: RoomScanMode) {
        scanMode = mode
        val prompt = when (mode) {
            RoomScanMode.Accept -> "Scan joiner Accept QR"
            RoomScanMode.Invite -> "Scan room invite QR"
            RoomScanMode.Identity -> "Scan their identity QR"
            RoomScanMode.SyncPath -> "Scan their sync path QR"
        }
        val need = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) !=
            PackageManager.PERMISSION_GRANTED
        if (need) {
            cameraPermLauncher.launch(Manifest.permission.CAMERA)
        } else {
            scanLauncher.launch(
                ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setPrompt(prompt)
                    .setBeepEnabled(false),
            )
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DeroomsColors.Ink)
            .navigationBarsPadding(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            TextButton(onClick = onBack) {
                Text("← Back", color = DeroomsColors.Moss)
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = displayName,
                    color = DeroomsColors.Cream,
                    style = androidx.compose.material3.MaterialTheme.typography.titleMedium,
                )
                QuietHint(
                    when {
                        mlsHandle?.hasGroup() == true ->
                            "MLS · epoch $mlsEpoch · ${mlsHandle?.memberCount()} member(s)"
                        members.isNotEmpty() ->
                            "${members.size} member(s) · ${roomIdHex.take(8)}…"
                        roomIdHex.isNotEmpty() -> "Room ${roomIdHex.take(8)}…"
                        else -> "Room"
                    },
                )
                QuietHint(
                    "Join via QR in person (OOB). Advanced paste is fallback only.",
                )
            }
            TextButton(onClick = { showAdvanced = true }) {
                Text("Advanced", color = DeroomsColors.Moss)
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = { tab = RoomTab.Messages }) {
                Text(
                    "Messages",
                    color = if (tab == RoomTab.Messages) DeroomsColors.Moss else DeroomsColors.CreamMuted,
                )
            }
            TextButton(onClick = { tab = RoomTab.Members }) {
                Text(
                    "Members",
                    color = if (tab == RoomTab.Members) DeroomsColors.Moss else DeroomsColors.CreamMuted,
                )
            }
            StatusChip(label = if (roomHandle != null) "Open" else "Cached", active = roomHandle != null)
            StatusChip(
                label = if (mlsHandle?.hasGroup() == true) "MLS" else "CRDT",
                active = mlsHandle?.hasGroup() == true,
            )
        }

        when (tab) {
            RoomTab.Messages -> {
                LazyColumn(
                    state = listState,
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(vertical = 12.dp),
                ) {
                    if (messages.isEmpty()) {
                        item {
                            EmptyState(
                                title = "No messages yet",
                                body = "Send below when the room is open. Members and invite QR live under the Members tab.",
                            )
                        }
                    }
                    items(messages) { bubble -> MessageBubble(bubble) }
                }

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(DeroomsColors.InkElevated)
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (status.isNotEmpty()) {
                        QuietHint(status)
                    }
                    OutlinedTextField(
                        value = if (mlsHandle?.hasGroup() == true) mlsDraft else draft,
                        onValueChange = {
                            if (mlsHandle?.hasGroup() == true) mlsDraft = it else draft = it
                        },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = {
                            Text(if (mlsHandle?.hasGroup() == true) "MLS-sealed message" else "Room message")
                        },
                        shape = RoundedCornerShape(16.dp),
                        colors = roomFieldColors(),
                        maxLines = 4,
                        enabled = roomHandle != null || mlsHandle?.hasGroup() == true,
                    )
                    PrimaryButton(
                        text = if (mlsHandle?.hasGroup() == true) "Send (MLS)" else "Send to room",
                        onClick = {
                            if (mlsHandle?.hasGroup() == true) {
                                val h = mlsHandle ?: return@PrimaryButton
                                val text = mlsDraft.trim()
                                if (text.isEmpty()) return@PrimaryButton
                                val sealed = h.sealText(text)
                                if (sealed.isEmpty()) {
                                    onStatus("MLS seal failed.")
                                    return@PrimaryButton
                                }
                                persistMls(h)
                                mlsSealedPaste = sealed
                                val peerAddr = peerListenPaste.trim()
                                if (peerAddr.isNotEmpty() && roomHandle != null) {
                                    pushOpaqueCiphertext(
                                        "MLS message",
                                        RoomSyncTags.MLS_SEALED + sealed,
                                    ) {
                                        val meta = "You · MLS · sync"
                                        messages.add(
                                            ChatBubbleModel(text, outbound = true, meta = meta),
                                        )
                                        if (roomIdHex.isNotEmpty()) {
                                            roomStore.appendLine(
                                                roomIdHex,
                                                RoomStore.RoomLine(
                                                    outbound = true,
                                                    text = text,
                                                    meta = meta,
                                                    atMs = System.currentTimeMillis(),
                                                ),
                                            )
                                        }
                                        mlsDraft = ""
                                    }
                                } else {
                                    val meta = "You · MLS · this device"
                                    messages.add(ChatBubbleModel(text, outbound = true, meta = meta))
                                    if (roomIdHex.isNotEmpty()) {
                                        roomStore.appendLine(
                                            roomIdHex,
                                            RoomStore.RoomLine(
                                                outbound = true,
                                                text = text,
                                                meta = meta,
                                                atMs = System.currentTimeMillis(),
                                            ),
                                        )
                                    }
                                    mlsDraft = ""
                                    onStatus(
                                        "MLS sealed locally — set peer under Advanced → Sync " +
                                            "to push, or share ciphertext.",
                                    )
                                }
                            } else {
                                val text = draft.trim()
                                val handle = roomHandle ?: return@PrimaryButton
                                if (text.isEmpty()) return@PrimaryButton
                                val peerAddr = peerListenPaste.trim()
                                val parents = roomStore.lastTipHexes(handle.roomIdHex())
                                roomExecutor.execute {
                                    try {
                                        val opaque = text.toByteArray(Charsets.UTF_8)
                                        val signed = handle.signTextEvent(opaque, parents)
                                        if (signed.wireEnvelope.isEmpty()) {
                                            onMainUi { onStatus("sign_text_event failed.") }
                                            return@execute
                                        }
                                        if (peerAddr.isNotEmpty()) {
                                            val secret = loadSecret() ?: return@execute
                                            val roomBytes = PeerChatController.hexToBytes(handle.roomIdHex())
                                            val tip = pushSignedEvent(
                                                secret,
                                                roomBytes,
                                                signed.wireEnvelope,
                                                peerAddr,
                                            )
                                            if (tip.startsWith("ERROR:") || tip.length != 64) {
                                                onMainUi { onStatus("Room sync push failed: $tip") }
                                                return@execute
                                            }
                                            onMainUi { savePeerPath() }
                                        }
                                        val meta = if (peerAddr.isNotEmpty()) {
                                            "You · LAN · ${signed.eventIdHex.take(8)}"
                                        } else {
                                            "You · local · ${signed.eventIdHex.take(8)}"
                                        }
                                        onMainUi {
                                            messages.add(
                                                ChatBubbleModel(text, outbound = true, meta = meta),
                                            )
                                            roomStore.appendLine(
                                                handle.roomIdHex(),
                                                RoomStore.RoomLine(
                                                    outbound = true,
                                                    text = text,
                                                    meta = meta,
                                                    eventIdHex = signed.eventIdHex,
                                                    parentHexes = parents,
                                                    atMs = System.currentTimeMillis(),
                                                ),
                                            )
                                            draft = ""
                                            onStatus(
                                                if (peerAddr.isNotEmpty()) {
                                                    "Room message synced (opaque / not MLS)."
                                                } else {
                                                    "Signed with ${parents.size} parent tip(s) — set peer under Advanced → Sync."
                                                },
                                            )
                                        }
                                    } catch (e: Exception) {
                                        onMainUi { onStatus("Room send failed: ${e.message}") }
                                    }
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = roomHandle != null || mlsHandle?.hasGroup() == true,
                    )
                }
            }

            RoomTab.Members -> {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = 20.dp, vertical = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    if (status.isNotEmpty()) QuietHint(status)

                    SectionLabel("Roster")
                    QuietHint(
                        "Joiner Accept syncs over LAN after you exchange sync QRs. " +
                            "Founder does not need to scan Accept for the roster to update.",
                    )
                    if (members.isEmpty()) {
                        QuietHint(
                            if (roomHandle == null) {
                                "Session not in memory — re-create/join under Advanced, or invite from a live founder device."
                            } else {
                                "No members listed yet."
                            },
                        )
                    } else {
                        members.forEach { id ->
                            val isSelf = identity?.identityIdHex?.equals(id, ignoreCase = true) == true
                            val isCreator = roomHandle?.creatorIdentityIdHex()
                                ?.equals(id, ignoreCase = true) == true
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    buildString {
                                        append("· ${id.take(16)}…")
                                        if (isSelf) append(" (you)")
                                        if (isCreator) append(" · admin")
                                    },
                                    color = DeroomsColors.Cream,
                                )
                                if (!isSelf && roomHandle != null) {
                                    TextButton(
                                        onClick = {
                                            val hex = roomHandle?.membershipMutationHex("remove", id)
                                            if (hex.isNullOrEmpty()) {
                                                onStatus("Remove unavailable until FFI rebuild (membership_mutation_hex).")
                                            } else {
                                                refreshMembers(roomHandle!!)
                                                if (peerListenPaste.trim().isNotEmpty()) {
                                                    pushOpaqueCiphertext(
                                                        "Remove",
                                                        RoomSyncTags.MEMBERSHIP + hex,
                                                    ) {
                                                        onStatus("Removed · roster synced to peer.")
                                                    }
                                                } else {
                                                    onStatus("Removed locally — scan peer sync QR to sync roster.")
                                                }
                                            }
                                        },
                                    ) {
                                        Text("Remove", color = DeroomsColors.Moss)
                                    }
                                }
                            }
                        }
                    }

                    SectionLabel("Invite")
                    QuietHint(
                        "Scan their identity QR (no typing). They can show it from Rooms — " +
                            "they do not need to create a room first.",
                    )
                    if (identity != null) {
                        PrimaryButton(
                            text = "Show my identity QR",
                            onClick = {
                                refreshIdentityCard()
                                showIdentityCard = true
                            },
                        )
                    }
                    PrimaryButton(
                        text = "Scan identity QR to invite",
                        onClick = { launchRoomScan(RoomScanMode.Identity) },
                        enabled = roomHandle != null,
                    )
                    OutlinedTextField(
                        value = inviteeIdPaste,
                        onValueChange = { inviteeIdPaste = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("Or paste invitee identity_id hex") },
                        singleLine = true,
                        colors = roomFieldColors(),
                        shape = RoundedCornerShape(12.dp),
                    )
                    PrimaryButton(
                        text = "Generate invite QR",
                        onClick = { generateInvite(inviteeIdPaste) },
                        enabled = roomHandle != null && inviteeIdPaste.trim().length == 64,
                    )
                    PrimaryButton(
                        text = "Scan invite to join",
                        onClick = { launchRoomScan(RoomScanMode.Invite) },
                    )
                    PrimaryButton(
                        text = "Scan Accept QR (founder)",
                        onClick = { launchRoomScan(RoomScanMode.Accept) },
                        enabled = roomHandle != null,
                    )
                    if (inviteQr != null || inviteMaterial.isNotEmpty()) {
                        PrimaryButton(
                            text = "Show invite QR",
                            onClick = { showInvite = true },
                        )
                    }
                    if (acceptReceipt.isNotEmpty()) {
                        QuietHint(
                            "Joiner: show Accept QR so the founder’s roster updates.",
                        )
                        PrimaryButton(
                            text = "Show Accept QR for founder",
                            onClick = { setAcceptReceipt(acceptReceipt, showSheet = true) },
                        )
                    }

                    SectionLabel("Sync path (LAN)")
                    QuietHint(
                        "Auto-listens on Wi‑Fi. Show your sync QR; peer scans it — no copy/paste.",
                    )
                    PrimaryButton(
                        text = if (myListenAddr.isNotEmpty()) "Show my sync QR" else "Start listen + show sync QR",
                        onClick = { ensureRoomListen(showQrAfter = true) },
                        enabled = roomHandle != null,
                    )
                    PrimaryButton(
                        text = "Scan peer sync QR",
                        onClick = { launchRoomScan(RoomScanMode.SyncPath) },
                        enabled = roomHandle != null,
                    )
                    if (peerListenPaste.isNotEmpty()) {
                        QuietHint("Peer path set · ${peerListenPaste.take(28)}…")
                    }
                    if (roomIdHex.isNotEmpty()) {
                        QuietHint("room_id")
                        CopyBlock(context, roomIdHex, label = "Copy room id")
                    }
                }
            }
        }
    }

    if (showInvite) {
        ModalBottomSheet(
            onDismissRequest = { showInvite = false },
            sheetState = inviteSheet,
            containerColor = DeroomsColors.InkElevated,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp)
                    .padding(bottom = 32.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    "Room invite",
                    style = androidx.compose.material3.MaterialTheme.typography.headlineMedium,
                    color = DeroomsColors.Cream,
                )
                QuietHint("Have the invitee scan this QR. Paste stays under Advanced.")
                val bmp = inviteQr
                if (bmp != null) {
                    Image(
                        bitmap = bmp.asImageBitmap(),
                        contentDescription = "Room invite QR",
                        modifier = Modifier.size(240.dp),
                    )
                    if (inviteUri.isNotEmpty() && !InviteQr.fitsPhoneCamera(inviteUri)) {
                        QuietHint("QR is dense — scan close, or use Advanced paste.")
                    }
                } else {
                    QuietHint("Invite too large for QR — use Advanced copy.")
                }
                if (inviteUri.isNotEmpty()) {
                    CopyBlock(context, inviteUri, label = "Copy invite link")
                }
                TextButton(onClick = { showInvite = false }) {
                    Text("Done", color = DeroomsColors.Moss)
                }
            }
        }
    }

    if (showAccept) {
        ModalBottomSheet(
            onDismissRequest = { showAccept = false },
            sheetState = acceptSheet,
            containerColor = DeroomsColors.InkElevated,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp)
                    .padding(bottom = 32.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    "Accept QR for founder",
                    style = androidx.compose.material3.MaterialTheme.typography.headlineMedium,
                    color = DeroomsColors.Cream,
                )
                QuietHint(
                    "Founder opens this room → Members → Scan Accept QR. " +
                        "Until then their roster will not show you as joined.",
                )
                if (acceptQr != null) {
                    Image(
                        bitmap = acceptQr!!.asImageBitmap(),
                        contentDescription = "Accept QR",
                        modifier = Modifier.size(220.dp),
                    )
                } else if (acceptReceipt.isNotEmpty()) {
                    QuietHint("QR too dense — founder can paste Accept under Advanced.")
                    CopyBlock(context, acceptReceipt, label = "Copy Accept receipt")
                }
                if (acceptUri.isNotEmpty()) {
                    CopyBlock(context, acceptUri, label = "Copy Accept link")
                }
                TextButton(onClick = { showAccept = false }) {
                    Text("Done", color = DeroomsColors.Moss)
                }
            }
        }
    }

    if (showIdentityCard) {
        ModalBottomSheet(
            onDismissRequest = { showIdentityCard = false },
            sheetState = identitySheet,
            containerColor = DeroomsColors.InkElevated,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp)
                    .padding(bottom = 32.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    "My identity",
                    style = androidx.compose.material3.MaterialTheme.typography.headlineMedium,
                    color = DeroomsColors.Cream,
                )
                QuietHint("Let a room admin scan this to invite you (no typing).")
                if (identityCardQr != null) {
                    Image(
                        bitmap = identityCardQr!!.asImageBitmap(),
                        contentDescription = "Identity QR",
                        modifier = Modifier.size(220.dp),
                    )
                } else {
                    QuietHint("Could not encode identity QR.")
                }
                if (identityCardUri.isNotEmpty()) {
                    CopyBlock(context, identityCardUri, label = "Copy identity link")
                }
                TextButton(onClick = { showIdentityCard = false }) {
                    Text("Done", color = DeroomsColors.Moss)
                }
            }
        }
    }

    if (showSyncPath) {
        ModalBottomSheet(
            onDismissRequest = { showSyncPath = false },
            sheetState = syncPathSheet,
            containerColor = DeroomsColors.InkElevated,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp)
                    .padding(bottom = 32.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    "Room sync path",
                    style = androidx.compose.material3.MaterialTheme.typography.headlineMedium,
                    color = DeroomsColors.Cream,
                )
                QuietHint(
                    "Peer scans this instead of copying listen addr + device_vk. Same Wi‑Fi.",
                )
                if (syncPathQr != null) {
                    Image(
                        bitmap = syncPathQr!!.asImageBitmap(),
                        contentDescription = "Sync path QR",
                        modifier = Modifier.size(220.dp),
                    )
                } else {
                    QuietHint(
                        if (myListenAddr.isEmpty()) {
                            "Listening… or no LAN IP yet."
                        } else {
                            "QR encode failed — use Advanced paste."
                        },
                    )
                }
                if (myListenAddr.isNotEmpty()) {
                    QuietHint(myListenAddr)
                }
                if (syncPathUri.isNotEmpty()) {
                    CopyBlock(context, syncPathUri, label = "Copy sync link")
                }
                TextButton(onClick = { showSyncPath = false }) {
                    Text("Done", color = DeroomsColors.Moss)
                }
            }
        }
    }

    if (showAdvanced) {
        ModalBottomSheet(
            onDismissRequest = { showAdvanced = false },
            sheetState = advancedSheet,
            containerColor = DeroomsColors.InkElevated,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp)
                    .padding(bottom = 32.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    "Advanced",
                    style = androidx.compose.material3.MaterialTheme.typography.headlineMedium,
                    color = DeroomsColors.Cream,
                )
                QuietHint(
                    "Paste paths for MLS and membership. Prefer QR invite on the Members tab.",
                )

                SectionLabel("Create / join (paste)")
                PrimaryButton(
                    text = "Create new room (founder)",
                    onClick = {
                        try {
                            val secret = loadSecret() ?: return@PrimaryButton
                            val createdSecs = System.currentTimeMillis() / 1000L
                            val handle = RoomsCoreBridge.openLocalRoomSession(
                                secret,
                                createdSecs.toULong(),
                            )
                            roomHandle = handle
                            refreshMembers(handle)
                            acceptReceipt = ""
                            inviteMaterial = ""
                            if (roomIdHex.isEmpty()) {
                                onStatus("Room founding failed (native missing or bad secret).")
                            } else {
                                displayName = RoomStore.defaultName(roomIdHex)
                                roomStore.upsert(
                                    roomIdHex = roomIdHex,
                                    displayName = displayName,
                                    mlsStatePath = mlsStateFile().absolutePath,
                                    createdUnixSecs = createdSecs,
                                )
                                onStatus("Founded room · ${handle.activeMemberCount()} member(s).")
                                showAdvanced = false
                            }
                        } catch (e: Exception) {
                            onStatus("Create room failed: ${e.message}")
                        }
                    },
                )
                OutlinedTextField(
                    value = joinMaterialPaste,
                    onValueChange = { joinMaterialPaste = it },
                    modifier = Modifier.fillMaxWidth().height(80.dp),
                    placeholder = { Text("Paste room invite material / derooms://room/v1/…") },
                    colors = roomFieldColors(),
                    shape = RoundedCornerShape(12.dp),
                )
                PrimaryButton(
                    text = "Join from paste",
                    onClick = {
                        try {
                            val secret = loadSecret() ?: return@PrimaryButton
                            val material = RoomInviteUri.decode(joinMaterialPaste.trim())
                                ?: joinMaterialPaste.trim()
                            val handle = RoomsCoreBridge.joinRoomFromInvite(secret, material)
                            roomHandle = handle
                            refreshMembers(handle)
                            val receipt = handle.acceptReceiptHex()
                            if (roomIdHex.isEmpty()) {
                                onStatus("Join failed — invite must target your identity_id.")
                            } else {
                                roomStore.upsert(
                                    roomIdHex = roomIdHex,
                                    displayName = displayName.ifBlank { RoomStore.defaultName(roomIdHex) },
                                    mlsStatePath = mlsStateFile().absolutePath,
                                    pendingAcceptReceiptHex = receipt,
                                )
                                setAcceptReceipt(receipt, showSheet = true)
                                onStatus("Joined — show Accept QR to founder.")
                                showAdvanced = false
                            }
                        } catch (e: Exception) {
                            onStatus("Join failed: ${e.message}")
                        }
                    },
                )
                if (acceptReceipt.isNotEmpty()) {
                    CopyBlock(context, acceptReceipt, label = "Copy Accept receipt")
                }
                if (inviteMaterial.isNotEmpty()) {
                    CopyBlock(context, inviteMaterial, label = "Copy invite material hex")
                }
                OutlinedTextField(
                    value = acceptReceiptPaste,
                    onValueChange = { acceptReceiptPaste = it },
                    modifier = Modifier.fillMaxWidth().height(80.dp),
                    placeholder = { Text("Paste joiner Accept receipt") },
                    colors = roomFieldColors(),
                    shape = RoundedCornerShape(12.dp),
                )
                PrimaryButton(
                    text = "Apply Accept",
                    onClick = {
                        val handle = roomHandle ?: return@PrimaryButton
                        val raw = acceptReceiptPaste.trim()
                        val decoded = RoomAcceptUri.decode(raw) ?: raw
                        val ok = handle.applyAcceptReceiptHex(decoded)
                        if (ok) {
                            refreshMembers(handle)
                            if (roomIdHex.isNotEmpty()) {
                                roomStore.upsert(roomIdHex, pendingAcceptReceiptHex = "")
                            }
                            onStatus("Accept applied · ${handle.activeMemberCount()} member(s).")
                        } else {
                            onStatus("Accept apply failed.")
                        }
                    },
                    enabled = roomHandle != null,
                )

                SectionLabel("Sync (LAN messages + MLS Welcome/Commit)")
                QuietHint(
                    "Prefer Members → Show/Scan sync QR. Inbox stays open after that; " +
                        "you should not need to wait for each message.",
                )
                PrimaryButton(
                    text = "Show my sync QR",
                    onClick = { ensureRoomListen(showQrAfter = true) },
                    enabled = roomHandle != null,
                )
                PrimaryButton(
                    text = "Scan peer sync QR",
                    onClick = {
                        showAdvanced = false
                        launchRoomScan(RoomScanMode.SyncPath)
                    },
                    enabled = roomHandle != null,
                )
                if (identity != null) {
                    QuietHint("Fallback: your device_vk")
                    CopyBlock(context, identity.devicePubkeyHex, label = "Copy my device_vk")
                }
                if (myListenAddr.isNotEmpty()) {
                    CopyBlock(context, myListenAddr, label = "Copy listen addr (fallback)")
                }
                OutlinedTextField(
                    value = peerListenPaste,
                    onValueChange = { peerListenPaste = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("Peer listen multiaddr (or scan sync QR)") },
                    colors = roomFieldColors(),
                    shape = RoundedCornerShape(12.dp),
                )
                OutlinedTextField(
                    value = peerAuthorVkPaste,
                    onValueChange = { peerAuthorVkPaste = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("Peer device_vk (or scan identity/sync QR)") },
                    colors = roomFieldColors(),
                    shape = RoundedCornerShape(12.dp),
                )
                PrimaryButton(
                    text = "Save peer path",
                    onClick = {
                        savePeerPath()
                        maybePushPendingAccept()
                        onStatus("Peer path saved for this room.")
                    },
                    enabled = roomIdHex.isNotEmpty(),
                )
                PrimaryButton(
                    text = "Push Welcome to peer",
                    onClick = {
                        val w = mlsWelcomePaste.trim()
                        if (w.isEmpty()) {
                            onStatus("Add member first (Welcome hex empty).")
                            return@PrimaryButton
                        }
                        pushOpaqueCiphertext("Welcome", RoomSyncTags.WELCOME + w)
                    },
                    enabled = roomHandle != null && mlsWelcomePaste.isNotEmpty(),
                )
                PrimaryButton(
                    text = "Push Commit to peer",
                    onClick = {
                        val c = mlsCommitPaste.trim()
                        if (c.isEmpty()) {
                            onStatus("Commit hex empty — run MLS add first.")
                            return@PrimaryButton
                        }
                        pushOpaqueCiphertext("Commit", RoomSyncTags.COMMIT + c)
                    },
                    enabled = roomHandle != null && mlsCommitPaste.isNotEmpty(),
                )
                PrimaryButton(
                    text = "Push sealed MLS ciphertext",
                    onClick = {
                        val s = mlsSealedPaste.trim()
                        if (s.isEmpty()) {
                            onStatus("Seal a message first.")
                            return@PrimaryButton
                        }
                        pushOpaqueCiphertext("MLS sealed", RoomSyncTags.MLS_SEALED + s)
                    },
                    enabled = roomHandle != null && mlsSealedPaste.isNotEmpty(),
                )
                PrimaryButton(
                    text = "Open inbox (Keep waiting for sync)",
                    onClick = {
                        val vkHex = peerAuthorVkPaste.trim()
                        if (vkHex.length != 64) {
                            onStatus("Need peer device_vk (64 hex) — scan their sync QR first.")
                            return@PrimaryButton
                        }
                        savePeerPath()
                        startReceiveLoop()
                        maybePushPendingAccept()
                        onStatus("Inbox open — later messages arrive without tapping Wait.")
                    },
                    enabled = roomHandle != null,
                )

                SectionLabel("MLS group")
                QuietHint("Create as founder, share KeyPackage as joiner, then Push Welcome/Commit via Sync above.")
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PrimaryButton(
                        text = "MLS create",
                        onClick = {
                            val label = identity?.identityIdHex ?: return@PrimaryButton
                            val h = RoomsCoreBridge.openMlsGroupSession(label)
                            if (!h.isReady()) {
                                onStatus("MLS session failed — rebuild Android FFI with rooms-mls.")
                                return@PrimaryButton
                            }
                            val gid = h.createGroup()
                            if (gid.isEmpty()) {
                                onStatus("MLS create_group failed.")
                                return@PrimaryButton
                            }
                            mlsHandle = h
                            refreshMls(h)
                            persistMls(h)
                            onStatus("MLS group created · epoch ${h.epoch()} · members ${h.memberCount()}")
                        },
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                    )
                    PrimaryButton(
                        text = "MLS joiner",
                        onClick = {
                            val label = identity?.identityIdHex ?: return@PrimaryButton
                            val h = RoomsCoreBridge.openMlsGroupSession(label)
                            if (!h.isReady()) {
                                onStatus("MLS session failed — rebuild FFI.")
                                return@PrimaryButton
                            }
                            mlsHandle = h
                            refreshMls(h)
                            if (roomIdHex.isNotEmpty()) RoomSessionCache.putMls(roomIdHex, h)
                            onStatus("MLS member ready — copy KeyPackage for founder.")
                        },
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                    )
                }
                PrimaryButton(
                    text = "Restore MLS from disk",
                    onClick = {
                        val f = mlsStateFile()
                        if (!f.exists()) {
                            onStatus("No saved MLS state.")
                            return@PrimaryButton
                        }
                        val h = RoomsCoreBridge.mlsSessionFromStateBlob(f.readBytes())
                        if (!h.hasGroup()) {
                            onStatus("MLS restore failed.")
                            return@PrimaryButton
                        }
                        mlsHandle = h
                        refreshMls(h)
                        if (roomIdHex.isNotEmpty()) RoomSessionCache.putMls(roomIdHex, h)
                        onStatus("MLS restored · epoch ${h.epoch()} · members ${h.memberCount()}")
                    },
                )
                if (mlsKeyPackage.isNotEmpty()) {
                    CopyBlock(context, mlsKeyPackage, label = "Copy KeyPackage")
                }
                OutlinedTextField(
                    value = mlsKpPaste,
                    onValueChange = { mlsKpPaste = it },
                    modifier = Modifier.fillMaxWidth().height(80.dp),
                    placeholder = { Text("Paste joiner KeyPackage hex") },
                    colors = roomFieldColors(),
                    shape = RoundedCornerShape(12.dp),
                )
                PrimaryButton(
                    text = "MLS add member (Welcome+Commit)",
                    onClick = {
                        val h = mlsHandle ?: return@PrimaryButton
                        val r = h.addMemberKeyPackageHex(mlsKpPaste.trim())
                        if (r.error.isNotEmpty()) {
                            onStatus("MLS add failed: ${r.error}")
                            return@PrimaryButton
                        }
                        persistMls(h)
                        mlsWelcomePaste = r.welcomeHex
                        mlsCommitPaste = r.commitHex
                        onStatus("MLS member added · epoch ${r.epoch} · count ${r.memberCount}.")
                    },
                    enabled = mlsHandle?.hasGroup() == true,
                )
                if (mlsWelcomePaste.isNotEmpty()) {
                    CopyBlock(context, mlsWelcomePaste, label = "Copy Welcome hex")
                }
                if (mlsCommitPaste.isNotEmpty()) {
                    CopyBlock(context, mlsCommitPaste, label = "Copy Commit hex")
                }
                PrimaryButton(
                    text = "MLS join from Welcome",
                    onClick = {
                        val h = mlsHandle ?: return@PrimaryButton
                        val ok = h.joinFromWelcomeHex(mlsWelcomePaste.trim())
                        if (!ok) {
                            onStatus("MLS join Welcome failed.")
                            return@PrimaryButton
                        }
                        persistMls(h)
                        refreshMls(h)
                        onStatus("Joined MLS group · epoch ${h.epoch()} · members ${h.memberCount()}")
                    },
                    enabled = mlsHandle != null,
                )
                PrimaryButton(
                    text = "MLS apply Commit",
                    onClick = {
                        val h = mlsHandle ?: return@PrimaryButton
                        if (!h.processCommitHex(mlsCommitPaste.trim())) {
                            onStatus("MLS process Commit failed.")
                            return@PrimaryButton
                        }
                        persistMls(h)
                        refreshMls(h)
                        onStatus("MLS Commit applied · epoch ${h.epoch()}")
                    },
                    enabled = mlsHandle?.hasGroup() == true,
                )
                OutlinedTextField(
                    value = mlsSealedPaste,
                    onValueChange = { mlsSealedPaste = it },
                    modifier = Modifier.fillMaxWidth().height(80.dp),
                    placeholder = { Text("Paste MLS ciphertext hex to open") },
                    colors = roomFieldColors(),
                    shape = RoundedCornerShape(12.dp),
                )
                PrimaryButton(
                    text = "MLS open ciphertext",
                    onClick = {
                        val h = mlsHandle ?: return@PrimaryButton
                        val pt = h.openMessageHex(mlsSealedPaste.trim())
                        if (pt.isEmpty()) {
                            onStatus("MLS open failed (wrong epoch or corrupt).")
                            return@PrimaryButton
                        }
                        persistMls(h)
                        val meta = "Peer · MLS"
                        messages.add(ChatBubbleModel(pt, outbound = false, meta = meta))
                        if (roomIdHex.isNotEmpty()) {
                            roomStore.appendLine(
                                roomIdHex,
                                RoomStore.RoomLine(
                                    outbound = false,
                                    text = pt,
                                    meta = meta,
                                    atMs = System.currentTimeMillis(),
                                ),
                            )
                        }
                        onStatus("MLS decrypted ok.")
                    },
                    enabled = mlsHandle?.hasGroup() == true,
                )

                TextButton(
                    onClick = { showAdvanced = false },
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                ) {
                    Text("Done", color = DeroomsColors.Moss)
                }
            }
        }
    }
}

@Composable
private fun roomFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = DeroomsColors.Moss,
    unfocusedBorderColor = DeroomsColors.Line,
    focusedTextColor = DeroomsColors.Cream,
    unfocusedTextColor = DeroomsColors.Cream,
    cursorColor = DeroomsColors.Moss,
    focusedContainerColor = DeroomsColors.Panel,
    unfocusedContainerColor = DeroomsColors.Panel,
    focusedPlaceholderColor = DeroomsColors.CreamMuted,
    unfocusedPlaceholderColor = DeroomsColors.CreamMuted,
)

