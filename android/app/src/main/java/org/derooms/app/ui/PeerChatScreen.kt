package org.derooms.app.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.derooms.app.core.CreatedIdentity
import org.derooms.app.peer.InviteQr
import org.derooms.app.peer.PeerChatController
import org.derooms.app.peer.PeerInviteUri
import org.derooms.app.ui.components.ChatBubbleModel
import org.derooms.app.ui.components.CopyBlock
import org.derooms.app.ui.components.EmptyState
import org.derooms.app.ui.components.MessageBubble
import org.derooms.app.ui.components.PrimaryButton
import org.derooms.app.ui.components.QuietHint
import org.derooms.app.ui.components.SectionLabel
import org.derooms.app.ui.components.StatusChip
import org.derooms.app.ui.theme.DeroomsColors

/**
 * Clean 1:1 thread UI. Connection / BLE / relay live in a bottom sheet so the
 * main screen stays a messenger, not a lab console.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PeerChatScreen(
    context: Context,
    identity: CreatedIdentity?,
    status: String,
    onStatus: (String) -> Unit,
    onBack: () -> Unit,
    controller: PeerChatController,
    pendingInviteUri: String? = null,
    onPendingInviteConsumed: () -> Unit = {},
) {
    val bubbles = remember { mutableStateListOf<ChatBubbleModel>() }
    var draft by remember { mutableStateOf("") }
    var peerInvitePaste by remember { mutableStateOf("") }
    var senderCardPaste by remember { mutableStateOf("") }
    var myInvite by remember { mutableStateOf("") }
    var mySenderCard by remember { mutableStateOf("") }
    var connected by remember { mutableStateOf(false) }
    var listening by remember { mutableStateOf(false) }
    var showConnect by remember { mutableStateOf(false) }
    var blePeers by remember { mutableStateOf(0) }
    var relayAddr by remember {
        mutableStateOf(controller.relayHostPort())
    }
    var relayStatus by remember { mutableStateOf(controller.relayUiStatus()) }
    var bleActive by remember { mutableStateOf(false) }
    var bleOnlyPeer by remember { mutableStateOf(false) }
    var wdActive by remember { mutableStateOf(false) }
    var fgsActive by remember { mutableStateOf(false) }
    var showHandshakeQr by remember { mutableStateOf(false) }
    var showNameDialog by remember { mutableStateOf(false) }
    var nameDraft by remember { mutableStateOf("") }
    var selfNameDraft by remember { mutableStateOf(controller.localDisplayName()) }
    var contactName by remember { mutableStateOf(controller.contactDisplayName()) }

    var signalReady by remember { mutableStateOf(false) }
    var transcriptLoaded by remember { mutableStateOf(false) }

    val controllerHolder = remember { arrayOfNulls<PeerChatController>(1) }
    val bleHolder = remember { arrayOfNulls<org.derooms.app.ble.BleMeshController>(1) }
    val wdHolder = remember { arrayOfNulls<org.derooms.app.wifi.WifiDirectBulkController>(1) }
    val listState = rememberLazyListState()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    var pendingBleSendAfterPerm by remember { mutableStateOf<String?>(null) }
    /** Text queued for BLE if relay send returns BLE_ONLY_SEND (offline + relay saved). */
    var pendingBleAfterRelay by remember { mutableStateOf<String?>(null) }
    var bleFallbackKick by remember { mutableStateOf(0) }
    val blePerms = if (Build.VERSION.SDK_INT >= 31) {
        arrayOf(
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
            // Some OEMs still gate LE scan behind location even on API 31+.
            Manifest.permission.ACCESS_FINE_LOCATION,
        )
    } else {
        // API ≤30: BLE scan requires app Location permission + Location services ON.
        arrayOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
        )
    }
    val wdPerms = arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)

    fun addLine(line: PeerChatController.ChatLine) {
        val who = if (line.outbound) "You" else controller.contactDisplayName()
        val device = line.deviceShort.ifBlank {
            if (line.outbound) "this device" else "their device"
        }
        val via = org.derooms.app.peer.ConversationStore.pathLabel(
            line.via.ifBlank { org.derooms.app.peer.ConversationStore.inferVia(line.meta) },
        )
        bubbles.add(
            ChatBubbleModel(
                text = line.text,
                outbound = line.outbound,
                meta = "$who · $device · $via",
            ),
        )
        if (line.outbound) {
            draft = ""
        }
        contactName = controller.contactDisplayName()
    }

    controllerHolder[0] = controller

    DisposableEffect(controller) {
        identity?.devicePubkeyHex?.takeIf { it.length == 64 }?.let {
            controller.setDeviceVkHex(it)
        }
        controller.attach(
            onMessage = { line ->
                org.derooms.app.onMainUi { addLine(line) }
            },
            onStatus = { msg ->
                org.derooms.app.onMainUi {
                    if (msg == "BLE_ONLY_SEND") {
                        val text = pendingBleAfterRelay
                        pendingBleAfterRelay = null
                        if (!text.isNullOrBlank()) {
                            pendingBleSendAfterPerm = text
                            bleFallbackKick += 1
                            onStatus("No internet for relay — starting BLE fallback…")
                        } else {
                            onStatus(
                                "Nearby send needs BLE — Start BLE on both phones, then Send again.",
                            )
                        }
                    } else {
                        onStatus(msg)
                    }
                }
            },
            onInviteReady = { inv ->
                org.derooms.app.onMainUi {
                    myInvite = inv
                    mySenderCard = controller.mySenderCardText()
                    listening = true
                }
            },
            onConnectedChanged = { ok ->
                org.derooms.app.onMainUi {
                    val justLinked = ok && !connected
                    connected = ok
                    signalReady = controller.signalReady()
                    contactName = controller.contactDisplayName()
                    if (justLinked) {
                        bleOnlyPeer = controller.isBleOnlyPeer()
                        showConnect = false
                        if (controller.needsContactName()) {
                            nameDraft = contactName
                            showNameDialog = true
                        }
                    }
                }
            },
        )
        controller.restoreAfterEnter()
        bleHolder[0] = org.derooms.app.ble.BleMeshController(
            context = context,
            onStatus = { msg -> org.derooms.app.onMainUi { onStatus(msg) } },
            onPeerSeen = { _ -> org.derooms.app.onMainUi { blePeers += 1 } },
            onSealedDelivered = { sealed ->
                org.derooms.app.onMainUi {
                    val opened = controllerHolder[0]?.openBleSealed(sealed, via = "ble")
                    if (!opened.isNullOrEmpty()) {
                        controller.noteLocalLine(opened, outbound = false, via = "ble")
                        bubbles.add(
                            ChatBubbleModel(
                                opened,
                                outbound = false,
                                meta = "${controller.contactDisplayName()} · ${
                                    org.derooms.app.peer.ConversationStore.deviceShort(
                                        "",
                                    ).ifBlank { "their device" }
                                } · BLE",
                            ),
                        )
                    }
                }
            },
        )
        wdHolder[0] = org.derooms.app.wifi.WifiDirectBulkController(
            context = context,
            onStatus = { msg -> org.derooms.app.onMainUi { onStatus(msg) } },
            onSealedDelivered = { sealed ->
                org.derooms.app.onMainUi {
                    val opened = controllerHolder[0]?.openBleSealed(sealed, via = "wifi-direct")
                    if (!opened.isNullOrEmpty()) {
                        controller.noteLocalLine(opened, outbound = false, via = "wifi-direct")
                        bubbles.add(
                            ChatBubbleModel(
                                opened,
                                outbound = false,
                                meta = "${controller.contactDisplayName()} · their device · Wi‑Fi Direct",
                            ),
                        )
                    }
                }
            },
        )
        org.derooms.app.sync.OpportunisticSyncWorker.enqueuePeriodic(context)
        onDispose {
            bleHolder[0]?.stop()
            wdHolder[0]?.stop()
        }
    }

    fun flushBleHandshakeOffer() {
        val ble = bleHolder[0] ?: return
        if (!ble.isActive()) return
        val offer = controller.takePendingBleHandshakeOffer() ?: return
        ble.queueSealedPayload(offer)
        onStatus("BLE: sending our handshake to the peer (${offer.size} B)…")
    }

    fun startBleMesh(): Boolean {
        val ble = bleHolder[0] ?: return false
        if (!ble.hasBlePermissions()) return false
        ble.start()
        bleActive = ble.isActive()
        if (bleActive) {
            flushBleHandshakeOffer()
        }
        return bleActive
    }

    fun sendSealedViaBle(text: String, requestPerms: (Array<String>) -> Unit) {
        val ble = bleHolder[0]
        if (ble == null) {
            onStatus("BLE controller missing — reopen Direct message.")
            return
        }
        if (!ble.isActive()) {
            if (!ble.hasBlePermissions()) {
                pendingBleSendAfterPerm = text
                onStatus(
                    if (Build.VERSION.SDK_INT < 31) {
                        "Allow Location for Derooms (required for Bluetooth scan on this Android)."
                    } else {
                        "Allow Nearby devices / Bluetooth (+ Location) for Derooms."
                    },
                )
                requestPerms(blePerms)
                return
            }
            if (!startBleMesh()) {
                onStatus("Could not start BLE — is Bluetooth on?")
                return
            }
        }
        flushBleHandshakeOffer()
        val sealed = controller.sealForBle(text)
        if (sealed == null) return
        ble.queueSealedPayload(sealed)
        controller.noteLocalLine(text, outbound = true, via = "ble")
        bubbles.add(ChatBubbleModel(text, outbound = true, meta = "You · this device · BLE"))
        draft = ""
        blePeers = ble.peersSeenCount()
        bleOnlyPeer = controller.isBleOnlyPeer()
    }

    val blePermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { granted ->
        val ok = if (Build.VERSION.SDK_INT >= 31) {
            granted[Manifest.permission.BLUETOOTH_ADVERTISE] == true &&
                granted[Manifest.permission.BLUETOOTH_SCAN] == true &&
                granted[Manifest.permission.BLUETOOTH_CONNECT] == true
        } else {
            granted[Manifest.permission.ACCESS_FINE_LOCATION] == true
        }
        if (ok) {
            if (startBleMesh()) {
                onStatus("BLE started. Keep Location ON and phones close.")
                val pending = pendingBleSendAfterPerm
                pendingBleSendAfterPerm = null
                if (pending != null) {
                    sendSealedViaBle(pending) { /* already granted */ }
                }
            } else {
                onStatus("Permissions granted but BLE failed to start — turn Bluetooth on.")
            }
        } else {
            pendingBleSendAfterPerm = null
            onStatus(
                if (Build.VERSION.SDK_INT < 31) {
                    "Location permission denied — Android 11 and older cannot BLE-scan without it."
                } else {
                    "Bluetooth permissions denied — cannot use Send sealed via BLE."
                },
            )
        }
    }

    // Offline + relay saved: controller returns BLE_ONLY_SEND → kick BLE path.
    LaunchedEffect(bleFallbackKick) {
        if (bleFallbackKick == 0) return@LaunchedEffect
        val pending = pendingBleSendAfterPerm ?: return@LaunchedEffect
        pendingBleSendAfterPerm = null
        sendSealedViaBle(pending) { blePermLauncher.launch(it) }
    }
    val wdPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { granted ->
        if (granted.values.all { it }) {
            wdHolder[0]?.start()
            wdActive = true
        } else {
            onStatus("Wi‑Fi Direct location permission denied.")
        }
    }
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val contents = result.contents ?: return@rememberLauncherForActivityResult
        if (PeerInviteUri.isKyberContinuation(contents)) {
            controller.applyKyberQr(contents)
            onStatus("Handshake QR captured — completing Signal…")
            return@rememberLauncherForActivityResult
        }
        val decoded = PeerInviteUri.decode(contents) ?: contents.trim()
        peerInvitePaste = decoded
        if (decoded.startsWith(PeerChatController.INVITE_MAGIC)) {
            controller.pastePeerInvite(decoded)
            mySenderCard = controller.mySenderCardText()
            bleOnlyPeer = decoded.contains("ble://") ||
                decoded.contains(PeerChatController.BLE_LISTEN_PLACEHOLDER)
            onStatus("Connecting Signal session…")
        } else {
            onStatus("QR was not a Derooms invite. Use Advanced paste.")
        }
    }
    val cameraPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            val opts = ScanOptions()
                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                .setPrompt("Scan peer invite QR")
                .setBeepEnabled(false)
            scanLauncher.launch(opts)
        } else {
            onStatus("Camera permission denied — paste invite in Advanced.")
        }
    }

    fun launchInviteScan() {
        val need = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) !=
            PackageManager.PERMISSION_GRANTED
        if (need) {
            cameraPermLauncher.launch(Manifest.permission.CAMERA)
        } else {
            val opts = ScanOptions()
                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                .setPrompt("Scan peer invite QR")
                .setBeepEnabled(false)
            scanLauncher.launch(opts)
        }
    }

    LaunchedEffect(bubbles.size) {
        if (bubbles.isNotEmpty()) {
            listState.animateScrollToItem(bubbles.lastIndex)
        }
    }

    LaunchedEffect(Unit) {
        if (!transcriptLoaded) {
            transcriptLoaded = true
            val lines = controller.loadTranscript(controller.lastPeerKey())
            if (lines.isNotEmpty() && bubbles.isEmpty()) {
                lines.forEach { line ->
                    val who = if (line.outbound) "You" else controller.contactDisplayName()
                    val device = line.deviceShort.ifBlank {
                        if (line.outbound) "this device" else "their device"
                    }
                    val via = org.derooms.app.peer.ConversationStore.pathLabel(
                        line.via.ifBlank { org.derooms.app.peer.ConversationStore.inferVia(line.meta) },
                    )
                    bubbles.add(
                        ChatBubbleModel(
                            text = line.text,
                            outbound = line.outbound,
                            meta = "$who · $device · $via",
                        ),
                    )
                }
            }
            listening = controller.isListening()
            connected = controller.isConnected()
            signalReady = controller.signalReady()
            bleOnlyPeer = controller.isBleOnlyPeer()
        }
    }

    LaunchedEffect(status) {
        relayAddr = controller.relayHostPort()
        relayStatus = controller.relayUiStatus()
        if (controller.hasPendingBleHandshakeOffer()) {
            flushBleHandshakeOffer()
        }
    }

    LaunchedEffect(pendingInviteUri) {
        val uri = pendingInviteUri ?: return@LaunchedEffect
        val decoded = PeerInviteUri.decode(uri)
        if (decoded != null) {
            peerInvitePaste = decoded
            controller.pastePeerInvite(decoded)
            onStatus("Invite from link — connecting…")
            showConnect = false
        }
        onPendingInviteConsumed()
    }

    // Open connect sheet automatically until linked once.
    LaunchedEffect(Unit) {
        if (!connected && !signalReady) showConnect = true
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
                    text = if (contactName.isNotBlank() && (connected || signalReady)) {
                        contactName
                    } else {
                        "Direct message"
                    },
                    color = DeroomsColors.Cream,
                    style = androidx.compose.material3.MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = identity?.identityIdHex?.take(12)?.plus("…") ?: "No identity",
                    color = DeroomsColors.CreamMuted,
                    style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
                )
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            StatusChip(
                label = when {
                    signalReady -> "Signal ready"
                    else -> "Signal off"
                },
                active = signalReady,
            )
            StatusChip(
                label = when {
                    relayAddr.isNotBlank() && listening -> "Relay"
                    listening -> "Listening"
                    bleActive -> "Nearby"
                    else -> "No path"
                },
                active = listening || bleActive || relayAddr.isNotBlank(),
            )
            StatusChip(
                label = if (blePeers > 0) "BLE seen $blePeers" else "Not nearby",
                active = blePeers > 0,
            )
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            QuietHint(
                text = when {
                    bleOnlyPeer && relayAddr.isNotBlank() && !controller.hasUsableInternet() ->
                        "Relay saved but offline · Send uses BLE nearby (Start BLE on both)."
                    relayAddr.isNotBlank() && signalReady && connected ->
                        "Peer linked · Send uses LAN on the same Wi‑Fi, or relay across networks."
                    bleOnlyPeer && relayAddr.isNotBlank() ->
                        "Relay online · far-away Send uses rooms-relay; offline nearby falls back to BLE."
                    bleOnlyPeer && bleActive && blePeers > 0 ->
                        "Nearby radios found — not the same as Signal ready. Send uses BLE."
                    bleOnlyPeer && bleActive ->
                        "BLE on · waiting for peer (both: Start BLE). Seen ≠ connected."
                    bleOnlyPeer ->
                        "BLE-only peer · nearby Send uses BLE; far-away needs a rooms-relay."
                    signalReady && connected -> "Peer linked · either side can send"
                    signalReady -> "Signal ready toward peer — they need the handshake to send back"
                    listening -> "Share your invite, then scan or paste theirs"
                    else -> "Tap Manage to start listening"
                },
                modifier = Modifier.weight(1f).fillMaxWidth(),
            )
            TextButton(onClick = { showConnect = true }) {
                Text("Manage", color = DeroomsColors.Moss)
            }
        }

        LazyColumn(
            state = listState,
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(vertical = 12.dp),
        ) {
            if (bubbles.isEmpty()) {
                item {
                    EmptyState(
                        title = "No messages yet",
                        body = "Same Wi‑Fi: Manage → Start listening → scan their QR → Send. " +
                            "Different networks or mobile data: Save a rooms-relay, then " +
                            "scan identity + handshake QR. Shared LAN is not required when relay is set.",
                    )
                }
            }
            items(bubbles) { bubble -> MessageBubble(bubble) }
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
                value = draft,
                onValueChange = { draft = it },
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("Message") },
                shape = RoundedCornerShape(16.dp),
                colors = fieldColors(),
                maxLines = 4,
            )
            PrimaryButton(
                text = "Send to peer",
                onClick = {
                    val text = draft.trim()
                    if (text.isEmpty()) {
                        onStatus("Type a message first.")
                        return@PrimaryButton
                    }
                    bleOnlyPeer = controller.isBleOnlyPeer()
                    signalReady = controller.canSealMessages()
                    // BLE when peer is nearby-only and (no relay or no internet).
                    if (controller.shouldSendViaBle()) {
                        if (!controller.canSealMessages()) {
                            onStatus(
                                "Signal not connected — Manage → scan/paste their invite → Connect. " +
                                    "BLE seen only means radios found each other.",
                            )
                            showConnect = true
                            return@PrimaryButton
                        }
                        onStatus(
                            if (controller.hasRelay() && !controller.hasUsableInternet()) {
                                "Offline — sending over BLE (relay saved for when data returns)…"
                            } else {
                                "Sending over BLE…"
                            },
                        )
                        sendSealedViaBle(text) { blePermLauncher.launch(it) }
                        return@PrimaryButton
                    }
                    if (!connected && !listening && !controller.hasRelay()) {
                        onStatus("Tap Manage → Start listening, then Connect with peer invite.")
                        return@PrimaryButton
                    }
                    pendingBleAfterRelay = text
                    controller.sendMessage(text)
                },
                modifier = Modifier.fillMaxWidth().testTag("send_to_peer"),
            )
        }
    }

    if (showConnect) {
        ModalBottomSheet(
            onDismissRequest = { showConnect = false },
            sheetState = sheetState,
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
                val inviteUri = remember(myInvite) {
                    if (myInvite.isEmpty()) "" else PeerInviteUri.encode(myInvite)
                }
                val qrBmp = remember(inviteUri) {
                    if (inviteUri.isEmpty()) null else InviteQr.bitmap(inviteUri)
                }
                val handshakeUri = remember(myInvite, showHandshakeQr) {
                    if (!showHandshakeQr || myInvite.isEmpty()) ""
                    else PeerInviteUri.encodeKyberContinuation(myInvite)
                }
                val handshakeBmp = remember(handshakeUri) {
                    if (handshakeUri.isEmpty()) null else InviteQr.bitmap(handshakeUri, size = 640)
                }
                Text(
                    "Connection",
                    style = androidx.compose.material3.MaterialTheme.typography.headlineMedium,
                    color = DeroomsColors.Cream,
                )
                QuietHint(
                    "Same Wi‑Fi → LAN. Different networks or mobile data → rooms-relay " +
                        "(TCP DRRL). Compact QR + handshake QR complete Signal; Kyber TCP " +
                        "fetch is not used across NAT. “Peer ephemeral seen” is only Bluetooth.",
                )

                SectionLabel("Your name")
                QuietHint("Shown to people who scan your invite. Stored only on this phone.")
                OutlinedTextField(
                    value = selfNameDraft,
                    onValueChange = { selfNameDraft = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("Name for this identity") },
                    singleLine = true,
                    colors = fieldColors(),
                    shape = RoundedCornerShape(12.dp),
                )
                PrimaryButton(
                    text = "Save name",
                    onClick = {
                        controller.setLocalDisplayName(selfNameDraft)
                        onStatus("Name saved — refresh invite if the QR is already showing.")
                    },
                )

                SectionLabel("1. Listen & share")
                PrimaryButton(
                    text = "Start listening",
                    onClick = { controller.startListening() },
                    modifier = Modifier.fillMaxWidth().testTag("start_listening"),
                )
                PrimaryButton(
                    text = "Refresh invite for this network",
                    onClick = {
                        controller.refreshInviteForCurrentNetwork()
                        showHandshakeQr = false
                    },
                    modifier = Modifier.fillMaxWidth().testTag("refresh_invite_network"),
                )
                QuietHint(
                    "Wi‑Fi ↔ mobile data: the QR stays the same unless your listen path " +
                        "actually changes. You do not need to force-stop the app. Peer Signal session stays.",
                )
                if (myInvite.isNotEmpty()) {
                    QuietHint("Your invite — show this QR or copy the link")
                    if (qrBmp != null) {
                        Image(
                            bitmap = qrBmp.asImageBitmap(),
                            contentDescription = "Invite QR",
                            modifier = Modifier
                                .size(240.dp)
                                .testTag("invite_qr"),
                        )
                    } else {
                        QuietHint("Invite too large for one QR — use Copy below.")
                    }
                    if (inviteUri.isNotEmpty()) {
                        CopyBlock(context, inviteUri, label = "Copy invite link")
                    }
                    TextButton(onClick = { showHandshakeQr = !showHandshakeQr }) {
                        Text(
                            if (showHandshakeQr) "Hide handshake QR" else "Show handshake QR (2 of 2)",
                            color = DeroomsColors.Cream,
                        )
                    }
                    if (showHandshakeQr) {
                        QuietHint(
                            "Different networks: scan this second QR after the identity QR. " +
                                "Same-Wi-Fi Connect can fetch this key without a second scan. " +
                                "Relay Send does not wait on Kyber TCP.",
                        )
                        if (handshakeBmp != null) {
                            Image(
                                bitmap = handshakeBmp.asImageBitmap(),
                                contentDescription = "Handshake QR",
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(320.dp)
                                    .testTag("handshake_qr"),
                            )
                        } else {
                            QuietHint("Handshake QR could not be encoded — use Copy invite text.")
                        }
                    }
                    CopyBlock(context, myInvite, label = "Copy invite text")
                }

                SectionLabel("2. Scan peer invite")
                QuietHint(
                    "Scan their QR in person (out-of-band). BLE seen ≠ Signal ready. " +
                        "Paste lives under Advanced.",
                )
                PrimaryButton(
                    text = "Scan invite QR",
                    onClick = { launchInviteScan() },
                    modifier = Modifier.fillMaxWidth().testTag("scan_invite_qr"),
                )

                SectionLabel("Public / NAT relay")
                QuietHint(
                    "Same Wi‑Fi = LAN. Wi‑Fi↔mobile data or far-away phones = this " +
                        "rooms-relay (TCP DRRL splice). The relay sees ciphertext and who " +
                        "connected, not plaintext. Not STUN/TURN, ngrok, bore.pub, or " +
                        "libp2p circuit v2 — those do not speak DeRooms DRRL.",
                )
                QuietHint(relayStatus)
                val baked = PeerChatController.DEFAULT_PUBLIC_RELAY.trim()
                if (baked.isNotEmpty()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Use public relay", color = DeroomsColors.Cream)
                            QuietHint(baked)
                        }
                        Switch(
                            checked = relayAddr == baked,
                            onCheckedChange = { on ->
                                if (on) {
                                    controller.applyDefaultPublicRelay()
                                } else {
                                    controller.setRelayHostPort("")
                                }
                                relayAddr = controller.relayHostPort()
                                relayStatus = controller.relayUiStatus()
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = DeroomsColors.Ink,
                                checkedTrackColor = DeroomsColors.Moss,
                            ),
                        )
                    }
                } else {
                    QuietHint(
                        "No public DeRooms relay is baked in. Self-host rooms-relay " +
                            "(see docs/relay-nat.md) and paste host:port below.",
                    )
                }
                OutlinedTextField(
                    value = relayAddr,
                    onValueChange = { relayAddr = it },
                    modifier = Modifier.fillMaxWidth().testTag("relay_host_port"),
                    placeholder = { Text(PeerChatController.DEFAULT_RELAY_HINT) },
                    singleLine = true,
                    colors = fieldColors(),
                    shape = RoundedCornerShape(12.dp),
                )
                PrimaryButton(
                    text = "Save relay address",
                    onClick = {
                        controller.setRelayHostPort(relayAddr)
                        relayAddr = controller.relayHostPort()
                        relayStatus = controller.relayUiStatus()
                        onStatus(
                            if (relayAddr.isBlank()) {
                                "Relay cleared — LAN or BLE only until you set a rooms-relay."
                            } else {
                                "Relay set to $relayAddr. Invite includes relay= for the peer."
                            },
                        )
                    },
                )

                SectionLabel("Nearby (no internet)")
                QuietHint(
                    buildString {
                        append("BLE peers seen: $blePeers · ")
                        append(if (bleActive) "radio on. " else "radio off. ")
                        append(
                            "Both phones: Start BLE after Connect, then Send sealed via BLE " +
                                "(or Send to peer). Android 11 and older: grant Location; " +
                                "system Location must be ON. “Peer ephemeral seen” ≠ encrypted.",
                        )
                    },
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PrimaryButton(
                        text = if (bleActive) "BLE on" else "Start BLE",
                        onClick = {
                            val ble = bleHolder[0]
                            if (ble == null) {
                                onStatus("BLE not ready — reopen Direct message.")
                                return@PrimaryButton
                            }
                            if (!ble.hasBlePermissions()) {
                                onStatus(
                                    if (Build.VERSION.SDK_INT < 31) {
                                        "Allow Location for Derooms to scan for BLE peers."
                                    } else {
                                        "Allow Nearby devices / Bluetooth for Derooms."
                                    },
                                )
                                blePermLauncher.launch(blePerms)
                            } else if (!startBleMesh()) {
                                onStatus("Could not start BLE — turn Bluetooth on.")
                            } else {
                                onStatus("BLE mesh active — peer should also tap Start BLE.")
                            }
                        },
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                    )
                    PrimaryButton(
                        text = "Stop BLE",
                        onClick = {
                            bleHolder[0]?.stop()
                            bleActive = false
                        },
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                    )
                }
                PrimaryButton(
                    text = "Send sealed via BLE",
                    onClick = {
                        val text = draft.trim().ifEmpty { "ble-sealed-ping" }
                        sendSealedViaBle(text) { perms -> blePermLauncher.launch(perms) }
                    },
                )

                SectionLabel("Wi‑Fi Direct bulk")
                QuietHint(
                    "Larger sealed payloads when BLE is too small. Both phones: " +
                        "Start Wi‑Fi Direct (receiver becomes group owner). Then sender: " +
                        "Send sealed via Wi‑Fi Direct. Wi‑Fi + location on; stay close. " +
                        "OEM flake is expected — Sync now / BLE remain the reliable path.",
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PrimaryButton(
                        text = if (wdActive) "WD on" else "Start Wi‑Fi Direct",
                        onClick = {
                            val need = wdPerms.any {
                                ContextCompat.checkSelfPermission(context, it) !=
                                    PackageManager.PERMISSION_GRANTED
                            }
                            if (need) wdPermLauncher.launch(wdPerms)
                            else {
                                wdHolder[0]?.startReceive()
                                wdActive = true
                            }
                        },
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                    )
                    PrimaryButton(
                        text = "Stop WD",
                        onClick = {
                            wdHolder[0]?.stop()
                            wdActive = false
                        },
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                    )
                }
                PrimaryButton(
                    text = "Send sealed via Wi‑Fi Direct",
                    onClick = {
                        val text = draft.trim().ifEmpty {
                            "wifi-direct-bulk-" + "x".repeat(200)
                        }
                        val sealed = controller.sealForWifiDirect(text)
                        if (sealed != null) {
                            val wd = wdHolder[0]
                            if (wd == null) {
                                onStatus("Wi‑Fi Direct not ready — reopen Direct message.")
                                return@PrimaryButton
                            }
                            if (!wdActive) {
                                wd.start(asReceiver = false)
                                wdActive = true
                            }
                            wd.queueSealedPayload(sealed, tip = "ui-bulk")
                            bubbles.add(
                                ChatBubbleModel(
                                    text.take(48) + "…",
                                    outbound = true,
                                    meta = "You · wd queue",
                                ),
                            )
                            wd.connectAndSend()
                        }
                    },
                )

                SectionLabel("Background")
                QuietHint(
                    "Doze suspends BLE/WD/TCP. Start FGS before expecting nearby sync; " +
                        "after screen-off or airplane, open the app and tap Sync now. " +
                        "Stop FGS when idle to save battery.",
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PrimaryButton(
                        text = if (fgsActive) "Stop FGS" else "Start FGS",
                        onClick = {
                            if (fgsActive) {
                                org.derooms.app.sync.SyncForegroundService.stop(context)
                                fgsActive = false
                                onStatus("Foreground sync stopped.")
                            } else {
                                org.derooms.app.sync.SyncForegroundService.start(context)
                                fgsActive = true
                                onStatus("Foreground sync started.")
                            }
                        },
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                    )
                    PrimaryButton(
                        text = "Sync now",
                        onClick = {
                            controller.syncNow()
                            org.derooms.app.sync.OpportunisticSyncWorker.enqueueNow(context)
                        },
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                    )
                }

                SectionLabel("Advanced (legacy lab)")
                QuietHint(
                    "Skip unless debugging Gate 1 sender cards or QR failed. Prefer scan above.",
                )
                OutlinedTextField(
                    value = peerInvitePaste,
                    onValueChange = { peerInvitePaste = it },
                    modifier = Modifier.fillMaxWidth().height(100.dp).testTag("paste_peer_invite"),
                    placeholder = { Text("Paste peer invite") },
                    colors = fieldColors(),
                    shape = RoundedCornerShape(12.dp),
                )
                PrimaryButton(
                    text = "Connect with peer invite",
                    onClick = {
                        if (peerInvitePaste.isBlank()) {
                            onStatus("Paste the other phone’s invite first.")
                            return@PrimaryButton
                        }
                        controller.pastePeerInvite(peerInvitePaste)
                        mySenderCard = controller.mySenderCardText()
                        bleOnlyPeer = peerInvitePaste.contains("ble://") ||
                            peerInvitePaste.contains(PeerChatController.BLE_LISTEN_PLACEHOLDER)
                        onStatus("Connecting Signal session…")
                    },
                    modifier = Modifier.fillMaxWidth().testTag("connect_peer_invite"),
                )
                if (mySenderCard.isNotEmpty()) {
                    CopyBlock(context, mySenderCard, label = "Copy sender card")
                }
                OutlinedTextField(
                    value = senderCardPaste,
                    onValueChange = { senderCardPaste = it },
                    modifier = Modifier.fillMaxWidth().height(80.dp),
                    placeholder = { Text("Paste peer sender card (legacy)") },
                    colors = fieldColors(),
                    shape = RoundedCornerShape(12.dp),
                )
                PrimaryButton(
                    text = "Accept sender card (legacy)",
                    onClick = { controller.pasteSenderCard(senderCardPaste) },
                )

                TextButton(
                    onClick = { showConnect = false },
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                ) {
                    Text("Done", color = DeroomsColors.Moss)
                }
            }
        }
    }

    if (showNameDialog) {
        AlertDialog(
            onDismissRequest = { showNameDialog = false },
            title = { Text("Name this chat", color = DeroomsColors.Cream) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    QuietHint("This label stays on this phone. Re-pairing the same identity continues this thread.")
                    OutlinedTextField(
                        value = nameDraft,
                        onValueChange = { nameDraft = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("Contact name") },
                        singleLine = true,
                        colors = fieldColors(),
                        shape = RoundedCornerShape(12.dp),
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        controller.setContactDisplayName(nameDraft)
                        contactName = controller.contactDisplayName()
                        showNameDialog = false
                    },
                ) {
                    Text("Save", color = DeroomsColors.Moss)
                }
            },
            dismissButton = {
                TextButton(onClick = { showNameDialog = false }) {
                    Text("Skip", color = DeroomsColors.CreamMuted)
                }
            },
            containerColor = DeroomsColors.InkElevated,
        )
    }
}

@Composable
private fun fieldColors() = OutlinedTextFieldDefaults.colors(
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
