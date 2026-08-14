package org.derooms.app

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.derooms.app.core.CreatedIdentity
import org.derooms.app.core.RoomsCoreBridge
import org.derooms.app.crypto.IdentityKeystore
import org.derooms.app.peer.PeerChatController
import org.derooms.app.room.RoomLanHub
import org.derooms.app.room.RoomStore
import org.derooms.app.ui.HomeScreen
import org.derooms.app.ui.LinkDeviceScreen
import org.derooms.app.ui.MoreScreen
import org.derooms.app.ui.PeerChatScreen
import org.derooms.app.ui.RoomScreen
import org.derooms.app.ui.RoomsListScreen
import org.derooms.app.ui.components.PrimaryButton
import org.derooms.app.ui.components.QuietHint
import org.derooms.app.ui.theme.DeroomsColors
import org.derooms.app.ui.theme.DeroomsTheme
import java.io.File

/**
 * Product Compose shell: onboarding → disclosure → home → peer chat / rooms / more.
 */
class MainActivity : ComponentActivity() {
    private val pendingInviteState = mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingInviteState.value = intent?.data?.toString()
        RoomsCoreBridge.tryLoadNative()
        setContent {
            DeroomsTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = DeroomsColors.Ink) {
                    AppRoot(this, pendingInviteState)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        pendingInviteState.value = intent.data?.toString()
    }
}

private enum class Screen {
    Onboarding,
    Disclosure,
    Home,
    PeerChat,
    RoomsList,
    Room,
    More,
    LinkDevice,
}

@Composable
private fun AppRoot(context: Context, pendingInviteState: MutableState<String?>) {
    val prefs = remember {
        context.getSharedPreferences("derooms_gate1", Context.MODE_PRIVATE)
    }
    var pendingInviteUri by pendingInviteState
    var pendingRoomInvite by remember { mutableStateOf<String?>(null) }
    var screen by remember {
        mutableStateOf(
            when {
                pendingInviteUri != null &&
                    prefs.getString("identity_id", null) != null &&
                    prefs.getBoolean("disclosure_accepted", false) -> {
                    val uri = pendingInviteUri
                    if (uri != null && org.derooms.app.room.RoomInviteUri.isRoomInvite(uri)) {
                        pendingRoomInvite = uri
                        Screen.RoomsList
                    } else {
                        Screen.PeerChat
                    }
                }
                !prefs.getBoolean("disclosure_accepted", false) &&
                    prefs.getString("identity_id", null) == null -> Screen.Onboarding
                !prefs.getBoolean("disclosure_accepted", false) -> Screen.Disclosure
                else -> Screen.Home
            },
        )
    }
    var identity by remember {
        mutableStateOf(
            prefs.getString("identity_id", null)?.let { id ->
                CreatedIdentity(
                    identityIdHex = id,
                    deviceIdHex = prefs.getString("device_id", "") ?: "",
                    masterPubkeyHex = prefs.getString("master_pubkey", "") ?: "",
                    devicePubkeyHex = prefs.getString("device_pubkey", "") ?: "",
                )
            },
        )
    }
    var status by remember { mutableStateOf("") }
    val peerController = remember {
        PeerChatController(
            context = context,
            onMessage = {},
            onStatus = {},
        )
    }
    val roomStore = remember { RoomStore(context) }
    val roomLanHub = remember { RoomLanHub(context, roomStore) }
    var openRoomId by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        roomLanHub.warmInboxes()
    }

    when (screen) {
        Screen.Onboarding -> OnboardingScreen(
            status = status,
            onCreate = {
                try {
                    val bundle = RoomsCoreBridge.createIdentityBundle()
                    val wrapped = IdentityKeystore.wrap(bundle.secretBlob)
                    File(context.filesDir, "identity.wrap").writeBytes(wrapped.blob)
                    File(context.filesDir, "device_pubkey.hex")
                        .writeText(bundle.publicIdentity.devicePubkeyHex)
                    prefs.edit()
                        .putString("identity_id", bundle.publicIdentity.identityIdHex)
                        .putString("device_id", bundle.publicIdentity.deviceIdHex)
                        .putString("master_pubkey", bundle.publicIdentity.masterPubkeyHex)
                        .putString("device_pubkey", bundle.publicIdentity.devicePubkeyHex)
                        .apply()
                    identity = bundle.publicIdentity
                    status = "Identity created and Keystore-wrapped."
                    screen = Screen.Disclosure
                } catch (e: Exception) {
                    status = "Identity create failed: ${e.message}"
                }
            },
        )
        Screen.Disclosure -> DisclosureScreen(
            onAccept = {
                prefs.edit().putBoolean("disclosure_accepted", true).apply()
                screen = Screen.Home
            },
        )
        Screen.Home -> HomeScreen(
            identity = identity,
            conversations = peerController.listConversations(),
            onOpenConversation = { key ->
                peerController.openConversation(key)
                screen = Screen.PeerChat
            },
            onNewChat = { screen = Screen.PeerChat },
            onOpenRooms = { screen = Screen.RoomsList },
            onOpenMore = { screen = Screen.More },
        )
        Screen.PeerChat -> PeerChatScreen(
            context = context,
            identity = identity,
            status = status,
            onStatus = { status = it },
            onBack = { screen = Screen.Home },
            controller = peerController,
            pendingInviteUri = pendingInviteUri,
            onPendingInviteConsumed = { pendingInviteUri = null },
        )
        Screen.RoomsList -> RoomsListScreen(
            context = context,
            identity = identity,
            roomStore = roomStore,
            status = status,
            onStatus = { status = it },
            onOpenRoom = { id ->
                openRoomId = id
                screen = Screen.Room
            },
            onBack = { screen = Screen.Home },
            pendingRoomInviteUri = pendingRoomInvite ?: pendingInviteUri?.takeIf {
                org.derooms.app.room.RoomInviteUri.isRoomInvite(it)
            },
            onPendingRoomInviteConsumed = {
                pendingRoomInvite = null
                if (pendingInviteUri != null &&
                    org.derooms.app.room.RoomInviteUri.isRoomInvite(pendingInviteUri!!)
                ) {
                    pendingInviteUri = null
                }
            },
        )
        Screen.Room -> RoomScreen(
            context = context,
            identity = identity,
            roomStore = roomStore,
            lanHub = roomLanHub,
            roomIdHexArg = openRoomId,
            status = status,
            onStatus = { status = it },
            onBack = { screen = Screen.RoomsList },
        )
        Screen.More -> MoreScreen(
            onShowDisclosure = { screen = Screen.Disclosure },
            onOpenLinkDevice = { screen = Screen.LinkDevice },
            onBack = { screen = Screen.Home },
        )
        Screen.LinkDevice -> LinkDeviceScreen(
            identityIdHex = identity?.identityIdHex,
            deviceIdHex = identity?.deviceIdHex,
            onBack = { screen = Screen.More },
        )
    }
}

@Composable
private fun OnboardingScreen(status: String, onCreate: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DeroomsColors.Ink)
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            "Derooms",
            style = MaterialTheme.typography.displayLarge,
            color = DeroomsColors.Moss,
        )
        Text(
            "Create your identity",
            style = MaterialTheme.typography.headlineMedium,
            color = DeroomsColors.Cream,
        )
        QuietHint(
            "A master identity and this device key are generated locally. " +
                "Secrets are wrapped with Android Keystore (AES-GCM).",
        )
        PrimaryButton(text = "Create identity", onClick = onCreate)
        if (status.isNotEmpty()) {
            Text(status, color = DeroomsColors.Moss)
        }
        QuietHint("Core: ${RoomsCoreBridge.identityHello()}")
    }
}

@Composable
private fun DisclosureScreen(onAccept: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DeroomsColors.Ink)
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            "Security limitations",
            style = MaterialTheme.typography.headlineMedium,
            color = DeroomsColors.Cream,
        )
        Text(
            text = "Derooms encrypts 1:1 message content end-to-end with Signal Protocol " +
                "when libsignal is available. Before you chat, know the limits:\n\n" +
                "• Same Wi‑Fi / LAN required for peer delivery (BLE or relay as fallback).\n\n" +
                "• Metadata residual risk — peers and networks can still observe " +
                "that you are communicating.\n\n" +
                "• No anonymity guarantee — not a Tor-class system.\n\n" +
                "• Room group MLS seal is available on-device via OpenMLS when FFI is " +
                "rebuilt; membership CRDT still applies separately.\n\n" +
                "Privacy (private beta):\n" +
                "• Identity and keys stay on-device (Android Keystore wrap).\n" +
                "• No third-party analytics in the secure APK flavor.\n" +
                "• Crash reporting is opt-in / off by default.\n" +
                "• Relays and mesh radios see ciphertext only — not message plaintext.\n" +
                "• Nearby radios (BLE / Wi‑Fi Direct) still reveal proximity to observers.\n" +
                "• Continuous background mesh is not promised under Doze — use Sync now / Start FGS.\n\n" +
                "You can re-read this notice later from More. Engineering privacy notes: " +
                "docs/privacy-beta.md (draft — not a published legal policy).",
            color = DeroomsColors.Cream,
            style = MaterialTheme.typography.bodyLarge,
        )
        PrimaryButton(text = "I understand — continue", onClick = onAccept)
    }
}
