package org.derooms.app.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.derooms.app.core.CreatedIdentity
import org.derooms.app.core.RoomsCoreBridge
import org.derooms.app.crypto.IdentityKeystore
import org.derooms.app.peer.InviteQr
import org.derooms.app.room.RoomIdentityUri
import org.derooms.app.room.RoomInviteUri
import org.derooms.app.room.RoomSessionCache
import org.derooms.app.room.RoomStore
import org.derooms.app.ui.components.CopyBlock
import org.derooms.app.ui.components.EmptyState
import org.derooms.app.ui.components.PrimaryButton
import org.derooms.app.ui.components.QuietHint
import org.derooms.app.ui.theme.DeroomsColors
import java.io.File

/**
 * Product rooms list: tap → detail; FAB / empty → create; scan QR to join.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RoomsListScreen(
    context: Context,
    identity: CreatedIdentity?,
    roomStore: RoomStore,
    status: String,
    onStatus: (String) -> Unit,
    onOpenRoom: (String) -> Unit,
    onBack: () -> Unit,
    pendingRoomInviteUri: String? = null,
    onPendingRoomInviteConsumed: () -> Unit = {},
) {
    var rooms by remember { mutableStateOf(roomStore.listRooms()) }
    var showIdentity by remember { mutableStateOf(false) }
    val identitySheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val identityUri = remember(identity?.identityIdHex, identity?.devicePubkeyHex) {
        RoomIdentityUri.encode(
            identity?.identityIdHex.orEmpty(),
            identity?.devicePubkeyHex.orEmpty(),
        )
    }
    val identityQr: Bitmap? = remember(identityUri) {
        if (identityUri.isNotEmpty()) InviteQr.bitmap(identityUri) else null
    }

    fun refresh() {
        rooms = roomStore.listRooms()
    }

    fun loadSecret(): ByteArray? {
        val wrapFile = File(context.filesDir, "identity.wrap")
        if (!wrapFile.exists()) {
            onStatus("No Keystore-wrapped identity — create identity first.")
            return null
        }
        return IdentityKeystore.unwrap(IdentityKeystore.WrappedSecret(wrapFile.readBytes()))
    }

    fun createRoom() {
        try {
            val secret = loadSecret() ?: return
            val createdSecs = System.currentTimeMillis() / 1000L
            val handle = RoomsCoreBridge.openLocalRoomSession(secret, createdSecs.toULong())
            val id = handle.roomIdHex().trim().lowercase()
            if (id.isEmpty()) {
                onStatus("Room founding failed (native missing or bad secret).")
                return
            }
            RoomSessionCache.putRoom(id, handle)
            val mlsPath = roomStore.mlsStateFile(id).absolutePath
            roomStore.upsert(
                roomIdHex = id,
                displayName = RoomStore.defaultName(id),
                mlsStatePath = mlsPath,
                createdUnixSecs = createdSecs,
                lastActivityMs = System.currentTimeMillis(),
            )
            refresh()
            onStatus("Created ${RoomStore.defaultName(id)}")
            onOpenRoom(id)
        } catch (e: Exception) {
            onStatus("Create room failed: ${e.message}")
        }
    }

    fun joinFromMaterial(material: String) {
        try {
            val secret = loadSecret() ?: return
            val handle = RoomsCoreBridge.joinRoomFromInvite(secret, material.trim())
            val id = handle.roomIdHex().trim().lowercase()
            if (id.isEmpty()) {
                onStatus("Join failed — invite must target your identity_id.")
                return
            }
            RoomSessionCache.putRoom(id, handle)
            val receipt = handle.acceptReceiptHex()
            roomStore.upsert(
                roomIdHex = id,
                displayName = RoomStore.defaultName(id),
                mlsStatePath = roomStore.mlsStateFile(id).absolutePath,
                lastActivityMs = System.currentTimeMillis(),
                pendingAcceptReceiptHex = receipt,
            )
            refresh()
            onStatus(
                if (receipt.isNotEmpty()) {
                    "Joined ${RoomStore.defaultName(id)} — show Accept QR to founder"
                } else {
                    "Joined ${RoomStore.defaultName(id)}"
                },
            )
            onOpenRoom(id)
        } catch (e: Exception) {
            onStatus("Join failed: ${e.message}")
        }
    }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val contents = result.contents ?: return@rememberLauncherForActivityResult
        val material = RoomInviteUri.decode(contents)
        if (material == null) {
            onStatus("QR was not a room invite. Use Advanced paste in a room.")
            return@rememberLauncherForActivityResult
        }
        joinFromMaterial(material)
    }
    val cameraPermLauncher = rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            scanLauncher.launch(
                ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setPrompt("Scan room invite QR")
                    .setBeepEnabled(false),
            )
        } else {
            onStatus("Camera permission denied — open a room and use Advanced paste.")
        }
    }

    fun launchScan() {
        val need = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) !=
            PackageManager.PERMISSION_GRANTED
        if (need) {
            cameraPermLauncher.launch(Manifest.permission.CAMERA)
        } else {
            scanLauncher.launch(
                ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setPrompt("Scan room invite QR")
                    .setBeepEnabled(false),
            )
        }
    }

    LaunchedEffect(pendingRoomInviteUri) {
        val uri = pendingRoomInviteUri ?: return@LaunchedEffect
        val material = RoomInviteUri.decode(uri)
        onPendingRoomInviteConsumed()
        if (material != null) {
            joinFromMaterial(material)
        } else {
            onStatus("Link was not a room invite.")
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(DeroomsColors.Ink)
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onBack) {
                Text("← Back", color = DeroomsColors.Moss)
            }
            Text(
                "Rooms",
                color = DeroomsColors.Cream,
                style = androidx.compose.material3.MaterialTheme.typography.titleLarge,
                modifier = Modifier.weight(1f),
            )
        }

        QuietHint(
            "Joining a room: show your identity QR so the founder can invite you. " +
                "Or scan their invite QR. You do not need to create a room first.",
        )

        if (status.isNotEmpty()) {
            QuietHint(status)
        }

        if (rooms.isEmpty()) {
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                contentAlignment = Alignment.Center,
            ) {
                EmptyState(
                    title = "No rooms yet",
                    body = "Show your identity QR so someone can invite you, scan an invite, or create a room.",
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(bottom = 8.dp),
            ) {
                items(rooms, key = { it.roomIdHex }) { row ->
                    RoomRow(row, onClick = { onOpenRoom(row.roomIdHex) })
                }
            }
        }

        PrimaryButton(
            text = "Show my identity QR",
            onClick = {
                if (identity == null || identityUri.isEmpty()) {
                    onStatus("Create identity first (home onboarding).")
                } else {
                    showIdentity = true
                }
            },
        )
        PrimaryButton(text = "Scan invite QR", onClick = { launchScan() })
        PrimaryButton(text = "Create room", onClick = { createRoom() })
    }

    if (showIdentity) {
        ModalBottomSheet(
            onDismissRequest = { showIdentity = false },
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
                QuietHint("Let a room founder scan this to invite you. You do not need a room yet.")
                if (identityQr != null) {
                    Image(
                        bitmap = identityQr.asImageBitmap(),
                        contentDescription = "Identity QR",
                        modifier = Modifier.size(220.dp),
                    )
                } else {
                    QuietHint("Could not encode identity QR.")
                }
                if (identityUri.isNotEmpty()) {
                    CopyBlock(context, identityUri, label = "Copy identity link")
                }
                TextButton(onClick = { showIdentity = false }) {
                    Text("Done", color = DeroomsColors.Moss)
                }
            }
        }
    }
}

@Composable
private fun RoomRow(row: RoomStore.RoomEntry, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(16.dp),
        color = DeroomsColors.Panel,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    row.displayName.ifBlank { RoomStore.defaultName(row.roomIdHex) },
                    style = androidx.compose.material3.MaterialTheme.typography.titleMedium,
                    color = DeroomsColors.Cream,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = row.lastText.ifBlank { "No messages yet" },
                    style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
                    color = DeroomsColors.CreamMuted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text("→", color = DeroomsColors.Moss)
        }
    }
}
