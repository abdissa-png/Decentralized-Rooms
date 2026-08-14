package org.derooms.app.ui

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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.derooms.app.core.CreatedIdentity
import org.derooms.app.peer.ConversationStore
import org.derooms.app.ui.components.BrandHeader
import org.derooms.app.ui.components.HomeActionRow
import org.derooms.app.ui.components.QuietHint
import org.derooms.app.ui.components.StatusChip
import org.derooms.app.ui.theme.DeroomsColors

@Composable
fun HomeScreen(
    identity: CreatedIdentity?,
    conversations: List<ConversationStore.Contact>,
    onOpenConversation: (String) -> Unit,
    onNewChat: () -> Unit,
    onOpenRooms: () -> Unit,
    onOpenMore: () -> Unit,
) {
    Column(
        Modifier
            .fillMaxSize()
            .background(DeroomsColors.Ink)
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        BrandHeader(
            subtitle = "Encrypted rooms · your keys stay on device",
            trailing = {
                StatusChip(
                    label = if (identity != null) "Ready" else "Setup",
                    active = identity != null,
                )
            },
        )

        QuietHint(
            text = identity?.identityIdHex?.let { "You · ${it.take(16)}…" }
                ?: "Create an identity to begin.",
        )

        HomeActionRow(
            title = "New chat",
            subtitle = "Scan or share an invite · LAN, BLE, or relay",
            onClick = onNewChat,
        )
        HomeActionRow(
            title = "Rooms",
            subtitle = "Create a group, or show your identity QR so someone can invite you",
            onClick = onOpenRooms,
        )
        HomeActionRow(
            title = "More",
            subtitle = "Security notice, tips, about",
            onClick = onOpenMore,
        )

        Text(
            "Chats",
            color = DeroomsColors.Cream,
            style = androidx.compose.material3.MaterialTheme.typography.titleMedium,
        )

        if (conversations.isEmpty()) {
            QuietHint("No conversations yet. Tap New chat, then Manage to pair with someone.")
            Box(Modifier.weight(1f).fillMaxWidth())
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(bottom = 8.dp),
            ) {
                items(conversations, key = { it.threadKey }) { row ->
                    InboxRow(row, onClick = { onOpenConversation(row.threadKey) })
                }
            }
        }
    }
}

@Composable
private fun InboxRow(row: ConversationStore.Contact, onClick: () -> Unit) {
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
                    row.displayName.ifBlank { ConversationStore.defaultName(row.deviceVkHex, row.identityIdHex) },
                    style = androidx.compose.material3.MaterialTheme.typography.titleMedium,
                    color = DeroomsColors.Cream,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = buildString {
                        if (row.lastText.isNotBlank()) append(row.lastText)
                        else append("No messages yet")
                        val via = ConversationStore.pathLabel(row.lastVia)
                        if (via.isNotBlank() && row.lastText.isNotBlank()) {
                            append(" · ")
                            append(via)
                        }
                    },
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
