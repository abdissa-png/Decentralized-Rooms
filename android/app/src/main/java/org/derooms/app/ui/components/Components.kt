package org.derooms.app.ui.components

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.derooms.app.ui.theme.DeroomsColors

data class ChatBubbleModel(
    val text: String,
    val outbound: Boolean,
    val meta: String = "",
)

@Composable
fun BrandHeader(
    subtitle: String? = null,
    trailing: @Composable (() -> Unit)? = null,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "Derooms",
                style = MaterialTheme.typography.displayLarge.copy(fontSize = 32.sp),
                color = DeroomsColors.Moss,
            )
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = DeroomsColors.CreamMuted,
                )
            }
        }
        trailing?.invoke()
    }
}

@Composable
fun StatusChip(
    label: String,
    active: Boolean,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(999.dp))
            .background(if (active) DeroomsColors.Moss.copy(alpha = 0.18f) else DeroomsColors.Panel)
            .border(
                width = 1.dp,
                color = if (active) DeroomsColors.Moss.copy(alpha = 0.45f) else DeroomsColors.Line,
                shape = RoundedCornerShape(999.dp),
            )
            .padding(horizontal = 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(
            modifier = Modifier
                .size(7.dp)
                .clip(CircleShape)
                .background(if (active) DeroomsColors.Moss else DeroomsColors.CreamMuted),
        )
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = if (active) DeroomsColors.Moss else DeroomsColors.CreamMuted,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
fun HomeActionRow(
    title: String,
    subtitle: String,
    onClick: () -> Unit,
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(16.dp),
        color = DeroomsColors.Panel,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 18.dp, vertical = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium, color = DeroomsColors.Cream)
                Spacer(Modifier.height(2.dp))
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = DeroomsColors.CreamMuted)
            }
            Text("→", color = DeroomsColors.Moss, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
fun MessageBubble(model: ChatBubbleModel) {
    val align = if (model.outbound) Alignment.End else Alignment.Start
    val bg = if (model.outbound) DeroomsColors.BubbleOut else DeroomsColors.BubbleIn
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = align,
    ) {
        if (model.meta.isNotEmpty()) {
            Text(
                model.meta,
                style = MaterialTheme.typography.bodySmall,
                color = DeroomsColors.CreamMuted,
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
            )
        }
        Box(
            modifier = Modifier
                .widthIn(max = 300.dp)
                .clip(RoundedCornerShape(18.dp))
                .background(bg)
                .padding(horizontal = 14.dp, vertical = 10.dp),
        ) {
            Text(model.text, style = MaterialTheme.typography.bodyLarge, color = DeroomsColors.Cream)
        }
    }
}

@Composable
fun PrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier.fillMaxWidth(),
    enabled: Boolean = true,
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.height(48.dp),
        shape = RoundedCornerShape(14.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = DeroomsColors.Moss,
            contentColor = DeroomsColors.Ink,
            disabledContainerColor = DeroomsColors.PanelSoft,
            disabledContentColor = DeroomsColors.CreamMuted,
        ),
    ) {
        Text(text, style = MaterialTheme.typography.labelLarge)
    }
}

@Composable
fun CopyBlock(context: Context, text: String, label: String = "Copy") {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(DeroomsColors.Ink)
            .border(1.dp, DeroomsColors.Line, RoundedCornerShape(12.dp))
            .padding(10.dp),
    ) {
        Text(
            text = text,
            fontFamily = FontFamily.Monospace,
            fontSize = 10.sp,
            color = DeroomsColors.CreamMuted,
            maxLines = 4,
            overflow = TextOverflow.Ellipsis,
        )
        TextButton(
            onClick = {
                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("derooms", text))
            },
        ) {
            Text(label, color = DeroomsColors.Moss)
        }
    }
}

@Composable
fun SectionLabel(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        color = DeroomsColors.Cream,
        modifier = Modifier.padding(top = 8.dp, bottom = 4.dp),
    )
}

@Composable
fun QuietHint(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = DeroomsColors.CreamMuted,
        modifier = modifier,
    )
}

@Composable
fun EmptyState(title: String, body: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium, color = DeroomsColors.Cream)
        Text(body, style = MaterialTheme.typography.bodyMedium, color = DeroomsColors.CreamMuted)
    }
}
