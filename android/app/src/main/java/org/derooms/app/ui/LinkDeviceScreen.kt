package org.derooms.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import org.derooms.app.ui.components.BrandHeader
import org.derooms.app.ui.components.QuietHint
import org.derooms.app.ui.components.SectionLabel
import org.derooms.app.ui.theme.DeroomsColors

/**
 * Phase 3a stub: multi-device link ceremony placeholder.
 * Does not generate link QR, cross-sign, or revoke — honesty only.
 */
@Composable
fun LinkDeviceScreen(
    identityIdHex: String?,
    deviceIdHex: String?,
    onBack: () -> Unit,
) {
    val safetyPlaceholder = formatSafetyNumberPlaceholder(identityIdHex, deviceIdHex)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DeroomsColors.Ink)
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack) {
            Text("← Back", color = DeroomsColors.Moss)
        }
        BrandHeader(subtitle = "Link device (stub)")

        SectionLabel("Safety number (placeholder)")
        Text(
            text = safetyPlaceholder,
            modifier = Modifier.fillMaxWidth(),
            style = MaterialTheme.typography.headlineSmall,
            color = DeroomsColors.Cream,
            textAlign = TextAlign.Center,
        )
        QuietHint(
            "This is a layout placeholder derived from local identity/device hex — " +
                "not a verified safety number, and not comparable across apps yet.",
        )

        SectionLabel("Phase 3a")
        QuietHint(
            "Phase 3a: link second device via QR (not shipping revoke yet). " +
                "Ceremony will be: QR from an existing device → new DeviceSigningKey on the " +
                "new phone → master cross-sign — never clone device or MLS secrets. " +
                "Each device keeps its own MLS leaf (answers.md §51 / ADR-0004).",
        )
    }
}

private fun formatSafetyNumberPlaceholder(identityIdHex: String?, deviceIdHex: String?): String {
    val raw = buildString {
        append((identityIdHex ?: "00000000").trim().lowercase().take(32))
        append((deviceIdHex ?: "00000000").trim().lowercase().take(32))
    }.padEnd(60, '0').take(60)
    return raw.chunked(5).joinToString(" ") { it.uppercase() }
}
