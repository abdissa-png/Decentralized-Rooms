package org.derooms.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.derooms.app.core.RoomsCoreBridge
import org.derooms.app.signal.LibsignalSession
import org.derooms.app.ui.components.BrandHeader
import org.derooms.app.ui.components.PrimaryButton
import org.derooms.app.ui.components.QuietHint
import org.derooms.app.ui.components.SectionLabel
import org.derooms.app.ui.theme.DeroomsColors

@Composable
fun MoreScreen(
    onShowDisclosure: () -> Unit,
    onOpenLinkDevice: () -> Unit,
    onBack: () -> Unit,
) {
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
        BrandHeader(subtitle = "Settings & honesty")

        SectionLabel("Security")
        PrimaryButton(
            text = "Security limitations",
            onClick = onShowDisclosure,
        )
        PrimaryButton(
            text = "Link device (stub)",
            onClick = onOpenLinkDevice,
        )
        QuietHint(
            "Derooms is E2E for content. It is not Tor-class anonymity. " +
                "LAN, BLE, or an optional relay may see that you are online. " +
                "No third-party analytics in the secure APK; crash reporting stays opt-in.",
        )

        SectionLabel("How to chat")
        QuietHint(
            "1. Home shows one row per person you paired with.\n" +
                "2. New chat → Manage → Start listening; show QR or copy invite link.\n" +
                "3. Scan the other phone’s QR. Name the chat when asked.\n" +
                "4. Send — LAN on the same Wi‑Fi; rooms-relay across networks " +
                    "when you Save a relay address; sealed BLE only for nearby with no relay.\n" +
                "Each bubble shows who, which device, and how it arrived (LAN / BLE / relay / Wi‑Fi Direct).\n" +
                "Re-scanning an old identity continues that conversation.\n" +
                "Leaving a chat keeps identity and the thread; listening stays up so Manage still works.\n" +
                "Rooms is a group thread with Members + Manage (MLS / invites).\n" +
                "Offline nearby: Start BLE on both after Connect, then Send.\n" +
                "After Doze / airplane: Manage → Sync now (and Start FGS if expecting mesh).\n" +
                "NAT: there is no public DeRooms relay fleet. Self-host rooms-relay (TCP DRRL); " +
                    "the relay sees ciphertext + who connected, not plaintext.",
        )

        SectionLabel("Private beta")
        QuietHint(
            "Pilot users: keep Wi‑Fi on for LAN; use BLE for proximity-only; " +
                "configure NAT relay only when peers lack a shared LAN. " +
                "Report delivery failures with device model + whether FGS was on. " +
                "Privacy notes are draft engineering honesty (docs/privacy-beta.md) — " +
                "not a published legal policy URL yet.",
        )

        SectionLabel("Build")
        QuietHint(
            "UniFFI: ${if (RoomsCoreBridge.isNativeUsable()) "ok" else "stub"} · " +
                "libsignal: ${if (LibsignalSession.isNativeAvailable()) "ok" else "pending"} · " +
                "hello: ${RoomsCoreBridge.identityHello()}",
        )
    }
}
