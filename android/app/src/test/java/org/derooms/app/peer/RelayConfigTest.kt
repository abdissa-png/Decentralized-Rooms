package org.derooms.app.peer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayConfigTest {
    @Test
    fun defaultPublicRelayIsNotLaptopTunnel() {
        val baked = PeerChatController.DEFAULT_PUBLIC_RELAY.trim()
        assertFalse(
            "do not bake bore.pub as the product default",
            baked.contains("bore.pub", ignoreCase = true),
        )
        assertFalse(
            "do not bake loopback as the product default",
            baked.startsWith("127.0.0.1:") || baked.startsWith("localhost:"),
        )
        // Empty is honest: there is no public DeRooms DRRL fleet yet.
        if (baked.isNotEmpty()) {
            val n = PeerChatController.normalizeRelayHostPort(baked)
            assertTrue("baked default must parse as host:port", n.contains(':'))
        }
    }

    @Test
    fun normalizeStripsSchemesAndInvitePrefix() {
        assertEquals(
            "relay.example:44099",
            PeerChatController.normalizeRelayHostPort("tcp://relay.example:44099/path"),
        )
        assertEquals(
            "10.0.0.2:44099",
            PeerChatController.normalizeRelayHostPort("relay=10.0.0.2:44099"),
        )
        assertEquals(
            "gateway.local:44100",
            PeerChatController.normalizeRelayHostPort("  https://gateway.local:44100  "),
        )
        assertEquals("", PeerChatController.normalizeRelayHostPort(""))
        assertEquals("", PeerChatController.normalizeRelayHostPort("no-port"))
        assertEquals("", PeerChatController.normalizeRelayHostPort("host:99999"))
    }

    @Test
    fun resolveInitialRelayKeepsEmptyWhenNoBakedDefault() {
        assertEquals(
            "",
            PeerChatController.resolveInitialRelay(saved = null, hasPref = false),
        )
        assertEquals(
            "192.168.1.10:44099",
            PeerChatController.resolveInitialRelay(
                saved = "192.168.1.10:44099",
                hasPref = true,
            ),
        )
        assertEquals(
            "",
            PeerChatController.resolveInitialRelay(saved = "", hasPref = true),
        )
    }

    @Test
    fun inviteRelayRoundTripTextAndCompact() {
        val vk = "ab".repeat(32)
        val inv = PeerChatController.PeerInvite(
            signalName = "d${vk.take(16)}",
            deviceVkHex = vk,
            prekeyB64 = "QUJD",
            listenAddr = PeerChatController.BLE_LISTEN_PLACEHOLDER,
            relayHostPort = "relay.example:44099",
        )
        val text = PeerChatController.encodeInvite(inv)
        assertTrue(text.contains("listen=ble://offline"))
        assertTrue(text.contains("relay=relay.example:44099"))
        val got = PeerChatController.decodeInvite(text)!!
        assertEquals(PeerChatController.BLE_LISTEN_PLACEHOLDER, got.listenAddr)
        assertEquals("relay.example:44099", got.relayHostPort)

        val uri = PeerInviteUri.encode(text)
        val decoded = PeerInviteUri.decode(uri)!!
        val round = PeerChatController.decodeInvite(decoded)!!
        assertEquals(PeerChatController.BLE_LISTEN_PLACEHOLDER, round.listenAddr)
        assertEquals("relay.example:44099", round.relayHostPort)
        assertEquals("", round.identityIdHex)
    }

    @Test
    fun inviteIdentityAndLabelSurviveTextRoundTrip() {
        val vk = "ab".repeat(32)
        val id = "cd".repeat(32)
        val inv = PeerChatController.PeerInvite(
            signalName = "d${vk.take(16)}",
            deviceVkHex = vk,
            prekeyB64 = "QUJD",
            listenAddr = PeerChatController.BLE_LISTEN_PLACEHOLDER,
            relayHostPort = "relay.example:44099",
            identityIdHex = id,
            displayLabel = "Ada",
        )
        val got = PeerChatController.decodeInvite(PeerChatController.encodeInvite(inv))!!
        assertEquals(id, got.identityIdHex)
        assertEquals("Ada", got.displayLabel)
        assertEquals(ConversationStore.threadKey(id, vk), ConversationStore.threadKey(got.identityIdHex, got.deviceVkHex))
    }

    @Test
    fun bleOnlyListenStillCarriesRelayForPeerAutoApply() {
        val text = PeerChatController.encodeInvite(
            PeerChatController.PeerInvite(
                signalName = "dabcd",
                deviceVkHex = "cd".repeat(32),
                prekeyB64 = "QUJD",
                listenAddr = "ble://offline",
                relayHostPort = "nat.example:44099",
            ),
        )
        val peer = PeerChatController.decodeInvite(text)!!
        assertTrue(PeerChatController.isBleListenAddr(peer.listenAddr))
        assertTrue(peer.relayHostPort.isNotBlank())
        // Same-LAN is not required once a rooms-relay is on the invite.
        assertNotEquals("/ip4/", peer.listenAddr.take(5))
    }

    @Test
    fun loopbackRelayIsReplacedByInviteHint() {
        assertTrue(PeerChatController.isLoopbackRelay("127.0.0.1:44099"))
        assertTrue(PeerChatController.isLoopbackRelay("localhost:44099"))
        assertFalse(PeerChatController.isLoopbackRelay("example.net:44099"))
    }

    @Test
    fun parsePushTipDetectsRelaySuffix() {
        val (hex, via) = PeerChatController.parsePushTip("a".repeat(64) + "+relay")
        assertEquals(64, hex.length)
        assertTrue(via)
        val (plain, notVia) = PeerChatController.parsePushTip("b".repeat(64))
        assertEquals("b".repeat(64), plain)
        assertFalse(notVia)
    }
}
