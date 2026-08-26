package org.derooms.app.peer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConversationStoreTest {
    @Test
    fun threadKeyPrefersIdentityId() {
        val id = "ab".repeat(32)
        val vk = "cd".repeat(32)
        assertEquals(id, ConversationStore.threadKey(id, vk))
        assertEquals(vk, ConversationStore.threadKey("", vk))
    }

    @Test
    fun sameIdentityContinuesSameThread() {
        val id = "11".repeat(32)
        val vkA = "aa".repeat(32)
        val vkB = "bb".repeat(32)
        assertEquals(
            ConversationStore.threadKey(id, vkA),
            ConversationStore.threadKey(id, vkB),
        )
    }

    @Test
    fun lineRoundTripKeepsViaAndDevice() {
        val line = ConversationStore.Line(
            outbound = true,
            text = "hello there",
            meta = "relay",
            via = "relay",
            deviceShort = "abcd1234",
            atMs = 1_700_000_000_000L,
        )
        val raw = ConversationStore.encodeLine(line).trimEnd()
        val got = ConversationStore.parseLine(raw)!!
        assertTrue(got.outbound)
        assertEquals("hello there", got.text)
        assertEquals("relay", got.via)
        assertEquals("abcd1234", got.deviceShort)
        assertEquals(1_700_000_000_000L, got.atMs)
    }

    @Test
    fun legacyThreeFieldLineStillParses() {
        val got = ConversationStore.parseLine("in|ble|hi from peer")!!
        assertFalse(got.outbound)
        assertEquals("hi from peer", got.text)
        assertEquals("ble", got.via)
    }

    @Test
    fun pathLabelsAreHuman() {
        assertEquals("BLE", ConversationStore.pathLabel("ble"))
        assertEquals("relay", ConversationStore.pathLabel("relay"))
        assertEquals("LAN", ConversationStore.pathLabel("lan"))
        assertEquals("Wi‑Fi Direct", ConversationStore.pathLabel("wd"))
    }
}
