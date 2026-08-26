package org.derooms.app.room

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RoomInviteUriTest {
    @Test
    fun roundTripHex() {
        val hex = "0123456789abcdef".repeat(8) // 128 hex chars
        val uri = RoomInviteUri.encode(hex)
        assertTrue(uri.startsWith(RoomInviteUri.PREFIX))
        assertEquals(hex, RoomInviteUri.decode(uri))
    }

    @Test
    fun decodeRawHex() {
        val hex = "ab".repeat(32)
        assertEquals(hex, RoomInviteUri.decode(hex))
    }

    @Test
    fun rejectGarbage() {
        assertNull(RoomInviteUri.decode("not-an-invite"))
        assertNull(RoomInviteUri.decode(""))
    }
}

class RoomAcceptUriTest {
    @Test
    fun roundTripAccept() {
        // DRAM magic 4452414d + payload
        val hex = "4452414d" + "01" + "ab".repeat(40)
        val uri = RoomAcceptUri.encode(hex)
        assertTrue(uri.startsWith(RoomAcceptUri.PREFIX))
        assertEquals(hex, RoomAcceptUri.decode(uri))
        assertEquals(hex, RoomAcceptUri.decode(hex))
    }

    @Test
    fun rejectNonDram() {
        assertNull(RoomAcceptUri.decode("deadbeef".repeat(8)))
        assertNull(RoomAcceptUri.decode("not-accept"))
    }
}

class RoomConnectUriTest {
    @Test
    fun identityCardRoundTrip() {
        val id = "a".repeat(64)
        val vk = "b".repeat(64)
        val uri = RoomIdentityUri.encode(id, vk)
        assertTrue(uri.startsWith(RoomIdentityUri.PREFIX))
        val card = RoomIdentityUri.decode(uri)
        assertNotNull(card)
        assertEquals(id, card!!.identityIdHex)
        assertEquals(vk, card.deviceVkHex)
    }

    @Test
    fun syncPathRoundTrip() {
        val room = "c".repeat(64)
        val listen = "/ip4/192.168.1.10/tcp/44002/p2p/12D3"
        val vk = "d".repeat(64)
        val uri = RoomSyncPathUri.encode(room, listen, vk)
        assertTrue(uri.startsWith(RoomSyncPathUri.PREFIX))
        val path = RoomSyncPathUri.decode(uri)
        assertNotNull(path)
        assertEquals(room, path!!.roomIdHex)
        assertEquals(listen, path.listenMultiaddr)
        assertEquals(vk, path.deviceVkHex)
    }
}

class RoomStoreSortTest {
    @Test
    fun sortByParentOrderChain() {
        val a = RoomStore.RoomLine(
            outbound = true,
            text = "a",
            meta = "",
            eventIdHex = "a".repeat(64),
            parentHexes = emptyList(),
        )
        val b = RoomStore.RoomLine(
            outbound = true,
            text = "b",
            meta = "",
            eventIdHex = "b".repeat(64),
            parentHexes = listOf("a".repeat(64)),
        )
        val c = RoomStore.RoomLine(
            outbound = false,
            text = "c",
            meta = "",
            eventIdHex = "c".repeat(64),
            parentHexes = listOf("b".repeat(64)),
        )
        // Insert out of order
        val sorted = RoomStore.sortByParentOrder(listOf(c, a, b))
        assertEquals(listOf("a", "b", "c"), sorted.map { it.text })
    }

    @Test
    fun mixedInboundOutboundKeepsTimeOrder() {
        val yours1 = RoomStore.RoomLine(
            outbound = true,
            text = "hi",
            meta = "You",
            eventIdHex = "a".repeat(64),
            parentHexes = emptyList(),
            atMs = 100L,
        )
        val theirs = RoomStore.RoomLine(
            outbound = false,
            text = "hello",
            meta = "Peer",
            eventIdHex = "",
            parentHexes = emptyList(),
            atMs = 200L,
        )
        val yours2 = RoomStore.RoomLine(
            outbound = true,
            text = "ok",
            meta = "You",
            eventIdHex = "b".repeat(64),
            parentHexes = listOf("a".repeat(64)),
            atMs = 300L,
        )
        val sorted = RoomStore.sortForDisplay(listOf(yours2, yours1, theirs))
        assertEquals(listOf("hi", "hello", "ok"), sorted.map { it.text })
    }

    @Test
    fun withTcpPortRewritesListenAddr() {
        val src = "/ip4/192.168.1.8/tcp/55111/p2p/dead"
        assertEquals(
            "/ip4/192.168.1.8/tcp/44002/p2p/dead",
            RoomLanHub.withTcpPort(src, 44002),
        )
    }

    @Test
    fun encodeParseLine() {
        val line = RoomStore.RoomLine(
            outbound = true,
            text = "hello",
            meta = "You · local",
            eventIdHex = "ab".repeat(32),
            parentHexes = listOf("cd".repeat(32)),
            atMs = 42L,
        )
        val raw = RoomStore.encodeLine(line).trimEnd()
        val got = RoomStore.parseLine(raw)
        assertNotNull(got)
        assertEquals(line.text, got!!.text)
        assertEquals(line.eventIdHex, got.eventIdHex)
        assertEquals(line.parentHexes, got.parentHexes)
        assertEquals(42L, got.atMs)
        assertTrue(got.outbound)
    }
}
