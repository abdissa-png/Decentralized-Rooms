package org.derooms.app.ble

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test

class BleMeshControllerTest {
    @Test
    fun stablePeerKey_prefersMac_notEphemeral() {
        assertEquals("AA:BB:CC:DD:EE:FF", BleMeshController.stablePeerKey("aa:bb:cc:dd:ee:ff"))
        assertNull(BleMeshController.stablePeerKey(null))
        assertNull(BleMeshController.stablePeerKey(""))
        assertNull(BleMeshController.stablePeerKey("00:00:00:00:00:00"))
        assertNull(BleMeshController.stablePeerKey("02:00:00:00:00:00"))
        assertEquals(
            BleMeshController.STABLE_UNKNOWN,
            BleMeshController.stablePeerKey("02:00:00:00:00:00")
                ?: BleMeshController.STABLE_UNKNOWN,
        )
    }

    @Test
    fun sameRadio_sameStableKey_acrossEphemeralRotation() {
        val mac = "11:22:33:44:55:66"
        val firstEphemeral = "aabbccddeeff00112233445566778899"
        val secondEphemeral = "99887766554433221100ffeeddccbbaa"
        assertNotEquals(firstEphemeral, secondEphemeral)
        assertEquals(
            BleMeshController.stablePeerKey(mac),
            BleMeshController.stablePeerKey(mac),
        )
    }

    @Test
    fun frame_roundTrip_doesNotDependOnAdvertiserRotation() {
        val sealed = "whisper-payload".toByteArray(Charsets.UTF_8)
        val id1 = ByteArray(BleMeshController.EPHEMERAL_LEN) { 1 }
        val id2 = ByteArray(BleMeshController.EPHEMERAL_LEN) { 2 }
        val decoded1 = BleMeshController.decodeFrame(BleMeshController.encodeFrame(id1, sealed))!!
        val decoded2 = BleMeshController.decodeFrame(BleMeshController.encodeFrame(id2, sealed))!!
        assertArrayEquals(sealed, decoded1.second)
        assertArrayEquals(sealed, decoded2.second)
        assertArrayEquals(id1, decoded1.first)
        assertArrayEquals(id2, decoded2.first)
    }
}
