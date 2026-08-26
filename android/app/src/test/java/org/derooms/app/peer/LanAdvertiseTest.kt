package org.derooms.app.peer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LanAdvertiseTest {
    @Test
    fun skipsCellularEvenWhenRfc1918() {
        val picked = LanAdvertise.pick(
            listOf(
                LanAdvertise.Candidate("ccmni0", "10.160.244.93"),
                LanAdvertise.Candidate("rmnet5", "10.163.184.223"),
            ),
        )
        assertNull("cellular 10.x must not be advertised as LAN", picked)
    }

    @Test
    fun prefersWlanOverCellular() {
        val picked = LanAdvertise.pick(
            listOf(
                LanAdvertise.Candidate("ccmni0", "10.160.244.93"),
                LanAdvertise.Candidate("wlan0", "192.168.1.42"),
                LanAdvertise.Candidate("rmnet5", "10.163.184.223"),
            ),
        )
        assertEquals("192.168.1.42", picked)
    }

    @Test
    fun wifiTenDotPreferredOverCellularTenDot() {
        val picked = LanAdvertise.pick(
            listOf(
                LanAdvertise.Candidate("rmnet0", "10.1.2.3"),
                LanAdvertise.Candidate("wlan0", "10.0.0.15"),
            ),
        )
        assertEquals("10.0.0.15", picked)
    }

    @Test
    fun skipsLoopbackLinkLocalUnspecified() {
        assertNull(
            LanAdvertise.pick(
                listOf(
                    LanAdvertise.Candidate("wlan0", "127.0.0.1"),
                    LanAdvertise.Candidate("wlan0", "0.0.0.0"),
                    LanAdvertise.Candidate("wlan0", "169.254.1.1"),
                ),
            ),
        )
    }

    @Test
    fun rewriteListenHostKeepsPortAndP2p() {
        val src = "/ip4/10.160.244.93/tcp/44001/p2p/abcd"
        val got = LanAdvertise.rewriteListenHost(src, "192.168.1.8")
        assertEquals("/ip4/192.168.1.8/tcp/44001/p2p/abcd", got)
    }

    @Test
    fun compactInviteWithWifiIpRoundTrips() {
        val invite = """
            DEROOMS_PEER_V1
            name=dabcdef012345678
            device_vk=${"ab".repeat(32)}
            prekey=QUJD
            listen=/ip4/192.168.1.8/tcp/44001
        """.trimIndent()
        val uri = PeerInviteUri.encode(invite)
        val decoded = PeerInviteUri.decode(uri)!!
        val got = PeerChatController.decodeInvite(decoded)!!
        assertEquals("/ip4/192.168.1.8/tcp/44001", got.listenAddr)
        val hp = PeerInviteUri.listenHostPort(got.listenAddr)!!
        assertEquals("192.168.1.8", hp.first)
        assertTrue(hp.second in 1..65535)
        assertTrue(hp.first != "0.0.0.0")
    }
}
