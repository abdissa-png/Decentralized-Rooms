package org.derooms.app.peer

import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.encoder.Encoder
import org.derooms.app.signal.PreKeyBundleCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class PeerInviteUriTest {
    @Test
    fun legacyTextUriStillDecodes() {
        val invite = """
            DEROOMS_PEER_V1
            name=dabcdef012345678
            device_vk=${"ab".repeat(32)}
            prekey=QUJD
            listen=/ip4/192.168.1.8/tcp/44001/p2p/dead
        """.trimIndent()
        val legacy = PeerInviteUri.PREFIX + Base64.getUrlEncoder().withoutPadding()
            .encodeToString(invite.toByteArray(Charsets.UTF_8))
        assertEquals(invite, PeerInviteUri.decode(legacy))
        assertEquals(invite, PeerInviteUri.decode(invite))
    }

    @Test
    fun unknownPayloadFailClosed() {
        assertNull(PeerInviteUri.decode("https://example.com"))
        assertNull(PeerInviteUri.decode("derooms://invite/v1/!!!!"))
        assertNull(PeerInviteUri.decode(""))
    }

    @Test
    fun compactUriRoundTripAndFitsPhoneQr() {
        val invite = typicalInvite(kyberPkSize = 1568)
        val uri = PeerInviteUri.encode(invite)
        assertTrue(uri.startsWith(PeerInviteUri.PREFIX))
        val utf8 = uri.toByteArray(Charsets.UTF_8).size
        assertTrue("URI utf8=$utf8 must be under ${PeerInviteUri.PHONE_QR_MAX_BYTES}", utf8 <= PeerInviteUri.PHONE_QR_MAX_BYTES)
        assertTrue(InviteQr.fitsPhoneCamera(uri))
        val version = InviteQr.qrVersion(uri)
        assertNotNull(version)
        assertTrue("QR version=$version should be ≤ ${InviteQr.PHONE_QR_MAX_VERSION}", version!! <= InviteQr.PHONE_QR_MAX_VERSION)

        val decoded = PeerInviteUri.decode(uri)
        assertNotNull(decoded)
        val original = PeerChatController.decodeInvite(invite)!!
        val got = PeerChatController.decodeInvite(decoded!!)!!
        assertEquals(original.signalName, got.signalName)
        assertEquals(original.deviceVkHex, got.deviceVkHex)
        assertEquals(original.listenAddr, got.listenAddr)
        assertEquals(original.relayHostPort, got.relayHostPort)
        assertTrue(PeerInviteUri.isDeferredInvite(decoded))
        assertTrue(PreKeyBundleCodec.isDeferred(Base64.getDecoder().decode(got.prekeyB64)))
    }

    @Test
    fun compactUriKeepsIdentityAndLabelUnderPhoneQr() {
        val invite = typicalInvite(kyberPkSize = 1568)
        val decoded = PeerChatController.decodeInvite(invite)!!
        val labeled = decoded.copy(
            identityIdHex = "cd".repeat(32),
            displayLabel = "Ada",
        )
        val uri = PeerInviteUri.encode(PeerChatController.encodeInvite(labeled))
        val utf8 = uri.toByteArray(Charsets.UTF_8).size
        assertTrue("URI utf8=$utf8", utf8 <= PeerInviteUri.PHONE_QR_MAX_BYTES)
        val got = PeerChatController.decodeInvite(PeerInviteUri.decode(uri)!!)!!
        assertEquals(labeled.identityIdHex, got.identityIdHex)
        assertEquals("Ada", got.displayLabel)
    }

    @Test
    fun compactUriMuchSmallerThanLegacyDoubleBase64() {
        val invite = typicalInvite(kyberPkSize = 1568)
        val compact = PeerInviteUri.encode(invite).length
        val legacy = PeerInviteUri.PREFIX.length + Base64.getUrlEncoder().withoutPadding()
            .encodeToString(invite.toByteArray(Charsets.UTF_8)).length
        println("E2E_INVITE_URI_LEN compact=$compact legacy=$legacy version=${InviteQr.qrVersion(PeerInviteUri.encode(invite))}")
        assertTrue("compact=$compact legacy=$legacy", compact < 520)
        assertTrue("legacy double-base64 still huge: $legacy", legacy > 2500)
    }

    @Test
    fun kyberContinuationCompletesDeferredInvite() {
        val invite = typicalInvite(kyberPkSize = 1568)
        val uri = PeerInviteUri.encode(invite)
        val deferredText = PeerInviteUri.decode(uri)!!
        val continuation = PeerInviteUri.encodeKyberContinuation(invite)
        assertTrue(continuation.startsWith(PeerInviteUri.PREFIX))
        assertTrue(PeerInviteUri.isKyberContinuation(continuation))
        val merged = PeerInviteUri.mergeKyberContinuation(deferredText, continuation)
        assertNotNull(merged)
        val got = PeerChatController.decodeInvite(merged!!)!!
        val orig = PeerChatController.decodeInvite(invite)!!
        val origWire = PreKeyBundleCodec.parseWire(Base64.getDecoder().decode(orig.prekeyB64))
        val gotWire = PreKeyBundleCodec.parseWire(Base64.getDecoder().decode(got.prekeyB64))
        assertFalse(gotWire.deferred)
        assertArrayEquals(origWire.kyberPreKey, gotWire.kyberPreKey)
        assertArrayEquals(origWire.identityKey, gotWire.identityKey)
        assertEquals(orig.listenAddr, got.listenAddr)
    }

    @Test
    fun kyberBootstrapLocalhostRoundTrip() {
        val blob = PeerInviteUri.encodeKyberBlob(1, ByteArray(1568) { 7 }, ByteArray(64) { 9 })
        val boot = InviteKyberBootstrap(0, blob)
        boot.start()
        try {
            var got: ByteArray? = null
            repeat(8) {
                got = InviteKyberBootstrap.fetch("127.0.0.1", boot.port, timeoutMs = 1_500)
                if (got != null) return@repeat
                Thread.sleep(50)
            }
            assertNotNull(got)
            assertArrayEquals(blob, got)
        } finally {
            boot.stop()
        }
    }

    @Test
    fun kyberBootstrapOfferRoundTrip() {
        val blob = PeerInviteUri.encodeKyberBlob(1, ByteArray(1568) { 7 }, ByteArray(64) { 9 })
        val offer = typicalInvite(kyberPkSize = 1568).toByteArray(Charsets.UTF_8)
        val boot = InviteKyberBootstrap(0, blob) { incoming ->
            assertTrue(incoming.contentEquals(offer))
            null
        }
        boot.start()
        try {
            var got: ByteArray? = null
            repeat(8) {
                got = InviteKyberBootstrap.fetch(
                    "127.0.0.1",
                    boot.port,
                    timeoutMs = 2_000,
                    offer = offer,
                )
                if (got != null) return@repeat
                Thread.sleep(50)
            }
            assertNotNull(got)
            assertArrayEquals(blob, got)
            assertArrayEquals(offer, boot.lastOffer())
        } finally {
            boot.stop()
        }
    }

    @Test
    fun kyberBootstrapOfferFailureDoesNotReturnBlob() {
        val blob = PeerInviteUri.encodeKyberBlob(1, ByteArray(1568) { 7 }, ByteArray(64) { 9 })
        val boot = InviteKyberBootstrap(0, blob) { "bad offer" }
        boot.start()
        try {
            Thread.sleep(80)
            val got = InviteKyberBootstrap.fetch(
                "127.0.0.1",
                boot.port,
                timeoutMs = 2_000,
                offer = "not-an-invite".toByteArray(),
            )
            assertNull(got)
        } finally {
            boot.stop()
        }
    }

    @Test
    fun zxingRejectsLegacyOversizeInvite() {
        val invite = typicalInvite(kyberPkSize = 1568)
        val legacy = PeerInviteUri.PREFIX + Base64.getUrlEncoder().withoutPadding()
            .encodeToString(invite.toByteArray(Charsets.UTF_8))
        assertTrue(legacy.length > 2953)
        var threw = false
        try {
            Encoder.encode(legacy, ErrorCorrectionLevel.L, emptyMap<com.google.zxing.EncodeHintType, Any>())
        } catch (_: Exception) {
            threw = true
        }
        assertTrue("legacy URI must exceed Version 40 (the old on-phone failure)", threw)
    }

    private fun typicalInvite(kyberPkSize: Int): String {
        val vk = "ab".repeat(32)
        val name = "d${vk.take(16)}"
        val wire = PreKeyBundleCodec.Wire(
            remoteName = name,
            registrationId = 42,
            deviceId = 1,
            preKeyId = 1,
            preKey = ByteArray(33) { 0x05 },
            signedPreKeyId = 1,
            signedPreKey = ByteArray(33) { 0x06 },
            signedSig = ByteArray(64) { 0x11 },
            identityKey = ByteArray(33) { 0x07 },
            kyberPreKeyId = 1,
            kyberPreKey = ByteArray(kyberPkSize) { 0x42 },
            kyberSig = ByteArray(64) { 0x22 },
        )
        val prekeyB64 = Base64.getEncoder().encodeToString(PreKeyBundleCodec.encodeWire(wire))
        return PeerChatController.encodeInvite(
            PeerChatController.PeerInvite(
                signalName = name,
                deviceVkHex = vk,
                prekeyB64 = prekeyB64,
                listenAddr = "/ip4/192.168.1.8/tcp/44001/p2p/deadbeef",
                relayHostPort = "",
            ),
        )
    }
}
