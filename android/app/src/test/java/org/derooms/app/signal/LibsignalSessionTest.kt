package org.derooms.app.signal

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.signal.libsignal.protocol.message.CiphertextMessage

/**
 * JVM unit tests for libsignal seal/open. Requires libsignal-client natives
 * (extracted from the Maven jar on Linux amd64). Skips cleanly if natives missing.
 */
class LibsignalSessionTest {
    @Test
    fun pending_session_refuses_crypto() {
        val s = PendingLibsignalSession()
        assertFalse(s.isEstablished())
        s.establish(ByteArray(32) { 1 }, ByteArray(0))
        assertTrue(s.isEstablished())
        try {
            s.encrypt("hi".toByteArray())
            throw AssertionError("expected SignalNotAvailableException")
        } catch (_: SignalNotAvailableException) {
            // expected
        }
    }

    @Test
    fun libsignal_alice_bob_round_trip() {
        assumeTrue(
            "libsignal JNI natives not available on this host",
            LibsignalSession.isNativeAvailable(),
        )
        val bob = LibsignalSession.create("bob")
        val alice = LibsignalSession.create("alice")
        alice.establish(ByteArray(0), bob.exportPreKeyBundle())
        assertTrue(alice.isEstablished())
        // Bob accepts Alice's first PreKeySignalMessage without processing Alice's bundle.
        bob.acceptIncomingFrom(alice.name, alice.deviceId)

        val plaintext = "gate1-libsignal-p0".toByteArray(Charsets.UTF_8)
        val sealed = alice.encrypt(plaintext)
        assertTrue(sealed.size > 1)
        val opened = bob.decrypt(sealed)
        assertArrayEquals(plaintext, opened)

        // Second message uses whisper ratchet.
        val sealed2 = alice.encrypt("second".toByteArray(Charsets.UTF_8))
        assertArrayEquals("second".toByteArray(Charsets.UTF_8), bob.decrypt(sealed2))
    }

    @Test
    fun libsignal_mutual_establish_either_side_sends_first() {
        assumeTrue(
            "libsignal JNI natives not available on this host",
            LibsignalSession.isNativeAvailable(),
        )
        val bob = LibsignalSession.create("bob")
        val alice = LibsignalSession.create("alice")
        alice.establish(ByteArray(0), bob.exportPreKeyBundle())
        bob.establish(ByteArray(0), alice.exportPreKeyBundle())
        assertTrue(alice.isEstablished())
        assertTrue(bob.isEstablished())

        val fromBob = bob.encrypt("bob-first".toByteArray(Charsets.UTF_8))
        assertArrayEquals("bob-first".toByteArray(Charsets.UTF_8), alice.decrypt(fromBob))
        val fromAlice = alice.encrypt("alice-reply".toByteArray(Charsets.UTF_8))
        assertArrayEquals("alice-reply".toByteArray(Charsets.UTF_8), bob.decrypt(fromAlice))
    }

    @Test
    fun decrypt_without_remote_throws_not_established() {
        assumeTrue(LibsignalSession.isNativeAvailable())
        val bob = LibsignalSession.create("bob")
        try {
            bob.decrypt(byteArrayOf(1, 2, 3, 4))
            throw AssertionError("expected SignalNotEstablishedException")
        } catch (_: SignalNotEstablishedException) {
            // expected — listener must handshake or acceptIncomingFrom
        }
    }

    @Test
    fun prekey_bundle_codec_round_trip() {
        assumeTrue(LibsignalSession.isNativeAvailable())
        val bob = LibsignalSession.create("bob")
        val bytes = bob.exportPreKeyBundle()
        val decoded = PreKeyBundleCodec.decode(bytes)
        assertTrue(decoded.remoteName == "bob")
        assertTrue(decoded.bundle.registrationId > 0)
    }

    @Test
    fun handshake_qr_then_offer_both_sides_decrypt() {
        assumeTrue(LibsignalSession.isNativeAvailable())
        val listener = LibsignalSession.create("dlistenerabcdef01")
        val scanner = LibsignalSession.create("dscannerfedcba10")
        val full = listener.exportPreKeyBundle()
        val wire = PreKeyBundleCodec.parseWire(full)
        val (deferred, kyberPk) = PreKeyBundleCodec.deferKyber(wire)
        val completed = PreKeyBundleCodec.completeDeferred(deferred, kyberPk)
        // Scanner applied identity QR + handshake QR.
        scanner.establish(ByteArray(0), completed)
        assertTrue(scanner.isEstablished())
        // Without the offer, listener cannot decrypt (one-way QR bug).
        try {
            listener.decrypt(scanner.encrypt("too-soon".toByteArray(Charsets.UTF_8)))
            throw AssertionError("listener should not decrypt before offer")
        } catch (_: Exception) {
            // expected
        }
        // DRKY2 / BLE ferry: listener establishes from scanner's full invite.
        listener.establish(ByteArray(0), scanner.exportPreKeyBundle())
        assertTrue(listener.isEstablished())
        val fromScanner = scanner.encrypt("ble-ping".toByteArray(Charsets.UTF_8))
        assertArrayEquals("ble-ping".toByteArray(Charsets.UTF_8), listener.decrypt(fromScanner))
        val fromListener = listener.encrypt("ble-reply".toByteArray(Charsets.UTF_8))
        assertArrayEquals("ble-reply".toByteArray(Charsets.UTF_8), scanner.decrypt(fromListener))
    }

    @Test
    fun second_and_third_messages_use_ratchet_not_new_pqxdh() {
        assumeTrue(LibsignalSession.isNativeAvailable())
        val bob = LibsignalSession.create("bob")
        val alice = LibsignalSession.create("alice")
        alice.establish(ByteArray(0), bob.exportPreKeyBundle())
        bob.establish(ByteArray(0), alice.exportPreKeyBundle())
        bob.decrypt(alice.encrypt("m1".toByteArray(Charsets.UTF_8)))
        // First inbound PreKey consumed Bob's one-time prekey. Export must still work.
        val again = bob.exportPreKeyBundle()
        assertTrue(again.isNotEmpty())
        val m2 = alice.encrypt("m2".toByteArray(Charsets.UTF_8))
        // Sender keeps wrapping as PreKey until it receives a reply (unacked PQXDH).
        assertArrayEquals("m2".toByteArray(Charsets.UTF_8), bob.decrypt(m2))
        val m3 = bob.encrypt("m3".toByteArray(Charsets.UTF_8))
        assertArrayEquals("m3".toByteArray(Charsets.UTF_8), alice.decrypt(m3))
        val m4pre = alice.encrypt("m4".toByteArray(Charsets.UTF_8))
        assertEquals(CiphertextMessage.WHISPER_TYPE, m4pre[0].toInt() and 0xff)
        // Re-processing Bob's bundle must not break Alice's ratchet.
        alice.establish(ByteArray(0), bob.exportPreKeyBundle())
        val m4 = alice.encrypt("m4b".toByteArray(Charsets.UTF_8))
        assertArrayEquals("m4b".toByteArray(Charsets.UTF_8), bob.decrypt(m4))
    }

    @Test
    fun establish_ignores_own_bundle() {
        assumeTrue(LibsignalSession.isNativeAvailable())
        val alice = LibsignalSession.create("alice")
        val bob = LibsignalSession.create("bob")
        alice.establish(ByteArray(0), bob.exportPreKeyBundle())
        assertTrue(alice.isEstablished())
        alice.establish(ByteArray(0), alice.exportPreKeyBundle())
        assertTrue(alice.isEstablished())
        assertEquals("bob", alice.remoteSignalName())
        bob.acceptIncomingFrom(alice.name, alice.deviceId)
        assertArrayEquals(
            "still-bob".toByteArray(Charsets.UTF_8),
            bob.decrypt(alice.encrypt("still-bob".toByteArray(Charsets.UTF_8))),
        )
    }

    @Test
    fun duplicate_prekey_ciphertext_does_not_break_later_whisper() {
        assumeTrue(LibsignalSession.isNativeAvailable())
        val bob = LibsignalSession.create("bob")
        val alice = LibsignalSession.create("alice")
        alice.establish(ByteArray(0), bob.exportPreKeyBundle())
        bob.acceptIncomingFrom(alice.name, alice.deviceId)
        val first = alice.encrypt("m1".toByteArray(Charsets.UTF_8))
        assertEquals(CiphertextMessage.PREKEY_TYPE, first[0].toInt() and 0xff)
        assertArrayEquals("m1".toByteArray(Charsets.UTF_8), bob.decrypt(first))
        try {
            bob.decrypt(first)
            throw AssertionError("duplicate PreKey should not decrypt twice")
        } catch (e: Exception) {
            val msg = e.message.orEmpty()
            assertTrue(
                "expected stale/invalid/duplicate, got $msg",
                msg.contains("stale prekey", ignoreCase = true) ||
                    msg.contains("invalid", ignoreCase = true) ||
                    msg.contains("prekeyrecord", ignoreCase = true) ||
                    msg.contains("old counter", ignoreCase = true) ||
                    msg.contains("duplicate", ignoreCase = true),
            )
        }
        assertTrue(bob.exportPreKeyBundle().isNotEmpty())
        val second = alice.encrypt("m2".toByteArray(Charsets.UTF_8))
        assertArrayEquals("m2".toByteArray(Charsets.UTF_8), bob.decrypt(second))
    }

    @Test
    fun same_device_name_with_new_signal_identity_replaces_stale_session() {
        assumeTrue(LibsignalSession.isNativeAvailable())
        val alice = LibsignalSession.create("alice")
        val bobBeforeRestart = LibsignalSession.create("bob")
        val oldBundle = bobBeforeRestart.exportPreKeyBundle()
        assertTrue(bobBeforeRestart.ownsPreKeyBundle(oldBundle))
        assertFalse(alice.ownsPreKeyBundle(oldBundle))

        alice.establish(ByteArray(0), oldBundle)
        bobBeforeRestart.acceptIncomingFrom(alice.name, alice.deviceId)
        assertArrayEquals(
            "before".toByteArray(),
            bobBeforeRestart.decrypt(alice.encrypt("before".toByteArray())),
        )

        // Process restart: stable app/Signal address name, new in-memory
        // libsignal identity and prekeys.
        val bobAfterRestart = LibsignalSession.create("bob")
        val newBundle = bobAfterRestart.exportPreKeyBundle()
        alice.establish(ByteArray(0), newBundle)
        bobAfterRestart.acceptIncomingFrom(alice.name, alice.deviceId)
        assertArrayEquals(
            "after".toByteArray(),
            bobAfterRestart.decrypt(alice.encrypt("after".toByteArray())),
        )
    }
}
