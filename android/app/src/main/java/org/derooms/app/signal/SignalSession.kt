package org.derooms.app.signal

import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.UntrustedIdentityException
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Application-layer 1:1 session facade (aligns with Rust `SignalSession`).
 *
 * Production path: Android **libsignal-client** / **libsignal-android** JNI
 * (X3DH/PQXDH + Double Ratchet). Do not invent a ratchet here.
 *
 * See docs/libsignal-android-plan.md and ADR-0003.
 */
interface SignalSession {
    fun establish(remoteIdentity: ByteArray, handshakeMaterial: ByteArray)
    fun isEstablished(): Boolean
    fun encrypt(plaintext: ByteArray): ByteArray
    fun decrypt(ciphertext: ByteArray): ByteArray
}

/**
 * Stub that records establish intent but refuses crypto (clear error).
 * Used only when libsignal natives are unavailable at runtime.
 */
class PendingLibsignalSession : SignalSession {
    private var established = false
    private var remoteIdentity: ByteArray = ByteArray(0)

    override fun establish(remoteIdentity: ByteArray, handshakeMaterial: ByteArray) {
        this.remoteIdentity = remoteIdentity.copyOf()
        established = true
    }

    override fun isEstablished(): Boolean = established

    override fun encrypt(plaintext: ByteArray): ByteArray {
        checkEstablished()
        throw SignalNotAvailableException()
    }

    override fun decrypt(ciphertext: ByteArray): ByteArray {
        checkEstablished()
        throw SignalNotAvailableException()
    }

    fun remoteIdentity(): ByteArray = remoteIdentity.copyOf()

    private fun checkEstablished() {
        if (!established) {
            throw SignalNotEstablishedException()
        }
    }
}

/**
 * Real Signal Protocol session via official libsignal-client JNI.
 *
 * Local party holds identity + prekeys in an in-memory store (persist later under
 * Keystore-wrapped storage). Peer establish consumes a Gate-1 prekey bundle blob
 * ([PreKeyBundleCodec]) typically carried in invite bootstrap material.
 *
 * Ciphertext framing for MessageEvent payloads:
 * `type(u8) || libsignal_serialize` where type is [CiphertextMessage.PREKEY_TYPE]
 * or [CiphertextMessage.WHISPER_TYPE].
 */
class LibsignalSession private constructor(
    private val localName: String,
    private val registrationId: Int,
    val deviceId: Int,
    private val identityKeyPair: IdentityKeyPair,
    private val store: InMemorySignalProtocolStore,
    private val signedPreKeyId: Int,
    private var preKeyId: Int,
    private var kyberPreKeyId: Int,
) : SignalSession {
    private var remoteAddress: SignalProtocolAddress? = null
    /** Last prekey bundle applied per Signal address; prevents duplicate reset. */
    private val remoteBundleHashes = ConcurrentHashMap<String, String>()

    val name: String get() = localName

    /**
     * Prepare to decrypt messages from a peer without processing their prekey bundle.
     * Needed for the first inbound [PreKeySignalMessage] after the peer established
     * toward us.
     *
     * Does **not** overwrite [remoteAddress] when an outbound session already exists
     * (overwriting broke encrypt with "Signal session not established").
     */
    @Synchronized
    fun acceptIncomingFrom(remoteName: String, remoteDeviceId: Int = 1) {
        val existing = remoteAddress
        if (existing != null && store.containsSession(existing)) {
            return
        }
        remoteAddress = SignalProtocolAddress(remoteName, remoteDeviceId)
    }

    fun remoteSignalName(): String? = remoteAddress?.name

    /** True when an invite bundle was produced by this in-memory Signal identity. */
    fun ownsPreKeyBundle(handshakeMaterial: ByteArray): Boolean {
        val wire = try {
            PreKeyBundleCodec.parseWire(handshakeMaterial)
        } catch (_: Exception) {
            return false
        }
        return wire.identityKey.contentEquals(identityKeyPair.publicKey.serialize())
    }

    fun localIdentityFingerprint(): String =
        sha256Hex(identityKeyPair.publicKey.serialize()).take(16)

    /** Export public prekey material for the remote to call [establish]. */
    @Synchronized
    fun exportPreKeyBundle(): ByteArray {
        replenishOneTimeIfMissing()
        replenishKyberIfMissing()
        val signed = store.loadSignedPreKey(signedPreKeyId)
        val oneTime = store.loadPreKey(preKeyId)
        val kyber = store.loadKyberPreKey(kyberPreKeyId)
        val bundle = PreKeyBundle(
            registrationId,
            deviceId,
            preKeyId,
            oneTime.keyPair.publicKey,
            signedPreKeyId,
            signed.keyPair.publicKey,
            signed.signature,
            identityKeyPair.publicKey,
            kyberPreKeyId,
            kyber.keyPair.publicKey,
            kyber.signature,
        )
        return PreKeyBundleCodec.encode(localName, bundle)
    }

    @Synchronized
    override fun establish(remoteIdentity: ByteArray, handshakeMaterial: ByteArray) {
        val decoded = PreKeyBundleCodec.decode(handshakeMaterial)
        val remoteIk = decoded.bundle.identityKey.serialize()
        val localIk = identityKeyPair.publicKey.serialize()
        if (remoteIk.contentEquals(localIk)) {
            // Echo of our own invite over BLE — do not overwrite the peer session.
            return
        }
        val address = SignalProtocolAddress(decoded.remoteName, decoded.bundle.deviceId)
        val addressKey = "${address.name}:${address.deviceId}"
        val bundleHash = sha256Hex(handshakeMaterial)
        val previousBundleHash = remoteBundleHashes[addressKey]
        if (store.containsSession(address) && previousBundleHash == bundleHash) {
            remoteAddress = address
            return
        }
        if (store.containsSession(address) && previousBundleHash != null &&
            previousBundleHash != bundleHash
        ) {
            // The peer restarted/rekeyed but retained its stable app device_vk/name.
            // A Signal session is bound to the old Signal identity and must not be
            // reused for the new prekey bundle.
            store.deleteSession(address)
        }
        store.saveIdentity(address, decoded.bundle.identityKey)
        if (store.containsSession(address)) {
            remoteAddress = address
            remoteBundleHashes[addressKey] = bundleHash
            return
        }
        SessionBuilder(store, address).process(decoded.bundle)
        store.saveIdentity(address, decoded.bundle.identityKey)
        remoteAddress = address
        remoteBundleHashes[addressKey] = bundleHash
        if (remoteIdentity.isNotEmpty()) {
            try {
                store.saveIdentity(address, IdentityKey(remoteIdentity))
            } catch (_: Exception) {
                // remoteIdentity may be empty or non-Signal bytes; bundle identity is enough.
            }
        }
    }

    @Synchronized
    override fun isEstablished(): Boolean =
        remoteAddress != null && store.containsSession(remoteAddress)

    /** True once a remote address is known (outbound session or inbound accept). */
    fun hasRemote(): Boolean = remoteAddress != null

    @Synchronized
    override fun encrypt(plaintext: ByteArray): ByteArray {
        val address = remoteAddress ?: throw SignalNotEstablishedException()
        if (!store.containsSession(address)) throw SignalNotEstablishedException()
        return try {
            val cipher = SessionCipher(store, address)
            val msg = cipher.encrypt(plaintext)
            frame(msg.type, msg.serialize())
        } catch (e: NoSessionException) {
            throw SignalNotEstablishedException(e)
        } catch (e: UntrustedIdentityException) {
            throw SignalSessionException("untrusted identity", e)
        }
    }

    @Synchronized
    override fun decrypt(ciphertext: ByteArray): ByteArray {
        val address = remoteAddress ?: throw SignalNotEstablishedException()
        if (ciphertext.size < 2) {
            throw SignalSessionException("ciphertext too short")
        }
        val type = ciphertext[0].toInt() and 0xff
        val body = ciphertext.copyOfRange(1, ciphertext.size)
        return try {
            decryptOnce(address, type, body)
        } catch (e: UntrustedIdentityException) {
            // Invite already authenticated the peer OOB — trust and retry once.
            val identity = e.untrustedIdentity
                ?: throw SignalSessionException("untrusted identity", e)
            val name = e.name ?: address.name
            val trustAddr = SignalProtocolAddress(name, address.deviceId)
            store.saveIdentity(trustAddr, identity)
            if (remoteAddress?.name != name) {
                remoteAddress = trustAddr
            }
            try {
                decryptOnce(trustAddr, type, body)
            } catch (e2: Exception) {
                throw SignalSessionException("untrusted identity (retry failed: ${e2.message})", e2)
            }
        } catch (e: InvalidMessageException) {
            throw SignalSessionException("invalid message", e)
        } catch (e: NoSessionException) {
            throw SignalNotEstablishedException(e)
        } catch (e: InvalidKeyException) {
            if (e.message.orEmpty().contains("prekeyrecord", ignoreCase = true) &&
                store.containsSession(address)
            ) {
                throw SignalSessionException("stale prekey", e)
            }
            throw SignalSessionException("invalid key", e)
        } catch (e: Exception) {
            val msg = e.message.orEmpty()
            if (msg.contains("prekeyrecord", ignoreCase = true) &&
                store.containsSession(address)
            ) {
                throw SignalSessionException("stale prekey", e)
            }
            throw e
        }
    }

    private fun decryptOnce(address: SignalProtocolAddress, type: Int, body: ByteArray): ByteArray {
        val cipher = SessionCipher(store, address)
        return when (type) {
            CiphertextMessage.PREKEY_TYPE -> {
                val plain = cipher.decrypt(PreKeySignalMessage(body))
                // First inbound PQXDH consumes the one-time + Kyber prekeys.
                // Replenish so export / a later invite still works; the live
                // session continues on the Double Ratchet (whisper).
                replenishOneTimePreKey()
                replenishKyberPreKey()
                plain
            }
            CiphertextMessage.WHISPER_TYPE -> cipher.decrypt(SignalMessage(body))
            else -> throw SignalSessionException("unknown ciphertext type $type")
        }
    }

    private fun replenishOneTimeIfMissing() {
        try {
            store.loadPreKey(preKeyId)
        } catch (_: Exception) {
            replenishOneTimePreKey()
        }
    }

    private fun replenishKyberIfMissing() {
        try {
            store.loadKyberPreKey(kyberPreKeyId)
        } catch (_: Exception) {
            replenishKyberPreKey()
        }
    }

    private fun replenishOneTimePreKey() {
        preKeyId += 1
        val oneTime = ECKeyPair.generate()
        store.storePreKey(preKeyId, PreKeyRecord(preKeyId, oneTime))
    }

    private fun replenishKyberPreKey() {
        kyberPreKeyId += 1
        val kyberPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kyberSig = identityKeyPair.privateKey.calculateSignature(kyberPair.publicKey.serialize())
        store.storeKyberPreKey(
            kyberPreKeyId,
            KyberPreKeyRecord(kyberPreKeyId, System.currentTimeMillis(), kyberPair, kyberSig),
        )
    }

    companion object {
        private val secureRandom = SecureRandom()

        /**
         * Probe whether libsignal JNI natives loaded. Fail-closed on any error.
         */
        fun isNativeAvailable(): Boolean =
            try {
                // Touch a cheap API that requires the native library.
                IdentityKeyPair.generate()
                true
            } catch (_: UnsatisfiedLinkError) {
                false
            } catch (_: Throwable) {
                false
            }

        /**
         * Create a local session identity + prekeys. Call [exportPreKeyBundle] for peers.
         */
        fun create(localName: String = "local", deviceId: Int = 1): LibsignalSession {
            val identity = IdentityKeyPair.generate()
            val registrationId = 1 + secureRandom.nextInt(16380)
            val store = InMemorySignalProtocolStore(identity, registrationId)

            val signedPreKeyId = 1
            val signedPair = ECKeyPair.generate()
            val signedSig = identity.privateKey.calculateSignature(signedPair.publicKey.serialize())
            store.storeSignedPreKey(
                signedPreKeyId,
                SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), signedPair, signedSig),
            )

            val preKeyId = 1
            val oneTime = ECKeyPair.generate()
            store.storePreKey(preKeyId, PreKeyRecord(preKeyId, oneTime))

            val kyberPreKeyId = 1
            val kyberPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val kyberSig = identity.privateKey.calculateSignature(kyberPair.publicKey.serialize())
            store.storeKyberPreKey(
                kyberPreKeyId,
                KyberPreKeyRecord(kyberPreKeyId, System.currentTimeMillis(), kyberPair, kyberSig),
            )

            return LibsignalSession(
                localName = localName,
                registrationId = registrationId,
                deviceId = deviceId,
                identityKeyPair = identity,
                store = store,
                signedPreKeyId = signedPreKeyId,
                preKeyId = preKeyId,
                kyberPreKeyId = kyberPreKeyId,
            )
        }

        /**
         * Prefer real libsignal; fall back to [PendingLibsignalSession] if natives missing.
         */
        fun createOrPending(localName: String = "local"): SignalSession =
            if (isNativeAvailable()) create(localName) else PendingLibsignalSession()

        private fun frame(type: Int, body: ByteArray): ByteArray {
            val out = ByteArray(1 + body.size)
            out[0] = type.toByte()
            System.arraycopy(body, 0, out, 1, body.size)
            return out
        }

        private fun sha256Hex(data: ByteArray): String =
            MessageDigest.getInstance("SHA-256")
                .digest(data)
                .joinToString("") { "%02x".format(it) }
    }
}

/**
 * Versioned Gate-1 encoding of a libsignal [PreKeyBundle] (+ remote name).
 * This is **not** cryptography — only a length-prefixed container for official
 * libsignal public key material carried in invites / bootstrap hints.
 */
object PreKeyBundleCodec {
    const val MAGIC = 0x4452504b // "DRPK"
    /** Compact-QR form: Kyber pk replaced by SHA-256 (libsignal still needs the pk at establish). */
    const val MAGIC_DEFERRED = 0x44525032 // "DRP2"
    private const val VERSION: Byte = 1

    data class Decoded(
        val remoteName: String,
        val bundle: PreKeyBundle,
    )

    /**
     * Length-prefixed public material without libsignal types — QR packing and
     * JVM tests can round-trip this without JNI.
     */
    data class Wire(
        val remoteName: String,
        val registrationId: Int,
        val deviceId: Int,
        val preKeyId: Int,
        val preKey: ByteArray,
        val signedPreKeyId: Int,
        val signedPreKey: ByteArray,
        val signedSig: ByteArray,
        val identityKey: ByteArray,
        val kyberPreKeyId: Int,
        /** Full Kyber pk (v1) or SHA-256 of that pk (deferred). */
        val kyberPreKey: ByteArray,
        val kyberSig: ByteArray,
        val deferred: Boolean = false,
    )

    fun encode(remoteName: String, bundle: PreKeyBundle): ByteArray = encodeWire(
        Wire(
            remoteName = remoteName,
            registrationId = bundle.registrationId,
            deviceId = bundle.deviceId,
            preKeyId = bundle.preKeyId,
            preKey = requireNotNull(bundle.preKey) { "preKey required" }.serialize(),
            signedPreKeyId = bundle.signedPreKeyId,
            signedPreKey = requireNotNull(bundle.signedPreKey) { "signedPreKey required" }.serialize(),
            signedSig = bundle.signedPreKeySignature,
            identityKey = bundle.identityKey.serialize(),
            kyberPreKeyId = bundle.kyberPreKeyId,
            kyberPreKey = requireNotNull(bundle.kyberPreKey) { "kyberPreKey required" }.serialize(),
            kyberSig = requireNotNull(bundle.kyberPreKeySignature) { "kyberSig required" },
        ),
    )

    fun encodeWire(wire: Wire, deferred: Boolean = wire.deferred): ByteArray {
        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { out ->
            out.writeInt(if (deferred) MAGIC_DEFERRED else MAGIC)
            out.writeByte(VERSION.toInt())
            out.writeUTF(wire.remoteName)
            out.writeInt(wire.registrationId)
            out.writeInt(wire.deviceId)
            out.writeInt(wire.preKeyId)
            writeBytes(out, wire.preKey)
            out.writeInt(wire.signedPreKeyId)
            writeBytes(out, wire.signedPreKey)
            writeBytes(out, wire.signedSig)
            writeBytes(out, wire.identityKey)
            out.writeInt(wire.kyberPreKeyId)
            writeBytes(out, wire.kyberPreKey)
            writeBytes(out, wire.kyberSig)
        }
        return baos.toByteArray()
    }

    fun parseWire(bytes: ByteArray): Wire {
        DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            val magic = input.readInt()
            val deferred = magic == MAGIC_DEFERRED
            require(magic == MAGIC || deferred) { "bad prekey bundle magic" }
            val version = input.readByte()
            require(version == VERSION) { "unsupported prekey bundle version $version" }
            return Wire(
                remoteName = input.readUTF(),
                registrationId = input.readInt(),
                deviceId = input.readInt(),
                preKeyId = input.readInt(),
                preKey = readBytes(input),
                signedPreKeyId = input.readInt(),
                signedPreKey = readBytes(input),
                signedSig = readBytes(input),
                identityKey = readBytes(input),
                kyberPreKeyId = input.readInt(),
                kyberPreKey = readBytes(input),
                kyberSig = readBytes(input),
                deferred = deferred,
            )
        }
    }

    fun isDeferred(bytes: ByteArray): Boolean =
        bytes.size >= 4 &&
            ((bytes[0].toInt() and 0xff) shl 24 or
                ((bytes[1].toInt() and 0xff) shl 16) or
                ((bytes[2].toInt() and 0xff) shl 8) or
                (bytes[3].toInt() and 0xff)) == MAGIC_DEFERRED

    /**
     * Replace the SHA-256 placeholder with the real Kyber pk after OOB fetch / second QR.
     * Fail-closed if the pk does not match the QR commitment.
     */
    fun completeDeferred(deferred: Wire, kyberPk: ByteArray): ByteArray {
        require(deferred.deferred) { "not a deferred prekey wire" }
        val hash = sha256(kyberPk)
        require(hash.contentEquals(deferred.kyberPreKey)) { "kyber pk does not match invite hash" }
        return encodeWire(deferred.copy(kyberPreKey = kyberPk, deferred = false), deferred = false)
    }

    fun deferKyber(wire: Wire): Pair<Wire, ByteArray> {
        require(!wire.deferred) { "already deferred" }
        val pk = wire.kyberPreKey
        val hashed = wire.copy(kyberPreKey = sha256(pk), deferred = true)
        return hashed to pk
    }

    fun decode(bytes: ByteArray): Decoded {
        val wire = parseWire(bytes)
        require(!wire.deferred) { "deferred prekey — complete Kyber first" }
        val bundle = PreKeyBundle(
            wire.registrationId,
            wire.deviceId,
            wire.preKeyId,
            org.signal.libsignal.protocol.ecc.ECPublicKey(wire.preKey),
            wire.signedPreKeyId,
            org.signal.libsignal.protocol.ecc.ECPublicKey(wire.signedPreKey),
            wire.signedSig,
            IdentityKey(wire.identityKey),
            wire.kyberPreKeyId,
            org.signal.libsignal.protocol.kem.KEMPublicKey(wire.kyberPreKey),
            wire.kyberSig,
        )
        return Decoded(wire.remoteName, bundle)
    }

    private fun sha256(data: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(data)

    private fun writeBytes(out: DataOutputStream, data: ByteArray) {
        out.writeInt(data.size)
        out.write(data)
    }

    private fun readBytes(input: DataInputStream): ByteArray {
        val len = input.readInt()
        require(len in 0..1_000_000) { "invalid length $len" }
        val buf = ByteArray(len)
        input.readFully(buf)
        return buf
    }
}

class SignalNotEstablishedException(cause: Throwable? = null) :
    IllegalStateException("Signal session not established", cause)

class SignalNotAvailableException :
    UnsupportedOperationException(
        "Signal Protocol encrypt/decrypt requires libsignal-client JNI; " +
            "see docs/libsignal-android-plan.md. Refusing toy crypto.",
    )

class SignalSessionException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)
