package org.derooms.app.peer

import org.derooms.app.signal.PreKeyBundleCodec
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64

/**
 * Product 1:1 invite packaging for QR / deep links.
 *
 * Locked prefix `derooms://invite/v1/` (ADR-0001). Payload is Base64URL-nopad
 * of a compact binary peer-invite (magic `DRPI`), not the verbose UTF-8
 * [PeerChatController.INVITE_MAGIC] text. Kyber-1024 public keys (~1568 B)
 * are committed by SHA-256 in this blob and completed on Connect (LAN fetch
 * or handshake QR) so the URI fits a phone-readable QR (ZXing Version ≤15,
 * ECC L, ≤[PHONE_QR_MAX_BYTES] UTF-8 bytes).
 *
 * Scanner still accepts:
 * - compact `DRPI` URIs (this encoder)
 * - legacy URIs whose payload is UTF-8 `DEROOMS_PEER_V1` text
 * - raw `DEROOMS_PEER_V1` paste
 * - handshake continuation `DRK1` (Kyber pk) to finish a deferred invite
 */
object PeerInviteUri {
    const val PREFIX = "derooms://invite/v1/"

    /**
     * ZXing QR Version 15, ECC L, byte mode capacity. Typical phone cameras
     * at ~6–8 cm / ~220 dp module size scan this density; Version 40 codes
     * encode but do not scan.
     */
    const val PHONE_QR_MAX_BYTES = 520

    /** Compact peer-invite binary. */
    const val MAGIC_COMPACT = 0x44525049 // "DRPI"

    /** Kyber continuation (second QR / LAN bootstrap body). */
    const val MAGIC_KYBER = 0x44524b31 // "DRK1"

    private const val COMPACT_VERSION: Byte = 1
    private const val FLAG_RELAY: Int = 0x01
    private const val FLAG_BLE: Int = 0x02
    private const val FLAG_P2P: Int = 0x04
    private const val FLAG_NAME: Int = 0x08
    private const val FLAG_LISTEN_UTF8: Int = 0x10
    private const val FLAG_IDENTITY: Int = 0x20
    private const val FLAG_LABEL: Int = 0x40

    fun encode(inviteText: String): String {
        val trimmed = inviteText.trim()
        if (trimmed.isEmpty()) return ""
        compactBytes(trimmed)?.let { raw ->
            return PREFIX + b64(raw)
        }
        // Legacy: Base64URL of the UTF-8 text (too large for phone QR when
        // the prekey still carries Kyber-1024).
        return PREFIX + b64(trimmed.toByteArray(Charsets.UTF_8))
    }

    /**
     * Accept a URI, raw invite, or scanned string. Null if unrecognised.
     * Compact URIs expand to `DEROOMS_PEER_V1` text with a deferred (DRP2)
     * prekey; call [mergeKyberContinuation] after fetch / second scan.
     */
    fun decode(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        if (trimmed.startsWith(PeerChatController.INVITE_MAGIC)) return trimmed
        val lower = trimmed.lowercase()
        if (!lower.startsWith(PREFIX)) return null
        val payload = trimmed.substring(PREFIX.length).substringBefore('?').substringBefore('#')
        if (payload.isEmpty()) return null
        return try {
            val bytes = Base64.getUrlDecoder().decode(padBase64Url(payload))
            when {
                startsWithMagic(bytes, MAGIC_COMPACT) -> expandCompact(bytes)
                startsWithUtf8Magic(bytes) -> bytes.toString(Charsets.UTF_8).trim().takeIf {
                    it.startsWith(PeerChatController.INVITE_MAGIC)
                }
                startsWithMagic(bytes, MAGIC_KYBER) -> null // not a full invite
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    fun isKyberContinuation(raw: String): Boolean {
        val bytes = continuationBytes(raw) ?: return false
        return startsWithMagic(bytes, MAGIC_KYBER)
    }

    /**
     * Handshake QR: `derooms://invite/v1/` + DRK1(kyber pk + sig + id).
     * Dense (Version ~29–36); show only as fallback when LAN fetch cannot run.
     */
    fun encodeKyberContinuation(inviteText: String): String {
        val inv = PeerChatController.decodeInvite(inviteText.trim()) ?: return ""
        val prekey = decodePrekey(inv.prekeyB64) ?: return ""
        val wire = try {
            PreKeyBundleCodec.parseWire(prekey)
        } catch (_: Exception) {
            return ""
        }
        if (wire.deferred || wire.kyberPreKey.size < 64) return ""
        return PREFIX + b64(encodeKyberBlob(wire.kyberPreKeyId, wire.kyberPreKey, wire.kyberSig))
    }

    fun mergeKyberContinuation(inviteText: String, continuationRaw: String): String? {
        val inv = PeerChatController.decodeInvite(inviteText.trim()) ?: return null
        val prekey = decodePrekey(inv.prekeyB64) ?: return null
        val wire = try {
            PreKeyBundleCodec.parseWire(prekey)
        } catch (_: Exception) {
            return null
        }
        if (!wire.deferred) return inviteText.trim()
        val blob = continuationBytes(continuationRaw) ?: return null
        val decoded = decodeKyberBlob(blob) ?: return null
        val pk = decoded.second
        val completed = try {
            PreKeyBundleCodec.completeDeferred(wire, pk)
        } catch (_: Exception) {
            return null
        }
        return PeerChatController.encodeInvite(
            inv.copy(prekeyB64 = Base64.getEncoder().encodeToString(completed)),
        )
    }

    fun isDeferredInvite(inviteText: String): Boolean {
        val inv = PeerChatController.decodeInvite(inviteText.trim()) ?: return false
        val prekey = decodePrekey(inv.prekeyB64) ?: return false
        return PreKeyBundleCodec.isDeferred(prekey)
    }

    /** UTF-8 byte length of the URI (QR byte-mode payload size). */
    fun uriUtf8Length(inviteText: String): Int = encode(inviteText).toByteArray(Charsets.UTF_8).size

    private fun compactBytes(inviteText: String): ByteArray? {
        val inv = PeerChatController.decodeInvite(inviteText) ?: return null
        val prekey = decodePrekey(inv.prekeyB64) ?: return null
        val wire = try {
            PreKeyBundleCodec.parseWire(prekey)
        } catch (_: Exception) {
            return null
        }
        val vk = hexToBytes(inv.deviceVkHex)
        if (vk.size != 32) return null
        val (deferredWire, _) = if (wire.deferred) {
            wire to ByteArray(0)
        } else {
            PreKeyBundleCodec.deferKyber(wire)
        }
        val derivedName = derivedSignalName(inv.deviceVkHex)
        val name = inv.signalName.ifBlank { wire.remoteName }
        val nameToStore = name.takeIf { it.isNotBlank() && it != derivedName }
        val ble = inv.listenAddr == PeerChatController.BLE_LISTEN_PLACEHOLDER ||
            inv.listenAddr.startsWith("ble://")
        val listen = if (ble) null else parseListen(inv.listenAddr)
        val listenUtf8 = if (!ble && listen == null) inv.listenAddr.trim() else null
        if (!ble && listen == null && listenUtf8.isNullOrEmpty()) return null
        val relay = inv.relayHostPort.trim()
        val identity = hexToBytes(inv.identityIdHex)
        val labelBytes = inv.displayLabel.trim().toByteArray(Charsets.UTF_8).takeIf { it.isNotEmpty() && it.size <= 64 }
        var flags = 0
        if (relay.isNotEmpty()) flags = flags or FLAG_RELAY
        if (ble) flags = flags or FLAG_BLE
        if (listen?.p2p != null) flags = flags or FLAG_P2P
        if (nameToStore != null) flags = flags or FLAG_NAME
        if (listenUtf8 != null) flags = flags or FLAG_LISTEN_UTF8
        if (identity.size == 32) flags = flags or FLAG_IDENTITY
        if (labelBytes != null) flags = flags or FLAG_LABEL

        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { out ->
            out.writeInt(MAGIC_COMPACT)
            out.writeByte(COMPACT_VERSION.toInt())
            out.writeByte(flags)
            out.write(vk)
            out.writeShort(deferredWire.registrationId and 0xffff)
            out.writeByte(deferredWire.deviceId and 0xff)
            out.writeShort(deferredWire.preKeyId and 0xffff)
            writeFixed(out, deferredWire.preKey, 33)
            out.writeShort(deferredWire.signedPreKeyId and 0xffff)
            writeFixed(out, deferredWire.signedPreKey, 33)
            writeFixed(out, deferredWire.signedSig, 64)
            writeFixed(out, deferredWire.identityKey, 33)
            out.writeShort(deferredWire.kyberPreKeyId and 0xffff)
            writeFixed(out, deferredWire.kyberPreKey, 32) // SHA-256 commitment
            writeFixed(out, deferredWire.kyberSig, 64)
            if (nameToStore != null) {
                val nb = nameToStore.toByteArray(Charsets.UTF_8)
                require(nb.size in 1..255)
                out.writeByte(nb.size)
                out.write(nb)
            }
            if (!ble && listen != null) {
                out.write(listen.ipv4)
                out.writeShort(listen.port)
                if (listen.p2p != null) {
                    require(listen.p2p.size in 1..255)
                    out.writeByte(listen.p2p.size)
                    out.write(listen.p2p)
                }
            }
            if (listenUtf8 != null) {
                val lb = listenUtf8.toByteArray(Charsets.UTF_8)
                require(lb.size in 1..255)
                out.writeByte(lb.size)
                out.write(lb)
            }
            if (relay.isNotEmpty()) {
                val rb = relay.toByteArray(Charsets.UTF_8)
                require(rb.size in 1..255)
                out.writeByte(rb.size)
                out.write(rb)
            }
            if (identity.size == 32) {
                out.write(identity)
            }
            if (labelBytes != null) {
                out.writeByte(labelBytes.size)
                out.write(labelBytes)
            }
        }
        return baos.toByteArray()
    }

    private fun expandCompact(bytes: ByteArray): String? {
        return try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                val magic = input.readInt()
                if (magic != MAGIC_COMPACT) return null
                val version = input.readByte()
                if (version != COMPACT_VERSION) return null
                val flags = input.readUnsignedByte()
                val vk = ByteArray(32).also { input.readFully(it) }
                val registrationId = input.readUnsignedShort()
                val deviceId = input.readUnsignedByte()
                val preKeyId = input.readUnsignedShort()
                val preKey = ByteArray(33).also { input.readFully(it) }
                val spkId = input.readUnsignedShort()
                val spk = ByteArray(33).also { input.readFully(it) }
                val spkSig = ByteArray(64).also { input.readFully(it) }
                val identity = ByteArray(33).also { input.readFully(it) }
                val kyberId = input.readUnsignedShort()
                val kyberHash = ByteArray(32).also { input.readFully(it) }
                val kyberSig = ByteArray(64).also { input.readFully(it) }
                val vkHex = vk.joinToString("") { "%02x".format(it) }
                var name = derivedSignalName(vkHex)
                if (flags and FLAG_NAME != 0) {
                    val nlen = input.readUnsignedByte()
                    name = ByteArray(nlen).also { input.readFully(it) }.toString(Charsets.UTF_8)
                }
                val ble = flags and FLAG_BLE != 0
                val listenUtf8 = flags and FLAG_LISTEN_UTF8 != 0
                val listen = when {
                    ble -> PeerChatController.BLE_LISTEN_PLACEHOLDER
                    listenUtf8 -> {
                        val llen = input.readUnsignedByte()
                        ByteArray(llen).also { input.readFully(it) }.toString(Charsets.UTF_8)
                    }
                    else -> {
                        val ipv4 = ByteArray(4).also { input.readFully(it) }
                        val port = input.readUnsignedShort()
                        val host = ipv4.joinToString(".") { (it.toInt() and 0xff).toString() }
                        val p2p = if (flags and FLAG_P2P != 0) {
                            val plen = input.readUnsignedByte()
                            ByteArray(plen).also { input.readFully(it) }
                        } else {
                            null
                        }
                        buildString {
                            append("/ip4/").append(host).append("/tcp/").append(port)
                            if (p2p != null) {
                                append("/p2p/").append(p2p.joinToString("") { "%02x".format(it) })
                            }
                        }
                    }
                }
                val relay = if (flags and FLAG_RELAY != 0) {
                    val rlen = input.readUnsignedByte()
                    ByteArray(rlen).also { input.readFully(it) }.toString(Charsets.UTF_8)
                } else {
                    ""
                }
                val identityHex = if (flags and FLAG_IDENTITY != 0) {
                    ByteArray(32).also { input.readFully(it) }.joinToString("") { "%02x".format(it) }
                } else {
                    ""
                }
                val label = if (flags and FLAG_LABEL != 0) {
                    val llen = input.readUnsignedByte()
                    ByteArray(llen).also { input.readFully(it) }.toString(Charsets.UTF_8)
                } else {
                    ""
                }
                val deferred = PreKeyBundleCodec.encodeWire(
                    PreKeyBundleCodec.Wire(
                        remoteName = name,
                        registrationId = registrationId,
                        deviceId = deviceId,
                        preKeyId = preKeyId,
                        preKey = preKey,
                        signedPreKeyId = spkId,
                        signedPreKey = spk,
                        signedSig = spkSig,
                        identityKey = identity,
                        kyberPreKeyId = kyberId,
                        kyberPreKey = kyberHash,
                        kyberSig = kyberSig,
                        deferred = true,
                    ),
                    deferred = true,
                )
                PeerChatController.encodeInvite(
                    PeerChatController.PeerInvite(
                        signalName = name,
                        deviceVkHex = vkHex,
                        prekeyB64 = Base64.getEncoder().encodeToString(deferred),
                        listenAddr = listen,
                        relayHostPort = relay,
                        identityIdHex = identityHex,
                        displayLabel = label,
                    ),
                )
            }
        } catch (_: Exception) {
            null
        }
    }

    internal fun encodeKyberBlob(id: Int, pk: ByteArray, sig: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { out ->
            out.writeInt(MAGIC_KYBER)
            out.writeByte(1)
            out.writeShort(id and 0xffff)
            out.writeInt(pk.size)
            out.write(pk)
            out.writeInt(sig.size)
            out.write(sig)
        }
        return baos.toByteArray()
    }

    internal fun decodeKyberBlob(bytes: ByteArray): Triple<Int, ByteArray, ByteArray>? {
        return try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                if (input.readInt() != MAGIC_KYBER) return null
                if (input.readByte() != 1.toByte()) return null
                val id = input.readUnsignedShort()
                val pkLen = input.readInt()
                if (pkLen !in 32..8_192) return null
                val pk = ByteArray(pkLen).also { input.readFully(it) }
                val sigLen = input.readInt()
                if (sigLen !in 32..256) return null
                val sig = ByteArray(sigLen).also { input.readFully(it) }
                Triple(id, pk, sig)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun continuationBytes(raw: String): ByteArray? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        val payload = if (trimmed.lowercase().startsWith(PREFIX)) {
            trimmed.substring(PREFIX.length).substringBefore('?').substringBefore('#')
        } else {
            trimmed
        }
        return try {
            Base64.getUrlDecoder().decode(padBase64Url(payload))
        } catch (_: Exception) {
            null
        }
    }

    private data class ListenParts(val ipv4: ByteArray, val port: Int, val p2p: ByteArray?)

    private fun parseListen(addr: String): ListenParts? {
        // /ip4/A.B.C.D/tcp/PORT[/p2p/hex]
        val m = Regex("^/ip4/(\\d{1,3}(?:\\.\\d{1,3}){3})/tcp/(\\d{1,5})(?:/p2p/([0-9a-fA-F]+))?$")
            .matchEntire(addr.trim()) ?: return null
        val host = m.groupValues[1]
        val port = m.groupValues[2].toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        val ipv4 = host.split('.').map { it.toInt() }
        if (ipv4.size != 4 || ipv4.any { it !in 0..255 }) return null
        val p2pHex = m.groupValues[3]
        val p2p = if (p2pHex.isEmpty()) null else hexToBytes(p2pHex).takeIf { it.isNotEmpty() }
        return ListenParts(
            ipv4 = byteArrayOf(
                ipv4[0].toByte(),
                ipv4[1].toByte(),
                ipv4[2].toByte(),
                ipv4[3].toByte(),
            ),
            port = port,
            p2p = p2p,
        )
    }

    fun listenHostPort(listenAddr: String): Pair<String, Int>? {
        val p = parseListen(listenAddr) ?: return null
        val host = p.ipv4.joinToString(".") { (it.toInt() and 0xff).toString() }
        return host to p.port
    }

    private fun derivedSignalName(vkHex: String): String =
        if (vkHex.length >= 16) "d${vkHex.take(16)}" else "d$vkHex"

    private fun writeFixed(out: DataOutputStream, data: ByteArray, n: Int) {
        require(data.size == n) { "expected $n bytes, got ${data.size}" }
        out.write(data)
    }

    private fun decodePrekey(b64: String): ByteArray? = try {
        Base64.getDecoder().decode(b64.trim())
    } catch (_: Exception) {
        null
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        if (clean.length % 2 != 0) return ByteArray(0)
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun b64(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun startsWithMagic(bytes: ByteArray, magic: Int): Boolean {
        if (bytes.size < 4) return false
        val v = ((bytes[0].toInt() and 0xff) shl 24) or
            ((bytes[1].toInt() and 0xff) shl 16) or
            ((bytes[2].toInt() and 0xff) shl 8) or
            (bytes[3].toInt() and 0xff)
        return v == magic
    }

    private fun startsWithUtf8Magic(bytes: ByteArray): Boolean {
        val prefix = PeerChatController.INVITE_MAGIC.toByteArray(Charsets.UTF_8)
        if (bytes.size < prefix.size) return false
        return bytes.copyOf(prefix.size).contentEquals(prefix)
    }

    private fun padBase64Url(s: String): String {
        val pad = (4 - s.length % 4) % 4
        return s + "=".repeat(pad)
    }
}
