package org.derooms.app.room

import java.util.Base64

/**
 * Compact room-invite packaging for QR / deep links.
 *
 * Prefix [PREFIX]. Payload is Base64URL-nopad of invite-material bytes
 * (hex-decoded). Scanners also accept raw invite-material hex.
 */
object RoomInviteUri {
    const val PREFIX = "derooms://room/v1/"

    fun encode(inviteMaterialHex: String): String {
        val hex = inviteMaterialHex.trim().lowercase()
        if (hex.isEmpty() || hex.length % 2 != 0) return ""
        val bytes = hexToBytes(hex) ?: return ""
        if (bytes.isEmpty()) return ""
        return PREFIX + b64(bytes)
    }

    /**
     * Accept URI, hex paste, or scanned string. Returns invite-material hex
     * or null if unrecognised.
     */
    fun decode(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        val lower = trimmed.lowercase()
        if (lower.startsWith(PREFIX)) {
            val payload = trimmed.substring(PREFIX.length).substringBefore('?').substringBefore('#')
            if (payload.isEmpty()) return null
            return try {
                val bytes = Base64.getUrlDecoder().decode(padBase64Url(payload))
                if (bytes.isEmpty()) null else bytesToHex(bytes)
            } catch (_: Exception) {
                null
            }
        }
        // Raw hex invite material (DRIM magic often starts after decode; accept even length hex).
        val hex = lower.removePrefix("0x")
        if (hex.length >= 64 && hex.length % 2 == 0 && hex.all { it in "0123456789abcdef" }) {
            return hex
        }
        return null
    }

    fun isRoomInvite(raw: String): Boolean = decode(raw) != null

    private fun b64(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun padBase64Url(s: String): String {
        val rem = s.length % 4
        return if (rem == 0) s else s + "=".repeat(4 - rem)
    }

    private fun hexToBytes(hex: String): ByteArray? {
        return try {
            ByteArray(hex.length / 2) { i ->
                hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }
}
