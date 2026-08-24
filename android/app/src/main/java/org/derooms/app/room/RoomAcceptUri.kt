package org.derooms.app.room

import java.util.Base64

/**
 * Accept-receipt packaging so the founder can scan the joiner’s DRAM after invite QR.
 *
 * Prefix [PREFIX]. Payload is Base64URL-nopad of accept-receipt bytes (hex-decoded).
 */
object RoomAcceptUri {
    const val PREFIX = "derooms://room/accept/v1/"

    fun encode(acceptReceiptHex: String): String {
        val hex = acceptReceiptHex.trim().lowercase()
        if (hex.isEmpty() || hex.length % 2 != 0) return ""
        val bytes = hexToBytes(hex) ?: return ""
        if (bytes.isEmpty()) return ""
        return PREFIX + b64(bytes)
    }

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
        // Raw DRAM hex (starts with 4452414d = "DRAM")
        val hex = lower.removePrefix("0x")
        if (hex.startsWith("4452414d") && hex.length % 2 == 0 &&
            hex.all { it in "0123456789abcdef" }
        ) {
            return hex
        }
        return null
    }

    fun isAccept(raw: String): Boolean = decode(raw) != null

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

/** Opaque MessageEvent ciphertext tags for room LAN sync of MLS control/app. */
object RoomSyncTags {
    const val WELCOME = "DRMW:"
    const val COMMIT = "DRMC:"
    const val MLS_SEALED = "DRMS:"
    /** Joiner Accept receipt (DRAM hex) for founder roster. */
    const val ACCEPT = "DRMA:"
    /** Signed membership mutation hex (remove/leave/promote). */
    const val MEMBERSHIP = "DRMM:"
}
