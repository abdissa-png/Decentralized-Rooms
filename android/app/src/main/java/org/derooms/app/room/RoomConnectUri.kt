package org.derooms.app.room

import java.net.URLDecoder
import java.net.URLEncoder

/**
 * Compact scannable cards for room invite + LAN sync (less copy/paste).
 */
object RoomIdentityUri {
    const val PREFIX = "derooms://id/v1/"

    /** identity_id (64 hex) + device verifying key (64 hex). */
    fun encode(identityIdHex: String, deviceVkHex: String): String {
        val id = identityIdHex.trim().lowercase()
        val vk = deviceVkHex.trim().lowercase()
        if (id.length != 64 || vk.length != 64) return ""
        if (!id.all { it in "0123456789abcdef" } || !vk.all { it in "0123456789abcdef" }) {
            return ""
        }
        return PREFIX + "i=$id&d=$vk"
    }

    data class Card(val identityIdHex: String, val deviceVkHex: String)

    fun decode(raw: String): Card? {
        val trimmed = raw.trim()
        if (!trimmed.lowercase().startsWith(PREFIX)) return null
        val q = trimmed.substring(PREFIX.length).substringBefore('#').trimStart('?', '/')
        val map = parseQuery(q)
        val id = map["i"]?.lowercase() ?: return null
        val vk = map["d"]?.lowercase() ?: return null
        if (id.length != 64 || vk.length != 64) return null
        if (!id.all { it in "0123456789abcdef" } || !vk.all { it in "0123456789abcdef" }) {
            return null
        }
        return Card(id, vk)
    }

    fun isIdentityCard(raw: String): Boolean = decode(raw) != null
}

object RoomSyncPathUri {
    const val PREFIX = "derooms://room/sync/v1/"

    fun encode(roomIdHex: String, listenMultiaddr: String, deviceVkHex: String): String {
        val room = roomIdHex.trim().lowercase()
        val listen = listenMultiaddr.trim()
        val vk = deviceVkHex.trim().lowercase()
        if (room.length != 64 || listen.isEmpty() || vk.length != 64) return ""
        val l = URLEncoder.encode(listen, Charsets.UTF_8.name())
        return PREFIX + "r=$room&l=$l&d=$vk"
    }

    data class Path(
        val roomIdHex: String,
        val listenMultiaddr: String,
        val deviceVkHex: String,
    )

    fun decode(raw: String): Path? {
        val trimmed = raw.trim()
        if (!trimmed.lowercase().startsWith(PREFIX)) return null
        val q = trimmed.substring(PREFIX.length).substringBefore('#').trimStart('?', '/')
        val map = parseQuery(q)
        val room = map["r"]?.lowercase() ?: return null
        val listenEnc = map["l"] ?: return null
        val vk = map["d"]?.lowercase() ?: return null
        if (room.length != 64 || vk.length != 64) return null
        val listen = try {
            URLDecoder.decode(listenEnc, Charsets.UTF_8.name())
        } catch (_: Exception) {
            return null
        }
        if (listen.isBlank()) return null
        return Path(room, listen, vk)
    }

    fun isSyncPath(raw: String): Boolean = decode(raw) != null
}

private fun parseQuery(q: String): Map<String, String> {
    if (q.isBlank()) return emptyMap()
    return q.split('&').mapNotNull { part ->
        val i = part.indexOf('=')
        if (i <= 0) return@mapNotNull null
        part.substring(0, i) to part.substring(i + 1)
    }.toMap()
}
