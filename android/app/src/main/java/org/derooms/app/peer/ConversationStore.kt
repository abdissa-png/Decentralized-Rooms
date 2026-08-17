package org.derooms.app.peer

import android.content.Context
import android.util.Log
import org.derooms.app.crypto.IdentityKeystore
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Identity-keyed inbox: contacts + transcripts at rest under AES-GCM
 * (Android Keystore). Decrypted bytes live in memory only.
 *
 * Thread key is [identityIdHex] when present, else [deviceVkHex] — pairing
 * the same identity again continues the old conversation.
 */
class ConversationStore(private val context: Context) {
    data class Contact(
        val threadKey: String,
        val identityIdHex: String,
        val deviceVkHex: String,
        val displayName: String,
        val lastText: String = "",
        val lastMeta: String = "",
        val lastAtMs: Long = 0L,
        val lastVia: String = "",
        val inviteText: String = "",
    )

    data class Line(
        val outbound: Boolean,
        val text: String,
        val meta: String,
        val via: String,
        val deviceShort: String,
        val atMs: Long,
    )

    @Volatile
    private var contacts: MutableList<Contact> = mutableListOf()

    @Volatile
    private var loaded = false

    fun list(): List<Contact> {
        ensureLoaded()
        return contacts.sortedByDescending { it.lastAtMs }
    }

    fun get(threadKey: String): Contact? {
        ensureLoaded()
        val key = threadKey.trim()
        if (key.isEmpty()) return null
        return contacts.firstOrNull { it.threadKey.equals(key, ignoreCase = true) }
    }

    fun upsertFromInvite(
        identityIdHex: String,
        deviceVkHex: String,
        suggestedName: String,
        inviteText: String = "",
    ): Contact {
        ensureLoaded()
        val vk = deviceVkHex.trim().lowercase()
        val id = identityIdHex.trim().lowercase()
        val key = threadKey(id, vk)
        val existing = contacts.firstOrNull { it.threadKey.equals(key, ignoreCase = true) }
            ?: contacts.firstOrNull { it.deviceVkHex.equals(vk, ignoreCase = true) && vk.length == 64 }
            ?: contacts.firstOrNull { id.length == 64 && it.identityIdHex.equals(id, ignoreCase = true) }
        val name = existing?.displayName?.takeIf { it.isNotBlank() }
            ?: suggestedName.trim().ifBlank { defaultName(vk, id) }
        val contact = (existing ?: Contact(
            threadKey = key,
            identityIdHex = id,
            deviceVkHex = vk,
            displayName = name,
        )).copy(
            threadKey = key,
            identityIdHex = id.ifBlank { existing?.identityIdHex.orEmpty() },
            deviceVkHex = vk.ifBlank { existing?.deviceVkHex.orEmpty() },
            displayName = name,
            inviteText = inviteText.ifBlank { existing?.inviteText.orEmpty() },
        )
        contacts.removeAll { it.threadKey.equals(contact.threadKey, ignoreCase = true) }
        contacts.add(contact)
        persistIndex()
        return contact
    }

    fun setDisplayName(threadKey: String, name: String): Contact? {
        ensureLoaded()
        val trimmed = name.trim().ifBlank { return get(threadKey) }
        val idx = contacts.indexOfFirst { it.threadKey.equals(threadKey, ignoreCase = true) }
        if (idx < 0) return null
        val updated = contacts[idx].copy(displayName = trimmed)
        contacts[idx] = updated
        persistIndex()
        return updated
    }

    fun needsName(threadKey: String): Boolean {
        val c = get(threadKey) ?: return true
        return c.displayName.isBlank() || c.displayName.startsWith("Peer ")
    }

    fun append(threadKey: String, line: Line) {
        ensureLoaded()
        val key = threadKey.ifBlank { return }
        val body = encodeLine(line)
        val prev = loadPlain(transcriptFile(key))
        writePlain(transcriptFile(key), prev + body)
        val idx = contacts.indexOfFirst { it.threadKey.equals(key, ignoreCase = true) }
        if (idx >= 0) {
            contacts[idx] = contacts[idx].copy(
                lastText = line.text,
                lastMeta = line.meta,
                lastAtMs = line.atMs,
                lastVia = line.via,
            )
            persistIndex()
        }
    }

    fun loadLines(threadKey: String): List<Line> {
        ensureLoaded()
        val key = threadKey.ifBlank { return emptyList() }
        val plain = loadPlain(transcriptFile(key))
        if (plain.isBlank()) {
            return migrateLegacy(key)
        }
        return plain.lineSequence().mapNotNull { parseLine(it) }.toList()
    }

    fun localDisplayName(): String {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return prefs.getString(PREF_SELF_NAME, "")
            .orEmpty()
            .trim()
    }

    fun setLocalDisplayName(name: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(PREF_SELF_NAME, name.trim())
            .apply()
    }

    private fun ensureLoaded() {
        if (loaded) return
        synchronized(this) {
            if (loaded) return
            contacts = loadIndex().toMutableList()
            loaded = true
        }
    }

    private fun persistIndex() {
        val arr = JSONArray()
        for (c in contacts) {
            arr.put(
                JSONObject()
                    .put("threadKey", c.threadKey)
                    .put("identityIdHex", c.identityIdHex)
                    .put("deviceVkHex", c.deviceVkHex)
                    .put("displayName", c.displayName)
                    .put("lastText", c.lastText)
                    .put("lastMeta", c.lastMeta)
                    .put("lastAtMs", c.lastAtMs)
                    .put("lastVia", c.lastVia)
                    .put("inviteText", c.inviteText),
            )
        }
        writePlain(indexFile(), arr.toString())
    }

    private fun loadIndex(): List<Contact> {
        val plain = loadPlain(indexFile())
        if (plain.isBlank()) return emptyList()
        return try {
            val arr = JSONArray(plain)
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    add(
                        Contact(
                            threadKey = o.optString("threadKey"),
                            identityIdHex = o.optString("identityIdHex"),
                            deviceVkHex = o.optString("deviceVkHex"),
                            displayName = o.optString("displayName"),
                            lastText = o.optString("lastText"),
                            lastMeta = o.optString("lastMeta"),
                            lastAtMs = o.optLong("lastAtMs"),
                            lastVia = o.optString("lastVia"),
                            inviteText = o.optString("inviteText"),
                        ),
                    )
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "inbox index parse failed: ${e.message}")
            emptyList()
        }
    }

    private fun migrateLegacy(threadKey: String): List<Line> {
        val names = listOf(threadKey, threadKey.take(48), threadKey.take(32)).distinct()
        val dir = File(context.filesDir, "peer_chat")
        for (name in names) {
            val safe = name.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(48)
            val legacy = File(dir, "$safe.txt")
            if (!legacy.exists()) continue
            val lines = legacy.readLines().mapNotNull { raw ->
                val parts = raw.split('|', limit = 3)
                if (parts.size < 3) return@mapNotNull null
                Line(
                    outbound = parts[0] == "out",
                    text = parts[2],
                    meta = parts[1],
                    via = inferVia(parts[1]),
                    deviceShort = "",
                    atMs = 0L,
                )
            }
            if (lines.isNotEmpty()) {
                writePlain(transcriptFile(threadKey), lines.joinToString("") { encodeLine(it) })
                return lines
            }
        }
        return emptyList()
    }

    private fun writePlain(file: File, plain: String) {
        file.parentFile?.mkdirs()
        val bytes = try {
            IdentityKeystore.wrapChat(plain.toByteArray(Charsets.UTF_8)).blob
        } catch (e: Exception) {
            Log.w(TAG, "chat wrap failed — not writing plaintext: ${e.message}")
            return
        }
        file.writeBytes(bytes)
    }

    private fun loadPlain(file: File): String {
        if (!file.exists()) return ""
        return try {
            val raw = file.readBytes()
            if (raw.isEmpty()) return ""
            String(IdentityKeystore.unwrapChat(IdentityKeystore.WrappedSecret(raw)), Charsets.UTF_8)
        } catch (e: Exception) {
            Log.w(TAG, "chat unwrap failed: ${e.message}")
            ""
        }
    }

    private fun indexFile(): File = File(dir(), "index.bin")

    private fun transcriptFile(threadKey: String): File {
        val safe = threadKey.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(48)
        return File(dir(), "$safe.bin")
    }

    private fun dir(): File = File(context.filesDir, "conversations").also { it.mkdirs() }

    companion object {
        private const val TAG = "DEROOMS_INBOX"
        private const val PREFS = "derooms_gate1"
        private const val PREF_SELF_NAME = "self_display_name"

        fun threadKey(identityIdHex: String, deviceVkHex: String): String {
            val id = identityIdHex.trim().lowercase()
            if (id.length == 64) return id
            return deviceVkHex.trim().lowercase().take(64)
        }

        fun defaultName(deviceVkHex: String, identityIdHex: String = ""): String {
            val src = identityIdHex.takeIf { it.length >= 8 } ?: deviceVkHex
            return "Peer ${src.take(8)}"
        }

        fun deviceShort(deviceVkHex: String): String =
            if (deviceVkHex.length >= 8) deviceVkHex.take(8) else deviceVkHex

        fun encodeLine(line: Line): String {
            val text = line.text.replace('\n', ' ').replace('|', '/')
            return "${if (line.outbound) "out" else "in"}|${line.meta}|${line.via}|${line.deviceShort}|${line.atMs}|$text\n"
        }

        fun parseLine(raw: String): Line? {
            val parts = raw.split('|', limit = 6)
            if (parts.size < 3) return null
            return if (parts.size >= 6) {
                Line(
                    outbound = parts[0] == "out",
                    meta = parts[1],
                    via = parts[2],
                    deviceShort = parts[3],
                    atMs = parts[4].toLongOrNull() ?: 0L,
                    text = parts[5],
                )
            } else {
                Line(
                    outbound = parts[0] == "out",
                    meta = parts[1],
                    via = inferVia(parts[1]),
                    deviceShort = "",
                    atMs = 0L,
                    text = parts[2],
                )
            }
        }

        fun inferVia(meta: String): String {
            val m = meta.lowercase()
            return when {
                m.contains("relay") -> "relay"
                m.contains("ble") -> "ble"
                m.contains("wifi-direct") || m.contains("wd") -> "wifi-direct"
                m.contains("lan") || m.contains("synced") -> "lan"
                else -> meta
            }
        }

        fun pathLabel(via: String): String = when (via.lowercase()) {
            "relay" -> "relay"
            "ble" -> "BLE"
            "wifi-direct", "wd" -> "Wi‑Fi Direct"
            "lan", "sealed+synced" -> "LAN"
            else -> via.ifBlank { "sync" }
        }
    }
}
