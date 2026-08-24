package org.derooms.app.room

import android.content.Context
import android.util.Log
import org.derooms.app.crypto.IdentityKeystore
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Persisted joined-rooms index + per-room transcript (DAG-aware lines).
 * Same wrap pattern as [org.derooms.app.peer.ConversationStore].
 */
class RoomStore(private val context: Context) {
    data class RoomEntry(
        val roomIdHex: String,
        val displayName: String,
        val lastActivityMs: Long = 0L,
        val mlsStatePath: String? = null,
        val lastText: String = "",
        val createdUnixSecs: Long = 0L,
        /** Joiner’s Accept receipt hex until founder applies it. */
        val pendingAcceptReceiptHex: String = "",
        /** Peer SyncLab multiaddr for room Offer/Want/Have. */
        val peerListenMultiaddr: String = "",
        /** Peer device ed25519 verifying-key hex (64 chars) for pull verify. */
        val peerDeviceVkHex: String = "",
    )

    data class RoomLine(
        val outbound: Boolean,
        val text: String,
        val meta: String,
        val eventIdHex: String = "",
        val parentHexes: List<String> = emptyList(),
        val atMs: Long = 0L,
    )

    @Volatile
    private var rooms: MutableList<RoomEntry> = mutableListOf()

    @Volatile
    private var loaded = false

    fun listRooms(): List<RoomEntry> {
        ensureLoaded()
        return rooms.sortedByDescending { it.lastActivityMs }
    }

    fun get(roomIdHex: String): RoomEntry? {
        ensureLoaded()
        val id = roomIdHex.trim().lowercase()
        if (id.isEmpty()) return null
        return rooms.firstOrNull { it.roomIdHex.equals(id, ignoreCase = true) }
    }

    fun upsert(
        roomIdHex: String,
        displayName: String? = null,
        mlsStatePath: String? = null,
        lastText: String? = null,
        lastActivityMs: Long? = null,
        createdUnixSecs: Long? = null,
        pendingAcceptReceiptHex: String? = null,
        peerListenMultiaddr: String? = null,
        peerDeviceVkHex: String? = null,
    ): RoomEntry {
        ensureLoaded()
        val id = roomIdHex.trim().lowercase()
        require(id.isNotEmpty()) { "roomIdHex required" }
        val existing = rooms.firstOrNull { it.roomIdHex.equals(id, ignoreCase = true) }
        val name = displayName?.trim()?.takeIf { it.isNotEmpty() }
            ?: existing?.displayName
            ?: defaultName(id)
        val entry = RoomEntry(
            roomIdHex = id,
            displayName = name,
            lastActivityMs = lastActivityMs ?: existing?.lastActivityMs ?: System.currentTimeMillis(),
            mlsStatePath = mlsStatePath ?: existing?.mlsStatePath,
            lastText = lastText ?: existing?.lastText.orEmpty(),
            createdUnixSecs = createdUnixSecs ?: existing?.createdUnixSecs ?: 0L,
            pendingAcceptReceiptHex = pendingAcceptReceiptHex
                ?: existing?.pendingAcceptReceiptHex.orEmpty(),
            peerListenMultiaddr = peerListenMultiaddr
                ?: existing?.peerListenMultiaddr.orEmpty(),
            peerDeviceVkHex = peerDeviceVkHex
                ?: existing?.peerDeviceVkHex.orEmpty(),
        )
        rooms.removeAll { it.roomIdHex.equals(id, ignoreCase = true) }
        rooms.add(entry)
        persistIndex()
        return entry
    }

    fun remove(roomIdHex: String) {
        ensureLoaded()
        val id = roomIdHex.trim().lowercase()
        rooms.removeAll { it.roomIdHex.equals(id, ignoreCase = true) }
        persistIndex()
        transcriptFile(id).delete()
        roomStateFile(id).delete()
        mlsStateFile(id).delete()
    }

    fun setDisplayName(roomIdHex: String, name: String): RoomEntry? {
        val trimmed = name.trim().ifBlank { return get(roomIdHex) }
        return upsert(roomIdHex, displayName = trimmed)
    }

    fun appendLine(roomIdHex: String, line: RoomLine) {
        ensureLoaded()
        val id = roomIdHex.trim().lowercase().ifBlank { return }
        val body = encodeLine(line)
        val prev = loadPlain(transcriptFile(id))
        writePlain(transcriptFile(id), prev + body)
        upsert(
            roomIdHex = id,
            lastText = line.text,
            lastActivityMs = line.atMs.takeIf { it > 0L } ?: System.currentTimeMillis(),
        )
    }

    fun loadLines(roomIdHex: String): List<RoomLine> {
        ensureLoaded()
        val id = roomIdHex.trim().lowercase().ifBlank { return emptyList() }
        val plain = loadPlain(transcriptFile(id))
        if (plain.isBlank()) return emptyList()
        val raw = plain.lineSequence().mapNotNull { parseLine(it) }.toList()
        return sortForDisplay(raw)
    }

    /** Causal tips: event ids that are not referenced as a parent by any later line. */
    fun lastTipHexes(roomIdHex: String, limit: Int = 4): List<String> {
        val lines = loadLines(roomIdHex)
        if (lines.isEmpty()) return emptyList()
        val referenced = lines.flatMap { it.parentHexes }.map { it.lowercase() }.toHashSet()
        val tips = lines
            .map { it.eventIdHex.trim().lowercase() }
            .filter { it.length == 64 && it !in referenced }
        return if (tips.isNotEmpty()) {
            tips.takeLast(limit)
        } else {
            lines.map { it.eventIdHex.trim().lowercase() }
                .filter { it.length == 64 }
                .takeLast(1)
        }
    }

    fun mlsStateFile(roomIdHex: String): File {
        val safe = roomIdHex.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(48)
        return File(dir(), "mls_$safe.bin")
    }

    fun roomStateFile(roomIdHex: String): File {
        val safe = roomIdHex.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(48)
        return File(dir(), "state_$safe.bin")
    }

    private fun ensureLoaded() {
        if (loaded) return
        synchronized(this) {
            if (loaded) return
            rooms = loadIndex().toMutableList()
            loaded = true
        }
    }

    private fun persistIndex() {
        val arr = JSONArray()
        for (r in rooms) {
            arr.put(
                JSONObject()
                    .put("roomIdHex", r.roomIdHex)
                    .put("displayName", r.displayName)
                    .put("lastActivityMs", r.lastActivityMs)
                    .put("mlsStatePath", r.mlsStatePath ?: "")
                    .put("lastText", r.lastText)
                    .put("createdUnixSecs", r.createdUnixSecs)
                    .put("pendingAcceptReceiptHex", r.pendingAcceptReceiptHex)
                    .put("peerListenMultiaddr", r.peerListenMultiaddr)
                    .put("peerDeviceVkHex", r.peerDeviceVkHex),
            )
        }
        writePlain(indexFile(), arr.toString())
    }

    private fun loadIndex(): List<RoomEntry> {
        val plain = loadPlain(indexFile())
        if (plain.isBlank()) return emptyList()
        return try {
            val arr = JSONArray(plain)
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    val path = o.optString("mlsStatePath").ifBlank { null }
                    add(
                        RoomEntry(
                            roomIdHex = o.optString("roomIdHex"),
                            displayName = o.optString("displayName"),
                            lastActivityMs = o.optLong("lastActivityMs"),
                            mlsStatePath = path,
                            lastText = o.optString("lastText"),
                            createdUnixSecs = o.optLong("createdUnixSecs"),
                            pendingAcceptReceiptHex = o.optString("pendingAcceptReceiptHex"),
                            peerListenMultiaddr = o.optString("peerListenMultiaddr"),
                            peerDeviceVkHex = o.optString("peerDeviceVkHex"),
                        ),
                    )
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "rooms index parse failed: ${e.message}")
            emptyList()
        }
    }

    private fun writePlain(file: File, plain: String) {
        file.parentFile?.mkdirs()
        val bytes = try {
            IdentityKeystore.wrapChat(plain.toByteArray(Charsets.UTF_8)).blob
        } catch (e: Exception) {
            Log.w(TAG, "room wrap failed: ${e.message}")
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
            Log.w(TAG, "room unwrap failed: ${e.message}")
            ""
        }
    }

    private fun indexFile(): File = File(dir(), "index.bin")

    private fun transcriptFile(roomIdHex: String): File {
        val safe = roomIdHex.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(48)
        return File(dir(), "t_$safe.bin")
    }

    private fun dir(): File = File(context.filesDir, "rooms").also { it.mkdirs() }

    companion object {
        private const val TAG = "DEROOMS_ROOMS"

        fun defaultName(roomIdHex: String): String =
            "Room ${roomIdHex.take(8).ifBlank { "…" }}"

        fun encodeLine(line: RoomLine): String {
            val text = line.text.replace('\n', ' ').replace('|', '/')
            val parents = line.parentHexes.joinToString(",")
            return "${if (line.outbound) "out" else "in"}|${line.meta}|${line.eventIdHex}|" +
                "$parents|${line.atMs}|$text\n"
        }

        fun parseLine(raw: String): RoomLine? {
            val parts = raw.split('|', limit = 6)
            if (parts.size < 3) return null
            return if (parts.size >= 6) {
                RoomLine(
                    outbound = parts[0] == "out",
                    meta = parts[1],
                    eventIdHex = parts[2],
                    parentHexes = parts[3].split(',').map { it.trim() }.filter { it.isNotEmpty() },
                    atMs = parts[4].toLongOrNull() ?: 0L,
                    text = parts[5],
                )
            } else {
                RoomLine(
                    outbound = parts[0] == "out",
                    meta = parts[1],
                    text = parts.getOrElse(2) { "" },
                )
            }
        }

        /**
         * Chat display order: wall-clock when timestamps exist, else file
         * append order. Do not Kahn-sort a mixed transcript — outbound events
         * have ids/parents and inbound often do not, which grouped "yours"
         * then "theirs" after leaving the room.
         */
        fun sortForDisplay(lines: List<RoomLine>): List<RoomLine> {
            if (lines.size <= 1) return lines
            if (lines.any { it.atMs > 0L }) {
                return lines.mapIndexed { i, line ->
                    Triple(if (line.atMs > 0L) line.atMs else Long.MAX_VALUE, i, line)
                }.sortedWith(compareBy({ it.first }, { it.second })).map { it.third }
            }
            return lines
        }

        /**
         * Trivial DAG order: Kahn-style topo when parent links exist; else keep
         * append order. Tie-break by eventIdHex.
         */
        fun sortByParentOrder(lines: List<RoomLine>): List<RoomLine> {
            if (lines.size <= 1) return lines
            val byId = linkedMapOf<String, RoomLine>()
            for (l in lines) {
                val id = l.eventIdHex.trim().lowercase()
                if (id.length == 64) byId[id] = l
            }
            if (byId.isEmpty()) return lines

            val children = hashMapOf<String, MutableList<String>>()
            val indegree = hashMapOf<String, Int>()
            for (id in byId.keys) indegree[id] = 0
            for ((id, line) in byId) {
                for (p in line.parentHexes.map { it.lowercase() }) {
                    if (p !in byId) continue
                    children.getOrPut(p) { mutableListOf() }.add(id)
                    indegree[id] = (indegree[id] ?: 0) + 1
                }
            }
            val queue = indegree.filter { it.value == 0 }.keys.sorted().toMutableList()
            val out = ArrayList<RoomLine>(byId.size)
            val seen = hashSetOf<String>()
            while (queue.isNotEmpty()) {
                val id = queue.removeAt(0)
                if (!seen.add(id)) continue
                byId[id]?.let { out.add(it) }
                for (c in children[id].orEmpty().sorted()) {
                    val d = (indegree[c] ?: 0) - 1
                    indegree[c] = d
                    if (d == 0) queue.add(c)
                    queue.sort()
                }
            }
            // Orphans / cycles: append remaining in original order.
            for (l in lines) {
                val id = l.eventIdHex.trim().lowercase()
                if (id.length == 64 && id !in seen) out.add(l)
                else if (id.length != 64) out.add(l)
            }
            return if (out.size == lines.size) out else lines
        }
    }
}
