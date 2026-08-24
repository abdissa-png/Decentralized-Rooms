package org.derooms.app.room

import org.derooms.app.core.LocalRoomHandle
import org.derooms.app.core.MlsGroupHandle
import java.util.concurrent.ConcurrentHashMap

/**
 * Process-lifetime handles for opened rooms (CRDT session is in-memory in UniFFI).
 * Cold start still shows the list + transcript; re-attach via create/join or MLS restore.
 */
object RoomSessionCache {
    private val rooms = ConcurrentHashMap<String, LocalRoomHandle>()
    private val mls = ConcurrentHashMap<String, MlsGroupHandle>()

    fun putRoom(roomIdHex: String, handle: LocalRoomHandle) {
        val id = roomIdHex.trim().lowercase()
        if (id.isNotEmpty()) rooms[id] = handle
    }

    fun getRoom(roomIdHex: String): LocalRoomHandle? =
        rooms[roomIdHex.trim().lowercase()]

    fun putMls(roomIdHex: String, handle: MlsGroupHandle) {
        val id = roomIdHex.trim().lowercase()
        if (id.isNotEmpty()) mls[id] = handle
    }

    fun getMls(roomIdHex: String): MlsGroupHandle? =
        mls[roomIdHex.trim().lowercase()]

    fun remove(roomIdHex: String) {
        val id = roomIdHex.trim().lowercase()
        rooms.remove(id)
        mls.remove(id)
    }
}
