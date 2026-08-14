package org.derooms.app.core

/**
 * Facade matching UniFFI surface (`ffi/src/rooms.udl`).
 *
 * When `librooms_ffi.so` + generated Kotlin bindings (`uniffi.rooms`) are present,
 * [RoomsCoreBridge] delegates to real Rust. Otherwise falls back to a fail-closed
 * stub so the Compose shell still builds without NDK artifacts.
 */
data class CreatedIdentity(
    val identityIdHex: String,
    val deviceIdHex: String,
    val masterPubkeyHex: String,
    val devicePubkeyHex: String,
)

data class CreatedIdentityBundle(
    val publicIdentity: CreatedIdentity,
    /** Opaque IdentitySecretBlob — wrap with Keystore; never log. */
    val secretBlob: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is CreatedIdentityBundle &&
            publicIdentity == other.publicIdentity &&
            secretBlob.contentEquals(other.secretBlob)

    override fun hashCode(): Int =
        31 * publicIdentity.hashCode() + secretBlob.contentHashCode()
}

data class SignedMessageEventWire(
    val wireEnvelope: ByteArray,
    val eventIdHex: String,
) {
    override fun equals(other: Any?): Boolean =
        other is SignedMessageEventWire &&
            eventIdHex == other.eventIdHex &&
            wireEnvelope.contentEquals(other.wireEnvelope)

    override fun hashCode(): Int =
        31 * eventIdHex.hashCode() + wireEnvelope.contentHashCode()
}

data class FoundedRoom(
    val roomIdHex: String,
    val creatorIdentityIdHex: String,
    val activeMemberIdHexes: List<String>,
    val activeMemberCount: UInt,
)

/** Local founded-room handle (UniFFI LocalRoomSession or stub). */
interface LocalRoomHandle {
    fun roomIdHex(): String
    fun creatorIdentityIdHex(): String
    fun activeMemberIdHexes(): List<String>
    fun activeMemberCount(): UInt
    fun inviteTokenHex(inviteeIdentityIdHex: String): String
    fun inviteMaterialHex(inviteeIdentityIdHex: String): String
    /**
     * DRIM v2 invite with optional Welcome/Commit CIDs. Falls back to
     * [inviteMaterialHex] until UniFFI regenerates these methods.
     */
    fun inviteMaterialWithWelcomeHex(
        inviteeIdentityIdHex: String,
        welcomeCidHex: String = "",
        commitCidHex: String = "",
    ): String
    fun welcomeCidHex(): String
    fun commitCidHex(): String
    fun membershipMutationHex(action: String, targetIdentityIdHex: String): String
    fun applyMembershipEventHex(eventHex: String): Boolean
    fun acceptReceiptHex(): String
    fun applyAcceptReceiptHex(receiptHex: String): Boolean
    fun exportStateBlob(): ByteArray
    fun signTextEvent(
        ciphertext: ByteArray,
        causalParentHexes: List<String> = emptyList(),
    ): SignedMessageEventWire
}

/** On-device OpenMLS group session handle. */
data class MlsAddResult(
    val commitHex: String,
    val welcomeHex: String,
    val epoch: ULong,
    val memberCount: UInt,
    val error: String,
)

interface MlsGroupHandle {
    fun isReady(): Boolean
    fun hasGroup(): Boolean
    fun credentialLabel(): String
    fun exportKeyPackageHex(): String
    fun createGroup(): String
    fun groupIdHex(): String
    fun epoch(): ULong
    fun memberCount(): UInt
    fun maxMembers(): UInt
    fun addMemberKeyPackageHex(keyPackageHex: String): MlsAddResult
    fun joinFromWelcomeHex(welcomeHex: String): Boolean
    fun processCommitHex(commitHex: String): Boolean
    fun sealText(plaintext: String): String
    fun openMessageHex(messageHex: String): String
    fun removeMemberLabel(credentialLabel: String): String
    fun exportStateBlob(): ByteArray
}

interface RoomsCore {
    fun protoDraftVersion(): String
    fun coreVersion(): String
    fun identityHello(): String
    fun createIdentityBundle(): CreatedIdentityBundle
    fun identityIdHexFromSecretBlob(secretBlob: ByteArray): String
    fun devicePubkeyHexFromSecretBlob(secretBlob: ByteArray): String
    fun createSignedTextEvent(
        secretBlob: ByteArray,
        roomId: ByteArray,
        ciphertext: ByteArray,
        causalParentHexes: List<String> = emptyList(),
    ): SignedMessageEventWire
    fun createFoundingRoom(secretBlob: ByteArray, createdUnixSecs: ULong): FoundedRoom
    fun openLocalRoomSession(secretBlob: ByteArray, createdUnixSecs: ULong): LocalRoomHandle
    fun joinRoomFromInvite(secretBlob: ByteArray, inviteMaterialHex: String): LocalRoomHandle
    fun localRoomSessionFromStateBlob(
        secretBlob: ByteArray,
        stateBlob: ByteArray,
    ): LocalRoomHandle
    fun openMlsGroupSession(credentialLabel: String): MlsGroupHandle
    fun mlsSessionFromStateBlob(blob: ByteArray): MlsGroupHandle
}

/**
 * Prefer UniFFI native library; stub only when `.so` / JNA load fails.
 */
object RoomsCoreBridge : RoomsCore {
    @Volatile
    private var nativeLoaded = false

    @Volatile
    private var nativeUsable = false

    fun tryLoadNative(): Boolean {
        if (nativeLoaded) return nativeUsable
        nativeLoaded = true
        nativeUsable = try {
            // UniFFI Kotlin loads via JNA (`rooms_ffi`); also try System.loadLibrary
            // so packaging without JNA still surfaces a clear path.
            try {
                System.loadLibrary("rooms_ffi")
            } catch (_: UnsatisfiedLinkError) {
                // JNA may still locate the library from jniLibs / java.library.path.
            }
            // Touch a cheap UniFFI call to verify contract.
            val v = uniffi.rooms.protoDraftVersion()
            v.isNotEmpty()
        } catch (_: Throwable) {
            false
        }
        return nativeUsable
    }

    fun isNativeUsable(): Boolean = nativeUsable

    override fun protoDraftVersion(): String =
        if (tryLoadNative()) {
            uniffi.rooms.protoDraftVersion()
        } else {
            "0.1.0-stub"
        }

    override fun coreVersion(): String =
        if (tryLoadNative()) {
            uniffi.rooms.coreVersion()
        } else {
            "0.1.0-stub"
        }

    override fun identityHello(): String =
        if (tryLoadNative()) {
            uniffi.rooms.identityHello()
        } else {
            "rooms-identity; identity≠device; draft=${protoDraftVersion()}"
        }

    override fun createIdentityBundle(): CreatedIdentityBundle {
        if (tryLoadNative()) {
            val b = uniffi.rooms.createIdentityBundle()
            return CreatedIdentityBundle(
                CreatedIdentity(
                    identityIdHex = b.publicIdentity.identityIdHex,
                    deviceIdHex = b.publicIdentity.deviceIdHex,
                    masterPubkeyHex = b.publicIdentity.masterPubkeyHex,
                    devicePubkeyHex = b.publicIdentity.devicePubkeyHex,
                ),
                b.secretBlob,
            )
        }
        // Deterministic-looking placeholder ids for UI shell only.
        val id = "a".repeat(64)
        val device = "b".repeat(64)
        val master = "c".repeat(64)
        val devicePk = "d".repeat(64)
        val blob = ByteArray(1 + 32 + 32 + 4) { 0 }
        blob[0] = 1
        return CreatedIdentityBundle(
            CreatedIdentity(id, device, master, devicePk),
            blob,
        )
    }

    override fun identityIdHexFromSecretBlob(secretBlob: ByteArray): String {
        if (tryLoadNative()) {
            return uniffi.rooms.identityIdHexFromSecretBlob(secretBlob)
        }
        if (secretBlob.isEmpty()) return ""
        return "a".repeat(64)
    }

    override fun devicePubkeyHexFromSecretBlob(secretBlob: ByteArray): String {
        if (tryLoadNative()) {
            return uniffi.rooms.devicePubkeyHexFromSecretBlob(secretBlob)
        }
        if (secretBlob.isEmpty()) return ""
        return "d".repeat(64)
    }

    override fun createSignedTextEvent(
        secretBlob: ByteArray,
        roomId: ByteArray,
        ciphertext: ByteArray,
        causalParentHexes: List<String>,
    ): SignedMessageEventWire {
        if (tryLoadNative()) {
            val w = uniffi.rooms.createSignedTextEvent(
                secretBlob,
                roomId,
                ciphertext,
                causalParentHexes,
            )
            return SignedMessageEventWire(w.wireEnvelope, w.eventIdHex)
        }
        return SignedMessageEventWire(ByteArray(0), "")
    }

    override fun createFoundingRoom(secretBlob: ByteArray, createdUnixSecs: ULong): FoundedRoom {
        if (tryLoadNative()) {
            val f = uniffi.rooms.createFoundingRoom(secretBlob, createdUnixSecs)
            return FoundedRoom(
                roomIdHex = f.roomIdHex,
                creatorIdentityIdHex = f.creatorIdentityIdHex,
                activeMemberIdHexes = f.activeMemberIdHexes,
                activeMemberCount = f.activeMemberCount,
            )
        }
        return FoundedRoom(
            roomIdHex = "",
            creatorIdentityIdHex = "",
            activeMemberIdHexes = emptyList(),
            activeMemberCount = 0u,
        )
    }

    override fun openLocalRoomSession(
        secretBlob: ByteArray,
        createdUnixSecs: ULong,
    ): LocalRoomHandle {
        if (tryLoadNative()) {
            val session = uniffi.rooms.LocalRoomSession(secretBlob, createdUnixSecs)
            return wrapLocalRoom(session)
        }
        return emptyLocalRoom()
    }

    override fun joinRoomFromInvite(
        secretBlob: ByteArray,
        inviteMaterialHex: String,
    ): LocalRoomHandle {
        if (tryLoadNative()) {
            val session = uniffi.rooms.joinRoomFromInvite(secretBlob, inviteMaterialHex)
            return wrapLocalRoom(session)
        }
        return emptyLocalRoom()
    }

    override fun localRoomSessionFromStateBlob(
        secretBlob: ByteArray,
        stateBlob: ByteArray,
    ): LocalRoomHandle {
        if (tryLoadNative()) {
            return try {
                wrapLocalRoom(uniffi.rooms.localRoomSessionFromStateBlob(secretBlob, stateBlob))
            } catch (_: Throwable) {
                emptyLocalRoom()
            }
        }
        return emptyLocalRoom()
    }

    override fun openMlsGroupSession(credentialLabel: String): MlsGroupHandle {
        if (tryLoadNative()) {
            return try {
                wrapMls(uniffi.rooms.MlsGroupSession(credentialLabel))
            } catch (_: Throwable) {
                emptyMls()
            }
        }
        return emptyMls()
    }

    override fun mlsSessionFromStateBlob(blob: ByteArray): MlsGroupHandle {
        if (tryLoadNative()) {
            return try {
                wrapMls(uniffi.rooms.mlsSessionFromStateBlob(blob))
            } catch (_: Throwable) {
                emptyMls()
            }
        }
        return emptyMls()
    }

    private fun wrapMls(session: uniffi.rooms.MlsGroupSession): MlsGroupHandle =
        object : MlsGroupHandle {
            override fun isReady(): Boolean = session.isReady()
            override fun hasGroup(): Boolean = session.hasGroup()
            override fun credentialLabel(): String = session.credentialLabel()
            override fun exportKeyPackageHex(): String = session.exportKeyPackageHex()
            override fun createGroup(): String = session.createGroup()
            override fun groupIdHex(): String = session.groupIdHex()
            override fun epoch(): ULong = session.epoch()
            override fun memberCount(): UInt = session.memberCount()
            override fun maxMembers(): UInt = session.maxMembers()
            override fun addMemberKeyPackageHex(keyPackageHex: String): MlsAddResult {
                val r = session.addMemberKeyPackageHex(keyPackageHex)
                return MlsAddResult(
                    commitHex = r.commitHex,
                    welcomeHex = r.welcomeHex,
                    epoch = r.epoch,
                    memberCount = r.memberCount,
                    error = r.error,
                )
            }
            override fun joinFromWelcomeHex(welcomeHex: String): Boolean =
                session.joinFromWelcomeHex(welcomeHex)
            override fun processCommitHex(commitHex: String): Boolean =
                session.processCommitHex(commitHex)
            override fun sealText(plaintext: String): String = session.sealText(plaintext)
            override fun openMessageHex(messageHex: String): String =
                session.openMessageHex(messageHex)
            override fun removeMemberLabel(credentialLabel: String): String =
                session.removeMemberLabel(credentialLabel)
            override fun exportStateBlob(): ByteArray = session.exportStateBlob()
        }

    private fun emptyMls(): MlsGroupHandle =
        object : MlsGroupHandle {
            override fun isReady(): Boolean = false
            override fun hasGroup(): Boolean = false
            override fun credentialLabel(): String = ""
            override fun exportKeyPackageHex(): String = ""
            override fun createGroup(): String = ""
            override fun groupIdHex(): String = ""
            override fun epoch(): ULong = 0u
            override fun memberCount(): UInt = 0u
            override fun maxMembers(): UInt = 50u
            override fun addMemberKeyPackageHex(keyPackageHex: String): MlsAddResult =
                MlsAddResult("", "", 0u, 0u, "MLS UniFFI unavailable — rebuild FFI")
            override fun joinFromWelcomeHex(welcomeHex: String): Boolean = false
            override fun processCommitHex(commitHex: String): Boolean = false
            override fun sealText(plaintext: String): String = ""
            override fun openMessageHex(messageHex: String): String = ""
            override fun removeMemberLabel(credentialLabel: String): String = ""
            override fun exportStateBlob(): ByteArray = ByteArray(0)
        }

    private fun wrapLocalRoom(session: uniffi.rooms.LocalRoomSession): LocalRoomHandle =
        object : LocalRoomHandle {
            override fun roomIdHex(): String = session.roomIdHex()
            override fun creatorIdentityIdHex(): String = session.creatorIdentityIdHex()
            override fun activeMemberIdHexes(): List<String> = session.activeMemberIdHexes()
            override fun activeMemberCount(): UInt = session.activeMemberCount()
            override fun inviteTokenHex(inviteeIdentityIdHex: String): String =
                session.inviteTokenHex(inviteeIdentityIdHex)
            override fun inviteMaterialHex(inviteeIdentityIdHex: String): String =
                session.inviteMaterialHex(inviteeIdentityIdHex)
            override fun inviteMaterialWithWelcomeHex(
                inviteeIdentityIdHex: String,
                welcomeCidHex: String,
                commitCidHex: String,
            ): String {
                // Prefer regenerated UniFFI when present; else v1 invite material.
                invokeStringMethod(
                    session,
                    "inviteMaterialWithWelcomeHex",
                    arrayOf(String::class.java, String::class.java, String::class.java),
                    arrayOf(inviteeIdentityIdHex, welcomeCidHex, commitCidHex),
                )?.let { return it }
                return session.inviteMaterialHex(inviteeIdentityIdHex)
            }
            override fun welcomeCidHex(): String =
                invokeStringMethod(session, "welcomeCidHex", emptyArray(), emptyArray())
                    .orEmpty()
            override fun commitCidHex(): String =
                invokeStringMethod(session, "commitCidHex", emptyArray(), emptyArray())
                    .orEmpty()
            override fun membershipMutationHex(
                action: String,
                targetIdentityIdHex: String,
            ): String =
                invokeStringMethod(
                    session,
                    "membershipMutationHex",
                    arrayOf(String::class.java, String::class.java),
                    arrayOf(action, targetIdentityIdHex),
                ).orEmpty()
            override fun applyMembershipEventHex(eventHex: String): Boolean =
                invokeBooleanMethod(
                    session,
                    "applyMembershipEventHex",
                    arrayOf(String::class.java),
                    arrayOf(eventHex),
                ) ?: false
            override fun acceptReceiptHex(): String = session.acceptReceiptHex()
            override fun applyAcceptReceiptHex(receiptHex: String): Boolean =
                session.applyAcceptReceiptHex(receiptHex)
            override fun exportStateBlob(): ByteArray = session.exportStateBlob()
            override fun signTextEvent(
                ciphertext: ByteArray,
                causalParentHexes: List<String>,
            ): SignedMessageEventWire {
                val w = session.signTextEvent(ciphertext, causalParentHexes)
                return SignedMessageEventWire(w.wireEnvelope, w.eventIdHex)
            }
        }

    private fun emptyLocalRoom(): LocalRoomHandle =
        object : LocalRoomHandle {
            override fun roomIdHex(): String = ""
            override fun creatorIdentityIdHex(): String = ""
            override fun activeMemberIdHexes(): List<String> = emptyList()
            override fun activeMemberCount(): UInt = 0u
            override fun inviteTokenHex(inviteeIdentityIdHex: String): String = ""
            override fun inviteMaterialHex(inviteeIdentityIdHex: String): String = ""
            override fun inviteMaterialWithWelcomeHex(
                inviteeIdentityIdHex: String,
                welcomeCidHex: String,
                commitCidHex: String,
            ): String = ""
            override fun welcomeCidHex(): String = ""
            override fun commitCidHex(): String = ""
            override fun membershipMutationHex(
                action: String,
                targetIdentityIdHex: String,
            ): String = ""
            override fun applyMembershipEventHex(eventHex: String): Boolean = false
            override fun acceptReceiptHex(): String = ""
            override fun applyAcceptReceiptHex(receiptHex: String): Boolean = false
            override fun exportStateBlob(): ByteArray = ByteArray(0)
            override fun signTextEvent(
                ciphertext: ByteArray,
                causalParentHexes: List<String>,
            ): SignedMessageEventWire =
                SignedMessageEventWire(ByteArray(0), "")
        }

    /** Call a UniFFI method if bindings were regenerated; null if missing. */
    private fun invokeStringMethod(
        target: Any,
        name: String,
        paramTypes: Array<Class<*>>,
        args: Array<Any?>,
    ): String? {
        return try {
            val m = target.javaClass.getMethod(name, *paramTypes)
            m.invoke(target, *args) as? String
        } catch (_: Throwable) {
            null
        }
    }

    private fun invokeBooleanMethod(
        target: Any,
        name: String,
        paramTypes: Array<Class<*>>,
        args: Array<Any?>,
    ): Boolean? {
        return try {
            val m = target.javaClass.getMethod(name, *paramTypes)
            m.invoke(target, *args) as? Boolean
        } catch (_: Throwable) {
            null
        }
    }
}
