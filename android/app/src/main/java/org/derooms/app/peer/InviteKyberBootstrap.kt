package org.derooms.app.peer

import android.util.Log
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Handshake socket on `syncTcpPort + [PORT_OFFSET]`.
 *
 * Compact QR omits the Kyber-1024 pk (too large). The scanner fetches it here
 * and **uploads their own full invite** so the listener can establish a Signal
 * session without a second QR. Kyber pk is public; the QR hash-binds it.
 *
 * DRKY1: kyber blob only (tests / old clients).
 * DRKY2: offer (scanner invite) then kyber blob. Listener applies offer
 * **before** responding so the scanner does not send into a void.
 */
class InviteKyberBootstrap(
    bindPort: Int,
    private val blob: ByteArray,
    private val onOffer: ((ByteArray) -> String?)? = null,
) {
    private val running = AtomicBoolean(false)
    private var server: ServerSocket? = null
    private var thread: Thread? = null
    private val lastOffer = AtomicReference<ByteArray?>(null)

    @Volatile
    var port: Int = bindPort
        private set

    fun lastOffer(): ByteArray? = lastOffer.get()

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val ss = ServerSocket(port, 8, InetAddress.getByName("0.0.0.0")).also { server = it }
        port = ss.localPort
        thread = Thread({
            while (running.get()) {
                try {
                    ss.accept().use { sock ->
                        sock.soTimeout = 8_000
                        serve(sock)
                    }
                } catch (_: Exception) {
                    if (!running.get()) break
                }
            }
        }, "derooms-kyber-boot").also {
            it.isDaemon = true
            it.start()
        }
        try {
            Log.i(TAG, "kyber bootstrap listen :$port bytes=${blob.size}")
        } catch (_: RuntimeException) {
            // android.util.Log is not mocked in JVM unit tests.
        }
    }

    fun stop() {
        running.set(false)
        try {
            server?.close()
        } catch (_: Exception) {
        }
        server = null
        thread = null
    }

    private fun serve(sock: Socket) {
        val input = DataInputStream(sock.getInputStream())
        val magic = ByteArray(5)
        input.readFully(magic)
        val v2 = magic.contentEquals(REQ_MAGIC_V2)
        if (!v2 && !magic.contentEquals(REQ_MAGIC)) return
        if (v2) {
            val offerLen = input.readInt()
            if (offerLen !in 1..MAX_OFFER) return
            val offer = ByteArray(offerLen).also { input.readFully(it) }
            lastOffer.set(offer)
            val err = onOffer?.invoke(offer)
            if (err != null) {
                val out = DataOutputStream(sock.getOutputStream())
                out.write(REQ_MAGIC_V2)
                out.writeInt(-1)
                val msg = err.toByteArray(Charsets.UTF_8)
                out.writeInt(msg.size)
                out.write(msg)
                out.flush()
                return
            }
        }
        val out = DataOutputStream(sock.getOutputStream())
        out.write(if (v2) REQ_MAGIC_V2 else REQ_MAGIC)
        out.writeInt(blob.size)
        out.write(blob)
        out.flush()
    }

    companion object {
        private const val TAG = "DEROOMS_KYBER"
        const val PORT_OFFSET = 1
        const val MAX_OFFER = 16_384
        val REQ_MAGIC: ByteArray = "DRKY1".toByteArray(Charsets.US_ASCII)
        val REQ_MAGIC_V2: ByteArray = "DRKY2".toByteArray(Charsets.US_ASCII)

        fun fetch(
            host: String,
            port: Int,
            timeoutMs: Int = 8_000,
            offer: ByteArray? = null,
        ): ByteArray? {
            return try {
                Socket().use { sock ->
                    sock.soTimeout = timeoutMs
                    sock.connect(
                        java.net.InetSocketAddress(host, port),
                        timeoutMs.coerceAtMost(5_000),
                    )
                    val out = DataOutputStream(sock.getOutputStream())
                    val input = DataInputStream(sock.getInputStream())
                    if (offer != null && offer.isNotEmpty()) {
                        out.write(REQ_MAGIC_V2)
                        out.writeInt(offer.size)
                        out.write(offer)
                        out.flush()
                        val magic = ByteArray(5)
                        input.readFully(magic)
                        if (!magic.contentEquals(REQ_MAGIC_V2)) return null
                        val len = input.readInt()
                        if (len < 0) return null
                        if (len !in 64..8_192) return null
                        ByteArray(len).also { input.readFully(it) }
                    } else {
                        out.write(REQ_MAGIC)
                        out.flush()
                        val magic = ByteArray(5)
                        input.readFully(magic)
                        if (!magic.contentEquals(REQ_MAGIC)) return null
                        val len = input.readInt()
                        if (len !in 64..8_192) return null
                        ByteArray(len).also { input.readFully(it) }
                    }
                }
            } catch (_: Exception) {
                null
            }
        }
    }
}
