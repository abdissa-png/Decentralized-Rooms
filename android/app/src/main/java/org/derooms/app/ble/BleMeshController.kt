package org.derooms.app.ble

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import androidx.core.content.ContextCompat
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * BLE proximity mesh (text-first, Briar-inspired at high level):
 * - Advertise/scan with **rotating ephemeral IDs** (not long-term identity)
 * - GATT transfer of **already-sealed** payloads only (text-first, ≤4 KiB sealed)
 * - Store-and-forward carrier: hold sealed frames and ferry when peers nearby
 *
 * Advertise carries ephemeral id in manufacturer data; sealed objects move over
 * a connectable GATT characteristic (chunked when ATT MTU is small).
 *
 * See `docs/ble-mesh.md` for OEM / airplane-mode limits.
 */
class BleMeshController(
    private val context: Context,
    private val onStatus: (String) -> Unit,
    private val onPeerSeen: (ephemeralIdHex: String) -> Unit,
    private val onSealedDelivered: (sealed: ByteArray) -> Unit = {},
) {
    private val executor = Executors.newSingleThreadScheduledExecutor()
    private val random = SecureRandom()
    private val ephemeralId = AtomicReference(ByteArray(EPHEMERAL_LEN).also { random.nextBytes(it) })
    private val outboundQueue = ConcurrentLinkedQueue<ByteArray>()
    private val carrierQueue = ConcurrentLinkedQueue<ByteArray>()
    private var rotateFuture: ScheduledFuture<*>? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var scanner: BluetoothLeScanner? = null
    private var gattServer: BluetoothGattServer? = null
    private var bluetoothManager: BluetoothManager? = null
    private var advertising = false
    private var scanning = false
    private val seenPeers = ConcurrentHashMap.newKeySet<String>()
    private val handedOffPeers = ConcurrentHashMap.newKeySet<String>()
    private val connecting = AtomicBoolean(false)
    private val activeClientGatt = AtomicReference<BluetoothGatt?>(null)
    private val serverChunkBuf = AtomicReference<ChunkAssembler?>(null)
    private val lastSeenDevice = AtomicReference<BluetoothDevice?>(null)
    private val lastSeenPeerId = AtomicReference<String?>(null)
    private val ownEphemeralHex = ConcurrentHashMap.newKeySet<String>()
    private val meshActive = AtomicBoolean(false)
    private var handoffRetryFuture: ScheduledFuture<*>? = null

    fun isActive(): Boolean = meshActive.get()
    fun peersSeenCount(): Int = seenPeers.size
    fun hasPendingOutbound(): Boolean = outboundQueue.isNotEmpty()

    fun hasBlePermissions(): Boolean {
        return if (Build.VERSION.SDK_INT >= 31) {
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_ADVERTISE) ==
                PackageManager.PERMISSION_GRANTED &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) ==
                PackageManager.PERMISSION_GRANTED &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) ==
                PackageManager.PERMISSION_GRANTED
        } else {
            // API ≤30: BLE scan legally requires location permission (+ location services on).
            ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
                PackageManager.PERMISSION_GRANTED
        }
    }

    /** Queue an already-sealed payload (MLS / libsignal ciphertext). Max [MAX_SEALED] B. */
    fun queueSealedPayload(sealed: ByteArray) {
        if (sealed.size > MAX_SEALED) {
            onStatus("BLE payload too large (max $MAX_SEALED B). Keep the message short.")
            return
        }
        if (!POLICY_TEXT_FIRST) {
            onStatus("BLE path requires text-first Low policy.")
            return
        }
        if (!meshActive.get()) {
            onStatus("BLE not started — tap Start BLE first (grant Location on Android 11 and older).")
            return
        }
        outboundQueue.offer(sealed.copyOf())
        persistCarrierOutbox(sealed)
        refreshServerCharacteristicValue()
        val peers = seenPeers.size
        onStatus(
            if (peers == 0) {
                "Queued ${sealed.size} B — waiting for peer BLE (both phones: Start BLE, stay close)."
            } else {
                "Queued ${sealed.size} B — connecting to $peers seen peer(s)…"
            },
        )
        Log.i(TAG, "E2E_BLE_QUEUED bytes=${sealed.size}")
        // New payload: allow another GATT write to the same radio (MAC),
        // not a new ephemeral id.
        handedOffPeers.clear()
        kickHandoffNow()
        scheduleHandoffRetries()
    }

    private fun kickHandoffNow() {
        val device = lastSeenDevice.get() ?: return
        val peerId = stablePeerKey(device.address) ?: lastSeenPeerId.get() ?: return
        handedOffPeers.remove(peerId)
        maybeGattHandoff(device, peerId)
    }

    private fun scheduleHandoffRetries() {
        handoffRetryFuture?.cancel(false)
        handoffRetryFuture = executor.scheduleAtFixedRate(
            {
                if (!meshActive.get() || outboundQueue.isEmpty()) {
                    handoffRetryFuture?.cancel(false)
                    handoffRetryFuture = null
                    return@scheduleAtFixedRate
                }
                kickHandoffNow()
            },
            2,
            3,
            TimeUnit.SECONDS,
        )
    }

    /** Pending sealed frames held for store-and-forward (not decrypted). */
    fun carrierPendingCount(): Int = carrierQueue.size + outboundQueue.size

    @SuppressLint("MissingPermission")
    fun start() {
        if (!hasBlePermissions()) {
            onStatus("BLE permissions missing — grant Nearby devices (API 31+) or location.")
            return
        }
        val mgr = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = mgr?.adapter
        bluetoothManager = mgr
        if (adapter == null) {
            onStatus("No Bluetooth adapter.")
            return
        }
        val enabled = try {
            adapter.isEnabled
        } catch (_: SecurityException) {
            // API 31+ without CONNECT can throw; fall through and probe LE APIs.
            true
        }
        advertiser = adapter.bluetoothLeAdvertiser
        scanner = adapter.bluetoothLeScanner
        if (!enabled && advertiser == null && scanner == null) {
            onStatus("Bluetooth off. Some OEMs disable BLE in airplane mode even when BT is on.")
            Log.w(TAG, "E2E_BLE_BT_OFF enabled=$enabled")
            return
        }
        if (advertiser == null || scanner == null) {
            onStatus("BLE advertiser/scanner unavailable (enabled=$enabled).")
            Log.w(TAG, "E2E_BLE_LE_UNAVAILABLE enabled=$enabled")
            return
        }
        if (!enabled) {
            // Some OEM builds report isEnabled=false while LE APIs still work.
            Log.w(TAG, "E2E_BLE_BT_STATE_FLAKY proceeding with LE APIs")
            onStatus("BT state flaky — trying BLE anyway.")
        }
        startGattServer(mgr)
        advertising = true
        scanning = true
        meshActive.set(true)
        rememberOwnEphemeral(ephemeralId.get())
        rotateFuture = executor.scheduleAtFixedRate(
            { rotateEphemeralAndAdvertise() },
            ROTATE_SECS,
            ROTATE_SECS,
            TimeUnit.SECONDS,
        )
        restartAdvertise()
        startScan()
        onStatus(
            "BLE mesh active — keep both phones on Start BLE, Location ON (Android ≤11), phones close.",
        )
        Log.i(TAG, "E2E_BLE_START_OK")
        if (outboundQueue.isNotEmpty()) {
            scheduleHandoffRetries()
        }
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        advertising = false
        scanning = false
        meshActive.set(false)
        rotateFuture?.cancel(false)
        rotateFuture = null
        handoffRetryFuture?.cancel(false)
        handoffRetryFuture = null
        stopAdvertise()
        stopScan()
        try {
            activeClientGatt.getAndSet(null)?.close()
        } catch (_: Exception) {
        }
        try {
            gattServer?.close()
        } catch (_: Exception) {
        }
        gattServer = null
        connecting.set(false)
        onStatus("BLE mesh stopped.")
        Log.i(TAG, "E2E_BLE_STOP")
    }

    /** Lab/helper: pull peer sealed from shared carrier path if present. */
    fun tryDeliverFromCarrierInbox() {
        val inbox = File(carrierDir(), "inbox.bin")
        if (!inbox.exists()) return
        val bytes = inbox.readBytes()
        val decoded = decodeFrame(bytes) ?: return
        if (decoded.second.isNotEmpty()) {
            deliverSealed(decoded.second, via = "carrier_inbox")
            inbox.delete()
        }
    }

    private fun carrierDir(): File = File(context.filesDir, "ble_carrier")

    private fun persistCarrierOutbox(sealed: ByteArray) {
        carrierDir().mkdirs()
        File(carrierDir(), "outbox.bin").writeBytes(encodeFrame(ephemeralId.get(), sealed))
        // Store-and-forward: keep a copy in the carrier FIFO (Low budget).
        while (carrierQueue.size >= CARRIER_MAX) {
            carrierQueue.poll()
        }
        carrierQueue.offer(sealed.copyOf())
    }

    private fun rotateEphemeralAndAdvertise() {
        val id = ByteArray(EPHEMERAL_LEN)
        random.nextBytes(id)
        ephemeralId.set(id)
        rememberOwnEphemeral(id)
        // Do not clear handedOffPeers — a rotated advertiser id is still the
        // same radio. Clearing caused a new GATT write of the first PreKey.
        restartAdvertise()
        refreshServerCharacteristicValue()
    }

    private fun rememberOwnEphemeral(id: ByteArray) {
        ownEphemeralHex.add(id.joinToString("") { b -> "%02x".format(b) })
    }

    @SuppressLint("MissingPermission")
    private fun startGattServer(mgr: BluetoothManager) {
        try {
            gattServer?.close()
        } catch (_: Exception) {
        }
        val server = mgr.openGattServer(context, gattServerCallback) ?: run {
            onStatus("GATT server unavailable.")
            return
        }
        gattServer = server
        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val charProps = BluetoothGattCharacteristic.PROPERTY_READ or
            BluetoothGattCharacteristic.PROPERTY_WRITE or
            BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or
            BluetoothGattCharacteristic.PROPERTY_NOTIFY
        val charPerms = BluetoothGattCharacteristic.PERMISSION_READ or
            BluetoothGattCharacteristic.PERMISSION_WRITE
        val characteristic = BluetoothGattCharacteristic(CHAR_UUID, charProps, charPerms)
        service.addCharacteristic(characteristic)
        server.addService(service)
        refreshServerCharacteristicValue()
    }

    @SuppressLint("MissingPermission")
    private fun refreshServerCharacteristicValue() {
        val server = gattServer ?: return
        val service = server.getService(SERVICE_UUID) ?: return
        val ch = service.getCharacteristic(CHAR_UUID) ?: return
        val sealed = outboundQueue.peek()
        if (sealed != null) {
            ch.value = encodeFrame(ephemeralId.get(), sealed)
        } else {
            ch.value = ByteArray(0)
        }
    }

    @SuppressLint("MissingPermission")
    private fun restartAdvertise() {
        if (!advertising) return
        stopAdvertise()
        val adv = advertiser ?: return
        val id = ephemeralId.get()
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .build()
        // Keep primary AD under 31 B: manufacturer ephemeral only.
        // 128-bit service UUID goes in scan response (else ADVERTISE_FAILED_DATA_TOO_LARGE).
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addManufacturerData(MANUFACTURER_ID, id)
            .build()
        val scanResponse = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()
        try {
            adv.startAdvertising(settings, data, scanResponse, advertiseCallback)
        } catch (e: Exception) {
            onStatus("Advertise failed: ${e.message}")
        }
    }

    @SuppressLint("MissingPermission")
    private fun stopAdvertise() {
        try {
            advertiser?.stopAdvertising(advertiseCallback)
        } catch (_: Exception) {
        }
    }

    @SuppressLint("MissingPermission")
    private fun startScan() {
        val sc = scanner ?: return
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setReportDelay(0)
            .build()
        try {
            sc.startScan(null, settings, scanCallback)
            Log.i(TAG, "E2E_BLE_SCAN_OK")
        } catch (e: Exception) {
            onStatus("Scan failed: ${e.message}")
            Log.w(TAG, "E2E_BLE_SCAN_FAIL ${e.message}")
        }
    }

    @SuppressLint("MissingPermission")
    private fun stopScan() {
        try {
            scanner?.stopScan(scanCallback)
        } catch (_: Exception) {
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.i(TAG, "E2E_BLE_ADVERTISE_OK")
        }

        override fun onStartFailure(errorCode: Int) {
            val why = when (errorCode) {
                ADVERTISE_FAILED_DATA_TOO_LARGE -> "DATA_TOO_LARGE"
                ADVERTISE_FAILED_TOO_MANY_ADVERTISERS -> "TOO_MANY"
                ADVERTISE_FAILED_ALREADY_STARTED -> "ALREADY_STARTED"
                ADVERTISE_FAILED_INTERNAL_ERROR -> "INTERNAL"
                ADVERTISE_FAILED_FEATURE_UNSUPPORTED -> "UNSUPPORTED"
                else -> "code=$errorCode"
            }
            onStatus("BLE advertise error $why")
            Log.w(TAG, "E2E_BLE_ADVERTISE_FAIL $why")
        }
    }

    private val scanCallback = object : ScanCallback() {
        @SuppressLint("MissingPermission")
        override fun onScanResult(callbackType: Int, result: ScanResult?) {
            val record = result?.scanRecord ?: return
            val device = result.device ?: return
            val mfg = record.getManufacturerSpecificData(MANUFACTURER_ID) ?: return
            if (mfg.size < EPHEMERAL_LEN) return
            // Manufacturer ephemeral is authoritative. Do not drop when OEM scan records
            // list unrelated service UUIDs without ours (common when UUID is scan-response only).
            val idHex = mfg.copyOf(EPHEMERAL_LEN).joinToString("") { b -> "%02x".format(b) }
            lastSeenDevice.set(device)
            val stable = stablePeerKey(device.address) ?: STABLE_UNKNOWN
            lastSeenPeerId.set(stable)
            if (seenPeers.add(stable)) {
                onPeerSeen(stable)
                onStatus("Peer nearby (BLE).")
                Log.i(TAG, "E2E_BLE_PEER_SEEN addr=${stable.take(17)} id=${idHex.take(16)}")
            }
            maybeGattHandoff(device, stable)
        }

        override fun onScanFailed(errorCode: Int) {
            Log.w(TAG, "scan failed $errorCode")
        }
    }

    @SuppressLint("MissingPermission")
    private fun maybeGattHandoff(device: BluetoothDevice, peerIdHex: String) {
        val hasOut = outboundQueue.isNotEmpty()
        if (!hasOut) return
        if (!handedOffPeers.add(peerIdHex)) return
        if (!connecting.compareAndSet(false, true)) return
        // connectGatt is more reliable from the main looper on many OEMs.
        android.os.Handler(android.os.Looper.getMainLooper()).post {
            try {
                onStatus("GATT connect → ${peerIdHex.take(12)}…")
                Log.i(TAG, "E2E_BLE_GATT_CONNECTING id=${peerIdHex.take(16)}")
                val gatt = if (Build.VERSION.SDK_INT >= 23) {
                    device.connectGatt(context, false, clientCallback, BluetoothDevice.TRANSPORT_LE)
                } else {
                    @Suppress("DEPRECATION")
                    device.connectGatt(context, false, clientCallback)
                }
                if (gatt == null) {
                    connecting.set(false)
                    handedOffPeers.remove(peerIdHex)
                    onStatus("GATT connect returned null.")
                    Log.w(TAG, "E2E_BLE_GATT_CONNECT_NULL")
                    return@post
                }
                activeClientGatt.set(gatt)
            } catch (e: Exception) {
                connecting.set(false)
                handedOffPeers.remove(peerIdHex)
                onStatus("GATT connect failed: ${e.message}")
                Log.w(TAG, "E2E_BLE_GATT_CONNECT_FAIL ${e.message}")
            }
        }
    }

    private val clientCallback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS) {
                Log.i(TAG, "E2E_BLE_GATT_CONNECTED")
                if (Build.VERSION.SDK_INT >= 21) {
                    gatt.requestMtu(517)
                } else {
                    gatt.discoverServices()
                }
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                try {
                    gatt.close()
                } catch (_: Exception) {
                }
                activeClientGatt.compareAndSet(gatt, null)
                connecting.set(false)
                // Allow retry while outbound still pending.
                if (outboundQueue.isNotEmpty()) {
                    lastSeenPeerId.get()?.let { handedOffPeers.remove(it) }
                }
            } else if (status != BluetoothGatt.GATT_SUCCESS) {
                try {
                    gatt.close()
                } catch (_: Exception) {
                }
                connecting.set(false)
                if (outboundQueue.isNotEmpty()) {
                    lastSeenPeerId.get()?.let { handedOffPeers.remove(it) }
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            gatt.discoverServices()
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                gatt.disconnect()
                return
            }
            val ch = gatt.getService(SERVICE_UUID)?.getCharacteristic(CHAR_UUID)
            if (ch == null) {
                onStatus("GATT: sealed characteristic missing.")
                gatt.disconnect()
                return
            }
            // Only write our outbound queue. Do not ferry received carrier
            // copies — that resent the first PreKey after ephemeral rotate.
            val sealed = outboundQueue.peek()
            if (sealed == null) {
                // Still try to read peer pending.
                gatt.readCharacteristic(ch)
                return
            }
            val frame = encodeFrame(ephemeralId.get(), sealed)
            writeFrameChunked(gatt, ch, frame)
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            val writer = characteristic.writeType
            if (status == BluetoothGatt.GATT_SUCCESS) {
                val pending = clientWriteQueue.poll()
                if (pending != null) {
                    characteristic.value = pending
                    characteristic.writeType = writer
                    gatt.writeCharacteristic(characteristic)
                    return
                }
                outboundQueue.poll()
                refreshServerCharacteristicValue()
                val next = outboundQueue.peek()
                if (next != null) {
                    val frame = encodeFrame(ephemeralId.get(), next)
                    writeFrameChunked(gatt, characteristic, frame)
                    return
                }
                handoffRetryFuture?.cancel(false)
                handoffRetryFuture = null
                Log.i(TAG, "E2E_BLE_SEND_OK")
                onStatus("BLE GATT sealed send OK.")
                // Read peer's pending sealed (bidirectional handoff).
                gatt.readCharacteristic(characteristic)
            } else {
                Log.w(TAG, "E2E_BLE_SEND_FAIL status=$status")
                onStatus("BLE GATT write failed status=$status")
                gatt.disconnect()
            }
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                val value = characteristic.value
                if (value != null && value.isNotEmpty()) {
                    handleIncomingFrame(value, via = "gatt_read")
                }
            }
            gatt.disconnect()
        }
    }

    private val clientWriteQueue = ConcurrentLinkedQueue<ByteArray>()

    @SuppressLint("MissingPermission")
    private fun writeFrameChunked(
        gatt: BluetoothGatt,
        ch: BluetoothGattCharacteristic,
        frame: ByteArray,
    ) {
        clientWriteQueue.clear()
        // ATT payload ≈ MTU-3; conservative 180 B chunks after MTU request.
        // WRITE_TYPE_DEFAULT so onCharacteristicWrite fires for multi-chunk
        // (NO_RESPONSE often never callbacks → stuck after chunk 0).
        val writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        val chunkSize = 180
        if (frame.size <= chunkSize) {
            ch.value = frame
            ch.writeType = writeType
            if (!gatt.writeCharacteristic(ch)) {
                Log.w(TAG, "E2E_BLE_SEND_FAIL writeCharacteristic=false")
                onStatus("BLE write failed to start.")
                gatt.disconnect()
            }
            // Completion + SEND_OK happen in onCharacteristicWrite.
            return
        }
        val total = ((frame.size + chunkSize - 1) / chunkSize).coerceAtMost(255)
        for (seq in 0 until total) {
            val start = seq * chunkSize
            val end = minOf(start + chunkSize, frame.size)
            val chunk = ByteArray(4 + (end - start))
            chunk[0] = CHUNK_MAGIC0
            chunk[1] = CHUNK_MAGIC1
            chunk[2] = seq.toByte()
            chunk[3] = total.toByte()
            System.arraycopy(frame, start, chunk, 4, end - start)
            if (seq == 0) {
                ch.value = chunk
                ch.writeType = writeType
            } else {
                clientWriteQueue.offer(chunk)
            }
        }
        if (!gatt.writeCharacteristic(ch)) {
            Log.w(TAG, "E2E_BLE_SEND_FAIL writeCharacteristic=false")
            onStatus("BLE chunked write failed to start.")
            gatt.disconnect()
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                Log.i(TAG, "E2E_BLE_SERVER_CONNECTED")
            }
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic,
        ) {
            val server = gattServer ?: return
            val value = characteristic.value ?: ByteArray(0)
            val slice = if (offset >= value.size) {
                ByteArray(0)
            } else {
                value.copyOfRange(offset, value.size)
            }
            server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?,
        ) {
            val server = gattServer ?: return
            if (value != null) {
                handleServerWrite(value)
            }
            if (responseNeeded) {
                server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
            }
        }
    }

    private fun handleServerWrite(value: ByteArray) {
        if (value.size >= 4 && value[0] == CHUNK_MAGIC0 && value[1] == CHUNK_MAGIC1) {
            val seq = value[2].toInt() and 0xff
            val total = value[3].toInt() and 0xff
            val payload = value.copyOfRange(4, value.size)
            var asm = serverChunkBuf.get()
            if (asm == null || asm.total != total) {
                asm = ChunkAssembler(total)
                serverChunkBuf.set(asm)
            }
            asm.add(seq, payload)
            if (asm.isComplete()) {
                serverChunkBuf.set(null)
                handleIncomingFrame(asm.join(), via = "gatt_write_chunked")
            }
            return
        }
        handleIncomingFrame(value, via = "gatt_write")
    }

    private fun handleIncomingFrame(bytes: ByteArray, via: String) {
        val decoded = decodeFrame(bytes) ?: run {
            Log.w(TAG, "E2E_BLE_BAD_FRAME via=$via len=${bytes.size}")
            return
        }
        val advertiserHex = decoded.first.joinToString("") { b -> "%02x".format(b) }
        if (ownEphemeralHex.contains(advertiserHex) ||
            decoded.first.contentEquals(ephemeralId.get())
        ) {
            Log.i(TAG, "E2E_BLE_OWN_FRAME via=$via")
            return
        }
        val sealed = decoded.second
        if (sealed.isEmpty()) return
        deliverSealed(sealed, via)
        // Store-and-forward: keep a copy for other nearby peers (carrier).
        while (carrierQueue.size >= CARRIER_MAX) {
            carrierQueue.poll()
        }
        carrierQueue.offer(sealed.copyOf())
        carrierDir().mkdirs()
        File(carrierDir(), "inbox.bin").writeBytes(bytes)
    }

    private fun deliverSealed(sealed: ByteArray, via: String) {
        Log.i(TAG, "E2E_BLE_RECV_OK via=$via bytes=${sealed.size}")
        onStatus("BLE sealed recv ${sealed.size} B ($via)")
        onSealedDelivered(sealed)
    }

    private class ChunkAssembler(val total: Int) {
        private val parts = arrayOfNulls<ByteArray>(total)
        private var count = 0

        fun add(seq: Int, data: ByteArray) {
            if (seq < 0 || seq >= total) return
            if (parts[seq] == null) {
                parts[seq] = data
                count++
            }
        }

        fun isComplete(): Boolean = count == total

        fun join(): ByteArray {
            val size = parts.sumOf { it?.size ?: 0 }
            val out = ByteArray(size)
            var o = 0
            for (p in parts) {
                val chunk = p ?: continue
                System.arraycopy(chunk, 0, out, o, chunk.size)
                o += chunk.size
            }
            return out
        }
    }

    companion object {
        const val TAG = "DEROOMS_BLE"
        val SERVICE_UUID: UUID = UUID.fromString("6b1d8f20-0c1a-4b7e-9f11-d00000000001")
        val CHAR_UUID: UUID = UUID.fromString("6b1d8f20-0c1a-4b7e-9f11-d00000000002")
        const val MANUFACTURER_ID = 0x0D30
        const val EPHEMERAL_LEN = 16
        /** libsignal sealed text is often 1–2 KiB; keep headroom under ATT chunking. */
        const val MAX_SEALED = 4096
        const val ROTATE_SECS = 30L
        /** Matches rooms-sync Low max_have_objects. */
        const val CARRIER_MAX = 32
        const val POLICY_TEXT_FIRST = true
        /** Fallback when the scan record has no usable Bluetooth address. */
        const val STABLE_UNKNOWN = "le-nearby"

        /**
         * Count / handoff key for a nearby radio. Prefer the Bluetooth address so
         * rotating advertisement ids do not look like a new peer.
         */
        fun stablePeerKey(address: String?): String? {
            val a = address?.trim()?.uppercase().orEmpty()
            if (a.isEmpty()) return null
            if (a == "00:00:00:00:00:00" || a == "02:00:00:00:00:00") return null
            return a
        }
        private val MAGIC = byteArrayOf(0x44, 0x52, 0x42, 0x4D) // DRBM
        private const val CHUNK_MAGIC0: Byte = 0x43 // 'C'
        private const val CHUNK_MAGIC1: Byte = 0x4B // 'K'

        fun encodeFrame(ephemeralId: ByteArray, sealed: ByteArray): ByteArray {
            require(ephemeralId.size == EPHEMERAL_LEN)
            val out = ByteArray(4 + 1 + EPHEMERAL_LEN + 2 + sealed.size)
            System.arraycopy(MAGIC, 0, out, 0, 4)
            out[4] = 1
            System.arraycopy(ephemeralId, 0, out, 5, EPHEMERAL_LEN)
            val len = sealed.size
            out[5 + EPHEMERAL_LEN] = (len and 0xff).toByte()
            out[5 + EPHEMERAL_LEN + 1] = ((len shr 8) and 0xff).toByte()
            System.arraycopy(sealed, 0, out, 5 + EPHEMERAL_LEN + 2, sealed.size)
            return out
        }

        fun decodeFrame(bytes: ByteArray): Pair<ByteArray, ByteArray>? {
            if (bytes.size < 4 + 1 + EPHEMERAL_LEN + 2) return null
            if (bytes[0] != MAGIC[0] || bytes[1] != MAGIC[1] ||
                bytes[2] != MAGIC[2] || bytes[3] != MAGIC[3]
            ) {
                return null
            }
            if (bytes[4].toInt() != 1) return null
            val id = bytes.copyOfRange(5, 5 + EPHEMERAL_LEN)
            val len = (bytes[5 + EPHEMERAL_LEN].toInt() and 0xff) or
                ((bytes[5 + EPHEMERAL_LEN + 1].toInt() and 0xff) shl 8)
            val start = 5 + EPHEMERAL_LEN + 2
            if (len < 0 || len > MAX_SEALED || start + len > bytes.size) return null
            return id to bytes.copyOfRange(start, start + len)
        }

        /** Stable tip label for carrier FIFO (not a crypto commitment). */
        fun tipHexForSealed(sealed: ByteArray): String {
            val dig = MessageDigest.getInstance("SHA-256").digest(sealed)
            return dig.take(8).joinToString("") { "%02x".format(it) }
        }
    }
}
