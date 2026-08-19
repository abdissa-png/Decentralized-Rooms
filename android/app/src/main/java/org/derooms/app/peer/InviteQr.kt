package org.derooms.app.peer

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.encoder.Encoder

/**
 * QR encoding for invite URIs. Uses ZXing only (no custom crypto).
 *
 * Phone-readable cap: ZXing Version 15 at ECC L holds [PHONE_QR_MAX_BYTES]
 * byte-mode codewords — dense Version 40 symbols encode but typical Android
 * cameras fail at ~6–8 cm. [bitmap] still attempts encode up to Version 40
 * (handshake Kyber QR); callers should prefer URIs under the cap.
 */
object InviteQr {
    const val PHONE_QR_MAX_BYTES = PeerInviteUri.PHONE_QR_MAX_BYTES
    const val PHONE_QR_MAX_VERSION = 15

    fun fitsPhoneCamera(contents: String): Boolean =
        contents.toByteArray(Charsets.UTF_8).size <= PHONE_QR_MAX_BYTES

    /** Actual ZXing version that would be chosen (ECC L), or null if unencodable. */
    fun qrVersion(contents: String): Int? {
        if (contents.isBlank()) return null
        return try {
            val hints = hashMapOf<EncodeHintType, Any>(
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
                EncodeHintType.CHARACTER_SET to "UTF-8",
            )
            Encoder.encode(contents, ErrorCorrectionLevel.L, hints).version.versionNumber
        } catch (_: Exception) {
            null
        }
    }

    fun bitmap(contents: String, size: Int = 512): Bitmap? {
        if (contents.isBlank()) return null
        return try {
            val hints = hashMapOf<EncodeHintType, Any>(
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
                EncodeHintType.MARGIN to 1,
                EncodeHintType.CHARACTER_SET to "UTF-8",
            )
            val matrix = QRCodeWriter().encode(contents, BarcodeFormat.QR_CODE, size, size, hints)
            val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
            for (x in 0 until size) {
                for (y in 0 until size) {
                    bmp.setPixel(x, y, if (matrix.get(x, y)) Color.BLACK else Color.WHITE)
                }
            }
            bmp
        } catch (_: Exception) {
            null
        }
    }
}
