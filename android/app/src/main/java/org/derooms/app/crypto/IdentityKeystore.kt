package org.derooms.app.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Wraps the UniFFI `secret_blob` with AES-256-GCM using an AndroidKeyStore key
 * (API 26+, ADR-0002 / docs/android-keystore-plan.md).
 *
 * Never log [plaintext] or decrypted blob bytes.
 */
object IdentityKeystore {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "org.derooms.app.identity_wrap_v1"
    private const val CHAT_ALIAS = "org.derooms.app.chat_wrap_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val IV_BYTES = 12

    /** Ciphertext layout: version(1) || iv(12) || ciphertext+tag */
    private const val WRAP_VERSION: Byte = 1

    data class WrappedSecret(
        val blob: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean =
            other is WrappedSecret && blob.contentEquals(other.blob)

        override fun hashCode(): Int = blob.contentHashCode()
    }

    fun wrap(plaintext: ByteArray): WrappedSecret = wrapWithAlias(KEY_ALIAS, plaintext)

    fun unwrap(wrapped: WrappedSecret): ByteArray = unwrapWithAlias(KEY_ALIAS, wrapped)

    /** AES-GCM wrap for chat transcripts / inbox index. Plaintext lives in memory only. */
    fun wrapChat(plaintext: ByteArray): WrappedSecret = wrapWithAlias(CHAT_ALIAS, plaintext)

    fun unwrapChat(wrapped: WrappedSecret): ByteArray = unwrapWithAlias(CHAT_ALIAS, wrapped)

    private fun wrapWithAlias(alias: String, plaintext: ByteArray): WrappedSecret {
        val key = getOrCreateKey(alias)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        require(iv.size == IV_BYTES) { "unexpected GCM IV length ${iv.size}" }
        val ct = cipher.doFinal(plaintext)
        val out = ByteArray(1 + iv.size + ct.size)
        out[0] = WRAP_VERSION
        System.arraycopy(iv, 0, out, 1, iv.size)
        System.arraycopy(ct, 0, out, 1 + iv.size, ct.size)
        return WrappedSecret(out)
    }

    private fun unwrapWithAlias(alias: String, wrapped: WrappedSecret): ByteArray {
        val bytes = wrapped.blob
        require(bytes.isNotEmpty() && bytes[0] == WRAP_VERSION) {
            "unsupported wrap version"
        }
        require(bytes.size > 1 + IV_BYTES) { "truncated wrap blob" }
        val iv = bytes.copyOfRange(1, 1 + IV_BYTES)
        val ct = bytes.copyOfRange(1 + IV_BYTES, bytes.size)
        val key = getOrCreateKey(alias)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ct)
    }

    private fun getOrCreateKey(alias: String): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        if (existing != null) {
            return existing.secretKey
        }
        val keyGen = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE,
        )
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()
        keyGen.init(spec)
        return keyGen.generateKey()
    }
}
