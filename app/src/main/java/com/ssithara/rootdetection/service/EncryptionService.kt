package com.ssithara.rootdetection.service

import android.util.Base64
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object EncryptionService {

    @Throws(Exception::class)
    private fun decrypt(data: ByteArray, keyBytes: ByteArray): String {
        require(keyBytes.size == 32) { "Key must be 32 bytes (256 bits)" }
        require(data.size > 12) { "Invalid input: data too short to contain IV + ciphertext" }

        val iv = data.copyOfRange(0, 12)
        val cipherTextAndTag = data.copyOfRange(12, data.size)

        val keySpec = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

        val plainBytes = cipher.doFinal(cipherTextAndTag)
        return String(plainBytes, StandardCharsets.UTF_8)
    }

    /**
     * Decrypts a Base64-encoded AES-256-GCM ciphertext.
     *
     * The key must match the one returned by [com.ssithara.rootkit.RootKit.getEncryptionKey]
     * for the RootKit instance that produced the ciphertext.
     *
     * @param cipherTextBase64  Base64-encoded ciphertext (IV prepended, NO_WRAP).
     * @param base64Key         Base64-encoded 32-byte AES key (NO_WRAP).
     * @return                  The decrypted plaintext string.
     */
    @Throws(Exception::class)
    fun decryptWithBase64Key(cipherTextBase64: String, base64Key: String): String {
        val keyBytes: ByteArray = Base64.decode(base64Key, Base64.NO_WRAP)
        val data: ByteArray = Base64.decode(cipherTextBase64, Base64.NO_WRAP)
        return decrypt(data, keyBytes)
    }
}
