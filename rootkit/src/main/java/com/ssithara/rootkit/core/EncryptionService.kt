package com.ssithara.rootkit.core

import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object EncryptionService {

    @Throws(Exception::class)
    private fun encrypt(plainText: String, keyBytes: ByteArray): String {
        require(keyBytes.size == 32) { "Key must be 32 bytes (256 bits)" }

        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)

        val keySpec = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        val ciphertextAndTag = cipher.doFinal(plainText.toByteArray(StandardCharsets.UTF_8))

        val out = ByteArray(iv.size + ciphertextAndTag.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(ciphertextAndTag, 0, out, iv.size, ciphertextAndTag.size)

        return Base64.encodeToString(out, Base64.NO_WRAP)
    }

    /**
     * Encrypts [plainText] using AES-256-GCM with the provided Base64-encoded key.
     *
     * The key must decode to exactly 32 bytes. Use [com.ssithara.rootkit.RootKit.getEncryptionKey]
     * to obtain the per-instance session key that was used to produce the ciphertext.
     *
     * @param plainText  The text to encrypt.
     * @param base64Key  A Base64-encoded 32-byte AES key.
     * @return           Base64-encoded ciphertext (IV prepended).
     */
    @Throws(Exception::class)
    fun encryptWithBase64Key(plainText: String, base64Key: String): String {
        val keyBytes: ByteArray = Base64.decode(base64Key, Base64.NO_WRAP)
        return encrypt(plainText, keyBytes)
    }
}
