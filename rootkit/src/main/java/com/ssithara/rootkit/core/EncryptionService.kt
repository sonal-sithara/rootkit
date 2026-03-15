package com.ssithara.rootkit.core

import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
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
     * @throws IllegalArgumentException if the key is not valid Base64 or is not 32 bytes
     * @throws GeneralSecurityException if encryption fails
     */
    @Throws(IllegalArgumentException::class, GeneralSecurityException::class)
    fun encryptWithBase64Key(plainText: String, base64Key: String): String {
        val keyBytes: ByteArray = Base64.decode(base64Key, Base64.NO_WRAP)
        return encrypt(plainText, keyBytes)
    }

    /**
     * Decrypts [cipherText] using AES-256-GCM with the provided Base64-encoded key.
     *
     * The cipherText must be Base64-encoded with the IV prepended (12 bytes),
     * followed by the 16-byte auth tag and ciphertext.
     *
     * @param cipherText  The Base64-encoded ciphertext to decrypt.
     * @param base64Key  A Base64-encoded 32-byte AES key.
     * @return           The decrypted plaintext string.
     * @throws IllegalArgumentException if the key or ciphertext is not valid
     * @throws GeneralSecurityException if decryption fails (wrong key, auth tag mismatch, etc.)
     */
    @Throws(IllegalArgumentException::class, GeneralSecurityException::class)
    fun decryptWithBase64Key(cipherText: String, base64Key: String): String {
        val keyBytes: ByteArray = Base64.decode(base64Key, Base64.NO_WRAP)
        require(keyBytes.size == 32) { "Key must be 32 bytes (256 bits)" }

        val encryptedData: ByteArray = Base64.decode(cipherText, Base64.NO_WRAP)
        require(encryptedData.size > 12) { "Ciphertext must be at least 12 bytes (IV)" }

        // Extract IV (first 12 bytes)
        val iv = ByteArray(12)
        System.arraycopy(encryptedData, 0, iv, 0, 12)

        // Extract ciphertext + auth tag (remaining bytes)
        val ciphertextAndTag = ByteArray(encryptedData.size - 12)
        System.arraycopy(encryptedData, 12, ciphertextAndTag, 0, ciphertextAndTag.size)

        val keySpec = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

        val plaintext = cipher.doFinal(ciphertextAndTag)
        return String(plaintext, StandardCharsets.UTF_8)
    }
}
