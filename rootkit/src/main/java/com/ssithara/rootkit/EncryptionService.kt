package com.ssithara.rootkit

import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec


object EncryptionService {

    private const val aseKey: String = "vL5x4Xqj4eS4E8XzV6Jt8Z9FvA4UrcJjx9pI5hHZzHk=";

    @Throws(Exception::class)
    private fun encrypt(plainText: String, keyBytes: ByteArray): String {
        require(!(keyBytes == null || keyBytes.size != 32)) { "Key must be 32 bytes (256 bits)" }

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

    @Throws(Exception::class)
    fun encryptWithBase64Key(plainText: String): String {
        val keyBytes: ByteArray = Base64.decode(aseKey, Base64.NO_WRAP)
        return encrypt(plainText, keyBytes)
    }
}
