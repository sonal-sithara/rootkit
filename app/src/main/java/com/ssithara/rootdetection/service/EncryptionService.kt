package com.ssithara.rootdetection.service

import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec


object EncryptionService {

    private const val aseKey: String = "vL5x4Xqj4eS4E8XzV6Jt8Z9FvA4UrcJjx9pI5hHZzHk=";

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

    @Throws(Exception::class)
    fun decryptWithBase64Key(cipherTextBase64: String): String {
        val keyBytes: ByteArray = Base64.decode(aseKey, Base64.NO_WRAP)
        val data: ByteArray = Base64.decode(cipherTextBase64, Base64.NO_WRAP)
        return decrypt(data, keyBytes)
    }
}
