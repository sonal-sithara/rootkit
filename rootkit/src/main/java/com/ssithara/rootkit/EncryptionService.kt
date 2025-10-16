package com.ssithara.rootkit

import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec


object EncryptionService {

    private const val aseKey: String = "QmC4IyeS3tpvF5Yt5A0D1xX6E6U9Lg9KqUJYh7RokNs=";

    @Throws(Exception::class)
    private fun encrypt(plainText: String, keyBytes: ByteArray): String? {
        require(!(keyBytes == null || keyBytes.size != 32)) { "keyBytes must be 32 bytes (256 bits)" }

        val iv = ByteArray(12)
        val rnd = SecureRandom()
        rnd.nextBytes(iv)

        val keySpec = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv) // 128-bit auth tag
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        val plaintextBytes = plainText.toByteArray(StandardCharsets.UTF_8)
        val ciphertextAndTag = cipher.doFinal(plaintextBytes)

        val out = ByteArray(iv.size + ciphertextAndTag.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(ciphertextAndTag, 0, out, iv.size, ciphertextAndTag.size)

        return Base64.getEncoder().encodeToString(out)
    }

    @Throws(Exception::class)
    fun encryptWithBase64Key(plainText: String): String? {
        val keyBytes = Base64.getDecoder().decode(aseKey)
        return encrypt(plainText, keyBytes)
    }
}
