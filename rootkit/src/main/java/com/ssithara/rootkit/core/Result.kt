package com.ssithara.rootkit.core

import androidx.annotation.Keep

/**
 * Result of a security detection check.
 *
 * Every detection method returns one of these values (after decryption):
 * - [FOUND] — A security threat was detected
 * - [NOT_FOUND] — No threat detected
 * - [ERROR] — The detection check failed to complete
 *
 * Import as [com.ssithara.rootkit.DetectionResult] for a cleaner import path.
 *
 * @see com.ssithara.rootkit.RootKit.decryptResult
 */
@Keep
enum class Result {
    /**
     * No security threat was detected.
     */
    @Keep NOT_FOUND,

    /**
     * A security threat was detected (root, tampering, emulator, etc.).
     */
    @Keep FOUND,

    /**
     * The detection check failed to complete due to an error.
     * This is distinct from [NOT_FOUND] — it means the check could not be performed.
     */
    @Keep ERROR
}
