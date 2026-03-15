package com.ssithara.rootkit.internal.dto

/**
 * Represents Magisk stub APK information for detection
 */
internal data class MagiskStubInfo(
    val version: String,
    val activities: Int,
    val services: Int,
    val broadcast_receivers: Int,
    val content_providers: Int,
    val class_name: String
)

// Type alias for backward compatibility
internal typealias MagiskStubInfoDto = MagiskStubInfo
