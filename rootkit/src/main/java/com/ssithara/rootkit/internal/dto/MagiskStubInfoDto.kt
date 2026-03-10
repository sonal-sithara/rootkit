package com.ssithara.rootkit.internal.dto

internal data class MagiskStubInfoDto(
    val version: String,
    val activities: Int,
    val services: Int,
    val broadcast_receivers: Int,
    val content_providers: Int,
    val class_name: String
)
