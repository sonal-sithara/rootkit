package com.ssithara.rootdetection.ui.model

/**
 * Data class representing an individual detection check item.
 * Contains information about the detection name, description, and result.
 *
 * @property id Unique identifier for the detection item
 * @property name Display name of the detection
 * @property description Brief description of what this detection checks
 * @property category The category this detection belongs to
 * @property result The current result state of this detection
 * @property details Optional map of sub-check names to their results (e.g., for Frida detection)
 * @property lastChecked Timestamp when this detection was last run
 */
data class DetectionItem(
    val id: String,
    val name: String,
    val description: String,
    val category: DetectionCategory,
    val result: DetectionResult = DetectionResult.Idle,
    val details: Map<String, Boolean>? = null,
    val lastChecked: Long? = null
)
