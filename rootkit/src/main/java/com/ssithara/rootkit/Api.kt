package com.ssithara.rootkit

/**
 * Public type aliases and convenience types for cleaner imports when consuming the RootKit library.
 *
 * Instead of importing types from internal packages, consumers can use these top-level aliases:
 * ```kotlin
 * import com.ssithara.rootkit.DetectionResult       // instead of core.Result
 * import com.ssithara.rootkit.RuntimeDetectionSummary // instead of detection.runtime.RuntimeTamperingDetection.DetectionSummary
 * ```
 */
typealias DetectionResult = com.ssithara.rootkit.core.Result

/**
 * Summary of runtime tampering detections (Frida, Xposed, Memory Tampering, Native Hooks).
 *
 * This is a typealias for [com.ssithara.rootkit.detection.runtime.RuntimeTamperingDetection.DetectionSummary],
 * exposed at the top-level package so consumers don't need to import from internal detection packages.
 */
internal typealias RuntimeDetectionSummary = com.ssithara.rootkit.detection.runtime.RuntimeTamperingDetection.DetectionSummary
