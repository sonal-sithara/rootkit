package com.ssithara.rootdetection.ui.model

/**
 * Data class holding display information for a detection sub-check.
 *
 * @param displayName User-friendly name for the detection
 * @param description Brief description of what this detection checks
 */
data class DetectionInfo(
    val displayName: String,
    val description: String
)

/**
 * Mapper object that converts technical snake_case keys to user-friendly
 * display names and descriptions.
 */
object DetectionInfoMapper {

    /**
     * Maps a technical key and category to a DetectionInfo with display name and description.
     *
     * @param key The technical snake_case key (e.g., "port_detection")
     * @param category The detection category (e.g., "frida", "xposed", "native_hook", "memory_tampering")
     * @return DetectionInfo with display name and description, or a default if not found
     */
    fun mapKeyName(key: String, category: String): DetectionInfo {
        return when (category.lowercase()) {
            "frida" -> getFridaInfo(key)
            "xposed" -> getXposedInfo(key)
            "native_hook" -> getNativeHookInfo(key)
            "memory_tampering" -> getMemoryTamperingInfo(key)
            "emulator" -> getEmulatorInfo(key)
            "debugger" -> getDebuggerInfo(key)
            else -> DetectionInfo(formatKeyName(key), "Detection check: $key")
        }
    }

    private fun getFridaInfo(key: String): DetectionInfo {
        return when (key) {
            "port_detection" -> DetectionInfo(
                displayName = "Frida Server Port",
                description = "Checks if Frida server port 27042 is open"
            )
            "memory_maps_detection" -> DetectionInfo(
                displayName = "Memory Maps Scan",
                description = "Scans /proc/self/maps for Frida signatures"
            )
            "thread_detection" -> DetectionInfo(
                displayName = "Thread Name Analysis",
                description = "Detects Frida-related thread names"
            )
            "library_detection" -> DetectionInfo(
                displayName = "Loaded Libraries",
                description = "Checks for frida-gadget.so and related libraries"
            )
            "file_descriptor_detection" -> DetectionInfo(
                displayName = "File Descriptor Check",
                description = "Detects Frida-related file descriptors"
            )
            "env_var_detection" -> DetectionInfo(
                displayName = "Environment Variables",
                description = "Checks for FRIDA_* environment variables"
            )
            else -> DetectionInfo(formatKeyName(key), "Frida detection check: $key")
        }
    }

    private fun getXposedInfo(key: String): DetectionInfo {
        return when (key) {
            "stack_trace_detection" -> DetectionInfo(
                displayName = "Stack Trace Analysis",
                description = "Analyzes stack traces for Xposed frames"
            )
            "package_detection" -> DetectionInfo(
                displayName = "Package Manager Scan",
                description = "Detects installed Xposed/LSPosed packages"
            )
            "loaded_classes_detection" -> DetectionInfo(
                displayName = "Class Loader Check",
                description = "Checks for XposedBridge and related classes"
            )
            "memory_maps_detection" -> DetectionInfo(
                displayName = "Memory Maps Scan",
                description = "Scans for Xposed signatures in memory"
            )
            "library_detection" -> DetectionInfo(
                displayName = "Library Injection",
                description = "Detects Xposed native libraries"
            )
            "zygote_detection" -> DetectionInfo(
                displayName = "Zygote Modification",
                description = "Checks for Zygote process modifications"
            )
            "riru_detection" -> DetectionInfo(
                displayName = "Riru Framework",
                description = "Detects Riru injection framework"
            )
            "zygisk_detection" -> DetectionInfo(
                displayName = "Zygisk Detection",
                description = "Checks for Zygisk (Magisk's Zygote hook)"
            )
            "hook_memory_detection" -> DetectionInfo(
                displayName = "Hook Memory Scan",
                description = "Scans memory for hook signatures"
            )
            else -> DetectionInfo(formatKeyName(key), "Xposed detection check: $key")
        }
    }

    private fun getNativeHookInfo(key: String): DetectionInfo {
        return when (key) {
            "inline_hook_detection" -> DetectionInfo(
                displayName = "Inline Hook Check",
                description = "Detects JMP instructions in function prologues"
            )
            "got_hook_detection" -> DetectionInfo(
                displayName = "GOT Hook Check",
                description = "Verifies GOT entries point to valid locations"
            )
            "plt_hook_detection" -> DetectionInfo(
                displayName = "PLT Hook Check",
                description = "Checks PLT entries for modifications"
            )
            "hook_framework_detection" -> DetectionInfo(
                displayName = "Hook Framework Scan",
                description = "Detects known hooking libraries"
            )
            "modified_function_pointer_detection" -> DetectionInfo(
                displayName = "Function Pointer Check",
                description = "Detects modified function pointers"
            )
            else -> DetectionInfo(formatKeyName(key), "Native hook detection check: $key")
        }
    }

    private fun getMemoryTamperingInfo(key: String): DetectionInfo {
        return when (key) {
            "suspicious_regions_detection" -> DetectionInfo(
                displayName = "Suspicious Memory Regions",
                description = "Detects unusual memory mappings"
            )
            "anonymous_exec_memory_detection" -> DetectionInfo(
                displayName = "Anonymous Executable Memory",
                description = "Finds anonymous memory with execute permissions"
            )
            "code_integrity_detection" -> DetectionInfo(
                displayName = "Code Integrity Check",
                description = "Verifies code section integrity"
            )
            "unusual_permissions_detection" -> DetectionInfo(
                displayName = "Permission Anomaly Check",
                description = "Detects RWX memory regions"
            )
            "code_caves_detection" -> DetectionInfo(
                displayName = "Code Cave Detection",
                description = "Finds unused space in code sections"
            )
            "modified_base_address_detection" -> DetectionInfo(
                displayName = "Base Address Check",
                description = "Detects ASLR bypass attempts"
            )
            else -> DetectionInfo(formatKeyName(key), "Memory tampering detection check: $key")
        }
    }

    private fun getEmulatorInfo(key: String): DetectionInfo {
        return when (key) {
            "device_model_check" -> DetectionInfo(
                displayName = "Device Model Analysis",
                description = "Checks Build.MODEL, Build.HARDWARE, Build.PRODUCT for emulator signatures"
            )
            "emulator_files_check" -> DetectionInfo(
                displayName = "Emulator File Detection",
                description = "Scans for emulator-specific files like /dev/socket/genyd, /dev/qemu_pipe"
            )
            else -> DetectionInfo(formatKeyName(key), "Emulator detection check: $key")
        }
    }

    private fun getDebuggerInfo(key: String): DetectionInfo {
        return when (key) {
            "adb_enabled_check" -> DetectionInfo(
                displayName = "ADB Debug Status",
                description = "Checks if USB debugging is enabled in developer options"
            )
            "frida_detection_check" -> DetectionInfo(
                displayName = "Frida Instrumentation",
                description = "Detects Frida instrumentation framework presence"
            )
            else -> DetectionInfo(formatKeyName(key), "Debugger detection check: $key")
        }
    }

    /**
     * Formats a snake_case key into a more readable format as a fallback.
     * E.g., "port_detection" -> "Port Detection"
     */
    private fun formatKeyName(key: String): String {
        return key.split("_")
            .joinToString(" ") { word ->
                word.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
            }
    }
}
