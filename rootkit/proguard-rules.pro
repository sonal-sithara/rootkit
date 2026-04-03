# ============================================================
# RootKit Library — ProGuard / R8 rules
# Applied when isMinifyEnabled = true for this library module.
# ============================================================

# --- Public API -----------------------------------------------------------------

# Keep the top-level facade so consumers can reference it by name
-keep public class com.ssithara.rootkit.RootKit { *; }

# Keep all public core types (Result, DetectorResult, AppZygote)
# Note: EncryptionService is internal and should NOT be kept as public API
-keep public class com.ssithara.rootkit.core.Result { *; }
-keep public class com.ssithara.rootkit.core.DetectorResult { *; }
-keep public class com.ssithara.rootkit.core.AppZygote { *; }

# Keep the entire periodic-check public API (config, controller, callbacks, DTOs)
-keep public class com.ssithara.rootkit.core.periodic.** { *; }

# --- JNI — class names must survive obfuscation (name-mangling depends on them) -

-keepclasseswithmembernames class com.ssithara.rootkit.detection.root.MagiskDetection {
    native <methods>;
}

-keepclasseswithmembernames class com.ssithara.rootkit.detection.runtime.FridaDetection {
    native <methods>;
}

-keepclasseswithmembernames class com.ssithara.rootkit.detection.runtime.XposedDetection {
    native <methods>;
}

-keepclasseswithmembernames class com.ssithara.rootkit.detection.runtime.NativeHookDetection {
    native <methods>;
}

-keepclasseswithmembernames class com.ssithara.rootkit.detection.runtime.MemoryTamperingDetection {
    native <methods>;
}

# --- Kotlin metadata & reflection -----------------------------------------------

-keepattributes *Annotation*
-keepattributes Signature
-keepattributes Exceptions
-keepattributes EnclosingMethod
-keepattributes InnerClasses

# Keep Kotlin metadata so reflection-heavy Kotlin libraries work correctly
-keep class kotlin.Metadata { *; }

# --- Miscellaneous --------------------------------------------------------------

# Suppress warnings for dependencies we don't control
-dontwarn **
