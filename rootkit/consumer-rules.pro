# =============================================================================
# consumer-rules.pro
#
# These rules are automatically applied to any app that depends on this AAR.
# They ensure that R8/ProGuard in the consumer's build does NOT rename or
# remove classes and methods whose names are load-bearing for JNI name mangling.
#
# JNI function resolution depends on the fully-qualified class name + method
# name matching the symbol in librootkit.so exactly. If R8 renames either side,
# the app will crash with UnsatisfiedLinkError at runtime.
# =============================================================================

# Keep the names of all classes that declare native methods, and keep the
# names of those native methods themselves.  R8 may still inline/remove
# non-native members of these classes — only native method names are locked.
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

# Keep the public facade so consumers can reference RootKit without fully
# qualifying it in their own keep rules.
-keep public class com.ssithara.rootkit.RootKit { public *; }

# Keep the public periodic-check API (interfaces, data classes, enums) so
# consumers that use the monitoring feature do not lose their callback types.
-keep public class com.ssithara.rootkit.core.periodic.** { public *; }

# Keep the Result enum so consumers can compare decrypted values by name.
-keep public enum com.ssithara.rootkit.core.Result { *; }

# Keep AppZygote — its name is referenced in the library AndroidManifest and
# must survive both the library and consumer build steps.
-keep class com.ssithara.rootkit.core.AppZygote { *; }

# Retain Kotlin metadata so reflection-based libraries (e.g. kotlinx.serialization,
# Moshi) can inspect the library's types correctly.
-keepattributes *Annotation*, Signature, InnerClasses, EnclosingMethod
