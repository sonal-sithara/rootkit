#-keepclasseswithmembernames class * { native <methods>; }
-keepclassmembernames class com.ssithara.rootkit.HookDetection$Companion {
    native boolean checkFridaByPort();
}

-keepclassmembernames class com.ssithara.rootkit.MagiskDetection {
    native boolean isMagiskPresentNative();
}

# Keep minimum metadata needed by runtime libraries you actually use.
-keep class kotlin.Metadata { *; }      # keep if you use reflection heavy kotlin libs (optional)

# Remove annotations and debug info we don't need
-keepattributes Signature
-dontwarn **

# Strip line numbers & sourcefile (already above)
-keepattributes !SourceFile, !LineNumberTable
