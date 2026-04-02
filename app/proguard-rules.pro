# Preserve line numbers for crash reports
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# RootKit library - keep all public API classes
-keep class com.ssithara.rootkit.RootKit { public *; }
-keep class com.ssithara.rootkit.core.Result { *; }
-keep class com.ssithara.rootkit.core.PeriodicCheckConfig$* { *; }

# JNI native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Encryption service - keep AES key handling
-keep class com.ssithara.rootkit.core.EncryptionService { *; }
-keep class com.ssithara.rootkit.data.EncryptionService { *; }

# Detector result base classes
-keep class com.ssithara.rootkit.core.DetectorResult { *; }
-keep,allowobfuscation class * extends com.ssithara.rootkit.core.DetectorResult {
    public <methods>;
}

# ViewModels
-keepclassmembers class * extends androidx.lifecycle.ViewModel {
    <init>(...);
}

# Compose
-dontwarn androidx.compose.**

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# RootBeer library
-keep class com.scottyab.rootbeer.** { *; }

# Xposed detector (prefab)
-keep class io.github.vvb2060.ndk.** { *; }
