# Code Mode Rules

## Detector Implementation Pattern

When creating new detection classes:

1. Extend [`DetectorResult`](rootkit/src/main/java/com/ssithara/rootkit/DetectorResult.kt:5) with `context: Context` constructor parameter
2. Implement `run(): Result` returning `Result.FOUND` or `Result.NOT_FOUND`
3. Register in [`RootKit`](rootkit/src/main/java/com/ssithara/rootkit/RootKit.kt:7) class using `by lazy` initialization

## Native Code Integration

- JNI functions must follow naming pattern: `Java_com_ssithara_rootkit_<Class>_<method>`
- Register new native methods in [`rootkit.cpp`](rootkit/src/main/cpp/src/rootkit.cpp:156)
- Update [`Android.mk`](rootkit/src/main/cpp/Android.mk:1) if adding new source files

## Encryption Requirement

All public detection results MUST be encrypted before returning:

```kotlin
return EncryptionService.encryptWithBase64Key(result.name)
```

## Activity-Dependent Features

Overlay detection requires Activity context. Always call `rootKit.updateActivity(activity)` before using overlay methods.
