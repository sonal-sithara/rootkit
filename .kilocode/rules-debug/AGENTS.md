# Debug Mode Rules

## Native Library Issues

If `UnsatisfiedLinkError` occurs:

1. Verify NDK version is `27.0.12077973` (check rootkit/build.gradle.kts)
2. Ensure `RootKit.initialize()` is called before any detection method
3. Check that `librootkit.so` is built for the target architecture

## Detection Debugging

- Detection results are encrypted - use [`EncryptionService.decryptWithBase64Key()`](app/src/main/java/com/ssithara/rootdetection/service/EncryptionService.kt) to view actual values
- Native logs tagged with `DetectMagiskNative` in logcat

## Common Failure Points

- Overlay detection silently fails without Activity context (check `updateActivity()` was called)
- Magisk stub detection requires `QUERY_ALL_PACKAGES` permission on Android 11+
