# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-04

### Added
- Root detection (Root binaries, SU commands, root management apps)
- Magisk framework detection (native and Java checks)
- MagiskHide/DenyList stub detection
- Frida instrumentation detection (ports, memory maps, threads, libraries, fd, env vars)
- Xposed/LSPosed detection (memory maps, libraries, zygote, riru, zygisk, hook memory)
- Memory tampering detection (6 integrity methods)
- Native hook detection (inline, GOT, PLT, frameworks, function pointers) with ARM64/ARM32/x86 support
- Emulator detection
- Debugger detection
- AES-256-GCM result encryption with per-instance session keys
- Periodic security monitoring with sequential, parallel, and staggered execution modes
- Lifecycle-aware periodic checks (auto-pause/resume with Activity lifecycle)
- App visibility-aware checks (pause in background or reduce frequency)
- DSL builder for periodic check configuration
- `RootKit` facade as single entry point
- `decryptResult()` public API for result decryption
- `runAllDetections()` returning typed `SecurityReport`
- `DetectionResult` and `RuntimeDetectionSummary` type aliases
- `Closeable` implementation for `use {}` block support
- Consumer ProGuard rules for automatic R8 compatibility
- JitPack publishing with POM metadata and sources JAR
