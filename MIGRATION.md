# Migration Guide

This guide helps you migrate between major versions of RootKit.

## Upcoming Versions

No migration guides yet — this is the initial `1.0.0` release.

### When a Migration is Needed

A migration guide will be added here when:

- A major version introduces breaking API changes
- A deprecated API is removed
- The integration steps change significantly
- The minimum SDK or dependencies change

### Versioning Policy

| Change | Version Bump | Migration Required |
|--------|-------------|-------------------|
| Bug fixes, detection updates | Patch (1.0.x) | No |
| New detections, new public API | Minor (1.x.0) | No |
| Breaking API changes | Major (x.0.0) | Yes |

### Deprecation Policy

Deprecated APIs will be maintained for at least one minor version before removal. Deprecation warnings will include the replacement API in their documentation.
