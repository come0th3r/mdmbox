# Subscription backend regression results

## Detached legacy parsing — 2026-10-15

Implemented `RawUpdater::stage_only`: URI, Base64, JSON and Clash parsing can
collect entities without adding them to `ProfileManager`. Ordinary direct
imports retain their existing immediate-write behavior. `GroupUpdater` stages
first and rejects an empty result or YAML exception before changing group
metadata, URL or existing profiles. The common-profile index-zero branch is
also corrected.

Windows baseline (Qt 6.7.2, MSVC 19.44, CMake 4.4.4):

- Test runner build: **PASS**.
- Detached entities, unchanged original profile bytes/file list/group, invalid
  empty/HTML/YAML/JSON/unrecognized payloads: **PASS, 22 checks**, exit 0.
- Reconfigure with `MDMBOX_SUBSCRIPTION_PARSER_TEST=OFF` and build production
  entry point: **PASS**.
- Full `GroupUpdater` download/update regression: **NOT RUN**.
- Write-error/crash rollback, concurrent updates, core validation and full
  mihomo policy storage: **NOT IMPLEMENTED / NOT RUN**.

Sources were tested in a separate remote snapshot with local changed files
overlaid, not by overwriting the older remote checkout. Initial snapshot copy
incorrectly nested QHotkey; corrected by explicitly copying directory contents.
Initial runner printed successful checks but PowerShell Start-Process returned
no exit code. Repeated with System.Diagnostics.Process: exit 0 confirmed.
Working directory is now restored before QTemporaryDir destruction; cleanup
warning disappeared. Offscreen OpenGL and legacy YAML conversion warnings
remain; no renderer or protocol claim is based on this test.

See `test/subscription-parser/README.md` for the opt-in build mode. This change
does **not** make individual legacy JSON writes atomic or reject every partially
unsupported subscription; managed-profile validation is subsequent work.
