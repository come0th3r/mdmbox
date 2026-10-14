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

## Detached full mihomo document — 2026-10-15

`sub/ManagedProfile.*` is a new standalone backend component. It retains exact
source bytes and SHA256, ordered proxy/group names and panel rules. DNS,
providers, unknown transport fields and comments remain in the original
document, without lossy re-emission or legacy list conversion.

Standalone C++17/Qt6 Core/yaml-cpp build on the baseline Windows toolchain:
**PASS**. CTest: **1/1 PASS**, with a synthetic full document accepted and
**14 invalid documents rejected**, prior source/hash preserved. Cases include
empty/HTML/malformed input, multiple documents, duplicate root/nested keys,
cyclic aliases, oversized/invalid UTF-8/NUL input, empty sections, conflicting
proxy/group names, nonscalar rules and malformed providers.

Only structural checks are implemented. The component is not yet wired into
GroupUpdater or persistent group storage. No complete mikan golden contract,
denial-stub detection, mihomo subprocess validation or protocol E2E claim is
made. Provider-only profiles are outside this initial inline mikan contract.
Traversal bounds apply after YAML parsing; hard parse-time memory/time limits
still require process isolation or another bounded parsing design.

## Atomic managed document storage — 2026-10-15

`ManagedProfileStore` adds a schema-1 envelope keyed by existing group ID;
it is not a separate group database. Exact source, kind and SHA256 are kept
together in one atomically replaced file. Commit requires a validator callback,
serialized by QLockFile, and uses QSaveFile without direct-write fallback.
Before replacement the last envelope is saved to `.previous`; failure to save
that snapshot prevents replacement. Corrupt current data is not overwritten.

Windows standalone build/CTest: **1/1 PASS**, including the previous structural
suite plus store/load byte preservation, rejected/missing validator, invalid
input/ID, writer lock contention, snapshot/replacement, corrupt current data
and deterministic snapshot-write failure with unchanged current bytes.
The tests use artificial validation callbacks, **not a real mihomo binary**.

Refresh integration, validator subprocess, core-version revalidation, private
data ACLs, disk-full, power-loss/process-crash injection, stale-lock recovery,
metadata and running-core rollback remain **NOT RUN / NOT IMPLEMENTED**.
Single-file atomic replacement does not constitute a complete subscription
transaction. Snapshot/profile files are private data, not encrypted by Base64.
