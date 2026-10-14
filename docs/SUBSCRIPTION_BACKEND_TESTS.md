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

## Pinned real mihomo config validation — 2026-10-15

Official `v1.19.32` Windows amd64-v1 archive obtained; archive SHA256 matched
the GitHub release API digest. Exact artifact and executable hashes are in
`libs/mihomo-windows-baseline.json`. `-v` reported `Mihomo Meta v1.19.32 windows
amd64 with go1.26.8`, build time Sep 30 2026, tag `with_gvisor`. Download/version
output was observed, though that SSH wrapper later timed out; the subsequent
validator integration completed normally and verified the executable hash.

`MihomoValidator` uses checksum-pinned binary, cleared CLASH environment,
temporary home, stdin config, discarded stdout/stderr and bounded wait/kill.
Upstream flags/control flow checked in `MetaCubeX/mihomo@v1.19.32/main.go`.

Windows build + base CTest: **PASS**. Real binary integration exit 0: **PASS**:

- synthetic SOCKS full profile accepted;
- structurally accepted unknown protocol rejected by real core;
- store commit using real validator succeeds for valid config;
- rejected replacement preserves existing envelope bytes;
- missing executable and wrong checksum rejected.

No external VPN session, protocol matrix or live mikan profile was exercised.
Timeout/crash injection, subprocess memory limits, network/file confinement,
provider provisioning, core runtime management and refresh integration remain
**NOT RUN / NOT IMPLEMENTED**. Config-check may access external resources;
temporary home is isolation of data, not an OS security sandbox.

## Metadata and request contract — 2026-10-15

Added `SubscriptionContract`: optional uint64 byte counters and int64 expiry,
unknown/unlimited/exhausted distinction, overflow-safe exhaustion, Base64 UTF-8
title, hour-based update interval and HTTP(S) metadata URLs. Strict malformed/
duplicate metadata rejection preserves the previous result. Managed request
builder requires HTTPS and version-shaped strings; preserves custom path and
other query values while replacing duplicate format values with `clash`.

Windows build and CTest **1/1 PASS**, including counters above 32 bits, uint64
overflow rejection, expiry boundary/range, unlimited/unknown states, Unicode
Base64 title, duplicate headers/counters, header injection, unsafe metadata
URL, invalid interval, repeated query values and malformed UA version input.
Structural/store tests also remain PASS. Real-mihomo integration was not rerun
for this contract-only change; no HTTP download or live mikan request performed.

The contract is not wired into the legacy request helper yet. Actual version
verification is the caller's responsibility; test app version is artificial.
HWID persistence, HTTP size/redirect/cancellation controls, metadata persistence,
denial-stub handling, scheduling and managed group integration remain pending.

## Persistent installation identity — 2026-10-15

Added `InstallationIdentity` with schema-1 UUID storage in caller-owned appdata,
QLockFile writer protection and QSaveFile atomic creation. No hardware serial
or registry identity is read. Corrupt, oversized or unavailable existing files
are rejected; no implicit identity regeneration or extra device slot is caused.

Windows build and CTest **1/1 PASS**, including creation, stable repeated reads,
contention rejection, portable-copy identity preservation and corrupt-file
rejection preserving the returned prior ID. Previous metadata/structure/store
suites remain PASS. Generated test IDs stayed in temporary directories and
were not printed or added to Git.

HTTP header integration, true concurrent-process/crash tests, ACL protection,
reinstall/reset policy and registration with a real mikan panel remain pending.
Portable data copied to another machine currently retains its identity; any
explicit rotate action must warn about panel registration/device-slot effects.

## Bounded managed download — 2026-10-15

Added worker-only `SubscriptionDownloader`: strict HTTPS (test target has
explicit loopback HTTP exception), peer verification, manual redirects,
4 MiB body cap, 64 KiB reply buffer, deadline and cancellation. Sends supplied
installation UUID as X-Hwid and Windows device header; does not derive HWID.
No automatic retry, raw error/body logging or inherited system proxy.
Failed download/metadata parsing leaves the previous result untouched.

Windows build/CTest **2/2 PASS**: synthetic local HTTP success/header delivery,
redirect/declared oversized/empty/malformed metadata/403/timeout rejection,
pre-cancel and in-flight cancellation. Separate target compiled without the
test exception confirms HTTP loopback rejection in production mode.

HTTPS certificate fixtures, chunked oversize, truncation, other HTTP statuses,
header memory bounds, proxy policy, approved redirect handling and live mikan
requests remain **NOT RUN**. Legacy request helper remains unchanged; managed
refresh/store/metadata integration is next and not available in production yet.

## Refresh orchestration and metadata persistence — 2026-10-15

`SubscriptionService` connects request/identity/download, rejects expired or
exhausted subscription metadata, validates the candidate and commits source
and normalized metadata together. Metadata counters remain decimal strings;
no uint64 precision is lost through JSON floating point. Service refresh locks
span download through commit; cancellation is rechecked after validation.

Windows build/base CTest **1/1 PASS**: synthetic refresh, metadata roundtrip
(including >32-bit usage/unlimited), expired rejection, validation rejection,
cancellation during validation and refresh lock contention all preserve the
last envelope on failure. Real pinned-core integration suite rerun: **PASS**,
exit 0. Service orchestration tests use injected transport/validator, not a
live mikan download followed by real validation in one invocation.

Production GroupUpdater binding, combined snapshot-read API, metadata
corruption recovery, denial stubs, scheduler and runtime apply/rollback remain
pending. No managed connection or complete subscription support claimed.

## Production binding (explicit backend mode) — 2026-10-15

Ordinary YAML-enabled client builds now include managed backend sources.
Existing group JSON gains `subscription_kind`, default `links`; an explicit
`mihomo-full` group uses the genuine downloader, identity service, atomic store
and pinned validator. Unknown kinds are refused rather than sent through the
legacy importer. Managed updates return before legacy profile deletion or
group metadata writes. Full source and metadata remain in the managed envelope
keyed by the existing group ID.

Pinned `mihomo.exe` beside the client is checksum-verified **before** requesting
the subscription/advertising its version; validation repeats the check. It is
not automatically downloaded or bundled by this change. There is intentionally
no UI mode selector yet, and managed runtime remains unavailable. Existing
legacy profiles are not converted or removed. The build version must satisfy
the existing version contract; no artificial release version is substituted.

Remote Windows ordinary Release build **PASS**. Standalone backend CTest
**1/1 PASS**; optional genuine mihomo integration **PASS**, exit 0, including
the extracted executable-preflight API (valid pin accepted, missing/wrong file
rejected). This does not exercise GroupUpdater refresh against an HTTPS fixture.
Group JSON roundtrip/migration, production group refresh, no-YAML build,
installer inclusion, UI availability and runtime E2E remain **NOT RUN**.

## Coherent snapshot and metadata integrity — 2026-10-15

Added `ManagedProfileStore::loadSnapshot`: one envelope read provides source
and metadata, with both outputs preserved on any error. Profile-only and
metadata-only reads share the complete envelope validator. Replacement now
refuses corrupt previous metadata, not only corrupt source/checksum. Older
schema-1 envelopes without metadata still load with unknown metadata.

Windows ordinary Release build **PASS**; backend CTest **1/1 PASS**; genuine
pinned mihomo integration **PASS**, exit 0. New cases cover wrong metadata
shape, malformed pairs/types, invalid counters, duplicate headers, coherent
roundtrip, failure preservation and missing-metadata compatibility.
Concurrent Windows read/replace stress and crash/disk-full recovery are still
**NOT RUN**. No automatic repair or runtime rollback is implied.

## Existing group persistence and production rejection — 2026-10-15

Extended isolated production-graph parser runner: Windows **27/27 PASS**,
process exit 0. Added group JSON disk roundtrip, old JSON defaulting to links,
preservation of URL/info/update timestamp/order, unknown-mode rejection and
managed missing-core preflight rejection through actual GroupUpdater. Existing
group/profile bytes remain unchanged and no managed envelope is created.

Initial configure needed explicit Qt6 (project defaults to Qt5); test code was
corrected to use public Group::Load rather than private LoadGroup. First run
failed because MainWindow log callback was unset in this isolated process;
runner now installs no-op log/dialog sinks. Final rebuild/run passed.
Existing offscreen OpenGL and legacy YAML `bad conversion` warnings remain.
Successful production HTTPS refresh/TLS fixtures and runtime E2E **NOT RUN**.

## mikan denial notices — 2026-10-15

Inspected `internal/panel/subs/handler.go`, `Handler.stub` at upstream revision
`a7b32c3efdfe85fe2450940f876fbb27fcf11ecc`. Clash notices have one SOCKS5
127.0.0.1:1 proxy with ⛔/⏸ prefix, one selector referencing it and one MATCH
rule. They omit DNS, so the previous full-profile requirements already refused
them generically. Parser now recognizes this compound structure before the
DNS requirement and returns a content-free notice error, including when DNS
is added. Neither name alone nor loopback endpoint alone triggers detection.

Windows production Release build **PASS**, backend CTest **1/1 PASS**, genuine
mihomo integration **PASS** exit 0. Twelve synthetic Russian/English notices
cover device limit, no suitable servers, banned device, missing HWID and
temporary/permanent unbinding. Tests assert refusal, unchanged stored envelope
and acceptance of an otherwise identical ordinary local proxy with DNS.

No distinct denial reason is inferred from translated text. URI/sing-box
notice paths, denial headers and live panel responses remain **NOT RUN** here.
Blocked-user/expired/exhausted handling beyond existing metadata checks is not
claimed. Future upstream notice shape changes require renewed contract tests.
