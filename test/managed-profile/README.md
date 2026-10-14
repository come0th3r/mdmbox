# Full panel document structural tests

Standalone C++17 target using Qt6 Core and the prepared yaml-cpp package:

```powershell
cmake -S test/managed-profile -B <separate-build-dir> -G Ninja -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=<qt-root>;<dependencies-root>"
cmake --build <separate-build-dir>
ctest --test-dir <separate-build-dir> --output-on-failure --timeout 30
```

Run in the MSVC developer environment with Qt DLLs available. No production
application, network, proxy or TUN lifecycle is started.

`ManagedProfile` retains the exact input bytes and SHA256 plus ordered display
indexes. Unknown transport fields, providers and DNS are not converted to old
Nekobox lists. Parsing requires a single full-profile mapping, distinct names,
and bounds on input size/traversal. Duplicate keys and cyclic/over-expanded
aliases are rejected. On failure the prior result is unchanged, and the error
does not contain remote document data.

`ManagedProfileStore` writes schema-1 envelopes keyed by existing group ID,
retains exact source bytes as Base64 with SHA256, and requires a validator
callback before commit. A per-group QLockFile serializes writers; QSaveFile
direct-write fallback is disabled. On replacement, the old envelope is saved
atomically to `.previous` before the current envelope is replaced. Invalid or
corrupt existing envelopes are not silently overwritten. Loading checks the
encoding, schema, group ID, checksum and document structure; it does not claim
runtime validation after a core version change.

Tests cover rejected validation, missing validator, malformed input, invalid
ID, lock contention, replacement/previous snapshot, corrupt current document
and failed snapshot write preserving the current bytes. Validator callbacks
in this suite are synthetic, not mihomo.

These components are not wired into subscription refresh yet.
Structural acceptance is **not** mihomo config validation or protocol support.
Provider-only profiles are outside this initial mikan inline-proxy contract.
Resource-bounded subprocess validation and rejection of mikan denial stubs
must precede accepting a document as a runnable managed subscription.
QSaveFile replacement is single-file atomic, not a multi-file transaction or
a power-loss durability guarantee. Process-crash injection, ACLs, disk-full,
lock recovery and metadata/active-runtime rollback are not tested here.
Envelopes and snapshots contain private profile material (Base64 is not
encryption); production must keep them under protected application data and
exclude them from exported logs and Git.

## Real mihomo validation

Run `mdmbox_managed_profile_tests.exe <absolute-path-to-pinned-mihomo.exe>`
to additionally test the real validator and store/validator integration.
The baseline artifact/hash is recorded in `libs/mihomo-windows-baseline.json`.
Without that argument CTest runs only the structural/store suite.

`MihomoValidator` checks the executable SHA256, clears inherited `CLASH_*`
overrides, uses a temporary home and sends the profile through stdin with
`-t -d <temporary-home> -f -`. Upstream v1.19.32 skips config.Init for stdin
and exits before runtime application in test mode. stdout/stderr are sent to
the null device; no private profile material is passed in arguments or logs.
Startup is bounded to 5 seconds, config check to 15 seconds; timeout kills
the child. The synchronous adapter must run on a worker thread.

This is not an OS sandbox: config parsing may access referenced local files
or fetch geodata/providers. Network/filesystem confinement, subprocess memory
limits, timeout/crash fault injection, executable TOCTOU protection and
provider/cache provisioning remain pending. The hard-coded Windows baseline
hash deliberately rejects other binaries, even ones reporting the same version.

## Subscription contract

`SubscriptionContract` parses case-insensitive metadata headers into optional
64-bit counters/expiry, title, safe web URLs and update interval in **hours**.
Missing total is unknown, zero total is unlimited, missing usage does not imply
zero usage. Exhaustion arithmetic avoids overflow. Invalid/duplicate known
headers or counters leave the previous result untouched. Update intervals
outside 1–168 hours are rejected; this is not yet scheduler/backoff behavior.

The request builder requires HTTPS, no embedded credentials/fragment and
version-shaped app/core strings. It replaces duplicate `format` parameters
with one `format=clash`, retaining other query values and the custom path.
It produces `MDMBOX/<app-version> mihomo/<core-version>`; callers must supply
the actual app and verified core versions. Unit-test `0.1.0` is synthetic,
not a new application release version. No download or HWID is implemented by
this contract; legacy URL header suffixes are not accepted here.

## Refresh orchestration

`SubscriptionService` connects request construction, persisted installation
identity, injected download, expiry/quota checks, validation and store commit.
A per-group lock spans download through commit (in the shared identity data
directory), preventing parallel refreshes using this service. Cancellation is
checked before download, after download and after validation before writing.
The store now records normalized metadata and source together in the same
atomic envelope; counters are represented as decimal strings, not JSON doubles.
Older envelopes without metadata load as unknown metadata.

Tests inject download/validation to verify metadata persistence, expired
subscription rejection, failed validation, cancellation during validation and
refresh lock contention without changing the prior envelope. Real core/store
integration remains separately exercised by the optional binary argument.

This service is not yet bound to the production GroupUpdater. The download
and validator dependencies must be bound to the genuine adapters, not mock
callbacks. The currently fixed core version is appropriate only for the pinned
1.19.32 adapter. Provider provisioning, denial-stub detection, scheduler,
reconnect and runtime selection are pending. Cancellation after the final
pre-commit check cannot roll back a completed commit.

`loadSnapshot` reads and validates source and metadata from one opened envelope;
both outputs stay unchanged on failure. `load` and `loadMetadata` use that same
reader, and commit validates previous metadata before replacing an envelope.
Use `loadSnapshot` when a consumer needs a coherent pair; separate calls can
still see different generations. Tests cover malformed metadata shape/entries,
invalid counters, duplicate headers, preservation on failed read/replacement,
and older envelopes without metadata (unknown values). No automatic corruption
repair is performed. Concurrent Windows replacement/read stress remains pending.

## Explicit runtime smoke

Build also produces `mdmbox_managed_runtime_smoke.exe`. Invoke manually with
the absolute pinned mihomo executable path. Ordinary CTest never starts it.
It verifies hash/config, starts a synthetic loopback-only projected profile
with temporary home and random in-memory API token, waits for authenticated
version API readiness, checks unauthenticated 401 and mixed TCP listener,
then terminates/kills its own child and checks both ports are unavailable.
No system proxy/TUN changes or external VPN sessions are requested.

Windows observed PASS, `forced=1`: terminate did not stop the console core in
two seconds, so bounded kill fallback was required. This is NOT graceful
shutdown proof. Actual proxy data path, production lifecycle integration,
process-tree cleanup, bind-race resilience and OS snapshot checks are pending.
Dynamic port reservation is released before start and cannot eliminate races.

Runtime smoke now also sends raw absolute-form HTTP through the mixed port
to a synthetic loopback HTTP origin. Exact response body and one origin request
are required, with 5-second timeout/8 KiB response bound. Raw TCP avoids client
automatic localhost proxy bypass. Two Windows runs PASS. This is mixed HTTP →
DIRECT → local origin, not SOCKS5 outbound/VPN protocol E2E. Graceful shutdown
still needs forced fallback; no improvement to that gate is claimed.

## Installation identity

`InstallationIdentity::loadOrCreate` stores a UUID in a schema-1 envelope under
the caller's application data directory, using a lock and atomic write with
no direct fallback. Existing malformed/oversized data is rejected without
silently rotating the ID. This avoids consuming a new panel device slot after
a transient or corrupt read. Machine serial numbers are not used.

Tests exercise creation, repeated reads, lock contention, corrupted identity
and copying the identity file to a portable data directory. Copying the data
preserves the same ID; a genuinely separate data directory creates a separate
identity. Reinstall policy, Windows ACLs and actual panel HWID registration
are not validated yet. The component is not wired into HTTP requests.
