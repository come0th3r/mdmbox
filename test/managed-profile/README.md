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

### Windows console shutdown update

The current smoke creates a separate hidden console for its core and invokes
test-only `mdmbox_test_console_break.exe` to attach to that console and send
CTRL_C (the helper filename is historical). It never broadcasts into the
parent SSH console. CTRL_BREAK did not produce normal exit 0 and was rejected.
Two final Windows runs with CTRL_C passed exit 0, forced=0, API/mixed ports
closed and HTTP data path intact. Prior forced=1 observations above describe
the older terminate path. Kill remains failure cleanup, not a passing shutdown.
This is still test-only: production lifecycle, crash/process-tree handling,
OS snapshot verification and installer packaging are pending.

### Reusable process owner

Smoke now exercises `sub/ManagedCoreProcess.*`, also compiled into the ordinary
YAML-enabled client. This synchronous single-worker-thread component owns its
child and temporary home, applies reviewed projection/config-check, rejects
duplicate starts, and exposes Stopped/Starting/Running/Stopping/Failed states.
Running is process liveness only, not API readiness or connected status.
Stop uses an injected bounded signal adapter; the Windows console helper stays
test-only and is not installed with the client. Application wiring is pending.

Windows ordinary client build and base CTest 1/1 PASS. Three smoke invocations
PASS (two initial plus final cleanup adjustment): missing executable rejected,
duplicate start preserves PID, graceful exit/closed ports, idempotent stop,
restart and absent-signal forced cleanup reports failure with no live owned PID
or listeners. Unconfirmed kill disables temporary-home auto-removal, preserving
files rather than deleting an active core's directory. That rare failure path,
destructor/process-tree/crash fault injection and non-Windows smoke are NOT RUN.

### Authenticated controller readiness

`waitReady(1..30000 ms)` probes only the stored loopback controller with the
stored token, NoProxy and no redirects. Each attempt has at most 500 ms, body
is bounded to 4096 bytes, and success requires HTTP 200, valid JSON and exact
version `v1.19.32` while the owned child is alive. Ready is controller readiness,
NOT a VPN connection. Bad timeout leaves the owned child untouched; failed
probes force cleanup and report Failed. Use on one worker, without reentrancy.

Windows ordinary build/base CTest 1/1 and two runtime runs PASS: initial and
repeat readiness, invalid timeout preserves PID/state, stopped readiness refused,
foreign API listener returning 401 refused with owned child cleaned up. Prior
HTTP/auth/graceful/forced-cleanup tests remain passing. The foreign-listener
case can also observe an early child exit on bind conflict; it does not prove
every HTTP parser rejection branch. Oversize/malformed/wrong-version/redirect,
slow-stream and actual core wrong-token fault injection remain NOT RUN.

### Unexpected child exit and owner destruction

Windows smoke additionally terminates its ready core through a held process
handle (avoids PID-reuse targeting), waits for Failed, rejects further readiness
and refuses to label the subsequent stop graceful. Separately destroys a ready
scoped owner without explicit stop and verifies child exit through a held kernel
handle. Both cases require API/mixed ports closed. Windows build, base CTest
1/1 and two full smoke runs PASS. This tests child crash simulation and ordinary
C++ destructor cleanup, NOT parent-process crash/power loss or descendant trees.

### Independent controller fixtures (ordinary CTest)

`controller-probe` exercises the same `ManagedControllerProbe` used by the
process owner, without starting mihomo or depending on bind-conflict timing.
Synthetic loopback server checks exact GET path/Bearer header. Accepted version,
wrong version, malformed JSON, array root, 401, >4096-byte body, redirect without
following, stalled response timeout and invalid-token/timeout preflight pass.
Windows ordinary client build PASS, CTest 2/2 PASS, real full runtime PASS exit 0.
Header allocation bounds, slow streaming, truncated/chunked responses and actual
core wrong-token injection remain NOT RUN. No OS trust/proxy changes are made.

### Production console signal adapter

Current `ManagedCoreProcess::stop(error)` uses `mdmbox_console_signal.exe`
beside the application on Windows; injected stop remains available for tests.
Helper source is `sys/managed-console-signal.cpp`, built by both ordinary client
and standalone tests. It validates PID, holds a process handle, attaches only
in its own process, and requires console membership exactly target+helper before
CTRL_C. Old test-only console-break source was removed. Non-Windows default
uses terminate (NOT RUN here). Bounded helper failure still leads to forced
cleanup, which returns failure rather than graceful success.

Windows ordinary build PASS, CTest 3/3 PASS (includes invalid PID refusal), full
real-core runtime 2/2 PASS with production default stop, exit 0/forced=0/closed
ports. Shared-console refusal, helper tampering, full installer delivery and
multi-config artifact colocation remain NOT RUN. Existing older helper remarks
above describe earlier revisions, not the current executable.

### Legacy managed fallback refusal

The production config builder refuses to generate a legacy config for
`mihomo-full` and unknown subscription kinds. The isolated parser runner checks
direct, `internal-full`, chain-member and front/global generation boundaries,
while ordinary `links` behavior remains accepted. Windows production build PASS;
parser runner 39/39 PASS; managed-profile CTest 3/3 and real runtime regression
PASS. Managed application lifecycle and single-core arbitration remain pending.

### Core ownership primitive

`CoreOwnership` is a mutex-protected None/Legacy/Managed token. Duplicate,
empty and cross-owner operations are rejected; two competing threads have one
winner. Windows CTest 4/4 PASS. This is not a singleton or production lifecycle
integration: callers must share the same instance. RPC failure handling and
actual core switching remain NOT RUN.

### Shared production arbitration

Both legacy profile start/stop and ManagedCoreProcess now use
`CoreOwnership::shared()`. Managed cleanup releases only after confirmed child
exit. Legacy releases only on successful RPC Stop; failed start/stop or crash
conservatively blocks subsequent acquisition until application restart.
Runtime fixture verifies synthetic Legacy ownership refuses managed start,
and running managed refuses Legacy acquisition and a second managed process.
Windows ordinary build PASS, CTest 4/4 PASS, full runtime PASS exit 0 including
`MIHOMO_SHARED_CORE_ARBITRATION_PASS`. Actual GUI RPC faults, core-only restart
recovery and external-child exit confirmation remain NOT RUN. This arbitration
is process-local, not an interprocess lock or OS resource ownership guarantee.

### Uncertain ownership outcomes

`CoreOwnership::State` distinguishes Free, Held and Uncertain. Only the active
owner can mark uncertainty; repeated notifications are idempotent. Uncertain
retains the owner and rejects acquisition by either runtime. `release` still
requires the caller to independently confirm shutdown; it does not inspect
processes. Legacy failed Start/Stop and crash paths mark Uncertain, as does a
managed cleanup whose child termination is unconfirmed. No automatic recovery
is added by this change.

Windows production build PASS, CTest 4/4 PASS, parser regression 39/39 PASS,
full real-mihomo runtime PASS exit 0 (graceful stop, forced=0).
`CORE_UNCERTAIN_OUTCOME_TRANSITIONS_PASS` covers both owners, invalid fault
notifications, retained ownership, blocked acquisition and simulated confirmed
shutdown. Actual GUI/RPC fault injection and external-process shutdown
confirmation remain NOT RUN; these component tests do not establish safe
automatic legacy recovery.

### Legacy stop outcome policy

Production `neko_stop` and component fixtures share
`LegacyCoreLifecycle::finishStop`. Release requires a successful RPC stop,
confirmed external-process cleanup and no previously uncertain outcome. A
later successful reply cannot clear Uncertain because it may come from a new
daemon. Fixtures cover all four RPC/cleanup result combinations, foreign-owner
protection and rejection of that later reply (`LEGACY_STOP_OUTCOME_MATRIX_PASS`).

Production now waits up to 5 seconds for the queued external cleanup callback.
It removes only QProcess entries confirmed NotRunning and retains handles for
entries still alive. This is not descendant-tree or OS-resource confirmation.
Windows production build PASS, CTest 4/4 PASS, parser 39/39 PASS and full
real-mihomo runtime PASS exit 0, forced=0. Actual GUI delayed cleanup, timeout
and RPC fault injection, real legacy external-child fixtures and automatic
recovery remain NOT RUN / pending.

### Real-child tracking cleanup fixtures

`process-cleanup` uses the same `cleanupTrackedProcesses` algorithm as the
production DS_cores callback. It launches its own executable as a child with
a 10-second self-exit deadline (no shell/network). An injected no-op stopper
retains the live PID and tracked handle; `finishStop` then retains Legacy in
Uncertain and blocks Managed. Real QProcess kill/wait confirms NotRunning/PID0
and removes the entry. Prior uncertainty stays blocked; a separate normal
cleanup permits switching. Mixed stopped/live entries, empty tracking and
null entries are covered; null tracking fails closed.

Windows production build PASS, CTest **5/5 PASS**, parser **39/39 PASS**, full
real-mihomo runtime PASS exit 0/forced=0. Direct runner prints
`TRACKED_LIVE_CHILD_REFUSAL_PASS`, `TRACKED_CHILD_CONFIRMED_EXIT_PASS` and
`TRACKED_CHILD_NORMAL_SWITCH_PASS`. The stopper is injected: this does not
test actual ExternalProcess::Kill, queued GUI delays/timeouts, descendant
trees or automatic recovery. No system proxy, TUN, DNS or routes are enabled.

### Production ExternalProcess kill retry regression

The production-graph subscription parser runner now includes
`test/subscription-parser/ExternalProcessFixture.hpp`. It starts real bounded
self-child processes through ExternalProcess::Start and calls the genuine
ExternalProcess::Kill for all four injected prior killed/crashed flag pairs.
Shared tracked cleanup confirms NotRunning/PID0 before normal ownership
switching; repeated Kill of an exited child is also checked. Production Kill
now retries live processes regardless of those flags instead of treating an
earlier stop request or error as proof of exit.

Windows production build PASS, `EXTERNAL_PROCESS_REAL_KILL_RETRY_PASS cases=4`,
parser 39/39 PASS, CTest 5/5 PASS and real-mihomo smoke PASS exit 0/forced=0.
Prior flags are injected; actual timeout/error callbacks, managed=true crash
notifications, GUI queue faults, descendants and automatic recovery are NOT
RUN. The fixture does not authorize clearing a previously uncertain owner.

### Queued cleanup completion and late replies

Production stop now uses `ProcessCleanupCompletion` for its queued cleanup
result (one producer and one waiting worker). Timeout is terminal, negative
timeouts fail closed, duplicate completion cannot overwrite the first result,
and the callback retains shared lifetime after the worker stops waiting.
The production deadline remains 5 seconds.

`cleanup-completion` tests real QThread queued success/failure, a gated late
callback after an actual timeout, caller reference release, missing callback,
duplicate reply and invalid timeout. Late success cannot unblock Uncertain.
Windows production build PASS, CTest **6/6 PASS**, direct runner
`CLEANUP_QUEUE_SUCCESS_FAILURE_TIMEOUT_LATE_REPLY_PASS`, parser 39/39 plus
production ExternalProcess cases=4 PASS, real-mihomo smoke PASS exit 0/forced=0.
These fixtures test the shared completion and isolated Qt queue, not the full
GUI runOnUiThread/RPC sequence. Automatic recovery, daemon-generation proof
and descendant/OS-resource cleanup remain pending.

### Atomic stop versus fault notifications

`CoreOwnership::finishStop` now evaluates owner, stop result and prior
uncertainty under one mutex and performs the resulting state transition in
the same critical section. LegacyCoreLifecycle delegates to this operation.
This removes the previous separate state-check/release race where a fault
could set Uncertain immediately before release cleared it. Independent
confirmed-cleanup `release` remains unchanged.

Windows production build PASS, CTest 6/6 PASS, parser 39/39 and production
ExternalProcess cases=4 PASS, full mihomo smoke PASS exit 0/forced=0.
`CORE_ATOMIC_STOP_FAULT_RACE_PASS iterations=200` races normal stop against
markUncertain and verifies mutually exclusive stop-first Free or fault-first
Legacy/Uncertain outcomes. This is a component concurrency fixture, not actual
GUI RPC fault injection. Generation tokens and explicit recovery remain
unimplemented; this change alone does not make recovery safe.

### Ownership generation checks

Successful acquisition now increments a monotonic quint64 generation and can
return it to the caller. Nonzero generation arguments on release, fault and
stop-result mutations are checked under the ownership mutex. Exhaustion fails
closed. Production managed cleanup stores its acquired generation; legacy
start failure and Stop pass the generation captured for their operation.

Windows production build PASS, CTest6/6 PASS,
`CORE_STALE_GENERATION_REFUSAL_PASS` (both owner types, same-owner reacquisition,
stale release/fault/successful and failed stop), race200 PASS, parser39/39 plus
ExternalProcess4 PASS, full mihomo smoke PASS exit0/forced0.

Zero/default generation remains an unversioned compatibility API for existing
fixtures; this is not an opaque mandatory lease. Legacy crash snapshots current
ownership and is not yet bound to the daemon process that emitted the event.
These counters do not prove process exit, authenticate a callback or authorize
automatic recovery. Daemon event generations and GUI/RPC fault E2E are pending.

### Daemon event generation binding

CoreProcess now advances an atomic launch generation before starting a stopped
daemon. CoreCrashed carries daemon generation and ownership generation captured
at event emission; CoreStarted carries daemon generation. GUI consumers parse
the payload and reject non-current generations. Crash handling uses the captured
ownership generation rather than looking up a potentially newer owner. Delayed
restart callbacks reject stale generations; Restart refuses to launch while the
previous QProcess exit is unconfirmed.

Windows final production build PASS (initial captured-state shadowing compile
error fixed), CTest6/6 PASS, `DAEMON_STALE_EVENT_GENERATION_PASS`, parser39/39
plus ExternalProcess4 PASS, real-mihomo runtime PASS exit0/forced0. The generation
fixture is component-level, not real daemon crash/GUI-queue E2E. The GUI generation
check and subsequent work are not a single cross-thread transaction. External
proxy Crashed messages remain unversioned. Automatic recovery and independently
confirmed daemon/descendant/OS cleanup remain pending.

### Real CoreProcess event producer fixture

The production-graph parser runner includes `CoreProcessFixture.hpp`. Genuine
CoreProcess starts a bounded synthetic self-child that prints the readiness
marker and exits with code42. An event collector checks CoreStarted profile77
and daemon generation, then CoreCrashed with the same daemon and captured
ownership generation. A manual Restart occurs before the production delayed
retry; the fixture checks old-generation refusal, duplicate Start PID stability,
and the new child's unchanged PID after 1300ms. Intentional shutdown emits no
additional crash notification. Fixture restores callbacks and datastore flags.

Windows runner build PASS; two runs print
`CORE_PROCESS_REAL_EVENTS_RESTART_STALE_TIMER_PASS`, parser39/39 and
ExternalProcess4 PASS. CTest6/6 and full real-mihomo smoke PASS exit0/forced0.
Only tests changed; ordinary production build was not repeated (previous
production revision build PASS). This exercises actual event production with a
synthetic child, not nekobox RPC or the real GUI consumer. Failed restart,
unconfirmed kill, descendant/OS cleanup and recovery remain NOT RUN.

### Snapshot-backed managed session

`ManagedSession` is a worker-thread-only service compiled into ordinary
YAML-enabled builds. It loads profile and metadata together by existing group
ID, refuses expired/exhausted snapshots, generates an in-memory API token and
starts the reviewed loopback runtime through authenticated readiness. Stop
uses the production platform adapter. Duplicate starts/group switches require
explicit stop. Ready is not VPN connected; no OS proxy/TUN/DNS/routes enabled.

Windows production build PASS, CTest6/6 PASS, parser39/39 plus previous process
fixtures PASS, two full real-mihomo runtime runs PASS exit0/forced0.
`MANAGED_SNAPSHOT_SESSION_READINESS_STOP_PASS` covers real-validator store
commit → snapshot → session readiness → graceful stop/closed ports → restart,
unchanged source, missing snapshot, invalid timeout, synthetic Legacy hold,
duplicate group switch/PID preservation and expired/exhausted refusal.
Production UI/application-state wiring, active refresh/reconnect, unconfirmed
cleanup fault injection and legacy recovery remain pending.

### Async session controller and application ownership

`ManagedSessionController` serializes start/stop on a dedicated QThread.
ManagedSession and QProcess are created and destroyed on that worker. Queued
status/result signals return command outcomes to the controller's owner thread;
busy commands are refused. MainWindow owns the controller in YAML-enabled
builds, but no user command or visual state binding is enabled yet.

Windows production build PASS, CTest6/6 PASS, parser39/39 and process fixtures
PASS, real-mihomo runtime `MANAGED_ASYNC_WORKER_STATUS_SHUTDOWN_PASS` exit0.
The fixture covers async Ready, busy refusal, stop, missing snapshot failure,
restart and controller destruction with an active child (closed ports/ownerNone).
Actual MainWindow lifetime runtime is NOT RUN. Destruction waits for the current
bounded operation plus cleanup; no cancellation/fast shutdown yet. Status is
published after commands only: continuous crash monitoring is not implemented,
so last Ready must not be interpreted as ongoing VPN connectivity. UI bridge,
refresh/reconnect, TUN/system proxy and explicit legacy recovery are pending.

### Async unexpected-exit monitor

Controller now polls process liveness on its worker every 100ms while a session
is active. An executing guard suppresses monitor reentry during nested readiness
event loops. Unexpected exit triggers cleanup, a one-shot Failed status and a
separate runtimeFailed signal. Owner-thread getters cache the latest delivered
state/group/PID. Manual restart re-enables monitoring; no automatic restart is
added. This detects process exit, not API stalls or lost VPN connectivity.

Windows production build PASS, CTest6/6 PASS, parser39/39 plus process fixtures
PASS, full real-mihomo smoke PASS exit0/forced0.
`MANAGED_ASYNC_UNEXPECTED_EXIT_MONITOR_PASS` uses a held Windows process handle
to terminate the actual managed child with exit42 and verifies Failed delivery,
cached PID0/group-1, closed ports, ownershipNone and successful manual restart.
Visible application/bridge wiring, cancellation, API/data-path health checks
and legacy recovery remain pending.

### Read-only managed shell snapshot

Controller exposes schema1 JSON with available, loopback-only scope, state,
busy, groupId, controllerReady and vpnConnected=false. MainWindow forwards it
as buildShellState.managedRuntime; legacy connected remains unchanged. The
fallback reports unavailable when no controller is compiled/installed. No PID,
token, source or executable path is exported.

Windows production build PASS, CTest6/6 PASS, parser39/39/process fixtures PASS,
full real-mihomo smoke PASS exit0/forced0.
`MANAGED_READONLY_SNAPSHOT_CONTRACT_PASS` checks stopped/ready/stopped/failed
JSON, schema, scope, field count, no token/PID and no VPN-connected claim.
Actual JS/QWebChannel delivery, visible rendering and no-YAML build are NOT RUN.
ControllerReady is initial authenticated readiness plus process-exit monitoring,
not ongoing API or data-path health. No start/stop bridge commands are added.

### Narrow application loopback command adapter

MainWindow now has explicit C++ managedLoopbackStart/Stop methods (not the
general connect toggle). Start validates the existing group is nonarchived
mihomo-full and refuses shutdown, active system proxy/TUN, started legacy or
Legacy ownership and busy controller. Store/executable/ports are internal fixed
values: managed-subscriptions, appdir/mihomo.exe, 17890/19090, readiness10s.
True means queued, not successful connection. Bind conflicts still require
runtime failure handling. No JS mutation command is exposed yet.

Windows production build PASS, CTest6/6 PASS,
`MANAGED_LAUNCH_POLICY_MATRIX_PASS cases=67`, parser39/39/process fixtures PASS,
full mihomo runtime PASS exit0/forced0. Actual MainWindow command E2E, no-YAML
and fixed-port collisions NOT RUN. Reciprocal system-mode guards during
pending/active managed sessions are still required before exposing commands;
application flags are not OS-state verification.

### Reciprocal legacy/system-mode guards

MainWindow refuses legacy start, system proxy/TUN enable and direct
StartVPNProcess before side effects while the managed controller is pending,
has an active group/live PID, or shared ownership belongs to Managed. Disable
remains available for cleanup. Managed start also refuses a nonzero vpn_pid.

Windows production/fixture builds PASS, CTest6/6 PASS,
`MANAGED_RECIPROCAL_MODE_POLICY_PASS cases=32`, launch policy67 PASS,
parser39/39 and real process fixtures PASS, full real-mihomo runtime PASS
exit0/forced0 (`RECIPROCAL_GUARD_REGRESSION_PASS`). A repeated PowerShell
stderr-redirection harness stopped at the known offscreen OpenGL warning;
rerunning without that redirection completed successfully.
Actual MainWindow/GUI mode-transition E2E, no-YAML and OS-state verification
are NOT RUN. These are application-state guards, not a cross-thread OS
transaction. QWebChannel mutation commands remain unexposed pending the
command/result bridge contract and its end-to-end tests.

### Explicit QWebChannel commands and acknowledgement

Production bridge now exposes managedStart(groupId, requestId) and
managedStop(requestId), separate from connectToggle. IDs must be JSON numbers
representing nonnegative integral int values; strings/booleans/fractions and
overflow are refused before group lookup. Shared ManagedCommandContract emits
schema1 command/accepted/queued/error/runtime. accepted means queued only.
requestId is echoed in managedCommandResult (acknowledgement, not completion).
The JS helper window.mdmboxManaged dispatches mdmbox-managed-command-result.

MainWindow forwards controller operationFinished/runtimeFailed in sanitized
managedRuntimeEvent objects (schemaVersion/type/success/runtime). JS dispatches
mdmbox-managed-runtime. No raw validator diagnostics or profile content are
sent in these completion events; events are global, not request-correlated.
No visible controls or automatic start/reconnect are added.

Production/fixture builds PASS, CTest6/6 PASS, parser39/39/process fixtures PASS,
full real-mihomo smoke PASS exit0/forced0. test/webengine-smoke uses real
offscreen Qt6.7.2 WebEngine/QWebChannel with the shared contract parser/result:
MANAGED_COMMAND_JSON_WEBCHANNEL_CONTRACT_PASS cases=10. Its backend always
refuses launch, checking JSON transport, invalid IDs, valid IDs71/0, request
echo and no VPN claim. Known GPU/font/offscreen warnings remain.
This is NOT a production MainWindow launch E2E. Actual group→JS→production
bridge→MainWindow→core→completion, stop transport, mode transitions, navigation
lifetime and no-YAML build remain NOT RUN.

### Production bridge start/stop E2E

The production-graph parser runner now accepts `--managed-bridge-e2e`.
It creates an isolated cwd, real database group and validated synthetic full
snapshot, constructs actual MainWindow/controller and shell bridge, then uses
an off-the-record WebEngine page with local synthetic HTML to invoke:
JS Start → busy Stop refusal → real mihomo Ready → JS completion → JS Stop →
JS stopped. It checks all three command acknowledgements, matching group ID,
no VPN claim, closed 17890/19090 ports, ownershipNone and unchanged source.
Actual MainWindow TUN/system proxy enable methods are called while active and
must refuse before side effects, leaving both flags false.

The parser build defines MDMBOX_ISOLATED_APPLICATION_TEST to exclude automatic
legacy daemon/remembered system-mode startup only. Ordinary production startup
is unchanged. Shell loadContent=false avoids design HTML, remote assets and
periodic refresh. WebEngine test code lives in a separate static library so Qt
QML compile definitions do not enable the incompatible legacy ZXing QML path.
The executable directory must contain pinned mihomo.exe and the console signal
helper; the fixture does not install or overwrite runtime binaries.

Windows production/fixture builds PASS, this E2E PASS twice,
`MANAGED_PRODUCTION_BRIDGE_JS_START_BUSY_READY_STOP_PASS`, CTest6/6 PASS,
parser39/39/process fixtures PASS, full mihomo smoke PASS exit0/forced0.
Known GPU/font/offscreen/libpng/deprecation warnings remain.
Production hookPage helper/CustomEvent/visible HTML, ordinary startup with a
legacy daemon, crash-to-JS, navigation/reload, destruction while pending,
no-YAML and OS proxy/DNS/routes snapshots remain NOT RUN.

### Production hook, JS context replacement and crash delivery

The bridge fixture now uses the shell's actual QWebEngineView/page/channel and
production hookPage helper, rather than constructing a separate QWebChannel.
It verifies the profile is off-the-record and loads only synthetic local HTML.
Start/Stop use window.mdmboxManaged; acknowledgements and runtime events pass
through the production CustomEvent listeners. Repeated hookPage calls must not
duplicate events. While the core is active, setHtml replaces the JS context;
the replacement page attaches listeners without implicitly restarting the core.

On Windows a held process handle terminates the actual managed child with
exit42. The new JS context must receive one runtimeFailed event with Failed
and controllerReady=false; C++ verifies PID0 and cleared managed guards. Manual
JS restart then reaches Ready and Stop closes ports/frees ownership. Source
bytes remain unchanged; ready/crash/stopped event counters reject duplicates.

Fixture build PASS, E2E PASS twice:
MANAGED_PRODUCTION_HOOK_CUSTOM_EVENT_RELOAD_PASS and
MANAGED_PRODUCTION_CRASH_JS_FAILED_RESTART_PASS. CTest6/6 PASS, parser39/39 and
process fixtures PASS, full real-mihomo smoke PASS exit0/forced0.
Only test code changed; ordinary production build was not rerun in this step.
This tests setHtml context replacement, not navigation/back/forward or snapshot
resync after a missed event. Normal daemon startup, visible design UI, pending
destruction, request-correlated completions, no-YAML and OS snapshots remain
NOT RUN. GPU/font/offscreen/libpng warnings remain.

### Snapshot resync and completion correlation

Bridge managedSnapshot returns the current read-only application snapshot.
After subscribing to runtime events, the production JS helper requests this
snapshot and exposes it as window.mdmboxManaged.runtime, dispatching
mdmbox-managed-snapshot. refresh() repeats the request. A local event revision
discards its callback if a runtime event arrived since the request, avoiding
overwriting that newer event. This is cached controller state, not API health.

Accepted bridge Start/Stop commands retain requestId and command in MainWindow
until operationFinished; they are cleared before emitting completion. Refused
busy commands cannot replace them. runtimeFailed stays a global event without
claiming to complete an earlier command. IDs are caller correlation labels,
not deduplication keys or durable operation history.

Production/fixture builds PASS. Production E2E checks restored Ready after JS
context replacement without Start, and matching Start/Stop completion fields
despite the busy Stop refusal:
MANAGED_PRODUCTION_RELOAD_READY_SNAPSHOT_RESYNC_PASS. Existing hook/crash tests,
CTest6/6, parser39/39/process fixtures and full real-mihomo smoke PASS
exit0/forced0. Snapshot callback/event race branch has not been forced
deterministically. Concurrent refresh response ordering, pending reload,
duplicate/reused request IDs, no-YAML and normal startup remain NOT RUN.

### Controlled reconnect foundation (worker/session only)

ManagedSession/Controller reconnect the same active Ready group to an already
stored snapshot. Timeout/group/live gates, snapshot load, metadata expiry and
exhaustion, reviewed loopback projection and pinned validation precede Stop.
Preflight rejection leaves the old process running. The captured candidate is
used after confirmed graceful Stop without rereading storage. Forced or
unconfirmed Stop refuses replacement; replacement failure has no automatic
rollback/retry. The controller serializes reconnect and restarts monitoring
even when a preflight refusal leaves the previous session active.

Windows production/fixture builds PASS, CTest6/6 PASS, parser39/39/process
fixtures PASS, production bridge/hook/reload/crash E2E PASS and full mihomo
smoke PASS exit0/forced0. Runtime marker:
MANAGED_CONTROLLED_RECONNECT_PREFLIGHT_PRESERVATION_PASS. Checks include invalid
timeout, wrong group, resource policy and expired metadata preserving PID/Ready;
successful reconnect to a refreshed comment snapshot advances ownership
generation, reaches Ready, preserves source and gracefully stops.

No UI/bridge reconnect command or automatic downloader integration is added.
Actual endpoint/data-path changes, failed executable validation, forced or
unconfirmed Stop injection, post-Stop replacement failure, concurrent snapshot
mutation and expiry during preflight are NOT RUN. Last-working runtime rollback
is not implemented; this does not complete the refresh/apply release gate.

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
