# Legacy subscription parser regression runner

Configure the ordinary application dependency graph with
`-DMDMBOX_SUBSCRIPTION_PARSER_TEST=ON` in a **separate build directory**.
This replaces the application entry point with `main.cpp` in this directory;
it never starts the production window, core, proxy or TUN lifecycle.
The console executable is `mdmbox_subscription_parser_test.exe` on Windows.
Run with Qt runtime DLLs available and `QT_QPA_PLATFORM=offscreen`.

The test uses a temporary working directory and artificial loopback profiles.
It checks that staging URI, Base64, JSON and Clash imports produces detached
entities without changing the existing group or profile files. Empty, HTML,
malformed YAML/JSON and unrecognized responses must produce no accepted
replacement. YAML exception details are not shown in a dialog in staging mode.

This is a parser regression test, **not** proof of atomic persistence, core
validation, full mihomo-profile preservation or protocol compatibility. The
legacy storage commit still uses individual JSON writes; crash recovery,
write-error rollback and subscription concurrency require subsequent work.

The default regression command also runs a synthetic legacy Clash VLESS REALITY
mapping case through production `RawUpdater::updateClash`. It checks that UUID,
Vision flow, SNI, client fingerprint, public key and short ID reach the Nekobox
bean, then verifies the production sing-box outbound and VLESS share-link
serialization/parse round-trip without changing stored group/profile files.
Credentials are deterministic test values and do not identify a real endpoint.
This covers the legacy single-node YAML import/export mapping only: it is not
the `mihomo-full` managed-document path, subscription refresh, mihomo YAML export
or a REALITY handshake/data-path test.

The runner also checks group JSON file roundtrip with `subscription_kind`,
legacy JSON without that field defaulting to `links`, and production
`GroupUpdater::Update` rejection for unknown mode and managed preflight failure.
Group/profile bytes, order and metadata must remain unchanged; no managed
envelope may be created. The test executable has no pinned mihomo next to it,
so this exercises missing-core rejection, not successful HTTPS refresh.
It installs no-op log/dialog callbacks normally supplied by MainWindow.

## Synthetic legacy-root reopen fixture

The early `--legacy-migration` branch uses `QCoreApplication`, the production
global profile loader and only an owned synthetic seed/clone. It checks valid
root load/save/reopen preservation with `flag_reorder=false`; it bypasses every
other parser, UI, refresh and core fixture. Full scope, checksum-pinned launcher
and the source-only/runtime evidence distinction are in [LEGACY_MIGRATION.md](LEGACY_MIGRATION.md).
C++ Release build and two checksum-pinned runs of this valid-root slice are
**PASS (2026-10-17)** on the SSH build host; artifact/source hashes and limits
are in that document. Full migration, failure/recovery and reorder acceptance
remain open; existing parser PASS results are separate evidence.

MIG-05/R1 adds seven offline malformed/orphan/duplicate/write-lock cases:
`LEGACY_MIGRATION_ADVERSARIAL.md`. The exact Windows candidate built and completed
the observation suite twice (16 positive + 35 negative children per run), with
valid-root PASS before/after. **Characterization only, acceptance=NOT_ACCEPTED**:
legacy loading deletes malformed/unsupported profiles, and blocked Save can
report changed while disk stays unchanged. Production persistence is not fixed.

**Update MIG-06/R1:** `LEGACY_PERSISTENCE.md` records checked atomic per-file save,
unchanged cache on failure and explicit error status; bool `Save()` remains a
change hint, not success. Exact Windows candidate rebuilt, valid-root before/after
PASS and adversarial suite repeated with `persistence=atomic-v1`. Full migration
and caller/UI failure propagation remain open; prior hashes above are historical.

## Production shell UI fixture

With the same Qt6/YAML-enabled test build, run
`mdmbox_subscription_parser_test.exe --shell-ui-only` with the Qt runtime on
`PATH` and `QT_QPA_PLATFORM=offscreen`. This separate fixture
constructs the production shell, local qrc page and QWebChannel in a temporary
    working directory, with synthetic in-memory groups/profiles. It checks empty
    home/server states, active navigation synchronization, HTML escaping, production
    badge rendering, server-selection bridge behavior, subscription auto-update
    interval/timer state, and the native log buffer's rendering/copy/clear actions.
    It does not start mihomo or enable TUN/system proxy.
    Supplying a capture directory additionally requests WebEngine PDF output; on the
    current offscreen Windows fixture this capture path is unstable and is not part
    of the passing integration command. PDFs are renderer output, not a native window
    screenshot or Figma pixel-diff. Import dialog, DPI, native handoff and full visual
    acceptance remain separate checks.

Verified Windows command uses `-DQT_VERSION_MAJOR=6` explicitly (project default
is Qt5), `-DCMAKE_POLICY_VERSION_MINIMUM:STRING=3.5`, Qt/dependency prefix,
Release/Ninja and the test option above. Use a separate build directory.

## Optional actual HTTPS/core/store refresh

Generate external short-lived localhost fixtures using
`test/subscription-download/tls-test.cnf` (see that runner's README). Place the
checksum-pinned v1.19.32 binary as `mihomo.exe` beside this test executable,
never overwrite a different existing binary. Then run:

```powershell
$env:QT_QPA_PLATFORM = 'offscreen'
<build-dir>/mdmbox_subscription_parser_test.exe <temp-dir>/test-cert.pem <temp-dir>/test-key.pem
```

Two arguments enable synthetic HTTPS origin and process-local certificate
trust. Actual GroupUpdater, downloader, persisted identity, real config-check
and atomic store execute with no injected transport/validator and no HTTP
exception. Temporary database is removed on exit. Checks include exact source
and metadata, genuine build/core UA, preserved path/query and single format,
stable HWID over four requests, unsupported protocol and denial refusal without
replacement, second successful generation and byte-exact previous snapshot.
Legacy profiles/group JSON remain unchanged by refresh. No raw request/HWID
is printed. Without arguments this optional test does not run.

This proves the production backend path in an isolated entry point, not the
actual application window, private/live panel, provider cache, VPN connection
or runtime apply/reconnect. Regenerate expired certificates; no system trust
or proxy/TUN changes are made.

## Managed refresh through the production bridge

On the isolated production-graph parser build, place the checksum-pinned
`mihomo.exe` beside the runner and generate a short-lived synthetic certificate
outside the repository using `test/subscription-download/tls-test.cnf`. Invoke:

```powershell
$env:QT_QPA_PLATFORM = 'offscreen'
<build-dir>/mdmbox_subscription_parser_test.exe --managed-bridge-e2e <cert.pem> <key.pem>
```

The fixture trusts that certificate only in-process and serves a synthetic
SOCKS5 profile over localhost HTTPS. It exercises actual shell hook/QWebChannel,
MainWindow guards, controller, downloader, pinned mihomo validation, atomic
store and apply path. A subsequent HTTP 200 response with expired metadata must
be rejected after fetch without validation/commit, leaving the current ready
process and stored source unchanged. The test-only CA override is restricted to
loopback URLs, synchronized across the controller worker, and compiled only in
the isolated parser target; production retains normal peer verification. No real
panel, profile, system certificate store, proxy, TUN or routes are used. There
is no automatic scheduler, and this does not imply a successful external VPN
connection.

## Combined REALITY refresh-to-runtime fixture

Build the test-only generator and run it with an already-created temporary
directory outside the repository (it generates random X25519 key, UUID, short
ID and ports):

```powershell
$fixture = Join-Path $env:TEMP ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$env:GO111MODULE = 'off'
go build -o (Join-Path $fixture 'generate-managed-reality-fixture.exe') `
  .\test\subscription-parser\generate-managed-reality-fixture.go
& (Join-Path $fixture 'generate-managed-reality-fixture.exe') $fixture
openssl req -x509 -newkey rsa:2048 -nodes -days 1 `
  -keyout (Join-Path $fixture 'key.pem') -out (Join-Path $fixture 'cert.pem') `
  -config .\test\subscription-parser\reality-test.cnf
```

Its `reality-server.json` inbound and
camouflage handshake target must both bind to `127.0.0.1`; the harness starts its
own TLS camouflage listener using the supplied test certificate and key. Use the
test-only sing-box binary built with `with_reality_server,with_utls`. Put the
checksum-pinned `mihomo.exe` beside the parser executable, then invoke:

```powershell
$env:QT_QPA_PLATFORM = 'offscreen'
<build-dir>/mdmbox_subscription_parser_test.exe <cert.pem> <key.pem> `
  <sing-box-test.exe> <reality-server.json> <managed-reality.yaml>
```

The certificate SAN includes both `localhost` (the local HTTPS refresh origin)
and `reality.test` (the REALITY camouflage SNI). Keep `$fixture` outside the
checkout and remove it after the run; it contains generated private keys and
credentials.

This opt-in path serves the matching full profile over the existing local HTTPS
fixture through production `GroupUpdater::Update`, verifies the managed source
commit and indexes, and starts its own synthetic REALITY server plus TLS
camouflage listener, bound to loopback. It then starts `ManagedSession` from that
exact envelope and checks one HTTP round-trip through REALITY Vision/TCP to a
synthetic loopback origin. It stops its own session, listeners and REALITY server
before returning. All REALITY
keys/UUID/short-ID values must be generated per run and remain outside Git. This
does not exercise UDP, public nodes, TUN/system proxy, or mihomo YAML export.

**Repeatability verified on 2026-10-17:** the repository-tracked Go profile
generator and `reality-test.cnf` were transferred together with the required
test overlay, built/run outside the checkout, and used for a full combined
production refresh-to-session run. The pinned sing-box server config and
mihomo client config were accepted, then markers included
`GROUPUPDATER_MANAGED_REALITY_REFRESH_TO_SESSION_LOOPBACK_DATA_PATH_PASS
requests=1`, `PRODUCTION_GROUP_HTTPS_REALITY_SESSION_E2E_PASS`, and
`SUBSCRIPTION_PARSER_STAGING_PASS checks=44`. The scratch overlay was restored
with matching SHA256 checks and fixture/core processes were absent after cleanup.
The certificate was generated with Go's standard crypto/x509 on that host,
because OpenSSL was not installed there; the tracked OpenSSL config remains the
documented certificate profile for environments that provide OpenSSL. Generated
credentials, keys, certificates, and temporary source overlays remain untracked
and outside the checkout.

After the HTTPS apply/rejection checks, the same fixture injects synthetic typed
controller completions (not process lifecycle results) through the production
`MainWindow` mapping, QWebChannel, production hook helper and JS CustomEvent handler.
It checks correlated `stop-failed`, `restore-failed` and `restored` payloads,
including request ID, outcome, error, sanitized runtime snapshot and
`vpnConnected=false`, then requests a fresh snapshot to confirm the injection did
not mutate controller state. This is delivery/serialization coverage; lifecycle
semantics remain in the real-core runtime fixture.
