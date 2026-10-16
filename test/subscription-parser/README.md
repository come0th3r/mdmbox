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

The runner also checks group JSON file roundtrip with `subscription_kind`,
legacy JSON without that field defaulting to `links`, and production
`GroupUpdater::Update` rejection for unknown mode and managed preflight failure.
Group/profile bytes, order and metadata must remain unchanged; no managed
envelope may be created. The test executable has no pinned mihomo next to it,
so this exercises missing-core rejection, not successful HTTPS refresh.
It installs no-op log/dialog callbacks normally supplied by MainWindow.

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
profile over localhost HTTPS. It exercises actual shell hook/QWebChannel,
MainWindow guards, controller, downloader, pinned mihomo validation, atomic
store and apply path. A subsequent HTTP 200 response with expired metadata must
be rejected after fetch without validation/commit, leaving the current ready
process and stored source unchanged. The test-only CA override is restricted to
loopback URLs, synchronized across the controller worker, and compiled only in
the isolated parser target; production retains normal peer verification. No real
panel, profile, system certificate store, proxy, TUN or routes are used. There
is no automatic scheduler, and this does not imply a successful external VPN
connection.