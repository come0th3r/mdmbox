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
