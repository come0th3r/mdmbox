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
