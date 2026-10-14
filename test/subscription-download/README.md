# Bounded managed subscription download tests

Build in MSVC developer environment with Qt6 Core/Network:

```powershell
cmake -S test/subscription-download -B <separate-build-dir> -G Ninja -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=<qt-root>"
cmake --build <separate-build-dir>
ctest --test-dir <separate-build-dir> --output-on-failure --timeout 30
```

The local QTcpServer test covers successful body/metadata/HWID delivery,
redirect rejection, declared oversize, empty body, malformed metadata, HTTP
403, timeout, pre-cancel and cancellation during a pending request. Failure
must preserve the previous download result. It uses synthetic ephemeral UUIDs
which are not printed or persisted. A separate production-mode target verifies
that plain HTTP loopback is rejected without the test-only compile definition.

Production downloader is HTTPS-only, verifies peers, disables automatic
redirects, caps accumulated body at 4 MiB and reply buffer at 64 KiB, uses a
bounded deadline/cancellation polling, never returns raw transport errors or
response bodies as error text, and explicitly uses NoProxy. Proxy support
must be supplied later as a deliberate policy; it does not inherit OS proxy
settings. It is synchronous worker code, not a GUI-thread API.

TLS certificate fixtures, streamed/chunked oversize, truncation, 429/backoff,
large header limits, explicit proxy policy and cross-origin approval remain
pending. Size bound applies to body, not all Qt/TLS internal allocations.
This component is not yet connected to legacy GroupUpdater or the store.
