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

429/backoff,
large header limits, explicit proxy policy and cross-origin approval remain
pending. Size bound applies to body, not all Qt/TLS internal allocations.
Production GroupUpdater now binds this component for explicit managed groups;
successful end-to-end refresh remains pending.

## Process-local TLS fixture

Generate a short-lived synthetic certificate/key outside the repository:

```powershell
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -config test/subscription-download/tls-test.cnf -keyout <temp-dir>/test-key.pem -out <temp-dir>/test-cert.pem
cmake -S test/subscription-download -B <separate-build-dir> -G Ninja -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=<qt-root>" "-DMDMBOX_TLS_TEST_CERT=<temp-dir>/test-cert.pem" "-DMDMBOX_TLS_TEST_KEY=<temp-dir>/test-key.pem"
cmake --build <separate-build-dir>
ctest --test-dir <separate-build-dir> --output-on-failure --timeout 60
```

Do not commit keys/certificates or use real credentials. Regenerate expired
fixtures. TLS target has no HTTP exception. Trust changes only inside the test
process, never in Windows certificate storage. Server VerifyNone means no
client certificate is requested; downloader still verifies server and hostname.

Checks: trusted HTTPS body/metadata/HWID; untrusted certificate and hostname
mismatch rejected before HTTP delivery; redirect with no second request;
truncated/chunked oversized bodies rejected with prior result preserved.
Expiry/revocation and successful GroupUpdater/core/store refresh are pending.
TLS test is registered only with both fixture paths; base 2/2 does not test TLS.
Windows with fixtures: 3/3 PASS.
