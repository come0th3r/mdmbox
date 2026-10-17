# Live subscription probe (explicitly authorized test accounts only)

This one-shot diagnostic exercises the production HTTPS downloader,
installation-identity header, metadata contract, managed-profile parser/store,
and checksum-pinned mihomo config validator. It does **not** start mihomo as a
runtime, connect to a proxy, enable TUN/system proxy, or contact any endpoint
other than the two supplied subscription URLs.

The two URLs are read from standard input so they are not command-line
arguments. The program generates one temporary installation UUID and reuses it
for both requests. URL strings, response bodies, profile data, headers, HWID,
and textual transport diagnostics are never printed. Only numeric HTTP status,
Qt network-error code, TLS-error boolean, response byte count, and coarse
pipeline outcome are reported. State is held only in a
`QTemporaryDir` and removed on exit. A request can still register the test
installation or consume a device slot on the subscription server; use only
accounts for which that side effect has been authorized.

The executable accepts only an absolute path to the checksum-pinned mihomo
1.19.32 binary. For each request it reports a coarse pipeline outcome plus
numeric HTTP status, Qt network-error code, TLS-error boolean, and response byte
count. Outcomes distinguish fetch rejection, denial/unavailable stub,
invalid/unsupported profile, expired/exhausted metadata, pinned-core config
rejection, later store rejection, and accepted/config-validated profile. It
does not print server-side reason text, response headers, body, or profile data.

Build this directory in an isolated Qt 6/MSVC build tree with yaml-cpp and
network access enabled. Feed exactly two newline-separated HTTPS URLs on stdin:

```powershell
$urls = @($revokedTestUrl, $workingTestUrl) -join "`n"
$urls | .\mdmbox_live_subscription_probe.exe <absolute-pinned-mihomo.exe>
```

Do not put real subscription URLs in repository files, shell history, logs,
diagnostics, or project memory. A rejected working control invalidates the
comparison; it does not prove the revoked link caused the failure.
