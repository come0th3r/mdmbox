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
