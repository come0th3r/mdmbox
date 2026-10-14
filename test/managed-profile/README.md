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

This first component is not wired into subscription refresh/storage yet.
Structural acceptance is **not** mihomo config validation or protocol support.
Provider-only profiles are outside this initial mikan inline-proxy contract.
Resource-bounded subprocess validation and rejection of mikan denial stubs
must precede accepting a document as a runnable managed subscription.
