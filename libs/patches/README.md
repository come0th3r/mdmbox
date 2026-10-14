# sing v0.4.3 compatibility patch

Base: `SagerNet/sing` tag `v0.4.3`, commit
`f7cd94b14d31ace655e3f2285463c2ebf30294aa`.

`sing-v0.4.3-linkname.patch` backports the one-file upstream fix
[`a33349366d899068145f2d0e3ea0f5b2632fa3f2`](https://github.com/SagerNet/sing/commit/a33349366d899068145f2d0e3ea0f5b2632fa3f2),
“Remove bad linkname usage”. Hunk offsets are adapted to v0.4.3;
the code change is unchanged. Upstream licensing remains applicable.

It removes a reference to the private standard-library sentinel
`net.errNoSuchInterface` and creates an error with the same message inside
the existing `net.OpError`. This follows upstream; callers must not rely
on identity with the private sentinel. No linker checks are disabled.

Apply only to the pinned, otherwise clean checkout after `git apply --check`.
Keep the resulting source diff visible; do not claim it is an unmodified tag.
Build scripts must not silently apply it during an ordinary build.

Validation on Windows/Go 1.27.2: patch check/apply and core build passed
with `-mod=readonly` and normal linker checks. Copy
`test/fixtures/sing-control-compat_test.go` into the dependency as
`common/control/mdmbox_compat_test.go`, then run:

```powershell
go test -mod=readonly -v ./common/control -run TestMDMBOX -count=1
```

Both cached IPv4/IPv6 lookup and missing-interface error tests passed.
The test file is an explicit test overlay, not part of the upstream tag.
