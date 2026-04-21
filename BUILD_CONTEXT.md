# NekoBox / Nekoray Build Context

## Workspace

- Root workspace: `C:\Users\0th3r\nekoray`
- Main source tree: `C:\Users\0th3r\nekoray\nekoray-main`
- Local patched dependency checkout: `C:\Users\0th3r\nekoray\sing`
- Local source checkouts used by Go build:
  - `C:\Users\0th3r\nekoray\libneko`
  - `C:\Users\0th3r\nekoray\sing-box`
  - `C:\Users\0th3r\nekoray\sing-quic`

## Goal already implemented

The local tree was modified to:

1. Improve subscription handling beyond plain `vless://` links.
2. Improve TUN stability and add a practical workaround for `Zapret + Discord + NekoBox`.
3. Preserve existing functionality while making the project buildable on this machine.
4. Make the app runnable locally from the `build` directory.

## Functional changes already made in app code

### Subscription support

Files changed:

- `sub/GroupUpdater.cpp`
- `main/HTTPRequestHelper.hpp`
- `main/HTTPRequestHelper.cpp`

Behavior added:

- Subscription parsing now accepts richer formats, not only simple base64/classic links.
- JSON provider-style payloads with arrays like `outbounds`, `proxies`, `servers`, `links`, `nodes` are handled.
- Custom headers in subscription URLs are supported via `|Header=Value`.
- One retry was added on request failure.

### TUN stability / Zapret compatibility

Files changed:

- `db/ConfigBuilder.cpp`
- `ui/dialog_vpn_settings.cpp`
- `ui/dialog_vpn_settings.ui`

Behavior added:

- Process matching supports both:
  - `process_name`
  - `process_path`
- TUN settings got a compatibility preset for:
  - `Discord.exe`
  - `DiscordCanary.exe`
  - `DiscordPTB.exe`
  - `DiscordDevelopment.exe`
  - `winws.exe`
  - `zapret.exe`
  - `zapret-discord.exe`
  - `GoodbyeDPI.exe`
  - `WinDivert.exe`

Practical conclusion:

- `Zapret + Discord + TUN` conflict is not a pure GUI bug.
- When Discord traffic is fully captured by sing-box TUN, Zapret/WinDivert may no longer see/process it the same way.
- The practical workaround is to bypass Discord and helper processes from TUN while keeping the rest tunneled.

### TUN stack mapping bug fixed

Files changed:

- `fmt/Preset.hpp`
- `db/ConfigBuilder.cpp`
- `ui/dialog_vpn_settings.cpp`
- `ui/dialog_vpn_settings.ui`

Important bug that was fixed:

- The UI order and config mapping for TUN stack were inconsistent.
- `Mixed` could be shown in UI while `gvisor` was actually written into config.

Current state:

- `gVisor` was removed from the visible UI choices.
- Supported runtime choices are now effectively:
  - `mixed`
  - `system`

Important conclusion:

- Split routing by app/path/CIDR does **not** require `gVisor`.
- Those rules are generated independently from the TUN stack backend.

## Build environment installed on this machine

Installed and used successfully:

- Go `1.26.2`
- CMake `4.3.1`
- Ninja `1.13.2`
- Python `3.12`
- Visual Studio Build Tools 2022 with MSVC + Windows SDK
- Qt `6.5.3` at `C:\Qt\6.5.3\msvc2019_64`

Helper script:

- `tools/enter-build-env.ps1`

## Third-party/dependency work already done

### C++ side

Built locally into `libs/deps/built`:

- `protobuf`
- `yaml-cpp`
- `zxing-cpp`

Several old upstream `CMakeLists.txt` files were patched for compatibility with newer CMake.

### Missing source trees fetched locally

These were fetched because the source archive alone was not enough:

- `libneko`
- `sing-box`
- `sing-quic`
- `3rdparty/QHotkey`

### Go side: actual compatibility fixes required

The original Go dependency graph was not buildable as-is on this machine due to:

- dead pseudo-versions
- API drift between `sing-box` and `github.com/sagernet/sing`
- old `go:linkname` usage broken by newer Go

Main fixes:

1. `github.com/sagernet/smux` dead pseudo-version was replaced with:
   - `github.com/xtaci/smux v1.5.34`
2. `github.com/sagernet/sing` is forced to local patched checkout:
   - `replace github.com/sagernet/sing => ../../../../sing`
3. Local `sing` checkout was created from module cache `v0.4.3`.
4. In `sing/common/control/bind_finder_default.go`, the old
   `//go:linkname net.errNoSuchInterface`
   hack was removed and replaced with a normal local error value.
5. Default core build currently excludes:
   - `with_gvisor`
   - `with_wireguard`

Reason:

- `gvisor` and older `wireguard-go` references were pinned to broken/unavailable pseudo-versions.
- The immediate goal was a stable reproducible build and runnable app.

## Runtime layout requirements

The GUI expects runtime assets next to `nekobox.exe`.

Required files in `build`:

- `nekobox.exe`
- `nekobox_core.exe`
- `geoip.db`
- `geosite.db`

This was verified by code path:

- `main/NekoGui.cpp`
- `db/ConfigBuilder.cpp`

The build script was updated to:

- copy `nekobox_core.exe` into `build`
- download `geoip.db`
- download `geosite.db`

## Build script status

Main script:

- `tools/build-local.ps1`

Current script behavior:

1. Loads MSVC/Qt environment.
2. Configures and builds GUI with CMake/Ninja.
3. Downloads `geoip.db` and `geosite.db` into `build`.
4. Builds `go/cmd/nekobox_core/nekobox_core.exe`.
5. Copies `nekobox_core.exe` into `build`.

Current expected successful command:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\build-local.ps1 -GoProxy direct
```

## Verified successful artifacts

Successful local build outputs:

- `build/nekobox.exe`
- `build/nekobox_core.exe`

The app was also verified to the point that:

- GUI starts
- core starts
- subscription import works
- URL test works
- TUN no longer fails due to missing `gVisor` if `mixed/system` is used

## Important current limitations

### 1. No `gVisor` in current core build

Current core is intentionally built without `with_gvisor`.

Impact:

- If an older config or UI mapping tries to use `gvisor`, TUN startup fails.
- After the UI/mapping fix, the normal runtime path should use `mixed` or `system`.

### 2. No `WireGuard` in current core build

Current core is also built without `with_wireguard`.

Reason:

- The previous pinned `wireguard-go` pseudo-version was broken.
- A proper return of WireGuard support should be done against official upstream and tested separately.

### 3. Local patch in dependency

There is a local patch in:

- `C:\Users\0th3r\nekoray\sing\common\control\bind_finder_default.go`

Any future rebuild strategy that removes the local `replace` must account for that patch or move to a compatible upstream version/toolchain.

## Recommended next development steps

### High priority

1. Re-test TUN with:
   - `mixed`
   - `system`
   - process/path bypass rules
   - CIDR bypass/proxy rules
2. Validate the `Zapret / Discord` preset in real usage.
3. Confirm imported subscriptions from:
   - direct link lists
   - base64 lists
   - JSON providers
   - Clash-style sources if relevant

### Medium priority

1. Properly restore WireGuard support.
2. Reintroduce `gVisor` only if it is really needed.
3. Clean up the Go module graph so the build does not depend on ad-hoc `droprequire` workarounds.

### WireGuard restoration direction

The user explicitly noted that WireGuard upstream points to the official repos.

That means the likely proper path is:

- use official `wireguard-go` upstream:
  - `https://git.zx2c4.com/wireguard-go`
- use official `wgctrl-go` upstream:
  - `https://github.com/WireGuard/wgctrl-go`

This should be done as a deliberate compatibility pass, not by reintroducing the old broken pseudo-version references.

## Files most relevant for continuing development

Feature/runtime logic:

- `db/ConfigBuilder.cpp`
- `sub/GroupUpdater.cpp`
- `main/HTTPRequestHelper.cpp`
- `main/HTTPRequestHelper.hpp`
- `ui/dialog_vpn_settings.cpp`
- `ui/dialog_vpn_settings.ui`
- `fmt/Preset.hpp`
- `main/NekoGui.cpp`

Build/runtime scripts:

- `tools/build-local.ps1`
- `tools/enter-build-env.ps1`

Go module/build context:

- `go/cmd/nekobox_core/go.mod`
- `go/cmd/nekobox_core/go.sum`
- `sing-box/go.mod`
- `sing/common/control/bind_finder_default.go`

## Short status summary

Current local state is good enough to continue app development from a working baseline:

- build is reproducible
- GUI runs
- core runs
- subscriptions import
- URL test works
- TUN stack mapping bug is fixed
- app/path/CIDR split-routing can be tested without `gVisor`

The main unfinished area is restoring optional advanced backends cleanly:

- `gVisor`
- `WireGuard`

