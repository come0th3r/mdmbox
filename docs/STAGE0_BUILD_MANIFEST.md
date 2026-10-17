# Stage 0: Windows build/dependency manifest (evidence snapshot)

Checked **2026-10-17** in the local `beta-ilya` worktree, based on HEAD
`be1e9f8f945db9a7fe5055de6a56c5bdfd761a40`. The source tree has unrelated
unstaged/untracked work; no build was run. This is an evidence snapshot, not a
claim of clean-checkout reproducibility or a release SBOM.

## Local preflight result

Ran `tools/check-build-environment.ps1` without arguments. It is a presence-only,
read-only check. Result: **BLOCKED, 18 missing checks** (script exit 1); Node.js
24.20.0 and the QHotkey source are present. Missing in this environment:

- MSVC/Windows SDK developer environment, CMake, Ninja and Go.
- Qt 6 modules: Qt6, Widgets, Network, Svg, LinguistTools, WebEngineWidgets,
  WebChannel.
- CMake packages yaml-cpp, ZXing and protobuf under the expected dependency
  prefix.
- Sibling local Go replacement checkouts `libneko`, `sing-box`, `sing-quic`,
  and `sing` under `D:\repo_github`.

The current preflight checks only fixed conventional locations and current
environment variables; BLOCKED means not found there, not proof that the SDKs
are absent from every disk or another build host. No installs, downloads,
network requests, cleanup, submodule update or source modification were done.

## Intended Windows Release inputs

| Component | Version/revision | Evidence / unresolved item |
|---|---|---|
| Target | Windows x64, MSVC | The historical build-host was Windows 11 build 26100. The current machine is Windows; no compiler available here. |
| C++ language/build | C++17; CMake + Ninja | `CMakeLists.txt` requires C++17. The project minimum is CMake 3.5; prior Qt 6 build used `-DCMAKE_POLICY_VERSION_MINIMUM:STRING=3.5`. Current tool binaries unavailable. |
| MSVC / SDK | Build Tools 2022 17.14.42; MSVC tools 14.44.35207, compiler 19.44.35229; Windows SDK 10.0.26100.0 | Reported by the separate 2026-10-15 build-host record in `docs/STAGE0_BASELINE.md`; not independently revalidated here. |
| CMake / Ninja | CMake 4.4.4; Ninja 1.13.2 | Historical build-host record; no local version executable. |
| Qt | Qt 6.7.2, MSVC2019 x64 | Historical build-host record and notices inventory. Required Widgets, Network, Svg, LinguistTools, WebEngineWidgets and WebChannel; SerialPort was needed by the broader windeployqt scan. Exact package archive SHA list is external to this repository and must be attached to a reproducible artifact manifest. |
| C++ dependencies | yaml-cpp 0.7.0 (`0579ae3d976091d7d664aa9d2527e0d0cff25763`); ZXing 2.0.0 (`bdb857efae30f5f2abfcf3d626bf1156dc055bae`); Protobuf 21.4 (`c9869dc7803eb0a21d7e589c40ff4f9288cd34ae`) | Historical Release builds passed on the separate host. `libs/build_deps_all.sh` fetches versions but has no archive checksum verification; do not use as a reproducible bootstrap without a pinned source/artifact manifest. |
| QHotkey | Repository submodule, current checked-out contents | Present locally. Record exact submodule gitlink commit in a clean source manifest; this preflight only checks that `CMakeLists.txt` exists. |
| Go | Go 1.27.2 windows/amd64 | Required by `tools/build-baseline-core.ps1`; historical build-host PASS. No local Go executable. |
| Core source checkouts | `libneko` `1c47a3af71990a7b2192e03292b4d246c308ef0b`; sing-box `06557f6cef23160668122a17a818b378b5a216b5`; sing-quic `b49ce60d9b3622d5238fee96bfd3c5f6e3915b42`; sing v0.4.3 `f7cd94b14d31ace655e3f2285463c2ebf30294aa` + documented linkname backport | Pins from `libs/get_source_env.sh` and `tools/build-baseline-core.ps1`. Separate sibling checkouts are missing locally. The sing source is intentionally patched; `libs/patches/README.md` documents the exact patch/test overlay. |
| Go RPC / module graph | `go/cmd/nekobox_core/go.mod` and `go.sum`; local replacements above; explicit remote sing-dns/smux replacements | Manifests are tracked. A true fresh-checkout build also needs a documented safe materialization procedure for sibling repositories and patch application review; the ordinary baseline core script refuses to clone, patch, or edit manifests. |
| mihomo validator/runtime binary | v1.19.32 windows-amd64-v1 | Pinned archive SHA256 `00549b347d8e124600e46cac67d59293358454f465e9d86d2511567da56b7029`; executable SHA256 `0b54ea7b10e26f6ca628b49e77c13ad9b2587b23393a5b715769cbaeed012af6`, in `libs/mihomo-windows-baseline.json`. This is a config-validation/runtime test pin, not protocol approval. |
| Xray | Current legacy path exists; no release pin identified | `tools/build-local.ps1` downloads `releases/latest` without a checksum and `package-installer.ps1` packages whichever `xray.exe` is present. Must pin version, source/release artifact and SHA256 before claiming reproducible package inputs. |
| Node.js / browser test tooling | Node.js 24.21.0 on historical test host; 24.20.0 in current shell | No root `package.json`, lockfile or Playwright config discovered. Browser automation/runtime version is therefore not fully pinned by repository manifests. |
| Geodata | `build-local.ps1` uses `releases/latest` for sing geo files and v2ray rules data | No checksummed, dated versions are declared in that path. Managed provider/geodata provisioning remains unaccepted. |
| Installer | Inno Setup 6 `ISCC.exe`; Qt `windeployqt` | `tools/package-installer.ps1` defaults to Qt 6.5.3, unlike the recorded Qt 6.7.2 test host; installer input/version mismatch needs an explicit selected package baseline. ISCC exact version and artifact hash are not recorded. Current build/package script does not run. |
| Visual assets | Local `ui/shell/` qrc resources | No Node package manifest/lock; Figma source asset/font checksums and browser-vs-Qt renderer baseline remain open and UI visual acceptance is deferred by project priority. |

## Historical build evidence (not this HEAD)

- Qt/MSVC Windows Release GUI build: PASS, 80/80 build steps, source
  `4ad14e088081a8063f0abb88556357bf10854189`; output SHA256
  `DE348F296676A83DAEBA6E86870DEBA1178E24F9B7B96777F5F43DBABC68ECBC`.
- Core build: PASS with Go 1.27.2, explicit tags and `-mod=readonly`; output
  SHA256 `D28E54C410C09981181DEBFED373002ACA49EEFD5E8954D90E52A819665BED31`.
- Qt WebEngine/WebChannel smoke and isolated client checks are recorded in
  `docs/STAGE0_BASELINE.md`; none represents a clean-checkout build or package
  of this current HEAD.

## Script and reproducibility risks

- `tools/check-build-environment.ps1` is safe/read-only but only checks presence.
- `tools/build-baseline-gui.ps1` consumes caller-provided/prepared Qt and C++
  dependencies. It does not bootstrap or verify their archive hashes itself.
- `tools/build-baseline-core.ps1` verifies expected sibling Git revisions,
  tracked changes, patched sing blob, allowed test overlay and Go version; it
  builds `go/cmd/nekobox_core` with module manifests read-only and checks their
  post-build hashes. It is a guarded build entry point, not a clean-checkout
  dependency bootstrap.
- Legacy `tools/build-local.ps1` has personal absolute paths, mutates/removes
  dependency/build outputs, downloads latest Xray/geodata, and sets
  `GOSUMDB=off`; it is not an accepted reproducible build path.
- `tools/package-installer.ps1` also has a Qt 6.5.3 personal default, removes
  and recreates `dist\mdmbox-stage`, copies optional binaries/assets by presence,
  and has no checksum-pinned Xray input. Do not run it against this worktree or
  any directory that may contain user data.
- `libs/build_deps_all.sh` removes its chosen install prefix and downloads
  dependency archives without checking an approved SHA256 manifest. It is not
  safe to use as a clean bootstrap without a new isolated destination and
  explicit artifact verification.

## Remaining evidence needed

1. Supply a clean Windows VM/worker with the exact inputs above and a source
   checkout at the candidate SHA; record archive URLs, upstream digests, local
   SHA256, signatures where available, tool versions, submodule gitlinks and
   dependency repository HEAD/patch diffs.
2. Define and test a **non-destructive** dependency materialization process in
   a fresh sibling root. Preserve `go.mod`/`go.sum`; verify `-mod=readonly` and
   normal Go checksum/linker checks. No live user configuration or VPN is used.
3. Align the selected Qt version across GUI build, package scripts and test
   fixtures; pin Xray, geodata and ISCC or explicitly mark them out of scope.
4. Run the documented Release configure/build from a clean checkout, then
   deployment, smoke and installer verification on a disposable clean VM. Keep
   build, deployment, package and system-network acceptance as separate gates.

Current result: **local build BLOCKED; remote valid-root parser target build/runtime PASS; clean-checkout reproducibility NOT RUN**.

## Remote worker revalidated and used (2026-10-17)

- User-confirmed SSH build host: `build@192.168.1.36` (`DESKTOP-G7VRDQJ`,
  Windows build 26100). Clean host is separately `clean@192.168.1.37`; it was
  not modified by this work. Local preflight blockers are not remote blockers.
- Existing `C:/BuildTools`, QtRoot
  `C:/Users/build/mdmbox-build/Qt/6.7.2/msvc2019_64`, DependencyRoot
  `C:/Users/build/mdmbox-build/cpp-built` reused. CMake 4.4.4, Ninja 1.13.2,
  compiler 19.44.35229, qmake 6.7.2, protoc 3.21.4 and VC++ x64 runtime
  v14.44.35211.00 verified. No SDK installation/download required.
- Fresh owned source/build root `C:/Users/build/mdmbox-build/mdm-mig-run-a4kdLv`:
  Release parser target configure/build **PASS**, checksum-pinned valid-root
  migration test **PASS twice**. All 493 input files retain their manifest SHA256
  after build and both runs; no remaining process for the exact artifact.
  This is a dirty-worktree snapshot, not a clean checkout or full GUI/core release.
- Artifact hash, source manifest, commands, failures fixed during setup and logs:
  `test/subscription-parser/LEGACY_MIGRATION.md`. Dependency archive verification,
  remote Go source revision/patch revalidation and clean bootstrap remain separate.
- Subsequent MIG-05/R1: fresh owned root
  `C:/Users/build/mdmbox-build/mdm-mig05-a8W68j-r1`, 494 hashed inputs unchanged.
  Release build PASS; valid-root before/after PASS; seven adversarial cases
  observed twice (16 positive + 35 rejection children per run), **not migration
  acceptance**. Artifact/source hashes and unsafe legacy behavior:
  `test/subscription-parser/LEGACY_MIGRATION_ADVERSARIAL.md`. Existing SDKs reused.
- MIG-06/R1 checked atomic-save fix: fresh owned root
  `C:/Users/build/mdmbox-build/mdm-mig06-PPOy4s-r1`, 494 hashes unchanged;
  Release configure/build PASS, valid-root before/after PASS, seven cases repeated
  with atomic-v1 persistence assertions. Remote tests 15/15, local source/probe
  29/29 PASS. No installs/downloads or clean-host changes. Exact hashes, commands,
  review and remaining failure-acceptance gaps:
  `test/subscription-parser/LEGACY_PERSISTENCE.md`. Still dirty-snapshot evidence,
  **not** clean-checkout or full GUI/core release reproduction.

## Safe local checks (2026-10-17)

MIG-07/R2: new owned root `C:/Users/build/mdmbox-build/mdm-mig07-m2gnBC-r2`,
494 hashes unchanged; Release configure/build PASS, valid-root before/after PASS,
11 preservation/characterization cases repeated (24+55 children each). Remote
16/16 and local source/probe 30/30 PASS. SDKs reused, no clean-host changes;
dirty snapshot, not clean checkout. Exact evidence:
`test/subscription-parser/LEGACY_LOAD_PRESERVATION.md`.

- `node --check ui/shell/app.js` — **PASS** (syntax only).
- `node --check tools/core-loopback-smoke.mjs` and
  `node --check tools/subscription-probe.mjs` — **PASS** (syntax only; no probes
  or network requests were started).
- `node --test test/subscription-probe.test.mjs` — **PASS, 14/14** synthetic
  tests. They use test-local HTTP fixtures and do not contact a live panel.
- `git diff --check` — **PASS** for the current worktree.

These checks do not need the missing C++/Go toolchain and do not change the
clean-checkout build status above.
