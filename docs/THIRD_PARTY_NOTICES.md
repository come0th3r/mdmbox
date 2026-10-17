# Third-party notices — technical alpha (audit in progress)

This inventory describes the intended Windows x64 alpha payload. It is not a
legal opinion, a complete SBOM, or authorization for public distribution.
The packaging script takes explicit Qt license inputs for the exact binary
build, verifies that the Qt WebEngine input list contains `LICENSE.Chromium`
and every file in `LICENSES/`, adds pinned core repositories' root licenses,
and records a per-module Go license inventory in the archive. The caller must
still establish which Qt licenses apply to the deployed modules and review
all components; collecting files does not make that determination.

## Main components

| Component | Pinned source/version | License evidence and status |
| --- | --- | --- |
| MDMBOX GUI | This repository; see `manifest.json` source commit | GPL-3.0-or-later, `LICENSE` included |
| nekobox_core | `go/cmd/nekobox_core/go.mod`; dependency pins in `libs/get_source_env.sh` | GPL-3.0-or-later source tree; bundled executable is compiled from that source |
| libneko | `1c47a3af71990a7b2192e03292b4d246c308ef0b` | Pinned tree has no root LICENSE file. **Unresolved licensing blocker**; do not treat this as clearance to redistribute. |
| sing-box | `06557f6cef23160668122a17a818b378b5a216b5` | GPL-3.0-or-later; upstream license adds a restriction on use of its name/association without consent. License copied into `LICENSES/`. |
| sing-quic | `b49ce60d9b3622d5238fee96bfd3c5f6e3915b42` | GPL-3.0-or-later; upstream license copied into `LICENSES/`. |
| sing | `v0.4.3`, `f7cd94b14d31ace655e3f2285463c2ebf30294aa` plus the documented one-file upstream backport | GPL-3.0-or-later; patched source and patch are in this repository; upstream license copied into `LICENSES/`. |
| mihomo | `v1.19.32`, Windows amd64 v1; executable SHA is in `libs/mihomo-windows-baseline.json` | GPL-3.0 source release; this archive contains the source project's GPL text as `LICENSES/GPL-3.0.txt`. Exact release notices/source offer still need review. |
| Qt runtime | Qt 6.7.2 MSVC 2019 x64; dynamically linked DLLs | Qt modules have module-specific LGPL/GPL/commercial terms. The exact Qt 6.7.2 source package's `LICENSES/` documents are required inputs and copied under `LICENSES/Qt/`. Module-to-binary applicability and corresponding-source/relink notices still require audit. |
| Qt WebEngine / Chromium | Qt WebEngine 6.7.2 deployment | Chromium and bundled third-party notices apply. Exact-version `LICENSE.Chromium` and complete upstream `LICENSES/` tree are required inputs, copied under `LICENSES/QtWebEngine-Chromium/`. The version/build-specific Chromium third-party inventory still requires review. |
| QHotkey | Repository submodule | BSD-3-Clause; license copied into `LICENSES/`. |
| Inter font | Repository `res/Inter` | SIL Open Font License 1.1; license copied into `LICENSES/`. |
| Go modules | Resolved runtime dependency graph of the pinned core | Root license/notice files are collected into `LICENSES/go-modules/`; the generated CSV identifies missing root files. This collection is not a source-level license scan. |
| MSVC runtime | Official `vc_redist.x64.exe` staged by `windeployqt` | Microsoft Visual C++ Redistributable x64. Vendor package is unmodified; Microsoft's license terms apply. |

## Source and review references

- Qt LGPL guidance: <https://doc.qt.io/qt-6/lgpl.html>
- Qt Windows deployment: <https://doc.qt.io/qt-6/windows-deployment.html>
- Qt WebEngine 6.7.2 notices: <https://github.com/qt/qtwebengine/tree/v6.7.2>
- mihomo v1.19.32: <https://github.com/MetaCubeX/mihomo/tree/v1.19.32>
- sing-box pinned source: <https://github.com/MatsuriDayo/sing-box/tree/06557f6cef23160668122a17a818b378b5a216b5>
- sing-quic pinned source: <https://github.com/MatsuriDayo/sing-quic/tree/b49ce60d9b3622d5238fee96bfd3c5f6e3915b42>
- sing pinned base: <https://github.com/SagerNet/sing/tree/f7cd94b14d31ace655e3f2285463c2ebf30294aa>
- libneko pinned tree: <https://github.com/MatsuriDayo/libneko/tree/1c47a3af71990a7b2192e03292b4d246c308ef0b>

**Distribution status: INTERNAL TEST CANDIDATE ONLY.** libneko's missing
license, Qt/Chromium applicability and corresponding-source obligations, the
three Go modules without root license files, full transitive notice review,
and clean-VM validation remain open. The generated inventory is evidence for
follow-up, not a legal clearance. Do not publish this archive as a release.
