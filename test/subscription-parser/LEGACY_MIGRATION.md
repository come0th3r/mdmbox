# Synthetic legacy-root reopen slice

Status: **valid-root slice built and executed twice: PASS, 2026-10-17**. This is a
bounded Stage 0 compatibility test, not a schema migration or reorder acceptance.

## Coordinator-approved boundary

- Reuse the production-graph parser executable, with a separate early CLI branch
  `--legacy-migration`. Do not execute production `main()`, parser/runtime probes,
  refresh, a core, TUN, system proxy or network requests.
- Construct historical-shaped synthetic JSON directly, not via current Add APIs:
  sparse IDs, non-ID order, duplicate names, flags, metadata, selection, two
  named routes, and one group without optional `subscription_kind`.
- Parent owns a fresh temporary workspace and immutable seed. A separate candidate
  clone is reopened by two sequential fresh child processes using production
  global `ProfileManager::LoadManager()`, explicitly with `flag_reorder=false`.
- Before the load/save phases and cleanup, validate ownership markers, canonical
  paths, exact file allowlist and reject symlink/junction/reparse/hard-link
  escapes. Accept no
  user-supplied application data directory in the parent mode.
- First child validates the semantic graph, then exercises existing Save APIs in
  the clone. Second child validates the persisted graph and unchanged bytes on
  load. Every saved file must equal the complete expected serialized object
  (including defaults such as `subscription_kind=links`), not just seed fields.
  The unchanged seed must fail this same oracle before saving. Parent checks
  the complete seed manifest after each child, stable file
  names, and identical candidate bytes across the second reopen. Save's return
  value is not write-success evidence: read back and validate JSON instead.
- Include negative argument/marker/path validation tests that never invoke the
  loader. Malformed/orphan/duplicate loading and Windows write-open failure now
  have a separate characterization slice, `LEGACY_MIGRATION_ADVERSARIAL.md`.
  Transactional recovery, concurrency and destructive `flag_reorder` acceptance
  remain unimplemented; characterization is not migration acceptance.

File ownership: coordinator owns this document, `LegacyMigrationFixture.hpp`,
`main.cpp` early dispatch, `tools/test-legacy-migration.mjs` and
`test/legacy-migration-source.test.mjs`. Sol reviewer
receives a frozen snapshot after implementation; fixture-engineer is not yet
activated. No production persistence fixes or shared CMake rewrites in this slice.

## Commands and evidence boundary

Source-only checks, without any compiled runner:

```powershell
node --check tools/test-legacy-migration.mjs
node --test test/legacy-migration-source.test.mjs
node tools/test-legacy-migration.mjs --inspect
```

2026-10-17 MIG-03 run: source/launcher tests **PASS 11/11**, existing
`test/subscription-probe.test.mjs` **PASS 14/14**, launcher syntax and inspect
command **PASS**. The source assertions inspect corpus/dispatch text; they do
not execute C++ path guards, Qt serialization, production loading or cleanup.
The Node checksum/hard-link check actually operates on owned synthetic files.

On an approved Windows worker, build the existing parser target with
`-DMDMBOX_SUBSCRIPTION_PARSER_TEST=ON` and the pinned dependencies described in
`docs/STAGE0_BUILD_MANIFEST.md`. Do not substitute an older parser binary. Record
the dirty candidate file manifest, build flags and resulting executable hash.
With Qt runtime DLLs on PATH, supply that independently recorded SHA256:

```powershell
node tools/test-legacy-migration.mjs --runner C:/approved-build/mdmbox_subscription_parser_test.exe --sha256 <recorded-64-hex-sha256>
```

This is a command template; the actual executed paths are recorded below. The launcher accepts no root,
network/core or reorder argument. It hashes a plain, single-link executable,
uses a fresh empty CWD, and accepts only exit zero plus the exact harness marker.
Checksum pinning identifies bytes; it does not independently prove their source
or make an untrusted executable safe. Use only the reviewed, trusted build.

Successful C++ execution must report:
`LEGACY_MIGRATION_VALID_ROOT_REOPEN_PASS children=2 guards=4 seed_files=15`.
Two valid-load children and four rejection children run sequentially. A rejected
child must return 64 and leave both manifests unchanged. Failed validation
retains the synthetic workspace rather than recursively deleting it.

## Executed Windows build and runtime evidence (2026-10-17)

- Host: SSH `build@192.168.1.36`, `DESKTOP-G7VRDQJ`, Windows build 26100.
  Existing SDKs reused; no installation/download needed. Qt 6.7.2 MSVC2019 x64,
  MSVC compiler 19.44.35229, CMake 4.4.4, Ninja 1.13.2, Node.js 24.21.0.
- Candidate: `beta-ilya`, HEAD `be1e9f8f945db9a7fe5055de6a56c5bdfd761a40`
  plus explicit dirty-worktree inputs. **Not a clean-checkout baseline.**
  Separate owned directory: `C:/Users/build/mdmbox-build/mdm-mig-run-a4kdLv`.
  Existing remote source/build trees were not overwritten.
- Inputs: `source/snapshot-manifest.json`, **493 files**, each SHA256 checked
  before build, after build, after runtime and after the repeat. All unchanged.
  Manifest SHA256: `e651407c4ab69389b780ed95ead848f35743f6476eb92b995ed6fee4fb7318dc`.
  Archive SHA256: `8ee55aaa337a667ffbf5ff02fd02b82ec3fb0dfb708a46676a950b25bd4859e4`.
- Configure: Release/Ninja, `QT_VERSION_MAJOR=6`,
  `MDMBOX_SUBSCRIPTION_PARSER_TEST=ON`,
  `CMAKE_POLICY_VERSION_MINIMUM:STRING=3.5`, existing Qt/dependency prefixes
  from project memory. Configure and build exit **0**. Full arguments are
  stored in `result.json`; executed script is `build-migration.ps1`.
- Artifact: `build/mdmbox_subscription_parser_test.exe`; SHA256
  `06b0457928077debe8e9b3aa99d8da9355c93176858c916dd0c060c05b8edff6`.
  Checksum-pinned Node launcher exit **0**, repeated with the same binary exit **0**.
  Both produced `LEGACY_MIGRATION_VALID_ROOT_REOPEN_PASS children=2 guards=4 seed_files=15`.
  Each run covers two valid children, four argument/root guard rejections,
  seed byte preservation, full serialized readback, persisted reopen and owned
  workspace cleanup. No remaining process for this exact artifact after repeat.
- Remote source/launcher tests **11/11 PASS**. Local source/launcher and existing
  subscription-probe regression tests **25/25 PASS**; launcher syntax and
  `git diff --check` **PASS**. No core, panel, TUN or system proxy was started.
- MIG-04 found a P2 no-op Save oracle gap; MIG-04-R1 confirmed it statically
  resolved with no new findings. Final build exposed an include-order conflict
  between Windows SDK declarations, project enum names and Qt macros; fixed
  by including `windows.h` first in the parser entrypoint, matching the existing
  bridge fixture. The resulting candidate compiled and ran as recorded above.
  An intentionally no-op-mutated binary was **NOT RUN**; the unchanged-seed
  negative oracle itself executed in both successful save children.
- Initial attempts failed on PowerShell native-warning handling and a missing
  root README in the staged CPack inputs; build script/snapshot corrected.
  These do not imply missing SDKs or production persistence fixes.
- Evidence beside the remote build: `result.json`, `verification.json`,
  `configure.log`, `build.log`, `migration.log`, `migration-repeat.log`,
  `source-tests.log`, `source/snapshot-manifest.json`. Local copied evidence:
  `C:/Users/atsun/AppData/Local/Temp/opencode/mdm-mig-run-a4kdLv/evidence`.

## Safety limits and remaining acceptance

The subsequent MIG-05/R1 build revalidated valid-root before/after two complete
adversarial runs; source/launcher tests increased to **14/14 PASS**. Exact current
artifact/manifest and observed unsafe legacy behavior are in
`LEGACY_MIGRATION_ADVERSARIAL.md`; prior MIG-03 hashes above remain historical.

- Tests assume no hostile concurrent filesystem mutator in the worker account.
  Preflight path checks are not an OS sandbox or a TOCTOU-proof handle-relative
  persistence layer; production Save still opens paths and truncates directly.
- Seed immutability is verified by byte manifests, not enforced by filesystem
  ACLs. Routing data lives under the production `routes_box/` prefix.
- Do not infer acceptance for malformed/orphan/duplicate inputs, process
  interruption, write failure, rollback, concurrency, destructive reorder,
  installer upgrade, arbitrary historical versions or VPN/protocol behavior.
- The local `KUNETSKY-HOME` presence-only preflight remains **BLOCKED (18 checks)**;
  it is not the build host. The remote exact-candidate test above is **PASS**.
  Clean-checkout reproducibility and full migration acceptance remain open.
