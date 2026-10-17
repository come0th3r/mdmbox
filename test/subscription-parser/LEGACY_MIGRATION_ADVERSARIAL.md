# Legacy loader adversarial characterization — MIG-05

Status, 2026-10-17: **observations COMPLETE, repeated; migration acceptance NOT_ACCEPTED**.
This test records existing behavior, including unsafe behavior. It does not fix
production persistence or approve data loss as a migration policy.

**Historical evidence below is MIG-05/R1, before the production save fix.**
MIG-06/R1 now uses checked atomic per-file persistence and keeps cache unchanged
on failure; current fixture marker adds `persistence=atomic-v1`. See
`LEGACY_PERSISTENCE.md` for current implementation, exact new hashes and reruns.
MIG-07/R2 subsequently fixes rejected-profile deletion and reserves skipped IDs;
see `LEGACY_LOAD_PRESERVATION.md`. Orphan/duplicate hazards remain open. The
deletion observations below describe the historical MIG-05 snapshot only.

## Scope and safety

`LegacyMigrationAdversarial.hpp` reuses the production-graph parser executable
and the owned-path/manifest helpers from `LegacyMigrationFixture.hpp`. Early
dispatch is before `QApplication` and other fixtures. Production
`ProfileManager::LoadManager()` runs with `flag_reorder=false` in fresh child
processes. No core, refresh, panel, network requests, TUN or system proxy.

Each case has a fresh owned workspace with an exact valid synthetic seed and
separate candidate. Candidate mutations are constructed from repository fixtures;
no parent application-root argument is accepted. Children validate ownership,
canonical paths, file allowlist, digest and exact case corpus before loading.
Symlink/reparse/hard-link guards and explicit allowlisted cleanup are retained.
Only candidate `profiles/205.json` may be absent, and only for the two cases
where legacy loading deletes it; the seed never permits missing files.

The seed manifest is byte-checked after every child, including failures.
Unexpected files/changes fail closed and are retained rather than recursively
deleted. This is not an OS sandbox: it assumes no hostile concurrent filesystem
mutator, and manifests are not filesystem ACLs.

## Executed observations

| Case | Observed production behavior, first and repeated load | Acceptance implication |
|---|---|---|
| `malformed-profile` | Malformed `profiles/205.json` is removed by `LoadManager()`; four profiles remain, group 21 retains stale order `[205]` and resolves no profile. No other bytes change. | Automatic destructive cleanup, no backup/quarantine/rollback demonstrated. Not an accepted migration policy. |
| `invalid-type` | Valid JSON with unsupported `type=synthetic-unknown` produces the same deletion. | Parsing the JSON does not establish profile compatibility or safe preservation. |
| `malformed-group` | Group 21 is omitted from the in-memory map/tabs. Its malformed file and profile 205 remain on disk. | Data remains but the group is not accessible through the loaded group map. |
| `orphan-profile` | Profile 205 retains `gid=999`; group 21's explicit order still resolves it by ID. | `ProfilesWithOrder()` does not require matching group membership. No automatic repair. |
| `duplicate-id` | Map key/filename 205 retains a profile whose embedded ID is 41; profile 41 remains separate. Group 21 resolves key 205 but observes embedded ID 41. | Identity consistency is not enforced. No collision normalization or migration approval. |
| `duplicate-order` | Tabs become `[12,7,12,34,21]`: missing group 999 is filtered but duplicate 12 remains. Group 7 resolves `[90,90,103]`, skipping missing 999 but retaining duplicate and cross-group references. Disk bytes stay unchanged. | Loaded order is not a validated one-to-one membership relation. |
| `write-lock` | Windows read handle denies write sharing; independent write-open probe returns `ERROR_SHARING_VIOLATION`. Production `Save()` returns changed=true and updates `last_save_content`, but profile disk bytes and every other file remain unchanged. | Save's return/cache is not I/O success evidence. No production error propagation or automatic recovery established. |

Write-lock runs four sequential fresh processes:

1. `locked`: latency 17→88 in memory, real write denied, disk stays exact seed.
2. `unrecovered`: after lock/process release, fresh load still sees 17. Opening
   the root did not recover the intended change.
3. `retry`: the fixture explicitly reapplies 88 and calls production `Save()`
   without the lock. Exactly one profile file changes; full JSON equals `ToJson()`.
4. `recovered`: another process sees 88 and full serialized equality, with no
   disk change. In-memory normalization to 17 is used only for shared baseline
   assertions, never saved.

This is **fixture-directed retry**, not application automatic recovery, backup
restore, transactional migration or a disk-full/short-write/interruption test.

## Commands and result contract

Build the parser target with `MDMBOX_SUBSCRIPTION_PARSER_TEST=ON`, then use the
same checksum-pinned launcher as valid-root testing:

```powershell
node tools/test-legacy-migration.mjs --runner C:/approved-build/mdmbox_subscription_parser_test.exe --sha256 <recorded-64-hex-sha256> --adversarial
```

The launcher accepts exactly seven ordered case observations and one final
marker, exit zero, no failure marker, and an unchanged empty launcher CWD.
It does not forward arbitrary application diagnostics. The final marker is:

```text
LEGACY_MIGRATION_ADVERSARIAL_OBSERVATIONS_COMPLETE cases=7 children=16 guards=35 acceptance=NOT_ACCEPTED
```

Six cases have first/repeat children; write-lock has four children: **16 positive
children**. Every case additionally runs five rejections: wrong token, digest,
root, extra reorder argument, and correct token/root/digest with a mismatched
declared synthetic corpus. Total **35 negative children**, all exit 64 and leave
both manifests unchanged. The corpus rejection checks specifically for
`LEGACY_MIGRATION_FAIL edge-not-synthetic` before the production loader. Negative
child diagnostics are matched by substring; positive markers by complete line.

## Exact R1 execution evidence

- Branch `beta-ilya`, HEAD `be1e9f8f945db9a7fe5055de6a56c5bdfd761a40` plus
  explicit dirty-worktree inputs. **Not a clean-checkout build.**
- SSH `build@192.168.1.36`, host `DESKTOP-G7VRDQJ`. Existing MSVC/Qt/dependency
  paths and versions from `LEGACY_MIGRATION.md` reused, without installation.
- Separate owned root: `C:/Users/build/mdmbox-build/mdm-mig05-a8W68j-r1`.
  Prior checkouts/builds, including the initial MIG-05 snapshot, not overwritten.
- `source/snapshot-manifest.json`: **494 input files**, SHA256 checked before
  build, after build and after each of four launcher runs; all unchanged.
  Manifest SHA256 `fb714b49ee6464f859db70b681977ee358e0014565b0ce85bd8182b2a773b203`.
  Archive SHA256 `9fadb0cbd9a25d526f2f3688fad93a920bda3d3cc966f18a990bd9e02a04ac3f`.
- Release/Ninja configure and build **PASS**, both exit 0. Full arguments in
  `result.json`; script `build-mig05.ps1`, logs `configure.log`, `build.log`.
- Artifact `build/mdmbox_subscription_parser_test.exe`, SHA256
  `59b5d34da4471c6fcc2f906de907406360611042b252f0b963a45d67c9c01c38`.
- Sequence, all exit 0: `valid-before`, `adversarial`, `adversarial-repeat`,
  `valid-after`. Two valid-root **PASS** runs and two complete adversarial
  observation runs with the marker above. This executes 114 child processes
  total (2×6 valid-root + 2×51 adversarial). No remaining process for this exact
  artifact at the final check. Every successful case completed owned cleanup.
- Remote source/launcher tests **14/14 PASS**. Local source/launcher **14/14**
  plus subscription-probe regression **14/14 PASS**. Source assertions do not
  substitute for C++ runtime evidence.
- Remote logs: `result.json`, `valid-before.log`, `adversarial.log`,
  `adversarial-repeat.log`, `valid-after.log`, `source-tests.log` alongside the
  build script and input manifest. PowerShell log files are UTF-16LE.
  Local evidence copy:
  `C:/Users/atsun/AppData/Local/Temp/opencode/mdm-mig05-a8W68j/r1/evidence`.
- Initial implementation also compiled/executed twice, with 28 guards and
  artifact `2963568b0c5caea0504cdeef328e41fdfc641c6fc328b8e158ac11f69981b86d`.
  It is historical evidence, not proof for R1's additional corpus guards.

## Review and remaining gates

Independent `mdm-reviewer`, session `ses_eb642defcffe37pUMJdCBN3HoM`, performed
read-only C++ static review, then targeted R1 review. No P0–P2 findings in that
scope. Its P3 missing independent corpus-gate regression was fixed by seven
additional rejection children and closed statically. The coordinator then ran
the exact R1 snapshot as above. Reviewer did not execute tests or independently
verify artifact provenance. Independent review of both `.mjs` files was
**BLOCKED by read permissions**; no bypass attempted. Node tests and execution
evidence are coordinator checks, not an independent JS review.

Production loader/save remain unchanged. The safety acceptance gap is real:
explicit malformed-input handling, error reporting, verified backup/quarantine
and rollback policy are still needed. Short writes, disk full, interrupted
commit/recovery, corrupt backups, concurrency, destructive reorder and installer
upgrade/uninstall are **NOT RUN**. A mutant binary with corpus validation removed
was **NOT RUN**; the new negative guard itself executed in both R1 runs.
