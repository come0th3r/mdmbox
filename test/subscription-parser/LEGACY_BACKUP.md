# Offline verified legacy-directory backup — MIG-08/R4

2026-10-17: bounded Create/Verify slice **PASS on Windows**. Full migration
acceptance remains **NOT_ACCEPTED**; restore is not implemented.

## Contract

`db/LegacyBackup.hpp` provides explicit Create(sourceRoot, backupParent) and
read-only Verify(directory), with **no startup integration**. Caller must quiesce
every writer and choose an existing private backup parent outside source.
Windows ACLs are inherited, not provisioned here. Real backup payloads/paths must
never enter git/logs: copies may contain credentials.

- Required groups/profiles/routes_box, all direct ordinary files including raw
  malformed JSON. Missing directories, subdirectories, failed listing, unsupported
  names or unreadable files refuse the operation. Not whole-appdata: managed
  snapshots, installation identity and other paths are excluded.
- Limits4096 files,8MiB/file,64MiB payload,255 UTF-16 units/leaf with portable
  filename restrictions,8MiB canonical manifest (checked before target creation).
- Canonical absolute paths; symlink/reparse/hard-link/alias refusal. Native
  error-aware enumeration distinguishes failure from empty directories.
- Fresh UUID directory, NewOnly writes, full length/flush/readback, byte-exact
  source rescan. Canonical relative-path/size/SHA256 manifest published LAST via
  QSaveFile without fallback. Verify requires exact tree and recomputed manifest.
- No removal/move/rewrite of originals or earlier backups. Failed attempts stay
  retained; successful Result.directory is populated only after verification.
  No restore, quarantine, repair, retention cleanup or writer-lock coordination.

Not hostile-TOCTOU sandbox, manifest authentication, multi-store transaction or
power-loss durability. Malicious replacement of payload AND manifest is outside
the corruption model. Header-only Qt Core primitive compiles via offline parser
fixture; production build lists unchanged.

## Executed synthetic fixtures

Owned temporary roots only, no appdata/network/core/TUN/proxy. Cleanup uses exact
allowlisted files and empty directories, never recursive deletion.

- Exact raw malformed-source preservation and payload comparison through both
  production scan and independent expected-path QFile reads.
- Fresh-process Verify with digest pin; wrong owner token rejected.
- Repeated Create preserves first manifest and expected payload bytes.
- Missing/corrupt manifest, corrupt payload and extra file rejected; source exact.
  These simulate corruption, **not** killed writer/power failure.
- Relative/missing/overlapping paths, nested source, locked input and source
  hard-link refused.
- Real ACL listing denial on source and backup profiles: SourceError/Verify
  refusal, access restored and bytes exact. Fixture disables backup/restore
  privileges only in its own process and attempts RAII restoration; no machine
  privilege policy changes. SSH token otherwise bypassed the synthetic deny.
- Partial destination conflict via internal writer seam: first real payload
  succeeds, fixture precreates sentinel at second destination, actual production
  NewOnly writer refuses. WriteError/empty result directory, sentinel unchanged,
  no manifest/Verify refusal; exact partial cleanup. Public Create always uses
  checked writer. This does **not** test disk-full/short-write/interruption.
-4096 empty files with180-character leaves: manifest >1MiB, independent complete
  expected-path reads, exact entry count, fresh Verify child PASS.4097th file
  gives SourceError; exact cleanup.

Exact launcher marker, required with exit0:

```text
LEGACY_MIGRATION_BACKUP_PASS scope=legacy-directories restore=NOT_IMPLEMENTED
```

## Exact R4 evidence

Dirty beta-ilya baseline `f912b3126a8d9c4b53365b4e723006b7970adc8b`, not clean
checkout. Remote root `C:/Users/build/mdmbox-build/mdm-mig08-77rWLi-r4`.

| Artifact | SHA256 |
| --- | --- |
| source.tar | `4e11ab580a2d392a8d2130dd02023eeb82b4b2e45d2698cdeec1e32871407e11` |
| snapshot-manifest.json | `5e824d35c1c5d5e52564f85ae9dfa8ed6389fd1a94777845f31b885bd76abe37` |
| build/mdmbox_subscription_parser_test.exe | `0443a0076f63c128cfb326c0fdb0a7d65b914775711792e7c668b89e3bd711e4` |

Qt6.7.2/MSVC14.44.35207/Ninja Release configure/build PASS with existing build-host
dependencies. Full commands/logs: build-mig08.ps1, result.json, configure.log,
build.log and named run logs in remote root. Sequence valid-before/adversarial/
adversarial-repeat/backup/backup-repeat/valid-after: all exit0.496 input hashes
unchanged before/after build and every run; no remaining exact-artifact processes.
Adversarial79 children/run, valid6/run, backup3/run:176 children total. Remote
source18/18, local source+probe32/32, JS syntax/inspect PASS. Success roots removed.

Local exact source/evidence:
`C:/Users/atsun/AppData/Local/Temp/opencode/mdm-mig08-77rWLi/r4/`;
pointer `C:/Users/atsun/AppData/Local/Temp/opencode/mig08-session.json`.

Run with Qt/dependency DLLs on PATH:

```powershell
node tools/test-legacy-migration.mjs --runner C:/Users/build/mdmbox-build/mdm-mig08-77rWLi-r4/build/mdmbox_subscription_parser_test.exe --sha256 0443a0076f63c128cfb326c0fdb0a7d65b914775711792e7c668b89e3bd711e4 --backup
```

## Review / failed attempts / limits

Independent read-only reviewer `ses_eb5f2b58affeYaHUHjB4DViPnW` found F1 P1 silent
listing failure and F2 P2 manifest-limit mismatch in initial source. Fixed and
closed STATIC in R1; final R4 delta has no new confirmed P0–P2. P3 remains: token
restoration is attempted by destructor without checked success/state comparison.
Reviewer did not execute tests, verify hashes or read JS/UI/build config; new
permission canaries/overrides not checked. Runtime evidence belongs to coordinator.

Initial runtime PASS missed review defects. R1/R2 builds PASS but ACL fixture FAIL
because SSH token bypassed deny. R3 listing fixture corrected, inherited write-ACL
test FAIL. R4 replaced that unreliable test with real NewOnly collision. Failed
owned synthetic roots are retained, not broadly cleaned.

Subsequent MIG-09/R2 adds detached raw Restore/VerifyRestored with actual owned
child-kill/retry fixtures: `LEGACY_RESTORE.md`. This does not retroactively change
MIG-08 evidence or add appdata switching/rollback/startup integration.

Appdata activation/rollback/startup gating, identity validation/quarantine, caller SaveChecked
propagation, cross-writer coordination, actual kill/interruption, disk-full/short-
write,8MiB/64MiB boundary execution, reparse/alias runtime matrix, installer
upgrade/uninstall and clean-checkout reproduction: **NOT RUN / not implemented**.
Do not enable destructive reorder or claim whole migration acceptance.
