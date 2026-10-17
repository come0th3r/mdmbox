# Detached legacy-directory restore — MIG-09/R2

2026-10-17: bounded offline Restore/VerifyRestored **PASS on Windows**. Full
migration acceptance remains **NOT_ACCEPTED**. This does not switch appdata,
invoke the loader, repair malformed files or implement automatic rollback.

## Contract

`LegacyBackup::Restore(backupDirectory, restoreParent)` validates the backup
before writes, re-reads payload plus canonical manifest and creates a fresh
`legacy-restore-<uuid>` inside an existing caller-owned private parent. Parent
must be neither within backup nor its ancestor, including volume roots. Shared
component-aware `within()` also protects Create's source containment check.

The restored tree contains groups/profiles/routes_box and a final
`.restore-manifest.json`. Public Restore always uses the checked NewOnly writer;
each file is read back. Before readiness publication the complete copied bytes,
backup payload and manifest are compared to the captured originals. The marker
uses QSaveFile without fallback, LAST. `VerifyRestored(directory, manifestSha256)`
requires the exact tree, bytes and pinned canonical manifest digest.

All scope/size/path/link limits of `LEGACY_BACKUP.md` apply. Writers must be
quiesced; private Windows ACL inheritance is caller responsibility. Neither
originals nor backup nor existing restores are removed/replaced. Failed attempts
remain unready and return an empty result path. Only the returned successful
directory is eligible for an explicit future switching policy; these directories
must not be discovered and loaded automatically merely because they exist.

This is raw-byte restoration, including malformed JSON, not schema validation or
a whole-appdata backup. Marker integrity is not authenticity against an attacker
rewriting both data and manifest. No hostile concurrency sandbox or power-loss
durability is claimed. Loader integration, activation, transactions and rollback
remain separate work.

## Executed owned synthetic fixtures

- Raw broken JSON restored byte-exact; independent expected-path reads plus
  production verifier. Repeated restores leave source, backup and first result
  unchanged. Fresh verify child passes; wrong owner/digest children refuse.
- Corrupt backup and missing manifest refuse before creating destination.
- Equal/ancestor/relative paths refuse. Pure path assertions cover Windows/POSIX
  roots, equality, ancestor, sibling and lookalike prefixes, without volume writes.
- Real NewOnly conflict at second destination after first checked write: sentinel
  unchanged, WriteError/empty path, no ready marker, verifier refusal.
- Ready output corruption, extra file and marker mutation each invalidate it.
- Fixture changes backup after first real copy: SourceChanged, no ready marker,
  original captured raw copy exact. Fixture explicitly repairs only its synthetic
  backup mutation and removes exact known partial files; not production recovery.
- Own child pauses after first fully checked write. Parent observes its marker,
  kills that QProcess, waits for nonzero exit and rejects any child failure output.
  Child stdout CRLF is normalized; the oracle checks ALL accumulated stdout and
  stderr. Negative assertions reject a natural completion diagnostic already in
  the earlier buffer, unfinished/not-running/zero-exit and prefixed markers.
- Interrupted directory is unready and contains exactly the expected first file
  under allowlisted cleanup. New restore retry occurs BEFORE partial cleanup;
  source, backup, earlier ready tree and interrupted bytes remain unchanged.
- Cleanup only exact checked files and empty expected directories, no recursive
  delete. Success roots removed; failed R0 diagnostic roots retained.

Real process interruption is tested at one pre-publication checkpoint, not every
write/commit boundary or loss of power. Disk-full/short-write NOT RUN.

Marker:

```text
LEGACY_MIGRATION_RESTORE_PASS scope=detached-directories interruption=kill-v1 acceptance=NOT_ACCEPTED
```

## Exact execution / review

Dirty beta-ilya source based on `e11e24518acc0bd80fd07f7bc874388047c83f6c`, not
clean checkout. Credential env is excluded from source selection/archive; no live
subscription requests, network, cores, TUN or system proxy used.

Remote root `C:/Users/build/mdmbox-build/mdm-mig09-CCSvoQ-r2`:

| Artifact | SHA256 |
| --- | --- |
| source.tar | `cc9d9a1b858aa318684e91c546cc0eb1ee1737f128862a4109bb4fe4c9f877a8` |
| snapshot-manifest.json | `dd093c62b4643bfb8589eb1c45bad2865ec2703c913b670f5b1b83b81bfda7df` |
| build/mdmbox_subscription_parser_test.exe | `817a9542b0c4b54168ad331149a2ba89e5b6c419c4ab85cbd24225882696eea3` |

Existing Qt6.7.2/MSVC14.44.35207/Ninja Release configure/build PASS. Commands in
build-mig09.ps1/result.json, full configure/build/run logs in remote root. Sequence
valid-before/adversarial twice/backup twice/restore twice/valid-after: all exit0.
497 input hashes unchanged before/after build and each run; no remaining exact
artifact processes. Remote source20/20, local source+probe34/34 PASS; syntax and
inspect PASS. Restore has4 children/run, including one forcibly killed child;
whole sequence184 child processes (not184 positive acceptance checks).

Local exact source/evidence:
`C:/Users/atsun/AppData/Local/Temp/opencode/mdm-mig09-CCSvoQ/r2/`;
pointer `C:/Users/atsun/AppData/Local/Temp/opencode/mig09-session.json`.

```powershell
# Qt and dependency DLLs on PATH
node tools/test-legacy-migration.mjs --runner C:/Users/build/mdmbox-build/mdm-mig09-CCSvoQ-r2/build/mdmbox_subscription_parser_test.exe --sha256 817a9542b0c4b54168ad331149a2ba89e5b6c419c4ab85cbd24225882696eea3 --restore
```

Independent read-only reviewer `ses_eb5f2b58affeYaHUHjB4DViPnW`: initial F1 P2
volume-root ancestor guard fixed/closed STATIC R1; R1 F2 P2 incomplete kill-output
oracle fixed/closed STATIC R2, no new confirmed P0–P2 in delta. Review did not run
tests or inspect JS/build config/secrets; hashes/provenance and runtime are
coordinator evidence. No new permission overrides/canaries checked.

R0 build PASS and regressions through backup PASS, restore-kill FAIL. R1 full
remote sequence eventually PASS despite240s SSH transport timeout, but does not
close the later F2 finding. R2 freshly rebuilt and reran all8 modes after closure.
These outcomes remain separate, not retroactively reported as an initial PASS.

Remaining: appdata activation/rollback, startup gating, schema/identity validation,
cross-writer coordination, full interruption matrix, disk-full/short-write,
8MiB/64MiB boundaries, reparse/alias runtime matrix, loader acceptance of restored
data, installer migration and clean-build reproducibility NOT RUN/not implemented.
