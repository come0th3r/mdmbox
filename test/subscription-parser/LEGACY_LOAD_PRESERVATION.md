# Non-destructive rejected-profile loading — MIG-07/R2

2026-10-17: bounded preservation regression **verified on Windows**. Full
migration/recovery remains **NOT_ACCEPTED**. No backup/quarantine policy is
implemented by this slice; rejected originals remain at their original paths.

## Production behavior

- `LoadManager()` excludes unreadable/unsupported profiles from the usable graph
  without deleting their files. `SkippedProfileCount()` exposes the count; the
  fixed warning `PROFILE_LOAD_SKIPPED count=<n> originals=preserved` contains no
  paths or profile data. This is not yet user-facing actionable recovery.
- Filename ID lists retain rejected IDs. Allocation uses those lists even when
  the loaded map is empty. The same rule for groups prevents default group 0
  from overwriting an existing corrupt group 0. Integer exhaustion refuses
  allocation instead of overflowing (runtime exhaustion coverage NOT RUN).
- `AddProfile`/`AddGroup` refuse a currently existing canonical destination before
  mutating the entity/graph. This is **sequential protection**, not atomic
  create-if-absent against a concurrent writer.
- `DeleteProfile()` for an ID absent from the loaded graph is a no-op, preserving
  rejected input even if an old caller tries to delete it. Explicit deletion of
  a successfully loaded profile retains its existing behavior.
- Reorder refuses skipped profiles or groups before its destructive rewrite.
  Other known reorder defects are not fixed: do not enable it as a migration.
- `LoadProxyEntity()` also checks the second load result and loaded invalid-bean
  sentinel. This does not introduce full schema/type/identity validation.

The loader is **not globally read-only**: when no groups load it still creates
a default group. With existing numeric group IDs 7/12/21/34, the new default is
35 rather than reusing an existing ID. No automatic moves, renames, quarantine,
repairs of rejected originals, subscription requests or core launches are added.

## Synthetic acceptance boundary

Owned seed/candidate corpus, canonical path/link/ownership guards, exact manifests,
fresh sequential child processes and non-recursive cleanup are reused from the
MIG-03/MIG-05 harness. The original seed always stays byte-identical.

Eleven cases: malformed-profile, invalid-type, malformed-group, orphan-profile,
duplicate-id, duplicate-order, write-lock, invalid-bean, all-invalid-profiles,
max-invalid-profile, all-invalid-groups.

- First/repeat loads preserve every rejected file byte-for-byte; skipped profiles
  never appear in the graph. Both all-invalid and mixed/max-invalid cases create
  new profile403, verify complete serialized readback, delete only that loaded
  fixture-created profile, then require exact original manifest/graph.
- A post-load synthetic sentinel at profile403 blocks AddProfile with entity,
  graph and sentinel unchanged. Fixture removes only its own checked sentinel
  and compares the entire original manifest again.
- A stale `DeleteProfile(rejectedId)` must preserve originals and graph.
- With rejected profile/group input only, fixture explicitly sets flag_reorder
  and invokes the production loader again: no completion dialogs, unchanged
  expected graph and exact original manifest. No successful destructive reorder
  is exercised.
- All-invalid-groups verifies default35 and complete JSON readback; fixture then
  removes **only this exact new file** before the strict fixed-allowlist snapshot.
  Original malformed groups remain exact. This is fixture cleanup, not automatic
  production recovery/rollback. Its in-memory profile/settings oracle is weaker
  than other cases (review P3); disk preservation is still fully checked.
- MIG-06 atomic-save lock/open/disabled/callback/retry/no-change/reopen assertions
  remain in the suite. Orphan/duplicate identity/order observations remain unsafe
  characterization, not accepted repair policy.

Current exact marker:

```text
LEGACY_MIGRATION_ADVERSARIAL_OBSERVATIONS_COMPLETE cases=11 children=24 guards=55 persistence=atomic-v1 load=preserve-v1 acceptance=NOT_ACCEPTED
```

Run with Qt DLLs on PATH:

```powershell
node tools/test-legacy-migration.mjs --runner C:/approved-build/mdmbox_subscription_parser_test.exe --sha256 <recorded-64-hex-sha256> --adversarial
```

## Executed evidence

- Base HEAD `20fdca629acf1164fef14e125a697d0daae7b9dd`, beta-ilya plus explicit
  dirty snapshot, **not clean checkout**. Separate root
  `C:/Users/build/mdmbox-build/mdm-mig07-m2gnBC-r2` on `build@192.168.1.36`.
- Existing Qt 6.7.2/MSVC/CMake/Ninja SDK reused. No installs/downloads, clean host
  not touched. Release configure/build **PASS**, exits 0.
- All **494 input hashes** checked unchanged before/after build and every run.
  Manifest SHA256 `7a24b10818b98b12350090d1708ab3874a57e7c9c44cdab841c2a270d7c5d2a5`;
  archive SHA256 `0e1b548d2903f46f39163558fa865395510c9c505177bd969c8c80f79b2fad78`.
- Runner `build/mdmbox_subscription_parser_test.exe`, SHA256
  `4f84e73084e1dafa860d9afa161807b36f7369ff4e2374aab41f12d04a248516`.
- Sequence valid-before **PASS**, adversarial **COMPLETE**, adversarial-repeat
  **COMPLETE**, valid-after **PASS**. Each adversarial execution: 24 positive
  children + 55 argument/corpus guard refusals. Total sequence **170 children**.
  Seed preservation, owned cleanup and no remaining exact-artifact process verified.
- Remote source tests **16/16 PASS**; local source+probe **30/30 PASS**; launcher
  syntax and `--inspect` **PASS** (inspect itself is source-only, not runtime).
- `build-mig07.ps1` records configure args and checksum-pinned launch commands;
  `result.json`, configure/build/source-tests and four run logs are beside it.
  Logs UTF-16LE; result JSON UTF-8. Local evidence copies:
  `C:/Users/atsun/AppData/Local/Temp/opencode/mdm-mig07-m2gnBC/r2/evidence`.
- Initial candidate compile **FAIL** (unqualified namespace in fixture); fixed
  before R1 build/runtime PASS. R2 adds the remaining guard cases and was freshly
  built/executed; earlier candidate successes are not substituted for R2.
- Independent read-only reviewer `ses_eb6040d8bffevIoga74fLwNglC`: F1 namespace
  and F2 missing guard coverage closed in targeted R2 static review, no new
  confirmed P0–P2. P3 all-invalid-groups in-memory oracle limit retained above.
  Reviewer did not execute tests or verify artifact provenance. Build-file access
  BLOCKED permissions; no bypass. Independent UI/JS review not performed.

## Open gates

Verified backup/quarantine/restore, interruption/disk-full/short-write, full schema
validation, ambiguous filename aliases, INT_MAX execution, second-read race,
separate AddGroup stale-path execution, concurrent no-clobber, caller/UI recovery,
cross-store transactions and installer upgrade/uninstall remain NOT RUN / not
implemented here. Current warnings and skipped count do not constitute complete
error UX. Do not promote this preservation slice to full migration acceptance.
