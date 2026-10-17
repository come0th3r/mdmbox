# Checked atomic JsonStore save — MIG-06/R1

2026-10-17: **per-file save regression verified on Windows**. Full migration,
cross-store transactions and automatic recovery remain **NOT_ACCEPTED**.

Subsequent MIG-07/R2 preserves rejected profile originals and adds ID/reorder
guards. Current expanded suite/hash evidence: `LEGACY_LOAD_PRESERVATION.md`.
The seven-case execution records below remain historical MIG-06/R1 results.

## Production change and compatibility

`JsonStore::SaveChecked()` returns `{status, changed}`:

- `Saved`: full bytes written and `QSaveFile::commit()` succeeded, even when
  `changed=false`. No unchanged-content short circuit skips the disk write.
- `Disabled`: saving intentionally suppressed; not a successful write.
- `OpenError`, `WriteError`, `CommitError`: failure stage, without raw OS text,
  filenames, credentials or document contents.

The existing before-save callback runs once per call, before the disabled check
and serialization, preserving legacy ordering. `QSaveFile` direct-write fallback
is explicitly disabled; partial writes are cancelled, commit is checked, and
`last_save_content` changes only after successful publication. This cache is not
an independent filesystem-state verifier or concurrency lock.

`Save()` wraps the checked API, still returning **content changed, not I/O
success**, including on failure. Failed saves emit only the sanitized diagnostic
`JSON_STORE_SAVE_FAILED stage=<number>`. Disabled does not warn. Existing callers
must not treat the bool as successful persistence. New apply/commit logic should
inspect `SaveChecked().ok()` and handle failures explicitly.

Coordinator inspected the bool consumers in `ui/dialog_manage_routes.cpp`,
`ui/edit/dialog_edit_profile.cpp` and `ui/mainwindow.cpp`: they use it as a change/
restart hint. They are unchanged by this slice. They still do not block apply/
restart on persistence failure; user-facing error propagation and in-memory
rollback remain work to do. A sanitized warning alone does not close that gap.

Reference: Qt QSaveFile documentation, retrieved through Context7 on 2026-10-17:
<https://doc.qt.io/qt-6/qsavefile.html>. Per-file atomic replacement is not a
verified multi-file transaction or a power-loss/filesystem durability guarantee.

## Runtime assertions

The existing owned adversarial suite now tests the fixed behavior rather than
requiring the historical cache-poisoning defect. Historical MIG-05 hashes/results
remain in `LEGACY_MIGRATION_ADVERSARIAL.md`.

- `locked`: real Windows handle denies write/delete sharing; a direct write-open
  probe confirms `ERROR_SHARING_VIOLATION`. Both checked API and bool wrapper
  attempt persistence. Checked result is OpenError or CommitError, changed=true;
  exact profile bytes and cache stay old. Full manifest has no unrelated changes
  or leftover QSaveFile temporary files. The wrapper retains changed semantics.
- `unrecovered`: a fresh process still reads old latency 17. No automatic retry.
- `retry`: absent parent yields OpenError with unchanged cache and exact manifest;
  Disabled invokes the callback once but preserves the same state. After restoring
  the real path, callback changes latency 87→88 **before this call's serialization**.
  The first successful retry has immediate complete JSON/cache/readback and
  single-file-delta assertions before any later save. A separate no-change save
  must succeed with changed=false and exact unchanged bytes; only then is the
  bool wrapper called and checked separately.
- `recovered`: fresh process confirms persisted latency 88 and full serialization
  equality, without writes. This remains **fixture-directed retry**, not automatic
  application recovery.

The other six legacy load characterization cases are unchanged: malformed/
unsupported profile deletion and unvalidated identity/membership remain defects,
not accepted migration policies. Every case verifies immutable seed, exact
candidate allowlist, five negative guards and explicit non-recursive cleanup.

Current final marker (intentionally distinct from the historical suite):

```text
LEGACY_MIGRATION_ADVERSARIAL_OBSERVATIONS_COMPLETE cases=7 children=16 guards=35 persistence=atomic-v1 acceptance=NOT_ACCEPTED
```

Run with Qt DLLs on PATH:

```powershell
node tools/test-legacy-migration.mjs --runner C:/approved-build/mdmbox_subscription_parser_test.exe --sha256 <recorded-64-hex-sha256> --adversarial
```

## Exact execution and independent review

- Base HEAD `435d8da3e510aa06301713ee2cc7ec399807d9b0`, `beta-ilya`, explicit
  dirty-worktree snapshot, **not clean-checkout evidence**. That preceding
  migration-fixture commit was made through Fork GUI; selective index preparation
  used Git CLI, preserving unrelated pre-existing changes.
- SSH worker `build@192.168.1.36`, existing Qt 6.7.2/MSVC/CMake/Ninja packages;
  no downloads/installations, clean host not touched. Separate owned root
  `C:/Users/build/mdmbox-build/mdm-mig06-PPOy4s-r1`.
- **494 inputs**, exact hashes checked before/after build and each runtime run.
  Manifest SHA256 `90e4a35aa68d4b33a35d4b25ba50c8a9274854f73fe8c768b65ce4bf3c641530`.
  Archive SHA256 `d9c2816cbfe015f20920d7a64a452f43a0e3540fb44e6d17977888109177429f`.
- Release/Ninja configure and build **PASS**, exit 0. Full arguments and
  compiler path in `result.json`, command script `build-mig06.ps1`.
- Runner `build/mdmbox_subscription_parser_test.exe`, SHA256
  `3262fe023ea75c99c8526ab1b06fd7367a6f5b8bd7a5d1ae2d5a7354920fdc3c`.
- `valid-before` **PASS**, `adversarial` **COMPLETE**, `adversarial-repeat`
  **COMPLETE**, `valid-after` **PASS**; all launcher exits 0, 114 child executions
  total. No remaining process for this exact artifact at final check.
- Remote source/launcher tests **15/15 PASS**; local source/launcher + subscription
  probe regression **29/29 PASS**, launcher syntax **PASS**.
- Remote logs `result.json`, `configure.log`, `build.log`, `valid-before.log`,
  `adversarial.log`, `adversarial-repeat.log`, `valid-after.log`, `source-tests.log`
  beside script/manifest. PowerShell logs UTF-16LE. Local copies under
  `C:/Users/atsun/AppData/Local/Temp/opencode/mdm-mig06-PPOy4s/r1/evidence`.
- Reviewer `ses_eb61ae3c2ffeTzi8qZf69Xc4IP` statically reviewed production API
  and fixture; no confirmed P0–P2 production findings. P2 test-oracle finding
  (later saves could hide a failed retry) fixed by immediate independent
  readbacks; targeted R1 review closed it without new P0–P2. Coordinator then
  executed exact R1. Reviewer did not execute tests; UI-callers independent
  review BLOCKED by permissions, JS outside scope. Coordinator checks do not
  substitute for those independent reviews.

## Still not proved

WriteError short-write/disk-full execution, interrupted commit, power loss,
corrupt backups, same-file concurrent writers, caller/UI failure handling,
non-destructive malformed loading, cross-store rollback, destructive reorder and
installer migration: **NOT RUN / not implemented in this slice**. No test-only
production I/O seams were added, and no global persistence guarantees are claimed.
