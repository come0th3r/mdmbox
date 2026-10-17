# Checked-save callers — MIG-10/R3

2026-10-17: bounded caller regression **PASS on Windows**. Independent production
review **BLOCKED permissions**; full migration acceptance **NOT_ACCEPTED**.

## Scope

- MainWindow's `UpdateDataStore` dispatcher uses `SaveChecked().ok()` before
  considering `changed`. Failure shows sanitized text and returns before refresh,
  proxy restart and NeedRestart processing in this handler. Disabled is failure.
- Existing-profile editor keeps a detached entity/bean. Accept checks live object,
  ID/group/type/path and unchanged baseline bean before applying the edit. It
  saves the live entity to retain latest traffic/latency, rolls back its own bean
  on failure, and emits neither accepted nor restart message until success.
- Cancel does not write the live entity. A replaced/moved/changed live profile
  refuses stale editor acceptance rather than overwriting newer state.
- Apply-to-group's source save now checks the same helper; target loops exclude
  the original live entity, not the detached copy. Group target persistence is
  still legacy unchecked/nontransactional and is NOT accepted by this slice.

**Important:** settings changes made before dispatcher invocation still remain in
memory after failure. This cancels automatic restart in this handler, not every
possible apply/start path or a full settings rollback. DialogBasicSettings may
already have performed timer/theme actions; its acceptance is not redesigned
here. Routing/multiple-store atomicity, new-profile AddProfile, imports/group
target saves, shutdown writes and other Save callers remain separate work.

Detached editor copies registered serializer fields as before, not unknown JSON
schema fields. No new claim of lossless unknown-schema preservation. Profile
guard is sequential UI-thread conflict detection, not hostile concurrency control.

## Executed fixture

Checksum-pinned launcher `--callers` creates only owned synthetic roots. Parent
uses QCoreApplication. Explicit guarded child alone uses QApplication/production
MainWindow and DialogEditProfile; automatic legacy/remembered core/OS mode startup
is excluded by existing `MDMBOX_ISOLATED_APPLICATION_TEST`. No WebEngine screen
capture/visual acceptance, live subscriptions or external VPN test performed.

Before MainWindow construction child validates owner, exact corpus digest and cwd.
Parent verifies wrong-owner refusal leaves candidate unchanged, immutable seed,
final allowlisted tree and exact cleanup. Failed synthetic roots remain retained.
MainWindow's known dashboard qrc copy is byte-checked before removing its read-only
bit and deleting that exact owned file, then empty directory. No recursive delete.

Actual production calls check:

1. Settings dispatcher with changed settings + RouteChanged/VPNChanged/NeedRestart:
   real absent parent → warning/no question, original bytes/cache unchanged.
2. Disabled settings save → warning/no question and unchanged bytes/cache.
3. Retry → exact serialized persisted bytes and one restart question, answered No;
   immediately repeated unchanged save → no question/warning.
4. Cancelled detached profile editor → original live serialization unchanged.
5. Disabled profile save → original bean/bytes/cache unchanged, no accepted/message.
6. Actual Windows sharing denial on the original profile destination → same failure
   preservation; fixture closes its owned handle before retry.
7. Retry → changed name saved, current latency333 retained, accepted once and
   `accept,restart` message. No actual proxy restart is requested by fixture sink.
8. Unchanged accept → `accept` only and immediate entity/cache/disk equality.
9. Replacement live object with same ID, changed fn, and newer live bean each
   refuse stale accept without success notification or overwriting data.

Observer answers every modal No, including accidental questions; it counts warnings,
questions and unexpected dialogs. No positive restart/exit confirmation is given.
Absence of dialogs is **not** an independent oracle for every apply/process/system
side effect. Production source early-return inspection and these runtime assertions
are coordinator evidence; full no-apply/start acceptance remains open.

## Exact build and evidence

Dirty beta-ilya snapshot based on `8089e4b6b2dbf918d0a25b770625d4848cb6f38d`, not
clean checkout. Env credentials excluded from manifest/archive; no live requests.
Existing Qt6.7.2/MSVC14.44.35207/Ninja Windows Release configure/build **PASS**.

Remote root: `C:/Users/build/mdmbox-build/mdm-mig10-togrtK-r3`.

| Artifact | SHA256 |
| --- | --- |
| source.tar | `742d7a16aab9172c89ed3cceea6e5919ed3f34ad290f7eb85f9b541ea0256e7e` |
| snapshot-manifest.json | `4b4a47f9f0b1a7cfeaed27d02ed93b0990fbba6a72cef861ea918ca714678fc2` |
| build/mdmbox_subscription_parser_test.exe | `1b22ec11a7e4a395179a34755f5dcc283af654e12d61b074c09e3f37d0611847` |

Sequence valid-before/adversarial twice/backup twice/restore twice/callers twice/
valid-after: all ten exit0.498 input hashes unchanged before/after build and each
run; no remaining exact artifact processes. Remote source22/22 and local source+
subscription-probe36/36 PASS; JS syntax/inspect PASS. Callers has one negative and
one main child/run; total sequence188 children, not188 positive acceptance checks.

```powershell
# Existing Qt/dependency DLLs on PATH
node tools/test-legacy-migration.mjs --runner C:/Users/build/mdmbox-build/mdm-mig10-togrtK-r3/build/mdmbox_subscription_parser_test.exe --sha256 1b22ec11a7e4a395179a34755f5dcc283af654e12d61b074c09e3f37d0611847 --callers
```

Marker:

```text
LEGACY_MIGRATION_CALLERS_PASS scope=settings-dispatch-existing-profile acceptance=NOT_ACCEPTED
```

Local source/build script/logs/result.json:
`C:/Users/atsun/AppData/Local/Temp/opencode/mdm-mig10-togrtK/r3/`;
pointer `C:/Users/atsun/AppData/Local/Temp/opencode/mig10-session.json`.

R0/R1 build/regressions before callers PASS; caller child crashed (3221225477)
after a stack-owned cancelled editor was destroyed before its queued adjust/show
callbacks. Fixture now pumps its event loop while the dialog is alive. R2 reached
final dashboard cleanup but FAIL on read-only qrc copy removal; R3 validates exact
bytes then checks permission adjustment/removal. Earlier outcomes are not relabeled
PASS. Diagnostic reruns used only new owned synthetic copies, retained on failure.

Independent reviewer `ses_eb5f2b58affeYaHUHjB4DViPnW` read permitted fixture and early
dispatch; production reads `ui/mainwindow.cpp` and `ui/edit/dialog_edit_profile.*`
denied, not bypassed. Production independent review remains BLOCKED. Initial fixture
review no confirmed P0–P2; coverage limits led to stronger no-change and identity/path
tests. Runtime/provenance are coordinator evidence. No new permission canaries or
session-override checks performed; JS/build files not independently reviewed.
Final R3 fixture-only rereview: no new confirmed P0–P2; no-change gap closed
STATIC. Fixed50/100ms event pumping is not universal callback lifetime evidence,
and no independent process/apply oracle was added. Production approval BLOCKED.

Remaining: independent production review, settings rollback/all start paths, new
profile creation, group target/route/multi-store persistence and activation/rollback,
startup gating, disk-full/short-write and clean-checkout reproducibility. Full
stages0–1 and migration acceptance are not closed.
