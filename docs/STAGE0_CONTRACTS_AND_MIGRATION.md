# Stage 0: backend/UI contracts and migration matrix (evidence draft)

Status: **draft from current implementation, not an approved/frozen contract**. Inspected the `beta-ilya` worktree based on HEAD `be1e9f8f945db9a7fe5055de6a56c5bdfd761a40` on 2026-10-17. The bridge and shell sources are modified in this worktree; revalidate this document against the final Stage 0 source before freezing. This file records existing behavior and unresolved migration choices; it does not prescribe new UI work.

## 1. Production shell data contract (observed)

Production shell is local HTML/JS (`ui/shell/`) hosted in Qt WebEngine. `MdmBoxShellWindow` registers `mdmboxBridge` on `QWebChannel`; native refresh invokes `window.mdmboxApp.update(state, servers, logs)`. This is an implementation snapshot, not yet a compatibility promise.

### 1.1 Read models

| Object | Observed fields / meaning | Caveats |
|---|---|---|
| `state` | `connected`, `managedRuntime`, `selectedId`, `startedId`, selected name/address, legacy TUN and system-proxy booleans, display strings, ping, traffic and `signal`, settings, app version | `connected` is derived from `started_id >= 0`; it is not an independently verified external connectivity claim. `managedRuntime.vpnConnected` is explicitly `false`. Some display fields (`statusSubtitle`, `ipAddress`) are presentation values, not network facts. |
| `state.managedRuntime` | schema v1: `available`, `scope: "loopback-only"`, `state`, `busy`, `groupId`, `controllerReady`, `vpnConnected` | `controllerReady` means managed local controller/core readiness only. Do not map `ready` to VPN connected. No subscription secret or API token is part of this snapshot. |
| `state.settings` | theme; subscription auto-update boolean and interval; on Windows, autostart state and availability | Platform-specific. UI offers a subset; advanced settings remain in legacy dialog. |
| `servers` | `{currentGroup, groups[], items[]}`; item includes profile/group IDs, type, name/address, transport/security where available, latency/traffic, running/selected flags | Projection is from legacy profile/group model. It is not the full managed `mihomo-full` proxy/group model. Address/name data is profile-derived and should be treated as user data. |
| `routing` | active routing name, default outbound and three tabs of domain/process/IP rules | Rules are edited through native bridge handlers and persisted in legacy routing/settings stores. No versioned public schema currently declared. |
| `logs` | lines, total, error count, formatted size and process uptime | Rendering summary is not a structured diagnostic API; logs may contain user-sensitive material. |

### 1.2 Commands and async lifecycle

The bridge currently exposes these groups of commands in `preview/mdmbox_shell_bridge.h`:

- Navigation/window: `navigate`, `minimizeWindow`, `maximizeWindow`, `startWindowMove`, `closeWindow`, `exitProgram`.
- Legacy actions: `connectToggle`, `toggleTun`, `toggleSystemProxy`, `importClipboard`, `openLegacy`, `openBasicSettings`, `selectServer`, `selectGroup`, `setAutoStart`, `setSubscriptionAutoUpdate`.
- Routing/log actions: `routingSetDefault`, `routingAddRule`, `routingEditRule`, `routingRemoveRule`, `routingImportClipboard`, `routingExportConfig`, `routingResetRules`, `clearLogs`, `copyLogs`, `exportLogs`.
- Managed loopback operations: `managedStart`, `managedStop`, `managedReconnect`, `managedRefresh`, `managedSnapshot`.

Most legacy commands are fire-and-forget `void` calls: they do not carry a common request ID or return a typed result. Managed commands validate group IDs and return `managedCommandResult(requestId, result)`; event snapshots arrive separately through `managedRuntimeEvent(event)` and JS `CustomEvent`s. Managed response schema v1 currently contains `command`, `accepted`, `queued`, `error`, and `runtime`. `accepted/queued` means command acceptance/enqueueing, not successful completion. The completion event carries request correlation/outcome and a sanitized runtime snapshot; consumers must not treat the immediate response as completion.

Managed launch currently requires an existing non-archived `mihomo-full` group and refuses active legacy core, TUN/system proxy, shutdown or a busy/unavailable controller. It uses local managed storage, a bundled `mihomo.exe` path and fixed loopback listener/API ports. This is not a general OS proxy/TUN contract.

### 1.3 Unresolved contract decisions

- Freeze field types, nullability, defaults, enum values, versioning and backwards-compatibility policy for read models and events.
- Decide whether legacy actions remain fire-and-forget or gain typed request/result semantics; specify UI feedback and timeout/cancellation behavior.
- Define stable distinction between selected, running, controller-ready and externally verified connectivity. Current `connected` naming is ambiguous and must not be strengthened without a real data-path contract.
- Decide whether shell contracts expose managed group/proxy data, or explicitly remain a view of the legacy group/profile model.
- Define privacy/redaction policy for address, logs, subscription metadata and exported diagnostics.
- Define provider/geodata, DNS and routing capabilities only after backend behavior is implemented and tested; do not add unsupported controls to the contract.

## 2. Migration/capability matrix (observed baseline)

| Data/runtime domain | Existing format/path | Compatibility evidence | Migration/rollback status |
|---|---|---|---|
| App settings | `groups/pm.json` manager index plus a `JsonStore` settings file; group order is an integer list | Current loader loads JSON fields through registered config items; MIG-06/R1 adds checked QSaveFile per-file save, with cache updated only after commit | No explicit global schema version, migration journal or verified backup. Bool `Save()` remains a changed hint; callers do not yet block apply on persistence failure. |
| Groups | One `groups/<id>.json` per group; includes name, URL, archive/skip-update flags, order, subscription kind and related UI fields | Missing `subscription_kind` initializes as `links`; a targeted parser runner checks this default and JSON round-trip | This is a field default, not a versioned migration. No full old-database to new-database acceptance or rollback. |
| Legacy profiles | One `profiles/<id>.json` per profile, bean type/version and group ID; `groups/pm.json` maintains group tab order, profile order stored in group records | Loader filters invalid entries; parser regression verifies its specific fixtures leave group/profile bytes unchanged | Per-file writes/deletes and reorder rewrite are not one transaction. No crash-safe backup/restore acceptance. Reorder path removes and rewrites profile/group files. |
| Routing | Separate named routing JSON plus settings fields for active routing and process/CIDR policy | Shell code round-trips current in-memory rules through existing native editors and persistence methods | No new versioned schema or atomic multi-file migration; no end-to-end preservation test for arbitrary legacy routing corpus identified here. |
| `mihomo-full` managed profile | `managed-subscriptions/<groupId>.json`: envelope schema 1, group ID, kind, metadata, Base64 exact source, SHA-256; sibling `.previous` snapshot | Synthetic tests cover envelope/source/metadata, validation, atomic `QSaveFile` writes and retained prior snapshot; managed refresh→runtime loopback evidence is documented separately | Atomic per-envelope commit and validation lock exist. Cross-writer ordering/revocation policy and atomicity with legacy group JSON + runtime are not established as one transaction. |
| Installation identity | Managed identity uses its own persisted file and atomic save path | Isolated synthetic refresh tests check identity stability across fixture requests | Not a migration format for user settings; no installer upgrade preservation contract implied. |
| Installer install/update/uninstall | Inno Setup x64-compatible admin installer copies staged tree, adds shortcuts and can launch post-install | Packaging scripts and script sources exist | Clean install, in-place upgrade, settings/profile preservation, uninstall cleanup, rollback and clean-VM acceptance for current HEAD remain open. |
| Figma assets/design references | Plan records file key `dpomJg0l41jhSZfAZOV2fB`, page `0:1`, frames `6:8`, `9:2`, `6:347`, `6:736`, `6:1077` | Design context metadata was previously obtained (see upgrade plan) | This is a reference index only. Full exported asset/font manifest, checksums, licensing, local resource paths and five-screen baselines are not frozen here; visual acceptance remains deferred. |

### 2.1 Legacy migration evidence boundary and identified risk

The current parser runner is not a general migration runner. Its default path
uses an isolated temporary working directory and verifies the old
`subscription_kind` default plus selected update-failure invariants; it does not
reconstruct and reopen a complete old-version application data root. The optional
managed refresh fixtures likewise verify subscription storage/runtime behavior,
not user-database migration or installer upgrade preservation.

The legacy `ProfileManager::LoadManager()` `flag_reorder` path is especially
unsafe to treat as an accepted migration: it removes loaded profile files before
writing their reordered replacements, then rewrites groups and IDs across
separate files. It has no verified backup/journal or rollback path. A crash,
write failure, orphan profile, duplicate ID or invalid order can therefore leave
the root partially rewritten. Do not enable or reuse this path as migration
acceptance; test it only in a disposable synthetic root after a separate safe
reproduction plan exists.

Additional static evidence from the independent MIG-02 pilot (2026-10-17; no
loader execution): group IDs 0/1 with tab order `[1,0]` can lose the first
replacement when the next iteration removes its old filename
(`db/Database.cpp:120–126`). A nonempty but incomplete profile order similarly
omits a profile after all original profile files have been removed
(`db/Database.cpp:88–109,382–391`). These are required negative fixtures, not
runtime reproduction results or approved repair behavior. See
`docs/SUBAGENT_PILOT_MIG01_MIG02.md` for the reviewed matrix and scope limits.

## 2.2 Executed characterization (2026-10-17)

Valid-root production-loader save/reopen is **PASS**. MIG-05/R1 separately built
and executed seven malformed/orphan/duplicate/write-lock cases twice on the SSH
Windows build host, with 16 positive and 35 rejection children per run; seed
preservation and owned cleanup verified. Exact hashes and outcomes:
`test/subscription-parser/LEGACY_MIGRATION_ADVERSARIAL.md`.

Confirmed legacy hazards, **not accepted policies**:

- Malformed/unsupported profile JSON is deleted during ordinary loading without
  a backup; damaged group JSON is omitted from the loaded graph, retained on disk.
- Orphan gid, duplicate embedded IDs/map-key mismatch and duplicate/cross-group
  explicit order references survive; missing order references are filtered only
  from the resolved view. There is no complete identity/membership validation.
- Historically, a real Windows sharing violation blocked Save from opening for write, yet its
  return/cache report changed. The file stays old on next launch; only an explicit
  fixture-directed retry persists the new value. Automatic recovery not proven.

MIG-05 made no production fixes. Subsequent **MIG-06/R1** introduces checked
per-file atomic save (`SaveChecked()`), no direct-write fallback, checked full
write/commit, and cache updated only on success. Legacy bool changed semantics
are retained; fixed sanitized warning reports failure. Exact new Windows build,
valid-root before/after and two atomic-v1 adversarial runs completed with old
file/cache preserved on failure and immediate explicit retry/no-change readbacks.
Evidence and review limits: `test/subscription-parser/LEGACY_PERSISTENCE.md`.

Full safety acceptance remains open: non-destructive load/backup/rollback and
caller-level failure propagation are not implemented; interrupted commit,
disk-full/short-write and destructive reorder execution are NOT RUN. Original
MIG-05 observations remain historical regression evidence, not the desired policy.

## 2.3 Required legacy-data invariants for acceptance fixtures

Fixtures should cover both data preservation and the existing loader's repair
behavior, while distinguishing observed behavior from an approved policy:

- Preserve stable group/profile IDs and file ownership; preserve tab order and
  each group's profile order, including explicit non-ID ordering.
- Preserve archived and skip-auto-update flags, subscription kind/source and
  typed metadata, current group/selected profile, front-proxy references, and
  active routing name plus routing contents.
- Include missing optional fields, missing/orphan/duplicate order entries,
  orphan profile/group files, malformed JSON and invalid bean types. Record
  whether current loading drops/repairs an entry; do not silently promote that
  existing repair behavior into the future migration contract.
- Exercise a repeated launch and injected interruption/write failure against a
  disposable root. The expected acceptance is byte-verified backup/rollback or
  a documented non-destructive recovery state, not merely successful parsing.
- Keep installer upgrade/uninstall preservation separate from the in-process
  database migration test.

## 3. Required migration acceptance (not yet implemented/accepted)

1. Build synthetic old-version fixtures with absent optional fields, explicit old ordering, archived/skip-update groups, malformed files, duplicate/orphan IDs, selected/current group, front-proxy references and representative custom routing data. Do not copy real user data or subscription URLs. Keep the legacy `flag_reorder` path isolated until its destructive rewrite behavior is replaced or has independently proven rollback.
2. Specify migrations as explicit source schema → target schema transformations; preserve IDs, group/profile order, subscription kind/source, active/selected profile, routing rules and settings unless a documented policy says otherwise.
3. Make migration idempotent and interruption-safe. Keep a verified backup until the new database is readable; on any failure retain/restore the previous state and report a sanitized actionable error.
4. Test first launch, upgrade, repeat launch, downgrade policy, disk-full/write failure, corrupt backup, interrupted migration and uninstall behavior using isolated temporary roots.
5. Separately define the relationship among managed envelope commit, legacy group metadata, runtime apply/reconnect and concurrent refresh/revocation. Existing per-file atomicity is not sufficient evidence for cross-store latest-wins.
6. Freeze the UI/backend contract only after its schema, async semantics and error states are covered by production bridge tests. Keep Figma asset manifest pending until original assets are exported and their provenance/checksums recorded.

## 4. Acceptance status

- **Observed contract draft:** recorded in this file; not frozen and not a completed UI implementation.
- **Migration/capability baseline:** current on-disk stores and a limited managed envelope are inventoried; no general migration acceptance.
- **Figma asset manifest:** reference identifiers are transcribed; source asset inventory is not complete.
- **Stage 0:** remains open. Clean-checkout dependency reproduction/build, full manifests and remaining explicit acceptance points are still required.

## 5. Sources inspected

`preview/mdmbox_shell_bridge.h`, `preview/mdmbox_shell_bridge.cpp`, `preview/mdmbox_shell_window.cpp`, `ui/shell/app.js`, `sub/ManagedCommandContract.hpp`, `sub/ManagedSessionController.cpp`, `sub/ManagedProfileStore.cpp`, `sub/ManagedProfile.cpp`, `db/Database.cpp`, `main/NekoGui.cpp`, `installer/mdmbox.iss`, `docs/BETA_ILYA_UPGRADE_PLAN.md`, `test/subscription-parser/README.md`, `test/managed-profile/README.md`.
