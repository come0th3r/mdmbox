# Карта вызовов MDMBOX

Обновлено: **2026-10-17**. Сверено с исходниками `beta-ilya` на базе
`d29619dad8b366ef93d02c6010e89aaa75b1aca9`; этот проход меняет документацию.
Карта описывает существующие цепочки, а не завершённый versioned API или
приёмку этапов 0–3. Начало работы: [UI_DEVELOPER_HANDOFF.md](UI_DEVELOPER_HANDOFF.md).

## Как поддерживать

При изменении вызова обновлять соответствующую цепочку **в том же коммите, что
и код**. Правило закреплено в [AGENTS.md](../AGENTS.md). Для новой подсистемы
добавлять раздел здесь либо ссылку на её контракт. Минимальная запись:

- Точка входа: UI event, slot, callback или backend caller.
- Цепочка `caller → callee`, source paths и условия переходов.
- Параметры: тип, единицы, границы, обязательность, смысл идентификаторов.
- Результат: return/signal/event, payload, корреляция и смысл success.
- Исполнение: синхронный участок, очередь/worker, завершение, timeout/cancel.
- Ошибки и эффекты: память, файлы, сеть, процессы, настройки ОС; что остаётся при отказе.
- Проверка/fixture и её границы. PASS указывать только после выполнения.

Согласовывать producer и consumer при изменении payload/requestId/событий.
Примеры — только synthetic; реальные URL подписок, токены, HWID, ключи и
тела пользовательских профилей сюда не помещать.

## 1. Транспорт, страницы и snapshots

Источники: [bridge header](../preview/mdmbox_shell_bridge.h),
[bridge implementation](../preview/mdmbox_shell_bridge.cpp),
[shell host](../preview/mdmbox_shell_window.cpp), [app.js](../ui/shell/app.js).

`MdmBoxShellWindow` создаёт `QWebEngineView`, `QWebChannel` и
`MdmBoxShellBridge`, регистрирует объект **`mdmboxBridge`**. Локальный
`app.js` получает его через `new QWebChannel(qt.webChannelTransport, ...)`.
Вызов из JS проходит через QWebChannel асинхронно; `void`-slot не даёт
прикладного подтверждения успеха. Внутри Qt handlers выполняются в UI thread,
если ниже явно не указаны worker/таймер.

| Вход | Цепочка и параметры | Результат, ошибки и эффекты |
| --- | --- | --- |
| Навигация `[data-page]` | `showPage(page)` → `bridge.navigate(pageKey)` → `MdmBoxShellWindow::navigate` | Поддержаны `dashboard`, `servers`, `settings`, `logs`; другой ключ открывает legacy через `triggerOpenLegacy`. Загружает `:/mdmbox-shell/index.html` или вызывает JS `mdmboxApp.navigate`. Ошибка чтения HTML даёт пустую строку; отдельного error event нет. |
| `loadFinished(ok)` / таймер 1200 мс / явный refresh | `refreshPageState` → `buildRefreshScript` → `buildShellState`, `buildServersState`, `buildRoutingState`, `buildLogsState` → `runJavaScript` → `window.mdmboxApp.update(state, servers, logs)` → `render` | Снимки заменяют JS model. При фокусе на input/select/textarea или refresh-freeze доставка пропускается. В локальном shell `routing` не передаётся в `update`; оставшийся injected DOM-код относится к legacy ветке. |
| Refresh dashboard/servers | `refreshPageState` → `MainWindow::shellMaybeScheduleSignalProbe` | Refresh не исключительно read-only: может запланировать signal probe. Сетевую работу учитывать при автоматизации. |
| Browser preview | `window.mdmboxApp.update(...)` / `navigate(...)` | Только модель и отображение в браузере; без Qt bridge не подтверждает native actions или runtime. |

`state` включает `connected`, выбранный/запущенный ID, настройки, счётчики и
`managedRuntime`; общего schemaVersion для всего shell snapshot пока нет.
UI `connected` legacy-ветки не является доказательством внешнего VPN.

**Разные consumers:** `hookPage()` сразу возвращает для схемы `qrc`. Поэтому
создаваемый этой функцией `window.mdmboxManaged` и DOM-события
`mdmbox-managed-command-result`, `mdmbox-managed-runtime`,
`mdmbox-managed-snapshot` относятся к non-qrc injection. В текущем локальном
`app.js` managed signal subscription не подключён; `state.managedRuntime`
приходит в polling snapshot. Не предполагать наличие `mdmboxManaged` в qrc UI.

## 2. Managed-команды и события

Цепочка: `MdmBoxShellBridge::managed*` →
`MdmBoxShellWindow::managedLoopback*Result` →
`MainWindow::managedLoopback*Result` → `ManagedSessionController` →
worker `ManagedSession` → managed store/validator/core.

Источники: [ManagedCommandContract.hpp](../sub/ManagedCommandContract.hpp),
[mainwindow.cpp](../ui/mainwindow.cpp),
[ManagedSessionController.cpp](../sub/ManagedSessionController.cpp),
[ManagedSession.cpp](../sub/ManagedSession.cpp),
[ManagedLaunchPolicy.hpp](../sub/ManagedLaunchPolicy.hpp).

| Slot / параметры | Backend и ограничения | Завершение и эффекты |
| --- | --- | --- |
| `managedStart(groupId, requestId)` | `managedLoopbackStartResult` → `managedLoopbackStart` → controller `start` → session `start`. Policy проверяет группу, archive/kind, конфликты legacy/TUN/system proxy/exit; controller должен быть свободен. | Очередь worker, чтение snapshot, проверка/запуск core и local readiness; затем `operationFinished`. |
| `managedStop(requestId)` | `managedLoopbackStopResult` → `managedLoopbackStop` → controller `stop` → session `stop`. Отказ при unavailable/busy controller. | Worker останавливает monitor и managed session; затем `operationFinished`. Это не команда остановки legacy proxy. |
| `managedReconnect(groupId, requestId)` | `managedLoopbackReconnectResult` → controller `reconnect` → session `reconnect`. Нужна та же активная Ready-группа и ненулевой PID, launch policy и свободный controller. | Читает сохранённый snapshot, применяет его с reconnect/recovery; `reconnectCompleted`. |
| `managedRefresh(groupId, requestId)` | `managedLoopbackRefreshResult` → controller `refreshAndReconnect` → session `refreshAndReconnect`. Те же guards, непустой URL группы. URL берётся из backend, не из JS payload. | Download/validate/commit и reconnect точного committed snapshot; `refreshCompleted`. Сеть, identity/store-файлы, процесс и local listeners. |
| `managedSnapshot()` | `managedRuntimeSnapshot` → `shellManagedRuntimeState` → controller `snapshot` | Возвращает JSON snapshot; JS получает его через callback QWebChannel. Нет запуска/остановки процесса. Без shell — `{}`; без controller — `available:false`, `state:"unavailable"`. |

`groupId` — именно JSON number, целое от 0 до INT_MAX (2147483647); строки,
дроби и нечисловые значения отклоняет `ManagedCommandContract::groupId`.
`requestId` — QString, возвращается в signal. Для reconnect/refresh обязателен
и ограничен 1..128 символами; у start/stop такой проверки сейчас нет. Это
корреляция, не idempotency key. Общего command cancel/progress/JS timeout нет.

MainWindow передаёт внутренние параметры: directory `managed-subscriptions`,
executable `<applicationDir>/mihomo.exe`, mixed port 17890, API port 19090,
readiness timeout 10000 мс. Это не параметры UI и не полный deadline download.
При `NKR_NO_YAML` runtime недоступен. Ошибки bridge: `Invalid group ID`,
`Shell is unavailable`; host без MainWindow — `Main window is unavailable`.

### Принятие и завершение

Slot выдаёт `managedCommandResult(requestId, result)` после попытки enqueue:

```json
{
  "schemaVersion": 1,
  "command": "managedRefresh",
  "accepted": true,
  "queued": true,
  "error": "",
  "runtime": {
    "schemaVersion": 1, "available": true, "scope": "loopback-only",
    "state": "ready", "busy": true, "groupId": 7,
    "controllerReady": false, "vpnConnected": false
  }
}
```

Это synthetic пример enqueue, **не успешное применение**. `queued` сейчас
равен `accepted`. Controller ставит `pending`, выполняет работу через
`Qt::QueuedConnection` в worker, затем `publish` возвращает завершение в UI
thread. `busy()` учитывает и доставку completion. `MainWindow` преобразует
signals controller в `managedRuntimeEvent`, shell пересылает его в bridge:

| `event.type` | Payload сверх `schemaVersion:1` и `runtime` |
| --- | --- |
| `operationFinished` | `requestId`, `command`, `success`; для start/stop, поля `error` нет. |
| `reconnectCompleted` | `requestId`, `command:"managedReconnect"`, `success`, `outcome`, `error`. |
| `refreshCompleted` | `requestId`, `command:"managedRefresh"`, `success`, `outcome`, `error` (пусто либо `Managed refresh/apply failed`). |
| `runtimeFailed` | `success:false`; нет command/requestId/error. Не привязывать автоматически к последнему запросу. |

`outcome`: `rejected`, `applied`, `stopped`, `restored`, `restore-failed`,
`stop-failed`, `none`. Восстановление старой сессии не означает применение
новой. Снимок completion reconnect/refresh фиксируется до observers;
дублирующий общий `operationFinished` для них MainWindow не пересылает.

Runtime state: `stopped`, `starting`, `running`, `ready`, `stopping`, `failed`
либо `unavailable` без controller. `controllerReady` требует Ready и !pending;
`vpnConnected` всегда false, scope `loopback-only`. Ready не доказывает внешний
VPN. Monitor worker проверяет unexpected failure каждые 100 мс.

### Обновление полной подписки

`ManagedSession::refreshAndReconnect` сначала проверяет executable и ready
session; затем `SubscriptionService::refresh` →
`ManagedSubscriptionRequest::build` → `InstallationIdentity::loadOrCreate` →
per-group `QLockFile` → fetch (`SubscriptionDownloader::fetch`) → metadata
checks → `ManagedProfileStore::commit` с guarded validator →
`reconnectSnapshot` точных `CommittedSnapshot.profile/metadata`.

Service возвращает bool и error, output committed меняет только на success.
Проверяет cancellation, expiry/traffic до commit и после validation; отказ
download sanitizes error. Применение может отказать **после disk commit**:
общая атомарность disk/runtime не обещана. Controller не передаёт UI cancel
в эту цепочку. Полный source сохраняется, legacy bean parsing — другая ветка.

Production `GroupUpdater::Update` также вызывает `SubscriptionService::refresh`
для `mihomo-full`, но его успешный commit сам по себе не запускает managed
session. Источники: [GroupUpdater.cpp](../sub/GroupUpdater.cpp),
[SubscriptionService.cpp](../sub/SubscriptionService.cpp),
[ManagedProfileStore.cpp](../sub/ManagedProfileStore.cpp).

## 3. Локальный shell: legacy-команды

Для таблицы общий префикс: DOM event → соответствующий slot
`MdmBoxShellBridge` → `MdmBoxShellWindow::trigger*` → указанный backend.
Все перечисленные slots — `void`, без requestId/result event. Silent guard
return не является success; последующий refresh не подтверждает запись.
Источники: [app.js](../ui/shell/app.js), [shell host](../preview/mdmbox_shell_window.cpp),
[mainwindow.cpp](../ui/mainwindow.cpp).

| Slot / вход | Цепочка, ограничения | Ошибки, исполнение и эффекты |
| --- | --- | --- |
| `connectToggle()` / `[data-action=connect]` | `triggerConnectToggle` → `neko_stop` при started_id≥0, иначе effective selected profile → `neko_start(id)` | Guard 1500 мс от повторного входа; нужны MainWindow/dataStore/bean. Меняет selected/group, вызывает compatibility `Save`. Старт/остановка legacy core, не managedStart. |
| `selectServer(id)` / выбор сервера | `triggerSelectServer` → `GetProfile` → `show_group`, selected_id, `Save`; при уже работающем proxy → `neko_start(id)` | Нужен существующий профиль. Выбор может перезапустить соединение. Save failure не останавливает этот путь. |
| `selectGroup(gid)` / выбор группы | `triggerSelectGroup` → `GetGroup` → current_group/`Save` → `show_group` → effective selected ID/`Save` | Нужна существующая группа; меняет память и настройки; отдельного result нет. |
| `toggleTun()` / `[data-toggle]` | `triggerTunToggle` → vpn_implementation=1/remember_enable/`Save` → `neko_set_spmode_vpn` | Изменяет TUN/системное сетевое поведение через legacy backend; checked persistence gate в этом wrapper отсутствует. |
| `toggleSystemProxy()` / `[data-toggle]` | `triggerSystemProxyToggle` → remember_enable/`Save` → `neko_set_spmode_system_proxy` | Изменение системного proxy; результат ОС не возвращается JS. |
| `setAutoStart(enabled)` / settings | `triggerSetAutoStart` → Windows `AutoRun_SetEnabled` → refresh | bool; меняет автозапуск ОС. На других платформах no-op кроме refresh; UI видит availability в snapshot. |
| `setSubscriptionAutoUpdate(enabled, intervalMinutes)` / settings | `triggerSetSubscriptionAutoUpdate` → qBound(30, minutes, 1440) → signed sub_auto_update/`Save` → `TM_auto_update_subsctiption_Reset_Minute` | Минуты; disabled хранится отрицательным значением, таймеру передаётся 0. Timer меняется и при unchecked save failure. Это не принятый managed scheduler. |
| `importClipboard()` / import | `triggerClipboardImport` → direct invoke `on_menu_add_from_clipboard_triggered` → `GroupUpdater::AsyncUpdate(clipboard)` | Чтение clipboard, async parse/download/persistence по содержимому. Refresh через 800/1800 мс не служит completion; нет bridge success/error. |
| `openBasicSettings()` / settings | `triggerOpenBasicSettings` → hide shell/show legacy → singleShot(0) → `on_menu_basic_settings_triggered` | Native settings dialog; выполнение после перехода event loop, не сохранение настроек само по себе. |
| `openLegacy()` / legacy | `triggerOpenLegacy` → hide shell → MainWindow show/raise/activate | Показывает существующий legacy UI. |

## 4. Routing slots

Slots существуют в bridge, однако routing не является локальной qrc страницей
`navigate`. Не считать их готовым полным UI для ordered mikan rules.
Общий backend — [shell host](../preview/mdmbox_shell_window.cpp).
`tabIndex`: 0 — domains, 1 — applications, **все остальные значения** идут в
IP-ветку; строгого enum range guard сейчас нет. `normalizedPolicy` только
trim/lowercase и пустое значение → `bypass`, не whitelist validator.

| Slot | Caller → callee и параметры | Эффекты/ошибки |
| --- | --- | --- |
| `routingSetDefault(policy)` | `triggerRoutingSetDefault` → def_outbound → `saveActiveRoutingState(true)` | При started_id≥0 явно вызывает `neko_start` после helper, без проверки результата записи helper. |
| `routingAddRule(tabIndex)` | `triggerRoutingAddRule` → `triggerRoutingEditRule(tabIndex, empty, empty)` | Modal native editor; cancel/пустой текст прекращает операцию. |
| `routingEditRule(tabIndex, value, policy)` | `triggerRoutingEditRule` → dialog → `collectRoutingRules` → `storeRoutingRules` | Старый value сравнивается case-insensitive + policy; замена добавляется в конец. Applications имеют общий Proxy/Bypass режим, смена при непустом списке запрашивает подтверждение. |
| `routingRemoveRule(tabIndex, value, policy)` | `triggerRoutingRemoveRule` → collect → удалить первое совпадение при проходе с конца → store | Даже без совпадения вызывается store; нет структурированного result. |
| `routingImportClipboard(tabIndex)` | `triggerRoutingImportClipboard` → JSON object либо построчный формат → append → store | Пустой clipboard показывает message. JSON parse failure переходит в plain-text разбор; это не strict full-profile import. |
| `routingResetRules(tabIndex)` | `triggerRoutingResetRules` → confirmation → очистка полей → save helper | Меняет текущую вкладку; отмена — return. |
| `routingExportConfig()` | `triggerRoutingExportConfig` → SaveFile dialog → `buildRoutingExportObject` → QFile write | Cancel/open error — return; длина записи не проверяется, bridge completion отсутствует. |

`storeRoutingRules` убирает пустые и дубли по policy + lower(value), затем
раскладывает domain/IP правила по policy; process list имеет единый режим.
Это не обещание сохранения произвольного ordered mikan ruleset.

`saveActiveRoutingState` → `syncRoutingSnapshot` → routing `Save()` →
dataStore `Save()` → `MW_dialog_message(UpdateDataStore[,RouteChanged])`.
`saveTunRuleState` аналогичен, отправляет `UpdateDataStore,RouteChanged,VPNChanged`.
Обе функции void, сохраняют разные файлы без общей transaction. Поздний
`SaveChecked` dispatcher не подтверждает успешность предшествующей routing
записи; rollback и общий apply gate здесь ещё не завершены.

## 5. Логи и окно

| Slot / событие | Цепочка | Результат/эффекты |
| --- | --- | --- |
| `clearLogs()` | `triggerClearLogs` → `MainWindow::shellClearLogs` → refresh | Очищает UI/backend буфер логов; не заявлять удаление всех disk logs. |
| `copyLogs()` | `triggerCopyLogs` → `shellLogText` → clipboard setText | Перезаписывает clipboard. Локальный JS показывает сообщение без backend ack. |
| `exportLogs()` | `triggerExportLogs` → SaveFile dialog → `shellLogText` → QFile write | Ошибка open показывает warning; cancel — return, short write не проверяется. |
| `data-log-action=pause/top/bottom` | Только `app.js`, `renderLogs`/scroll | Pause останавливает автопрокрутку, не core logging/получение snapshot. |
| `minimizeWindow()` | bridge → `showMinimized` | Операция окна, void. |
| `maximizeWindow()` | bridge → `isMaximized` → `showNormal`/`showMaximized` | Переключает состояние окна, void. |
| `startWindowMove()` | bridge → windowHandle `startSystemMove` | Вызывается при левой кнопке titlebar; без handle no-op, bool backend не пересылается. |
| `closeWindow()` | bridge → window `close` → `closeEvent` | По умолчанию hide shell/MainWindow и ignore event: это не exit. |
| `exitProgram()` | `triggerExitProgram` → allowHardClose=true → `on_menu_exit_triggered` | Выход через legacy cleanup; не эквивалент closeWindow. |

## 6. Checked persistence и MIG-10

Источники: [NekoGui_ConfigItem.hpp](../main/NekoGui_ConfigItem.hpp),
[NekoGui.cpp](../main/NekoGui.cpp), [mainwindow.cpp](../ui/mainwindow.cpp),
[dialog_edit_profile.cpp](../ui/edit/dialog_edit_profile.cpp).

`JsonStore::SaveChecked()` синхронно вызывает callback_before_save, проверяет
save_control_no_save, сериализует, пишет через QSaveFile с запрещённым direct
fallback и проверяет длину/commit. Cache обновляется только после commit.
Результат `{status, changed}`: `Saved`, `Disabled`, `OpenError`, `WriteError`,
`CommitError`; `ok()` истинно только при `Saved`. `changed` — отличие от
последнего успешного cache, не I/O success. Даже unchanged путь выполняет
запись. Compatibility `Save()` возвращает только changed и sanitized warning
при ошибке (кроме Disabled); не использовать этот bool как разрешение apply.

| Вход | Цепочка | Граница гарантии |
| --- | --- | --- |
| `MW_dialog_message(..., info)` с `UpdateDataStore` | UI dispatch → `MainWindow::dialog_message_impl` → dataStore `SaveChecked` → status check → refresh/restart prompts | При failure warning и return до automatic restart. Уже изменённые settings остаются в памяти; все ранние effects/будущие start paths этим не защищены. `RouteChanged`/`NeedRestart` меняют restart policy после success. |
| Existing-profile accept | `DialogEditProfile::accept` → `onEnd` detached entity → `saveExistingProfile` → live entity `SaveChecked` → message accept/restart → `QDialog::accept` | Сверяет live identity/id/gid/type/path/bean. Сохраняет актуальную live metadata, меняет только bean; при save failure откатывает собственный bean edit и не закрывает диалог/не просит restart. |
| New profile / apply-to-group | Другие ветки того же editor | New `AddProfile` и group targets не получили общую MIG-10 гарантию; checked source save не делает group операцию атомарной. |

Offline `LegacyBackup::Create/Verify/Restore/VerifyRestored` не подключены как
готовая startup activation/rollback цепочка. Их bounded contracts и fixtures:
[LEGACY_BACKUP.md](../test/subscription-parser/LEGACY_BACKUP.md),
[LEGACY_RESTORE.md](../test/subscription-parser/LEGACY_RESTORE.md).

## 7. Проверки и открытые границы

- Bridge/runtime fixtures и команды: [subscription-parser README](../test/subscription-parser/README.md), [ManagedBridgeFixture.cpp](../test/subscription-parser/ManagedBridgeFixture.cpp). Они проверяют конкретные synthetic/native slices, а не все перечисленные UI-цепочки.
- Save API evidence: [LEGACY_PERSISTENCE.md](../test/subscription-parser/LEGACY_PERSISTENCE.md); bounded dispatcher/editor evidence: [LEGACY_SAVE_CALLERS.md](../test/subscription-parser/LEGACY_SAVE_CALLERS.md). Historical PASS относятся к указанным там exact snapshots.
- Проверка документации 2026-10-17: все 31 public bridge slot представлены в карте, относительные ссылки четырёх изменённых документов разрешаются; **PASS**. Это проверка полноты перечня/ссылок, не автоматическое доказательство семантики.
- Локальные source checks 2026-10-17: `node --test test/legacy-migration-source.test.mjs test/subscription-probe.test.mjs` — **36/36 PASS**. Это не C++ runtime и не visual acceptance.
- Открыты общий versioned shell contract, qrc managed consumer, command timeout/cancel, settings rollback, все routing/group/new-profile callers и multi-store disk/runtime atomicity.
- Independent production review MIG-10 остаётся BLOCKED прежними UI-read permissions; карта вызовов его не заменяет.
- C++ rebuild, native UI/runtime/live-subscription проверки в documentation-only проходе **NOT RUN**. Build/clean стенды для документации не требуются.

При следующих изменениях сверять эту карту с исходниками и профильными
fixtures; обновление документации не закрывает implementation gates
[BETA_ILYA_UPGRADE_PLAN.md](BETA_ILYA_UPGRADE_PLAN.md).
