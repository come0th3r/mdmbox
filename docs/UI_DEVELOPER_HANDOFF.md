# Передача UI-разработчику — 2026-10-17

Рабочая ветка: **`beta-ilya`**. Это WIP source handoff, не beta-релиз,
не установщик и не закрытие этапов плана. `main` не изменять без release gates.
Пользователь временно передаёт UI другому разработчику; прежний приоритет
backend-этапов 0–1 не запрещает эту отдельную согласованную UI-работу.

## Получение

```powershell
git clone --branch beta-ilya https://github.com/come0th3r/mdmbox.git
cd mdmbox
git switch -c ui-polish
```

Если репозиторий уже есть, сначала сохранить свои изменения, затем обновить
`beta-ilya` fast-forward и создать собственную UI-ветку. Не делать reset/force-push.
Вернуть UI-изменения через отдельную ветку/PR в `beta-ilya`, не сразу в `main`.

## Где работать

Карта вызовов: [FUNCTION_CALLS.md](FUNCTION_CALLS.md). При изменении UI-команды,
bridge slot, payload или backend-цепочки обновлять её **в том же коммите**.
Указывать параметры, ответы/события, ошибки, побочные эффекты и проверки;
`accepted` не означает завершение операции. Правило закреплено в `AGENTS.md`.

| Путь | Назначение |
| --- | --- |
| `ui/shell/index.html` | Разметка dashboard/servers/settings/logs |
| `ui/shell/styles/app.css` | Геометрия, цвета, типографика, responsive |
| `ui/shell/app.js` | Рендер состояния, навигация, события |
| `ui/shell/assets/logs/` | Локальные SVG |
| `ui/shell/shell.qrc` | Перечень ресурсов; новый asset включать сюда |
| `preview/mdmbox_shell_window.cpp/.h` | Qt WebEngine host, snapshots, legacy injections |
| `preview/mdmbox_shell_bridge.cpp/.h` | QWebChannel slots |
| `ui/mainwindow.cpp`, `ui/mdmbox_mainwindow.cpp` | Native/backend интеграция; не менять без проверки контракта |
| `test/subscription-parser/ManagedBridgeFixture.cpp` | Production bridge/shell fixtures |

Самостоятельный просмотр: открыть `ui/shell/index.html` в браузере. `qrc:///`
QWebChannel script вне Qt недоступен — это ожидаемо; native команды не работают.
Навигация и рендер доступны, но это **не полноценный mock bridge**.
Для synthetic состояния в DevTools использовать существующий API:

```javascript
window.mdmboxApp.update(
  { connected: false, selectedId: -1, startedId: -1, settings: {} },
  { items: [], groups: [], currentGroup: -1 },
  { lines: [], total: 0 }
);
window.mdmboxApp.navigate('servers'); // dashboard / settings / logs
```

Не добавлять demo-данные в production snapshots и не показывать fake latency,
квоты или «VPN подключён» по одному Ready/started_id. В legacy shell уже есть
неполные статусные тексты — их требуется согласовать с backend-контрактом.
Browser-preview не заменяет проверку в Qt WebEngine.

## Figma и визуальная приёмка

Файл: https://www.figma.com/design/dpomJg0l41jhSZfAZOV2fB

| Frame | Node | Размер |
| --- | --- | --- |
| Главная Disconnected | `6:8` | 1280×1024 |
| Главная Connected | `9:2` | 1280×1024 |
| Серверы | `6:347` | 1280×1024 |
| Настройки | `6:736` | 1280×1244 |
| Логи | `6:1077` | 1280×1024 |

Требования и исходные tokens — разделы 5–6
`docs/BETA_ILYA_UPGRADE_PLAN.md`. Проверить Liberation Sans/Liberation Mono
по оригиналу, не подменять молча Inter. Assets хранить локально, без runtime CDN
или временных Figma URLs; screenshot не использовать как фон интерфейса.
Локальные промежуточные screenshots не передаются как эталоны Figma.

Открыто: reference/asset/font manifest, все пять visual diffs, native Qt captures,
DPI100/125/150/200%, empty/loading/error/expired/device-limit/unsupported состояния,
клавиатура/focus/scroll и контекстные меню. Геометрию сохранять; противоречивые
demo-статусы макета заменять данными backend, документируя отличие.

## Проверки и сборка

```powershell
node --check ui/shell/app.js
node --test test/legacy-migration-source.test.mjs test/subscription-probe.test.mjs
```

Build setup: `docs/STAGE0_BUILD_MANIFEST.md`, `tools/check-build-environment.ps1`,
`tools/build-baseline-gui.ps1`. Локальный компьютер автора не содержит полного
Qt/MSVC toolchain. На согласованном build-host использовались Qt6.7.2/MSVC2022;
наличие этих SDK не означает воспроизводимую clean-checkout сборку.

Parser target: `-DMDMBOX_SUBSCRIPTION_PARSER_TEST=ON`, затем
`mdmbox_subscription_parser_test.exe --shell-ui-only <capture-directory>`.
Сначала проверить prerequisites fixture и пользоваться disposable synthetic cwd;
не запускать тесты в каталоге пользовательской установки. Native window snapshot
и browser screenshot различаются. GUI/resources надо пересобирать после изменений.

Последний выполненный exact snapshot MIG-10/R3: Windows Release build +10 migration
modes PASS,498 hashes неизменны, local36/36. Evidence:
`test/subscription-parser/LEGACY_SAVE_CALLERS.md`. Это не полный C++/UI release gate
текущего handoff-коммита. Новая полная clean-checkout сборка и visual acceptance
для handoff **NOT RUN**. Packaging/notices передаются как незавершённый WIP;
новый дистрибутив не собран. Исторический alpha smoke не относится ко всему HEAD.

## Что нельзя сломать

- `SaveChecked()` различает success и changed. Сохранение не удалось — нельзя
  показывать успех, закрывать редактор или автоматически перезапускать proxy.
- MIG-10 settings failure ещё оставляет изменения в памяти; rollback и все apply
  paths открыты. Независимый production UI review BLOCKED, fixture review завершён.
- Полный managed mihomo source/proxy-groups/rules/DNS сохранять; не flatten-ить.
- Detached backup/restore не активирует appdata и не является полной миграцией.
- Часть settings идёт в legacy UI/отключена. Не заменять unsupported действия
  оптимистическим «успехом» и не расширять runtime capabilities ради внешнего вида.
- TUN/system proxy, реальные подписки и панель не трогать для визуальных тестов.
- Не менять backend `sub/`, `db/`, persistence и packaging в UI-PR без отдельного
  согласованного scope; добавлены в handoff для сохранения текущей общей базы.

Секретный `.env.mikan-test.local`, generated keys/configs, browser logs,
локальные `.opencode` настройки и промежуточные screenshots не передаются.
При необходимости live-тестов получить отдельный безопасный доступ; три выделенные
подписки в последнем срезе **NOT RUN**. Release/merge-main не разрешены.

Актуальные ограничения: `PROJECT_MEMORY.md`; подробная приёмка:
`docs/BETA_ILYA_UPGRADE_PLAN.md`. После UI-работы обновить handoff, указать SHA,
реально выполненные tests/captures и оставшиеся BLOCKED/NOT RUN.
