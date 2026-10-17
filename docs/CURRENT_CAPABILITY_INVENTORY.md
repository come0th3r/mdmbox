# Инвентарь фактических возможностей клиента

Инвентарь проверен в рабочем дереве `beta-ilya`, основанном на HEAD `be1e9f8f945db9a7fe5055de6a56c5bdfd761a40` (2026-10-17); tracked backend/UI/test files содержат незакоммиченные изменения, поэтому это не чистый снимок указанного коммита. Документ фиксирует наличие кода и границы имеющихся доказательств; это не заявление о полном принятии функций, совместимости mikan или готовности к выпуску. Перед дальнейшим использованием сверить инвентарь с актуальным HEAD и состоянием изменений.

## Термины статуса

- **Реализовано (legacy)** — есть соответствующий путь в существующем клиенте/ядре. Это не означает приёмку сценария на текущем HEAD.
- **Ограниченно подтверждено** — пройдена только указанная synthetic/localhost проверка.
- **Не принято** — реализация отсутствует, ограничена или требуемое acceptance-доказательство не найдено. Не следует выводить поддержку из parsing или генерации конфигурации.

## Возможности и границы

| Область | Фактическое состояние в коде | Имеющееся подтверждение и ограничения |
|---|---|---|
| Импорт профилей | Legacy `RawUpdater` принимает ссылки, Base64, JSON и Clash YAML; поддерживает отдельные bean-типы и преобразование профиля в sing-box outbound/share link. `mihomo-full` — отдельный managed путь, сохраняющий исходный документ. | `test/subscription-parser/README.md`: parser regression и отдельный synthetic managed refresh/runtime путь. Набор импортируемых схем и протоколов не равен protocol acceptance matrix; полный mihomo YAML export не заявлен. |
| Группы и порядок | Группы/профили хранятся в JSON-файлах; порядок групп, вкладок и профилей хранится отдельно в модели. В `Group` есть архив, пропуск автообновления, URL и `subscription_kind`; старый JSON без `subscription_kind` получает значение `links`. | Точечный file round-trip/default-to-`links` покрыт `test/subscription-parser`. Полная миграция данных, rollback и crash recovery для legacy-хранилища не подтверждены. |
| Обновление подписок | Legacy `GroupUpdater::Update` сохраняет прежний importer; managed `mihomo-full` проходит production downloader/service/store validation и хранит source + metadata envelope. Обновление по таймеру есть в legacy `MainWindow`; интервал запускается только при значении не меньше 30 минут. | Synthetic production refresh и combined refresh-to-session loopback E2E описаны в `test/subscription-parser/README.md`. Managed автоматический scheduler, panel-driven interval policy, jitter/backoff и координация всех writers не реализованы/не приняты. Legacy запись отдельных JSON-файлов не является транзакцией. |
| Выбор и запуск узла | Legacy UI выбирает профиль, строит sing-box config, вызывает core по gRPC и обновляет состояние/счётчики. Есть отдельный managed controller/session для `mihomo-full`; владение legacy/managed core сериализуется и конфликтующий запуск блокируется. | `test/managed-profile/README.md` и `test/subscription-parser/README.md` подтверждают отдельные loopback slices. Статус managed `Ready` означает локальную readiness ядра/API, не внешний VPN. Полная пользовательская матрица протоколов не пройдена. |
| Протоколы | В legacy bean/parser и генераторах встречаются SOCKS/HTTP, Shadowsocks, VMess, Trojan, VLESS, Naive, TUIC и Hysteria2; часть VLESS transport/TLS-параметров также преобразуется. Managed policy сейчас принимает только ограниченный reviewed loopback-контракт. | Успешный parse/config-build не доказывает соединение. Подтверждены только перечисленные в README конкретные synthetic runtime cases (включая VLESS REALITY Vision/TCP, SOCKS5 slices и HTTP CONNECT); остальные варианты, включая REALITY UDP, XHTTP/gRPC и общая Hysteria2/TUIC совместимость, остаются непринятыми. |
| TUN / VPN mode | Legacy sing-box builder умеет создавать TUN inbound с auto/strict route, MTU, IPv4/опциональным IPv6 и выбранным stack; UI имеет включение и проверку привилегий. Managed запуск требует loopback и отказывает при активном TUN. | В рамках текущего этапа системный TUN не запускался. Нет acceptance-проверок OS routes, DNS, аварийного восстановления или managed TUN. Конфигурация — не доказательство работающего VPN. |
| System proxy | Legacy UI переключает системный proxy; низкоуровневая реализация содержит платформенные ветви Windows/Linux/macOS. Вызов из UI передаёт настроенный mixed inbound port; проверка реального OS state не выполнялась. Managed запуск отказывает, пока system proxy активен. | В этой работе системные настройки не менялись. Не приняты rollback/recovery, сохранение и точное восстановление прежнего proxy state, а также OS acceptance. |
| DNS, маршрутизация и правила | Legacy `ConfigBuilder` генерирует DNS servers/rules, domain/IP/geosite/geoip rules, process matching, route final, optional FakeIP для внутреннего TUN. Требуемые geo assets ищутся локально, при отсутствии build завершается ошибкой. | Это подтверждение наличия генерации, не поведения трафика. Managed policy fail-closed для неподдержанного DNS/provider/reference; synthetic правила и отдельные policy checks см. `test/managed-profile/README.md`. Реальная семантика DNS/FakeIP, геоданных, process routing и внешних providers не принята. |
| Трей и автозапуск | Main window создаёт system tray icon/context menu; закрытие окна скрывает его, если иконка доступна. Windows autostart записывает команду `-tray` в HKCU Run. В `AutoRun.cpp` есть также реализации для других ОС. | Наличие кода не является проверкой поведения на версиях Windows/desktop environments. Установка/удаление autostart и восстановление состояния на чистой VM не принимались. |
| Горячие клавиши | При наличии QHotkey регистрируются глобальные shortcuts для окна, групп, routing и system-proxy menu; при `NKR_NO_QHOTKEY` используется пустая реализация. | Функциональная acceptance-матрица горячих клавиш не подтверждена; доступность зависит от build configuration и регистрации ОС. |
| Настройки и хранение | Общие настройки, включая группы, ports, routing/TUN, расписание, tray/minimal start и shortcuts, сериализуются через `JsonStore`. MIG-06/R1 добавляет checked per-file `SaveChecked()` через QSaveFile, без cache update при отказе. | Bool `Save()` по-прежнему change hint, не success; callers/UI пока не блокируют apply при ошибке записи. Нет verified backup, журнала или multi-store transaction. Windows per-file evidence: `test/subscription-parser/LEGACY_PERSISTENCE.md`. У managed envelope и installation identity собственные `QSaveFile` пути. |
| Миграция данных | Совместимое значение по умолчанию для отсутствующего `subscription_kind`; MIG-07 сохраняет rejected profile originals и их filename IDs, не включает их в usable graph, отказывает reorder при rejected input. | Windows preservation slices приняты ограниченно: `test/subscription-parser/LEGACY_LOAD_PRESERVATION.md`. Нет verified backup/quarantine/rollback и full schema/identity validation. Default-group creation всё ещё пишет новый файл; single-writer stale-path guard не concurrent no-clobber. Полная миграция/upgrade не приняты. |
| Установщик | `installer/mdmbox.iss` задаёт x64-compatible Inno Setup installer с admin privileges, копированием staged tree, shortcuts и post-install запуском. Для package есть `tools/package-installer.ps1`. | Скрипт/описание не подтверждают чистую установку, upgrade-in-place, сохранение данных, uninstall cleanup или чистую VM-приёмку текущего HEAD. |
| UI / backend boundary | Существуют legacy Qt Widgets и новый local HTML/Qt WebChannel shell; backend hooks покрывают часть навигации, выбора профиля, настроек и managed lifecycle. | Synthetic bridge и shell fixture описаны в parser README. Это не полная Figma visual acceptance, не полный native interaction coverage и не contract freeze для всех экранов. UI polishing по решению пользователя отложен после этапов 0/1. |

## Вывод для этапов 0/1

1. Нельзя считать клиент «не имеющим функций»: legacy импорт, sing-box config generation, группы, TUN/system proxy, DNS/routing, tray и Windows autostart уже существуют.
2. Нельзя переносить этот статус на managed `mihomo-full`: он намеренно loopback-only и fail-closed для части OS/provider/DNS функций.
3. Нельзя считать parsing, core config-check или локальный `Ready` доказательством внешнего VPN. Runtime-доказательства ограничены конкретными synthetic fixtures и перечисленными в профильных README сценариями.
4. Миграция и legacy persistence остаются отдельным риском: совместимость одного поля проверена, но общей атомарной миграции и upgrade acceptance нет.
5. Инвентарь закрывает только пункт «Составить список текущих возможностей» этапа 0. Он не закрывает backend/UI contracts, migration/capability matrix acceptance, dependency/toolchain manifest, чистую сборку или этап 0 целиком.

## Проверенные источники

- `sub/GroupUpdater.cpp`, `sub/SubscriptionService.cpp`, `sub/ManagedProfileStore.cpp`, `sub/ManagedSession.cpp`, `sub/ManagedRuntimePolicy.cpp`
- `db/Database.cpp`, `db/ConfigBuilder.cpp`, `main/NekoGui.cpp`
- `fmt/Link2Bean.cpp`, `fmt/Bean2CoreObj_box.cpp`
- `ui/mainwindow.cpp`, `ui/mainwindow_grpc.cpp`, `sys/AutoRun.cpp`, `3rdparty/qv2ray/v2/components/proxy/QvProxyConfigurator.cpp`
- `installer/mdmbox.iss`, `tools/package-installer.ps1`
- `test/subscription-parser/README.md`, `test/managed-profile/README.md`

Это code inventory текущего дерева, а не полный тестовый аудит каждого перечисленного поведения.
