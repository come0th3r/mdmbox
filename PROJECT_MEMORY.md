# MDMBOX — Project Memory

Обновлено: **2026-10-15**.
Назначение: восстановить контекст проекта между сессиями. Факты, предложения и результаты проверок ниже разделены.

## 1. Цель пользователя

Обновить Windows-клиент MDMBOX:

- Поддержать подписки, автоправила и протоколы панели mikan.
- Выполнить pixel-perfect перенос предоставленного интерфейса Figma.
- Изучить существующий стек и связи с Nekobox; интерфейс можно сначала разрабатывать отдельно, затем интегрировать.
- Отправлять законченные изменения в `beta-ilya` через установленный и авторизованный Fork.
- Самостоятельно провести испытания, затем объединить результат с основной веткой и выпустить релиз.

Пользователь первоначально допускал Python только для Qt-интерфейса и спросил о Qt на C++. Исследование показало, что текущий UI-хост уже написан на C++; рабочий план предлагает **полностью обойтись без Python**, включая UI, тесты и собственные скрипты.

## 2. Источники и контрольные ревизии

| Источник | Идентификатор |
| --- | --- |
| MDMBOX | `https://github.com/come0th3r/mdmbox` |
| mikan | `https://github.com/Miroshka000/mikan` |
| Figma | `https://www.figma.com/design/dpomJg0l41jhSZfAZOV2fB/MDMBOX-Ilya?node-id=0-1` |
| Подробный рабочий план | `docs/BETA_ILYA_UPGRADE_PLAN.md` |
| База исследования MDMBOX | `a7a9d133ba8bb8f1278fc7536bb3d2ac01e30c30` |
| Исследованная ревизия mikan | `a7b32c3efdfe85fe2450940f876fbb27fcf11ecc` |
| Опубликованный коммит плана | `16cfdeb2dd27b74204dfe96177a9f32a2da2f571` |

Это snapshots исследования, не утверждение о будущих latest-версиях. Перед обновлением зависимостей проверять upstream и фиксировать новую базу совместимости.

## 3. Текущий статус и точка продолжения

**Текущий этап: 0 — исследование и воспроизводимая основа; этап ещё не завершён.**

Сделано:

- Изучены основные подсистемы MDMBOX, генераторы подписок mikan и контекст пяти Figma frames.
- Составлен и опубликован подробный план с критериями готовности, матрицей протоколов и release gates.
- Создана ветка `beta-ilya` от `origin/main`, настроен upstream `origin/beta-ilya`.
- Проверены UTF-8, структура документа, исходные пути и staged diff; публикация плана подтверждена remote SHA.
- Созданы эта память и корневой `AGENTS.md` с порядком чтения контекста.
- Пользователь передал тестовую подписку и поручил начать реализацию. Ссылка считается секретом и здесь не хранится.
- Добавлены read-only build preflight, ограниченный HTTPS subscription probe и автономные синтетические тесты; результаты и команды — `docs/STAGE0_BASELINE.md`.
- Выполнено 14/14 тестов probe — PASS; PowerShell syntax и diff-check — PASS.
- Проверены живые HEAD и GET uri/clash: HTTP 200; URI-ответ содержит 20 ссылок (16 VLESS, 4 TUIC), Clash candidate — секции proxies/proxy-groups/rules/dns. Это не runtime validation.
- Preflight: 19 BLOCKED checks; найдены Node.js 24.20.0 и QHotkey, прочие SDK/packages/replacement checkout не найдены в проверенных местах. Baseline build не выполнен.
- Пользователь предоставил отдельную Windows 11 машину для сборки/тестов. SSH-вход через Bitvise подтверждён; credentials и адрес стенда в памяти не сохраняются. Read-only inventory: Windows build 26100, RAM 16 GiB, 8 logical CPUs, свободно около 85 GiB; Git 2.56.0.windows.2, Go 1.27.2 windows/amd64, Node.js 24.21.0. CMake/Ninja/MSVC не найдены в PATH, Qt/MSVC/CMake — в проверенных стандартных каталогах. Установка SDK и сборка там ещё не выполнялись.
- Пользователь разрешил установку и настройку стенда; предоставил fallback proxy (секреты не сохранять). Создан отдельный checkout `%USERPROFILE%\mdmbox-build\mdmbox` на `beta-ilya`, восстановлены соседние libneko/sing-box/sing-quic по SHA из плана. На стенде 14/14 тестов probe — PASS. Установлены Scoop CMake 4.4.4 и Ninja 1.13.2 с успешной проверкой хешей. Запущены установка Microsoft Build Tools 2022 (VCTools + recommended, без reboot; перед запуском проверяется подпись Microsoft) и загрузка Qt 6.7.2 MSVC2019 x64 base/WebEngine/WebChannel/Positioning/ShaderTools с HTTPS-зеркала Berkeley (проверка опубликованного SHA1, запись SHA256). Завершение этих двух фоновых задач ещё не подтверждено; не считать SDK установленными до проверки результатов. Qt 6.7.2 — кандидат baseline, не окончательный runtime release pin.
- Build Tools завершён: exit 0, vswhere 17.14.42, `C:\BuildTools`, reboot не требуется. Проверены MSVC tools 14.44.35207 и Windows SDK 10.0.26100.0: реальная компиляция и запуск C++17 smoke с `windows.h` и WinAPI — PASS. Bootstrap SHA256 `2A6AA7D94E38D457A4EB3930FC60056ECAB06865B2EB925E5275B8473A017583`, подпись Microsoft Valid. Повторный preflight — 12 BLOCKED (Qt, четыре C++ packages, sing checkout). Первый Qt download остановился на timeout checksum qtsvg; запущена повторная задача с retry и инкрементальным manifest. Её завершение ещё не подтверждено; Qt readiness не заявлять.
- Qt download завершён: все 11 архивов проверены/распакованы, manifest в `mdmbox-build/downloads/qt-6.7.2-manifest.json` на стенде. `Qt/6.7.2/msvc2019_64/bin/qmake -query QT_VERSION` вернул 6.7.2; все семь package presence checks — PASS. Qt compile/WebEngine runtime smoke ещё NOT RUN. Исправляется ложное требование C++ gRPC в preflight: CMake использует только Protobuf (см. `cmake/myproto.cmake`). Запущена сборка yaml-cpp 0.7.0, ZXing 2.0.0, Protobuf 21.4 в отдельных `cpp-sources`/`cpp-built` с manifest source SHA; результат ещё не получен. Для старых CMakeLists под CMake 4 явно передаётся `CMAKE_POLICY_VERSION_MINIMUM=3.5`, без изменения upstream sources.
- C++ dependency job завершился без ошибки: yaml-cpp/ZXing/Protobuf установлены в `mdmbox-build/cpp-built`, Protobuf v21.4 commit `c9869dc7803eb0a21d7e589c40ff4f9288cd34ae`. Запущена первая GUI-only Release configure/build в отдельном `mdmbox-build/baseline-gui` с Qt и prefix зависимостей; результат ещё не получен. Go core и runtime smoke не выполнены.
- Первый GUI configure завершился ошибкой: CMake сообщал `CMAKE_POLICY_VERSION_MINIMUM=3` вместо переданных без кавычек `3.5`. Вероятна обработка аргумента PowerShell, не доказанная несовместимость Qt/CMake. Запущен повтор с массивом строк и `'-DCMAKE_POLICY_VERSION_MINIMUM:STRING=3.5'`, с выводом cache entry. Результат пока не получен; Qt configs не модифицировались.
- Повторный GUI Release configure/build — PASS: cache policy `3.5`, 80/80 steps, source `4ad14e0`, удалённое дерево чистое. `baseline-gui/mdmbox.exe` 15901184 bytes, SHA256 и source dependency SHA записаны в `docs/STAGE0_BASELINE.md`. Runtime, deployment, Go core и чистая VM — NOT RUN. Это не полная baseline-сборка и не завершение этапа 0. Далее согласовать sing replacement, собрать core и подготовить runtime smoke; оформить воспроизводимые scripts.
- Добавлен и проверен на стенде `tools/build-baseline-gui.ps1` (повторный configure/build PASS, прежний SHA256 GUI). Не удаляет trees, не меняет manifests, восстанавливает process environment. Получен SagerNet/sing v0.4.3 SHA `f7cd94b14d31ace655e3f2285463c2ebf30294aa`; core build с Go 1.27.2, checksum verification и `-mod=readonly` FAILED на linkname `net.errNoSuchInterface` в sing/common/control. Manifests чистые, linker checks не отключались. Следующий шаг — исследовать upstream fix/совместимый pinned fork и тесты interface finder, затем повтор core build. Runtime пока NOT RUN. На стенде новый build script временно скопирован в tools как untracked; перед pull проверить и сохранить/сопоставить файл, не удалять вслепую.

- Linkname blocker снят backport однофайлового upstream fix `SagerNet/sing@a33349366d899068145f2d0e3ea0f5b2632fa3f2` на v0.4.3: `libs/patches/sing-v0.4.3-linkname.patch`. Проверка/применение патча и core build Go 1.27.2 — PASS, linker/checksum checks включены, manifests не менялись. Dependency sing теперь patched плюс test overlay, не чистый tag. Version CLI: sing-box 1.9.7-neko-1, NekoBox N/A, revision 8b06edc. 2/2 compatibility tests interface finder — PASS; valid direct-only config accepted и invalid outbound rejected — PASS. SHA256 core записан в baseline doc. Далее: явный pinned bootstrap/core build entry point, loopback/runtime smoke и Qt deployment; GUI/WebEngine runtime, proxy/TUN/RPC/E2E и чистая VM ещё NOT RUN.

**Ещё не сделано:** реализация managed subscriptions/mihomo, новая вёрстка, интеграция, полная clean-VM baseline-проверка, runtime/E2E/visual tests, beta/stable release. Предлагаемые `SubscriptionService`, `ManagedProfileService`, `CoreManager` и `ui/shell/` — будущие элементы, а не готовый код.

Последняя проверка data path: добавлен `tools/core-loopback-smoke.mjs`; на стенде Node.js 24.21.0 дважды PASS HTTP inbound → direct outbound → локальный HTTP origin, по одному запросу. Syntax PASS, несуществующий core ожидаемо отклонён с exit 1; повторный успешный запуск PASS. Скрипт использует только synthetic config/loopback, очищает свои процессы/временный каталог, не меняет proxy/TUN/routes. Локально Node по PATH не найден, локальный запуск не выполнен. Внешние VPN-протоколы/RPC/TUN/DNS-политика не проверены. Далее оформить pinned bootstrap/core build и Qt deployment/WebEngine runtime smoke.

Добавлен `tools/build-baseline-core.ps1`: проверка pinned dependency HEAD/diff и exact sing patch blob, разрешённый test overlay, Go 1.27.2, readonly manifests/checksum verification; source preparation отдельно. Первый запуск выявил несколько Go executable в PATH, исправлен выбор первого. Повторная сборка через script PASS, SHA256 совпал с прежним; новый binary loopback PASS. На удалённом checkout 8b06edc теперь скопированы untracked core script и fixture вместе с прежним GUI script: перед обновлением сопоставить с tracked файлами, не удалять вслепую. Далее dependency bootstrap и Qt deployment/runtime; negative provenance checks ещё NOT RUN.

Qt runtime smoke: самостоятельный `test/webengine-smoke` собран и развёрнут windeployqt в новом каталоге на стенде; запуск без Qt SDK в PATH PASS (`WEBENGINE_LOCAL_HTML_JS_PASS Qt=6.7.2`), sandbox не отключён. Проверены local HTML load и JS, QWebChannel установлен, но roundtrip не проверен. Warnings: NMEA plugin missing Qt6SerialPort.dll, VMware SVGA → LLVMPipe, Vulkan/GPU detection и DPI awareness failed. Полнота deployment/GPU/DPI/visual gates не закрыты; это не запуск MDMBOX и не clean VM. Далее исправить/ограничить deployment dependencies, проверить bridge roundtrip и isolated MDMBOX startup; pinned bootstrap тоже незавершён.

WebEngine smoke расширен Q_OBJECT bridge (echo + complete), JS загружает локальный Qt qwebchannel.js и проверяет C++ reply; добавлен AUTOMOC. Rebuild/deploy в новый `webengine-channel-deploy` и runtime без SDK PATH — PASS: `WEBENGINE_LOCAL_HTML_JS_PASS` и `WEBENGINE_QWEBCHANNEL_ROUNDTRIP_PASS`, Qt 6.7.2. Sandbox не отключался. Warnings SerialPort/NMEA, VMware LLVMPipe/Vulkan/GPU/DPI сохраняются. Проверен synthetic bridge отдельного target, не production bridge MDMBOX. Далее — закрыть runtime dependency warning и isolated client startup, затем pinned bootstrap; release gates не закрыты.

SerialPort/NMEA missing dependency устранена: Qt SerialPort 6.7.2 из того же repository, SHA1 проверен, SHA256 в baseline doc. Deployment автоматически включает Qt6SerialPort.dll. Вызов вне VsDevCmd выявил missing DXCompiler/DXIL/VCINSTALLDIR warnings; повтор в x64 VsDevCmd устранил их и добавил dxcompiler.dll/dxil.dll/vc_redist.x64.exe. Presence этих файлов и QtWebEngineProcess PASS; HTML/JS/QWebChannel runtime без SDK PATH снова PASS. VMware software rendering/Vulkan/GPU/DPI warnings остаются. Далее isolated MDMBOX startup после аудита side effects, pinned bootstrap; clean VM и полная DLL/installer проверка NOT RUN.

Isolated startup observation завершена: новые client-startup-deploy/client-startup-data, `-many -appdata`, исходный GUI + verified core, windeployqt в VsDevCmd и запуск без SDK PATH. Audit: defaults spmode false, remember_id -1919, remember_spmode empty; существующие данные не использовались. Через 12 секунд clientAlive true, прямые дети QtWebEngineProcess.exe и nekobox_core.exe; HKCU proxy snapshot неизменён до/после очистки. MainWindowHandle 0/title empty, newdesign отсутствует; наличие отображаемого окна не подтверждено. Это PARTIAL startup observation, не GUI/RPC PASS. Созданные клиент и наблюдавшиеся прямые дети принудительно завершены; graceful shutdown и отсутствие потомков второго уровня не проверены. Далее исследовать видимость окна/отсутствующие assets, проверить RPC readiness и graceful shutdown; pinned bootstrap и clean VM gate остаются незавершёнными.

При начале реализации проверено: `beta-ilya` отслеживает `origin/beta-ilya`, HEAD `d124815`, рабочее дерево было чистым, staged diff пустым. Эти значения не заменяют новую проверку git в следующей сессии.

### Следующая рабочая задача

Последнее указание пользователя: продолжать самостоятельно, спрашивать только о существенных решениях. Приоритет — backend подписок до новой Figma UI; незакрытые stage-0 gates не объявлять выполненными.

После `deb5d09`: RawUpdater получил detached staging mode; GroupUpdater сначала разбирает ответ без записи и отклоняет пустой/ошибочный результат до удаления профилей или изменения metadata/URL. Исправлено сохранение совпавшего профиля с индексом 0. Это ранняя защита от потери данных, НЕ полная транзакция: individual JSON writes, core validation, partial unsupported imports, concurrency/crash rollback остаются. Opt-in parser regression runner с временной БД на Windows: 22/22 checks PASS, process exit 0; production entry point build после отключения test option PASS. Snapshot QHotkey copy, cwd cleanup и PowerShell exit-code observation исправлены после выявленных сбоев тестового harness. Исходный remote checkout не менялся. Warnings offscreen OpenGL и legacy YAML bad conversion остаются. Далее full managed-profile model/storage + mihomo validation; GroupUpdater empty-response guard нуждается в end-to-end update тесте, не только parser staging.

После опубликованного `15d3951` добавлен standalone `sub/ManagedProfile.*`: exact full mihomo source bytes/SHA256 и ordered display indexes, без flatten DNS/groups/rules/providers/unknown fields. Структурно требует inline proxies/groups/rules/dns, отклоняет duplicate keys/names, multi-document, malformed/oversized/invalid UTF-8/NUL и bounded traversal aliases. Windows standalone build + CTest 1/1 PASS: synthetic full profile принят, 14 invalid cases отклонены, прежний source/hash сохранён. Это НЕ core validation; пока не подключено к GroupUpdater/storage, mikan denial stubs и hard parse-time resource limits ещё не реализованы. Далее pinned mihomo validator + managed storage atomic commit, затем связать сервис refresh с существующими группами; backend прежде UI.

После `24a48cd` добавлен `ManagedProfileStore`: schema-1 single-file envelope по existing group ID, exact Base64 source/SHA256, mandatory validator callback, QLockFile writer serialization, QSaveFile без direct fallback, previous snapshot перед replacement. Windows build/CTest 1/1 PASS: rejected/missing validator, invalid input/ID, lock contention, replacement/previous bytes, corrupt current rejection, snapshot-write failure preserves current. Валидаторы тестов synthetic, НЕ mihomo; refresh/group metadata/runtime integration ещё нет. ACL/disk-full/process-crash/power-loss/stale lock recovery NOT RUN. Далее получить pinned mihomo и bounded config-check adapter, затем подключение refresh и typed metadata. Snapshot содержит приватный профиль и должен храниться только в защищённом appdata; Base64 не encryption.

После `c4ee56f` получен official mihomo v1.19.32 windows-amd64-v1, archive digest проверен по release API, executable SHA256 pinned в `MihomoValidator` и `libs/mihomo-windows-baseline.json`. Version output: v1.19.32/go1.26.8/with_gvisor. Adapter `-t -d temporary -f -` stdin, очищает CLASH_* env, null stdout/stderr, 5s start/15s config timeout+kill; worker-only synchronous. Windows build/base CTest PASS, real integration PASS exit 0: valid SOCKS config accepted, unknown protocol rejected, real-validator store rollback preserves bytes, wrong hash/missing exe rejected. Это config-check, НЕ protocol support/runtime; temporary home не sandbox, parse может обращаться к provider/geodata/local files. Timeout fault injection/memory/confinement/TOCTOU NOT RUN. Далее typed subscription metadata/request contract, refresh integration с existing groups и безопасное runtime projection/provider provisioning; UI не начат.

После `8a39f96` добавлен `SubscriptionContract`: optional uint64 usage/total + int64 expiry, unknown vs unlimited, overflow-safe exhaustion, Base64 UTF-8 title и web URLs, интервал 1–168 часов. HTTPS request builder сохраняет custom path/query values, заменяет format на clash, строит MDMBOX/app mihomo/core UA из переданных version-shaped strings (actual verification обязан caller). Windows build/CTest 1/1 PASS включая malformed/duplicate/overflow/header-injection/query tests и прежние structure/store suites. Это пока standalone contract, не HTTP service; metadata persistence/HWID/scheduler/denial stubs/managed refresh integration остаются. Далее bounded download service + persisted installation identity, затем сквозной refresh existing group → metadata/document → real core validation → atomic commit. Не считать managed subscriptions уже доступными в клиенте.

После `dc61ac3` добавлен standalone `InstallationIdentity`: schema-1 UUID file в appdata, lock + atomic write; corrupt/unavailable identity не регенерируется автоматически, machine identifiers не читаются. Windows build/CTest 1/1 PASS: creation/stable reuse/lock rejection/portable-copy reuse/corrupt rejection без замены прежнего result. Synthetic UUID не выводились и не сохранены в Git. HTTP integration/reinstall policy/ACL/real panel HWID registration ещё нет. Далее bounded managed download service (TLS/size/timeout/cancel/redirect policy) + identity headers, metadata+profile persistence и сквозной refresh. Новые компоненты пока opt-in tests, не доступны в production клиенте.

После `687308c` добавлен standalone `SubscriptionDownloader`: HTTPS/VerifyPeer, no auto redirects, NoProxy explicit, 4MiB body/64KiB reply buffer, bounded timeout/cancel, X-Hwid supplied UUID + Windows header, no raw response/error logging. Windows build/CTest 2/2 PASS local synthetic success/header, redirect/declared oversize/empty/bad metadata/403/timeout/pre-cancel/in-flight cancel; production-mode separate target rejects HTTP loopback (test exception не включена). TLS cert/chunked oversize/truncation/header bounds/proxy policy/live mikan NOT RUN. Далее связать download + identity + metadata/profile atomic envelope + real validator в refresh service и existing groups; GroupUpdater пока не использует managed components.

После `a726354` добавлен standalone `SubscriptionService` orchestration: request+identity → injected fetch → expired/exhausted rejection → validation → atomic source+metadata commit. Per-group refresh lock spans fetch/commit, cancellation recheck после validation. Store metadata в том же schema-1 envelope, counters decimal strings без потери uint64; старые envelopes metadata unknown. Windows build/CTest 1/1 PASS synthetic refresh/metadata roundtrip/expiry/validation rejection/cancel during validation/lock contention; real pinned validator/store suite повторно PASS exit 0. Service orchestration пока injected tests, production binding отсутствует. Далее подключить production adapters/CMake/explicit managed group mode, combined snapshot load API, HTTP+real validator integration и mikan denial stub handling. UI/runtime/provider/scheduler gates не закрыты.

После `98e7418` подключены managed sources к ordinary YAML-enabled production CMake и explicit `Group.subscription_kind` (default links). GroupUpdater для mihomo-full вызывает genuine download/identity/store/validator и возвращается до legacy удаления/metadata writes; unknown kind refused. Проверка SHA256 `mihomo.exe` рядом с клиентом выполняется до запроса/объявления версии и повторно при validation. UI selector/automatic core provisioning не добавлены, managed runtime недоступен. Windows ordinary Release build PASS; backend CTest 1/1 PASS + genuine pinned core integration PASS exit 0, включая extracted executable preflight. Group JSON roundtrip/production HTTPS refresh/no-YAML build NOT RUN. Далее combined snapshot API + metadata corruption refusal, production group regression/HTTPS fixtures и denial stub detection; не объявлять usable managed VPN по build успеху.

После `c132542` добавлен `ManagedProfileStore::loadSnapshot`: source+metadata из одного прочитанного envelope, оба результата сохраняются при отказе. load/loadMetadata используют общий полный validator; commit отказывается заменять current с повреждёнными metadata. Старые schema-1 envelopes без metadata читаются как unknown. Windows ordinary Release build PASS; backend CTest 1/1 PASS и genuine mihomo integration PASS exit 0; wrong metadata shape/pairs/types/counters/duplicate headers/failure preservation/old-envelope compatibility покрыты. Concurrent read/replace stress/crash/disk-full recovery NOT RUN. Далее production group persistence/refresh regression, HTTPS fixtures и exact mikan denial-stub detection по upstream, затем runtime/provider работу; UI/VPN readiness не заявляется.

После `ef20f1f` расширен isolated production-graph parser runner: Windows 27/27 PASS exit 0, disk group JSON roundtrip/new field, legacy default links, сохранение URL/info/timestamp/order, actual GroupUpdater unknown-mode и managed missing-core отказ без изменения group/profile bytes/создания envelope. Отдельный remote `group-regression-build`, production build cache не переключался. Initial Qt5 configure/private API compile/unset MainWindow log callback failures исправлены в harness (explicit Qt6/public Group::Load/no-op callbacks); финальный run PASS. Offscreen OpenGL/legacy bad conversion warnings остаются. Далее successful HTTPS refresh/TLS fixtures и upstream denial stubs; managed runtime/UI readiness всё ещё нет.

После `7f8329d` сверён upstream handler.stub (mikan pinned a7b32c3) и добавлено structural Clash notice recognition: singleton SOCKS5 127.0.0.1:1 с ⛔/⏸, singleton selector/reference/MATCH. Ранее stub отклонялся generic missing DNS; теперь content-free notice reason, даже с добавленным DNS. Windows production Release build PASS, backend CTest 1/1 PASS + genuine core integration PASS exit 0; 12 RU/EN synthetic notices отвергнуты без замены envelope, ordinary local proxy не классифицируется по endpoint alone. URI/singbox notices/denial headers/live panel NOT RUN, exact user-block reason не заявлен. Далее HTTPS certificate/refresh fixtures и production happy-path, затем managed runtime/provider provisioning; UI/VPN gates остаются открыты.

1. Проверить branch/status и перечитать незавершённые пункты этапа 0 в плане.
2. Проверить установленные Qt/MSVC/CMake/Ninja/Go и сборочные scripts, не запускать разрушительную пересборку до их аудита.
   Использовать предоставленный удалённый Windows-стенд: SSH уже проверен; следующий шаг — отдельный checkout и полный preflight, затем подготовка недостающих SDK. Не считать стенд чистой VM без проверки.
3. Сопоставить `go.mod` replacements с `libs/get_source*.sh`; получить и исследовать закреплённые `libneko`, `sing-box`, `sing-quic`, `sing`.
4. Сделать воспроизводимый bootstrap без чужих абсолютных путей, мутаций manifests во время сборки и отключения проверки Go-модулей.
5. Выполнить baseline Release build, записать команды/версии/результаты и исходные дефекты. Затем перейти к контрактным fixtures mikan и этапу 1.

Не требовать повторного исследования уже записанных фактов без причины; до implementation перепроверить непосредственно изменяемые участки и актуальные зависимости.

## 4. Подтверждённая архитектура MDMBOX

| Подсистема | Точки входа |
| --- | --- |
| C++17 / Qt / CMake | `CMakeLists.txt`, `main/`, `ui/` |
| HTML shell, QWebEngineView, QWebChannel | `preview/mdmbox_shell_window.*`, `preview/mdmbox_shell_bridge.*`, `preview/mdmbox_shell_host.*` |
| Загрузка и разбор подписок | `sub/GroupUpdater.*`, `main/HTTPRequestHelper.*`, `fmt/Link2Bean.cpp` |
| Профили, группы и JSON-хранилище | `db/Group.hpp`, `db/Database.*`, `db/ProxyEntity.hpp` |
| Генерация runtime-конфигураций | `db/ConfigBuilder.cpp`, `fmt/Bean2CoreObj_box.cpp`, `fmt/Bean2External.cpp` |
| Go core / RPC | `go/cmd/nekobox_core/`, `go/grpc_server/`, `rpc/gRPC.cpp` |
| Внешние процессы / Xray | `sys/ExternalProcess.*`, `sub/GroupUpdater.cpp` |
| Сборка, зависимости, installer | `tools/`, `libs/get_source*.sh`, `installer/mdmbox.iss`, `.github/workflows/` |

MDMBOX — форк кодовой базы Nekobox; установка отдельного Nekobox для интеграции не требуется.

## 5. Рабочие решения из плана

Статус: **рабочая архитектура, подлежащая проверке реализацией и тестами**. Пользователь поручил начать реализацию и предоставил тестовую подписку; отдельного подтверждения каждой технической детали не было.

- C++17/Qt 6 — хост, сервисы, хранение и управление runtime; Go — сетевые ядра.
- Локальные HTML/CSS/JavaScript в Qt WebEngine, связь через versioned QWebChannel contract. Независимый browser-preview использует mock того же bridge.
- Для полного покрытия mikan — полный Clash/mihomo-профиль и управляемый процесс mihomo. Кандидат исходной совместимости — 1.19.32 из исследованной панели; Windows-артефакт и возможности ещё нужно проверить.
- Сохранить sing-box/nekobox_core и существующий Xray-путь для совместимости; не переписывать протоколы самостоятельно.
- Только один активный владелец TUN, DNS и системных маршрутов. Статус connected — после подтверждения готовности, не сразу после команды start.
- Обновление подписок атомарное: download → parse → validate → snapshot → apply; при отказе остаётся последняя рабочая конфигурация.
- Сохранять profile целиком: `proxies`, `proxy-groups`, `rules`, `rule-providers`, `dns`, порядок и происхождение правил. Исходный документ, локальные overrides и runtime settings хранить раздельно.
- Никаких внешних CDN/Figma URLs в production UI; assets и шрифты поставляются локально.

## 6. Особенности mikan, которые нельзя потерять

По исходникам указанной ревизии; детали и файлы-источники — в плане.

- `format` выбирает представление, но **не отменяет** фильтрацию протоколов по User-Agent, семейству и версии ядра. Не выдавать желаемую версию за реально установленную.
- URL подписки сохранять с исходным префиксом/query; не жёстко задавать `/sub/`.
- Метаданные включают traffic/expiry, Base64 title, support/page URLs, update interval и HWID-состояния. `Profile-Update-Interval: 1` здесь — один час.
- Отказ устройства/подписки может быть профилем-заглушкой при успешном HTTP; это не рабочий сервер.
- Автоправила: клиентская routing policy `all`/`ru_direct`/`blocked`; автоматические proxy-группы; серверный autotune с обновлением endpoint. Не смешивать эти механизмы.
- sing-box export рассчитан на схему 1.12+ и имеет потери возможностей относительно mihomo. URI-only импорт не доказывает сохранение DNS и правил.
- Матрица из 17 пресетов/протоколов находится в разделе 4.2 плана; каждый требует E2E, включая XHTTP, PQ, AnyTLS, TrustTunnel, ShadowQUIC, Mieru, Sudoku и Snell.

## 7. Figma и визуальные критерии

Файл: `dpomJg0l41jhSZfAZOV2fB`, страница `0:1`.

| Экран | Node ID | Размер frame |
| --- | --- | --- |
| Главная Disconnected | `6:8` | 1280 × 1024 |
| Главная Connected | `9:2` | 1280 × 1024 |
| Серверы | `6:347` | 1280 × 1024 |
| Настройки | `6:736` | 1280 × 1244 |
| Логи | `6:1077` | 1280 × 1024 |

- Зафиксированные tokens: sidebar 224 px, верхняя область 40 px; фон `#0D0E11`, поверхности `#1B1B1F`/`#292A2D`, акцент `#F59E0B`/`#FFC174`, текст `#E3E2E6`.
- В design context: Liberation Sans, в логах Liberation Mono. Проверить оригинальные font assets; имеющийся Inter не считать точной заменой.
- Frame Disconnected содержит текст «Подключено»; версии, IP, метрики и часть protocol badges демонстрационные. Сохранять geometry, production-данные брать из backend, смысловые исправления документировать.
- Эталонные размеры берутся из frames, не из уменьшенных картинок чата. Проверять полноразмерные screenshots, overlay/diff, Qt WebEngine и DPI 100/125/150/200%.
- Полноразмерные локальные эталоны/assets ещё не закреплены; при переходе к UI получить актуальный Figma context и экспорт.

## 8. Известные технические препятствия

1. `RawUpdater::updateClash()` импортирует прежде всего список прокси, а не полную policy mikan.
2. `GroupUpdater::Update()` меняет metadata/может удалить старые профили до успешного разбора нового ответа.
3. Shell зависит от отсутствующего в checkout внешнего `newdesign` и жёсткого пути предыдущего автора.
4. Большие JavaScript-инъекции и polling 1200 мс в C++ shell требуют контрактного разделения.
5. Go local replacements и исходные scripts получения зависимостей не согласованы; runtime-форки полностью ещё не исследованы.
6. Build script содержит Python paths, мутации `go.mod` и отключение checksums; Qt/Go версии локальной сборки и CI нужно согласовать.
7. Исследованный mikan объявляет `go 1.27`; наличие toolchain/подходящего закреплённого тестового образа не проверено.
8. Готовность build environment, живой mikan-стенд и Windows VM пока не подтверждены. Отсутствие утилиты в PATH не доказывает отсутствие её установки.
9. Strict Kill Switch, Fragment packets и font antialiasing из макета требуют реальной реализации/проверки; нельзя имитировать готовность переключателем.

## 9. Среда и работа с Git

- Исследованная рабочая копия: `D:\repo_github\mdmbox`; Windows/PowerShell. Есть настоящий `.git`, несмотря на исходную подсказку окружения об обратном.
- При исследовании `git` не находился через PATH. Рабочий executable обнаружен в `%LOCALAPPDATA%\Fork\gitInstance\2.50.1\cmd\git.exe`; перед использованием проверить наличие, версия Fork может измениться.
- Plan commit/push выполнены bundled Git из Fork; Fork GUI был открыт на репозитории. Не записывать это как GUI-click automation.
- Пользователь просит регулярные updates в `beta-ilya`; коммитить только относящиеся к текущей задаче файлы и проверять remote SHA после push.
- Не сохранять временные checkout/asset URLs как обязательные зависимости. Не переносить персональные имена и локальные credentials в проектную конфигурацию.
- Возможность push уже проверена для плана; способ создания GitHub Release ещё не проверен. Fork auth не доказывает доступ другого клиента к Release API.

## 10. Проверки и выпуск

Выполнены проверки документации/Git, автономные тесты subscription probe, build preflight и безопасные HTTP contract probes. Подробности — `docs/STAGE0_BASELINE.md`. Проверок готовности приложения не было.

Планируемые инструменты: Qt Test/CTest, Go tests и HTTP fixtures, валидаторы закреплённых ядер, Node.js visual tests, PowerShell и Windows VM. Полная матрица и gates находятся в разделе 7 плана.

Release sequence: профильные проверки → push beta → beta artifact → protocol/system/visual/installer E2E → актуализация относительно main → merge → CI merge SHA → version tag → проверенные release assets/checksums → скачивание и smoke test опубликованного installer.

Обязательный невыполненный тест — **NOT RUN**; недоступная предпосылка — **BLOCKED** с причиной. Не обозначать такие результаты PASS и не выпускать stable до прохождения обязательных gates.

## 11. Как обновлять эту память

- После значимого результата обновлять дату, текущий этап, выполненные проверки, оставшиеся блокеры и конкретный следующий шаг.
- Указывать подтверждённые SHA/команды/отчёты, не выдумывать номера релизов и результаты тестов.
- Отделять требования пользователя, рабочие предложения и уже реализованное. Новые указания пользователя имеют приоритет над старой записью.
- Checklist хранить в подробном плане; здесь оставлять краткий handoff. Не дублировать всю историю чата.
- Не хранить реальные токены подписок, HWID, приватные endpoints или GitHub credentials.
