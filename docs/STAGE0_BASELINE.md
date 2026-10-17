# Этап 0: исходное окружение и диагностика

Исследование начато 2026-10-14; ниже сохранён хронологический журнал исходного baseline. Он не является текущим status dashboard: ранние BLOCKED/NOT RUN формулировки относятся к состоянию до установки build-host и последующих проверок. По состоянию на 2026-10-17 Qt/MSVC builds, managed runtime, synthetic E2E и ограниченный clean-VM alpha startup/shutdown подтверждены отдельно; воспроизводимая clean-checkout baseline текущего HEAD и release gates по-прежнему не закрыты. Актуальный handoff: `PROJECT_MEMORY.md`; acceptance checklist: `docs/BETA_ILYA_UPGRADE_PLAN.md`.

## Инструменты

- `tools/check-build-environment.ps1` — read-only preflight. Проверяет наличие MSVC через vswhere, CMake, Ninja, Go, Node.js, Qt 6 modules, CMake packages и Go local replacements. Не устанавливает ПО и не изменяет manifests. PASS здесь означает только наличие файла, не совместимость версий или успешную сборку.
- `tools/subscription-probe.mjs` — HTTPS HEAD/GET диагностика. Тело GET читается только в память, максимум 4 MiB; timeout по умолчанию 20 секунд. Redirect не выполняется, TLS-проверка не отключается. Отчёт содержит только HTTP status, признаки metadata и структурную сводку, без URL, заголовков с приватными значениями и raw profile.
- `test/subscription-probe.test.mjs` — автономные синтетические тесты без внешней сети.

Это вспомогательные инструменты, **не реализация сервиса подписок в приложении**. URI/JSON summaries не подтверждают валидность полей, отсутствие профиля-заглушки или работу соединения. YAML определяется только структурными признаками, без полноценного parsing. Протоколы и routing требуют проверки реальным ядром.

## Запуск

```powershell
& .\tools\check-build-environment.ps1 -QtRoot $env:MDMBOX_QT_ROOT
node --test test/subscription-probe.test.mjs
node tools/subscription-probe.mjs --help
```

Если Node.js отсутствует в PATH, использовать найденный `node.exe`. Локальная версия во время первоначального preflight (2026-10-14): **24.20.0**; позже на отдельном build-host проверен Node.js 24.21.0.

Все команды и параметры probe ниже относятся только к синтетическим localhost fixtures. Не передавать live-panel URL, реальные subscription URL или device identifiers; прежние инструкции для ручного live-запроса отозваны.

Дополнительные переменные:

- `MDMBOX_PROBE_FORMAT`: `uri`, `clash`, `singbox`.
- `MDMBOX_PROBE_USER_AGENT`: по умолчанию `MDMBOX-contract-probe/0.1`. Runtime-UA должен соответствовать реально установленному ядру; не подставлять выдуманную версию.
- `MDMBOX_TEST_HWID`: только synthetic fixture identifier; реальные HWID не использовать.
- `MDMBOX_PROBE_HWID_RANDOM=1`: историческая опция; не использовать против live-panel.

## Подтверждённые результаты

Автономные тесты: **14/14 PASS** (`node --test test/subscription-probe.test.mjs`); синтаксический разбор PowerShell preflight — PASS; `git diff --check` — PASS. Тесты покрывают query/format, HTTPS restrictions, metadata, privacy summaries, redirects, HTTP errors, size limits и некорректные настройки.

На локальной машине исходный preflight 2026-10-14 вернул **BLOCKED: 19 checks**. Были найдены Node.js и исходники QHotkey; в проверенных местах не найдены MSVC, CMake, Ninja, Go, семь Qt 6 package configs, четыре C++ package configs и четыре checkout Go replacements. Это исторический результат, не текущий preflight и не доказательство отсутствия SDK в произвольных каталогах.

Ранее записанные сводки live subscription probe исключены из актуальной evidence: их результаты не следует использовать или повторять. Здесь не сохраняются URL, содержимое профиля и endpoints. Таблицы старого runtime/build статуса ниже также относятся только к датам своих записей.

## Дальнейшие проверки (хронологический журнал)

### Дополнение: удалённый стенд, 2026-10-15

Пользователь разрешил установку SDK. На отдельном Windows 11 build 26100 стенде подтверждены:

- Build Tools 2022 17.14.42; MSVC tools 14.44.35207, compiler 19.44.35229; Windows SDK 10.0.26100.0. C++17/WinAPI compile-and-run smoke — PASS. Reboot не потребовался.
- CMake 4.4.4, Ninja 1.13.2, Go 1.27.2, Node.js 24.21.0; автономные тесты probe — 14/14 PASS.
- Qt 6.7.2 MSVC2019 x64: 11 архивов с HTTPS-зеркала Berkeley проверены по опубликованному SHA1, локальные SHA256 сохранены в manifest на стенде. WebEngine/WebChannel включены; qmake и семь presence checks — PASS.
- Release static dependency builds — PASS: yaml-cpp 0.7.0 (`0579ae3d976091d7d664aa9d2527e0d0cff25763`), ZXing 2.0.0 (`bdb857efae30f5f2abfcf3d626bf1156dc055bae`), Protobuf 21.4 (`c9869dc7803eb0a21d7e589c40ff4f9288cd34ae`).

**GUI-only Release build — PASS**, source SHA `4ad14e088081a8063f0abb88556357bf10854189`, чистое рабочее дерево на стенде; 80/80 build steps. Получен `baseline-gui/mdmbox.exe`, 15901184 bytes, SHA256 `DE348F296676A83DAEBA6E86870DEBA1178E24F9B7B96777F5F43DBABC68ECBC`.

Команды после импорта x64 VsDevCmd environment; переменные указывают на локальные SDK и отдельные build directories:

```powershell
$configureArgs = @(
    '-S', $repo, '-B', $build, '-G', 'Ninja',
    '-DCMAKE_BUILD_TYPE=Release', '-DQT_VERSION_MAJOR=6',
    "-DCMAKE_PREFIX_PATH=$qt;$prefix", "-DProtobuf_DIR=$prefix\cmake",
    '-DCMAKE_POLICY_VERSION_MINIMUM:STRING=3.5'
)
& cmake @configureArgs
& cmake --build $build --parallel 4
```

Исходный некавыченный аргумент policy version в PowerShell привёл к значению `3` и configure failure; строковый массив исправил ошибку. Qt configs не изменялись. Остались warnings Qt deprecated API/стороннего кода и отсутствующих optional Vulkan headers; они не помешали linking.

В preflight удалено ложное требование C++ gRPC: `cmake/myproto.cmake` требует Protobuf, не gRPC package. Ранее записанные 19/12/5 BLOCKED — исторические результаты прежнего preflight, не текущий статус.

**На момент этой записи (2026-10-15) NOT RUN:** запуск mdmbox/WebEngine, Qt deployment, Go core build, protocol E2E, installer и чистая VM-проверка. Эти пункты частично закрыты последующими историческими записями ниже; не использовать эту строку как текущий статус. GUI-only build сам по себе не закрывал baseline/release gate этапа 0.

### Воспроизводимый GUI entry point и попытка Go build

Добавлен `tools/build-baseline-gui.ps1`: принимает `QtRoot`, `DependencyRoot`, `BuildDirectory`, опционально `VsDevCmd` и `Parallel`. Использует подготовленные SDK, не скачивает зависимости, не удаляет build tree, не завершает процессы и не меняет manifests. Импортирует x64 MSVC environment и восстанавливает окружение вызывающего процесса после работы. Проверен на стенде повторным configure/build: **GUI_BUILD_PASS**, SHA256 бинарника совпадает с результатом выше. Полная повторная сборка с нуля этим скриптом пока NOT RUN.

```powershell
& .\tools\build-baseline-gui.ps1 -QtRoot $qt -DependencyRoot $prefix -BuildDirectory $build
```

Получен upstream `SagerNet/sing` v0.4.3 (`f7cd94b14d31ace655e3f2285463c2ebf30294aa`) — версия из текущего go.mod. Попытка core build с Go 1.27.2, `CGO_ENABLED=0`, `GOSUMDB=sum.golang.org`, `GOPROXY=https://proxy.golang.org,direct`:

```powershell
go build -mod=readonly -trimpath -tags 'with_clash_api,with_quic,with_utls,with_ech' -o $coreOutput .
```

**FAIL на линковке:** `github.com/sagernet/sing/common/control: invalid reference to net.errNoSuchInterface`. В `sing/common/control/bind_finder_default.go` действительно присутствует `//go:linkname` на приватный символ стандартной библиотеки. Ограничение документировано в [Go 1.23 release notes](https://go.dev/doc/go1.23#linker). `go.mod` и `go.sum` не изменились. Проверка `checklinkname` не отключалась. Это дефект совместимости старой зависимости, а не сетевой сбой. Нужен проверенный upstream fix/совместимый закреплённый fork; произвольное обновление или замена error sentinel без тестов неприемлемы.

Go core build теперь **выполнен и FAILED**, запуск core/runtime — NOT RUN. Последняя GUI script-проверка использовала source `8b06edc` плюс новый untracked script, без изменения исходников приложения.

### Устранение linkname blocker, 2026-10-15

Найден upstream commit `SagerNet/sing@a33349366d899068145f2d0e3ea0f5b2632fa3f2`
(“Remove bad linkname usage”). Его однофайловое изменение перенесено на
закреплённый v0.4.3 без обновления остальных API: `libs/patches/sing-v0.4.3-linkname.patch`.
`git apply --check`, применение и dependency diff-check — PASS. Dependency checkout
теперь **модифицирован этим патчем**, а не является чистым upstream tag.

- Core build с прежними tags, `-mod=readonly`, Go 1.27.2, CGO disabled и включёнными checksum/linker checks — **PASS**.
- `nekobox_core.exe version` — **PASS**: sing-box `1.9.7-neko-1`, NekoBox `N/A`, revision `8b06edcf341fb4baa6d2ffe4532eab93aab57ccd`. N/A не заменялось вымышленной версией; build metadata ещё нужно согласовать.
- Core SHA256: `D28E54C410C09981181DEBFED373002ACA49EEFD5E8954D90E52A819665BED31`.
- Штатный `go test ./common/control` сообщил `[no test files]`, это не функциональное покрытие.
- Выполнены две дополнительные проверки из `test/fixtures/sing-control-compat_test.go`, явно скопированного в dependency checkout: cached IPv4/IPv6/name/index lookup и missing-interface `net.OpError` — **2/2 PASS**. Адреса synthetic, интерфейсы не создавались; fallback только читает системные интерфейсы.
- `core check` синтетического direct-only config без inbounds — **PASS**; неизвестный outbound type отклонён с ненулевым exit code — **PASS**.
- Manifests приложения не менялись. На стенде остаётся ранее скопированный untracked GUI script; перед pull сопоставить с tracked версией, не удалять чужие файлы.

Это снимает прежний blocker **компиляции ядра**, но не доказывает proxy/TUN/RPC или протокольную совместимость. На дату записи GUI/WebEngine deployment/runtime, loopback connection smoke, E2E и чистая VM — NOT RUN. Последующие разделы содержат результаты этих отдельных шагов; закреплённый full bootstrap/release reproduction остаётся открытым.

### Loopback data-path smoke

Добавлен `tools/core-loopback-smoke.mjs`. Node.js создаёт HTTP origin на
`127.0.0.1` с ephemeral port и временный synthetic config ядра с HTTP inbound
на другом loopback port и direct outbound. После readiness выполняется один
HTTP proxy request; проверяются status 200, точный body, число origin requests
и отсутствие преждевременного завершения ядра. В `finally` останавливается
только созданный процесс ядра, закрывается origin и удаляется только созданный
скриптом временный каталог. Порт proxy резервируется перед стартом; возможная
гонка занятия порта считается ошибкой проверки, а не успехом.

```powershell
node tools/core-loopback-smoke.mjs <path-to-nekobox_core.exe>
```

На Windows-стенде с Node.js 24.21.0 и patched core выше:

- `node --check` — PASS.
- Loopback HTTP inbound → direct outbound → origin — PASS два последовательных запуска, ровно один origin request каждый раз.
- Несуществующий core executable — ожидаемый FAIL с exit code 1, без зависания; затем повторный положительный запуск — PASS.

Локальный вызов Node по PATH не выполнен на момент проверки (команда не найдена); все указанные
результаты получены на удалённом стенде. Проверка не читает реальные профили,
не меняет system proxy/TUN/routes и не обращается к внешнему origin.
**На момент этого smoke NOT TESTED:** RPC, DNS-политика, VPN-протоколы, TUN и внешние соединения. Позднейшие synthetic/runtime tests частично расширили покрытие, но ограничения и clean-VM/release gates см. в актуальной памяти и плане.

### Проверяемый core build entry point

Добавлен `tools/build-baseline-core.ps1 -OutputFile <absolute-path>`.
Проверяет HEAD всех четырёх sibling dependencies, tracked changes, точный blob
patched sing и содержимое разрешённого test overlay. Не клонирует, не применяет
патч и не редактирует manifests. Требует Go 1.27.2 windows/amd64, задаёт явные
GOOS/GOARCH/tags, отключает workspace и внешние GOFLAGS, включает checksum
verification; после сборки восстанавливает изменённые переменные окружения и
проверяет хеши application Go manifests.

Первый запуск выявил ошибку обработки нескольких Go executable в PATH;
исправлено явным выбором первого результата Get-Command. Повтор на стенде —
**CORE_BUILD_PASS**, SHA256 совпал с предыдущим core
`D28E54C410C09981181DEBFED373002ACA49EEFD5E8954D90E52A819665BED31`.
Новый артефакт прошёл loopback smoke — **PASS**. Исходники приложения не
изменялись; сборка использовала удалённый checkout 8b06edc плюс явно
скопированные build script/test fixture. Полный dependency bootstrap и
негативные тесты проверок provenance на дату этой записи были NOT RUN.

### Qt WebEngine deployment smoke, 2026-10-15

Добавлен самостоятельный C++17 target `test/webengine-smoke` (Qt Widgets,
WebEngineWidgets, WebChannel). Создаёт временный локальный HTML и off-the-record
profile, устанавливает QWebChannel, проверяет `loadFinished` и результат
JavaScript `MDMBOX_LOCAL_HTML:42`. Timeout — 30 секунд; renderer termination и
ошибки загрузки дают ненулевой exit code. Bridge roundtrip здесь не проверяется.

На стенде MSVC/Qt 6.7.2: configure/build — **PASS**; `windeployqt --release
--no-translations` в новый отдельный каталог — exit 0. Запуск с PATH только
Windows/System32 и без Qt plugin/WebEngine overrides — **PASS**, вывод
`WEBENGINE_LOCAL_HTML_JS_PASS Qt=6.7.2`. Sandbox не отключался.

Предупреждения, которые нельзя скрывать:

- Deployment не нашёл `Qt6SerialPort.dll` для position/NMEA plugin. Текущий
  HTML smoke его не использует; полноту distribution это не подтверждает.
- VMware SVGA initialization failed, fallback LLVMPipe, Vulkan instance failed
  и GPU vendor detection failed. Smoke прошёл на software rendering; GPU/DPI
  и visual/performance gates остаются NOT RUN.
- `SetProcessDpiAwarenessContext` failed; соответствие DPI макетам не проверено.

Это **runtime smoke отдельного target**, не запуск MDMBOX, не installer test
и не clean-Windows gate (на стенде установлен MSVC). Реальный QWebChannel
roundtrip, WebEngineWidgets view/rendering, комплектность runtime dependencies
и изолированный запуск MDMBOX остаются следующими задачами.

### QWebChannel roundtrip

Тот же smoke target расширен QObject bridge с `Q_INVOKABLE echo` и
`complete`; включён AUTOMOC. HTML загружает `qrc:///qtwebchannel/qwebchannel.js`,
регистрирует клиент через `qt.webChannelTransport`, вызывает C++ echo,
получает callback и отправляет ответ в C++ complete. Успех — только при
точном ответе `cpp:MDMBOX_LOCAL_HTML:42`; timeout остаётся 30 секунд.

Rebuild и deployment в отдельный новый каталог на Windows-стенде — **PASS**.
Запуск без SDK в PATH, без отключения sandbox — **PASS**:

```text
WEBENGINE_LOCAL_HTML_JS_PASS Qt=6.7.2
WEBENGINE_QWEBCHANNEL_ROUNDTRIP_PASS Qt=6.7.2
```

Warnings отсутствующей SerialPort/NMEA dependency и VMware software
rendering/Vulkan/DPI повторились; они остаются незакрытыми. Этот результат
подтверждает synthetic JS → C++ → JS → C++ roundtrip, но не production bridge,
визуальный вывод, startup MDMBOX или clean-VM deployment.

### Устранение SerialPort deployment warning

Установлен Qt SerialPort из того же Qt 6.7.2 repository package
`qt.qt6.672.addons.qtserialport.win64_msvc2019_64`, version
`6.7.2-0-202406110335`. Архив проверен по опубликованному SHA1
`B1043FD3C0D652C9A646F2C5869FD309C828FC66`; SHA256
`6BC18CDE624680F57591325EE262328C77A12AC8043867C8D6C3241B06AA544B`.
Отдельный manifest сохранён на стенде в downloads.

Повторный windeployqt в новом каталоге включил `Qt6SerialPort.dll` для
`qtposition_nmea.dll`, прежнее missing dependency warning исчезло.
Первый вызов вне VsDevCmd выдал warnings о dxcompiler/dxil и VCINSTALLDIR;
повтор после импорта x64 VsDevCmd добавил DXCompiler/DXIL и VC redistributable
без этих deployment warnings. Наличие `Qt6SerialPort.dll`, `dxcompiler.dll`,
`dxil.dll`, `vc_redist.x64.exe`, `QtWebEngineProcess.exe` — **PASS**.
HTML/JS и QWebChannel roundtrip с очищенным SDK PATH — повторно **PASS**.

VMware LLVMPipe/Vulkan/GPU/DPI warnings сохраняются. Наличие redist installer
не означает проверку его установки на чистой Windows. Это исправление
конкретного missing dependency, а не аудит всех DLL или release-ready package.
На момент этой записи запуск самого MDMBOX ещё NOT RUN: перед ним проверить startup/shutdown
side effects, отдельный data directory и отсутствие изменения system proxy.

### Изолированное наблюдение запуска MDMBOX

Сам клиент развёрнут в новый `client-startup-deploy` через windeployqt в
x64 VsDevCmd; рядом проверенное ядро. Запуск `-many -appdata <new-empty-dir>`
без Qt SDK в PATH. Данные пользователя/подписки не использовались.
Audit defaults: spmode_system_proxy/spmode_vpn false, remember_id -1919,
remember_spmode empty. Startup умеет восстанавливать эти режимы из сохранённых
данных, поэтому пустой data directory обязателен для этой проверки.

Результат через 12 секунд — **PARTIAL**, не полноценный startup PASS:

- Клиент жив; прямые дочерние процессы `QtWebEngineProcess.exe` и `nekobox_core.exe` присутствуют.
- `MainWindowHandle=0`, title empty: отображение окна не подтверждено.
- `newdesign` отсутствовал в том alpha deployment. Это исторический дефект того source/archive; позднее новый `ui/shell/` подключён как qrc resource. Не переносить это наблюдение на текущий shell.
- Значения HKCU Internet Settings ProxyEnable/ProxyServer/ProxyOverride/AutoConfigURL совпали до запуска, во время наблюдения и после очистки. Это не аудит всех системных сетевых настроек.
- В stderr VMware SVGA fallback LLVMPipe.

Созданный клиент и наблюдавшиеся прямые дети принудительно завершены.
Graceful shutdown, RPC handshake/readiness, потомки второго уровня, окно и
production bridge **на том наблюдении NOT VERIFIED**. Наличие процесса ядра не доказывает
успешный RPC. Позднее были отдельные interactive/clean-VM alpha startup/shutdown и
production bridge проверки; они не превращают это старое наблюдение в полный
installer/release gate. Чистая baseline-сборка текущего HEAD всё ещё не подтверждена.

Исторический next-step списка на момент 2026-10-15 (не текущий план): восстановить dependencies, зафиксировать toolchain, выполнить clean baseline и подключить mihomo. Позднейшие разделы документируют частичное выполнение этих задач. Текущие blockers и следующий handoff находятся в `PROJECT_MEMORY.md` и `docs/BETA_ILYA_UPGRADE_PLAN.md`.
