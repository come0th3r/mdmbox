# Этап 0: исходное окружение и диагностика

Дата: 2026-10-14. Ветка: `beta-ilya`. Этап 0 **не завершён**.

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

Если Node.js отсутствует в PATH, использовать найденный `node.exe`. Проверенная локальная версия: **24.20.0**.

Ссылку передавать через приватно заданную переменную `MDMBOX_TEST_SUBSCRIPTION_URL`, не через аргументы CLI и не через tracked-файлы. По умолчанию probe использует HEAD. `--get` выполняет чтение профиля; панель может учитывать запрос или зарегистрировать устройство. После проверки удалить переменную окружения. Не вставлять секрет в команды, сохраняемые в истории терминала.

Дополнительные переменные:

- `MDMBOX_PROBE_FORMAT`: `uri`, `clash`, `singbox`.
- `MDMBOX_PROBE_USER_AGENT`: по умолчанию `MDMBOX-contract-probe/0.1`. Runtime-UA должен соответствовать реально установленному ядру; не подставлять выдуманную версию.
- `MDMBOX_TEST_HWID`: стабильный тестовый идентификатор при необходимости device binding. Не использовать реальный HWID в fixtures или отчётах.
- `MDMBOX_PROBE_HWID_RANDOM=1`: только для разового теста регистрации; повторные вызовы могут расходовать слоты. По умолчанию выключено.

## Подтверждённые результаты

Автономные тесты: **14/14 PASS** (`node --test test/subscription-probe.test.mjs`); синтаксический разбор PowerShell preflight — PASS; `git diff --check` — PASS. Тесты покрывают query/format, HTTPS restrictions, metadata, privacy summaries, redirects, HTTP errors, size limits и некорректные настройки.

На текущей машине preflight вернул **BLOCKED: 19 checks**. Найдены Node.js и исходники QHotkey. Не найдены в проверенных местах MSVC, CMake, Ninja, Go, семь Qt 6 package configs, четыре C++ package configs и четыре checkout Go replacements. Это не доказательство отсутствия SDK в произвольных других каталогах.

На предоставленной пользователем тестовой подписке, без HWID и без подмены версии ядра:

| Проверка | Результат |
| --- | --- |
| HTTPS HEAD исходного URL | HTTP 200; признаки traffic/title metadata; интервал 1 час |
| GET `format=uri` | HTTP 200; 8216 bytes; Base64; 20 ссылок: 16 VLESS, 4 TUIC |
| GET `format=clash` | HTTP 200; 15050 bytes; YAML candidate; найдены proxies, proxy-groups, rules, dns |
| Metadata GET | Признаки upload/download/total/expire, title/support/page; interval 1 час |
| Проверенные HWID notice headers | Не обнаружены; это не доказательство отсутствия ограничений устройства |
| Core config validation | NOT RUN — нужное закреплённое ядро ещё не получено |
| Runtime/protocol E2E | NOT RUN |
| Baseline Release / clean Windows VM | BLOCKED — toolchain/dependencies и VM ещё не подготовлены |

Ссылку, endpoints и содержимое профиля не сохраняли в репозиторий. Наличие секций не означает корректность YAML или сохранение policy существующим importer. Набор протоколов относится только к этому ответу с диагностическим UA, не ко всей панели.

## Следующий шаг

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

**NOT RUN:** запуск mdmbox/WebEngine, Qt deployment, Go core build, protocol E2E, installer и чистая VM-проверка. GUI-only build не закрывает baseline/release gate этапа 0. Следующие задачи — воспроизводимые scripts, согласование sing replacement, Go build и изолированный runtime smoke без изменения proxy/TUN.

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

Это снимает прежний blocker **компиляции ядра**, но не доказывает proxy/TUN/RPC или протокольную совместимость. GUI/WebEngine deployment/runtime, loopback connection smoke, E2E и чистая VM — NOT RUN. Обычный build не должен неявно применять патчи; закреплённый bootstrap ещё предстоит оформить.

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

Локальный вызов Node по PATH не выполнен (команда не найдена); все указанные
результаты получены на удалённом стенде. Проверка не читает реальные профили,
не меняет system proxy/TUN/routes и не обращается к внешнему origin.
**NOT TESTED:** RPC, DNS-политика, VPN-протоколы, TUN и внешние соединения.
GUI/WebEngine deployment/runtime и clean-VM gate остаются NOT RUN.

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
негативные тесты проверок provenance пока NOT RUN.

1. Восстановить закреплённые checkout libneko/sing-box/sing-quic; установить происхождение `sing`, которого нет в `libs/get_source_env.sh`, но есть в Go replacements.
2. Зафиксировать Windows toolchain и checksums SDK/dependency bundles; убрать прежние мутации manifests и персональные пути из build flow.
3. Выполнить локальный baseline, затем обязательную чистую VM-сборку.
4. Получить и проверить mihomo, повторить профильный запрос с честным runtime-UA и config-check. Затем переходить к transactional update и synthetic fixtures.
