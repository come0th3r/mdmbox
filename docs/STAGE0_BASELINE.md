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

1. Восстановить закреплённые checkout libneko/sing-box/sing-quic; установить происхождение `sing`, которого нет в `libs/get_source_env.sh`, но есть в Go replacements.
2. Зафиксировать Windows toolchain и checksums SDK/dependency bundles; убрать прежние мутации manifests и персональные пути из build flow.
3. Выполнить локальный baseline, затем обязательную чистую VM-сборку.
4. Получить и проверить mihomo, повторить профильный запрос с честным runtime-UA и config-check. Затем переходить к transactional update и synthetic fixtures.
