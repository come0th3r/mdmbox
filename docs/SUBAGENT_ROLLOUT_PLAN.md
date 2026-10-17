# MDMBOX: план подключения сабагентов

Дата: **2026-10-17**. Статус: **два read-only профиля установлены; pilot и MIG-04/MIG-05 C++ reviews завершены**. MIG-02 принят как static review, MIG-01 — частично как карта кода. Итоги пилота: `docs/SUBAGENT_PILOT_MIG01_MIG02.md`. Coordinator выполнил valid-root PASS и adversarial characterization; full migration acceptance открыта. Writer отложен.

## 1. Решение и исходная точка

Начать с основного агента-координатора и двух read-only помощников. После проверки их качества подключить одного исполнителя изолированных тестовых задач. Максимум два одновременно работающих сабагента; максимум один пишущий исполнитель, включая координатора, в общем checkout. Это стартовые ограничения, а не обещание ускорения.

Приоритет проекта: сначала этапы 0 и 1 из `docs/BETA_ILYA_UPGRADE_PLAN.md`. UI/Figma polishing — после их приёмки. Manifest и контрактные зависимости этапа 0 остаются в его scope, но не становятся поводом начинать UI-реализацию.

На проверке: ветка `beta-ilya`, HEAD `be1e9f8f945db9a7fe5055de6a56c5bdfd761a40`; staged diff пуст, множество modified/untracked файлов. Использован установленный Git CLI, не GUI Fork. Текущий source — HEAD плюс незакоммиченные изменения, а не один SHA. По project memory чистая C++ сборка в этой среде BLOCKED; в рамках этого планирования toolchain повторно не проверялся.

## 2. Состав и ответственность

| Участник | Когда подключать | Задача | Обязательный результат | Начальный бюджет |
|---|---|---|---|---|
| Координатор — основной агент | Всегда | Выбрать пункт плана, выдать задания, согласовать контракты, интегрировать, организовать проверки | Принятый diff, доказательства, честный статус | По размеру задачи |
| `mdm-explorer` | Первая очередь | Исследовать одну цепочку production-кода или одну зависимость | Карта вызовов с `file:line`, invariants, точки изменения, пробелы | 12 model steps |
| `mdm-reviewer` | Первая очередь | Независимо проверить дизайн или фиксированный diff | Конкретные дефекты, severity, сценарий проявления, недостающие проверки | 16 model steps |
| `mdm-fixture-engineer` | Вторая очередь | Написать один synthetic harness или независимый набор fixtures | Узкий diff в разрешённых файлах, команды проверки, ожидаемые результаты | 24 model steps |

Бюджеты — предложенные стартовые значения. При достижении лимита вернуть полезный частичный результат и BLOCKED/NOT RUN; не выдавать незавершённую работу за успех. Дополнительный проход разрешает координатор после оценки конкретного пробела.

Отдельных постоянных «архитектора», «документатора», «DevOps» и «менеджера агентов» сейчас не создавать. Build/dependency audit отдавать `mdm-explorer` отдельным заданием; production refactor и архитектурные решения оставлять координатору. UI-специалиста рассматривать только после этапов 0–1.

### `mdm-explorer`

- Отвечает на один проверяемый вопрос, а не пересказывает весь репозиторий.
- Читает только относящиеся к задаче исходники и документы; возвращает до 10 значимых ссылок и короткую рекомендацию.
- Отделяет observed behavior, предположение и желаемый контракт.
- Не редактирует, не запускает команды, не устанавливает зависимости и не использует внешние сервисы.

### `mdm-reviewer`

- Проверяет correctness, регрессии, потери данных, concurrency и соответствие конкретному acceptance criterion.
- Получает задачу, invariants, baseline и diff; выводы автора не принимает как доказательство.
- Для каждого finding указывает `file:line`, сценарий, последствия и способ воспроизведения/проверки.
- Приоритеты: P0 — критический ущерб; P1 — потеря/повреждение данных или нарушение обязательного контракта; P2 — ограниченная регрессия; P3 — необязательное улучшение. Стиль сам по себе не блокирует приёмку.
- Если дефектов не найдено, перечисляет границы просмотра; отсутствие findings не означает прохождение тестов.
- Не правит проверяемый код и не запускает тесты. Отчёт об исполнении тестов предоставляет координатор, с явным источником evidence.

### `mdm-fixture-engineer`

- Работает только с явно перечисленными файлами одного тестового пакета. Production hooks и общие CMake-изменения предлагает координатору.
- Использует C++/Qt, Go, PowerShell или JavaScript по назначению; Python не добавляет.
- Не читает реальные профили, ключи, HWID и subscription URLs. Все данные synthetic/localhost.
- На старте пишет fixtures/harness без shell-доступа; тесты запускает координатор после проверки команд и изоляции.
- При нехватке runtime/toolchain сдаёт исходники со статусом NOT RUN/BLOCKED, а не имитирует PASS.

## 3. План конфигурации OpenCode V2

Предлагаемые файлы при подключении:

```text
.opencode/agents/mdm-explorer.md
.opencode/agents/mdm-reviewer.md
.opencode/agents/mdm-fixture-engineer.md  # только после пилота
```

Проверено по официальной документации V2: project agents задаются Markdown в `.opencode/agents/`; нужны `description`, `mode: subagent`, `permissions` и выбранный лимит `steps`. При отсутствии `model` сабагент наследует модель родительской сессии. Для пилота модель не фиксировать; конкретные provider/model IDs выбирать только после проверки доступности и результатов пилота.

Permissions — упорядоченные правила, последнее совпадение выигрывает. У дочернего профиля собственные права: нельзя предполагать, что ограничения родителя автоматически образуют верхнюю границу его доступа. `edit` охватывает patch/write, но не shell. `execute` и MCP требуют отдельного учёта.

Для каждого профиля сначала запретить все действия, затем разрешить минимальные исключения:

| Возможность | Explorer / reviewer | Fixture engineer |
|---|---|---|
| `read` | Только согласованные project files | Контекст задачи и разрешённые исходники |
| `glob`, `grep` | Разрешить для поиска по scope задания | То же |
| `edit` | Запретить | Разрешить только точные пути пакета fixtures |
| `shell`, `execute`, MCP | Запретить | Запретить на первом этапе |
| `webfetch`, `websearch` | Запретить; внешние справки даёт координатор | Запретить |
| `subagent` | Запретить | Запретить |
| Доступ вне рабочего каталога | Запретить | Запретить; scratch готовит координатор |

Ресурс `grep` — выражение поиска, `glob` — шаблон, а не гарантированная файловая граница. Scope поиска задавать явно в задании; не считать такой allowlist полноценной изоляцией секретов. В тестовый контекст передавать только проверенный synthetic corpus.

До активации проверить effective permissions с учётом global/project/session настроек. В disposable sandbox проверить разрешённое чтение, отказ записи для read-only профилей, отказ shell/execute/delegation и отказ записи исполнителя за пределами его файлов. Только безвредные canary-операции, без реальных секретов и системных изменений.

Источник синтаксиса: `https://opencode.ai/v2/docs/agents` и `https://opencode.ai/v2/docs/permissions`, проверены 2026-10-17. Документация не заменяет smoke-проверку установленной версии.

## 4. Правила совместной работы

1. Одна задача — один результат и один владелец файлов. Делегировать независимый кусок, который можно проверить отдельно.
2. В общем checkout один writer за раз. Когда пишет fixture engineer, координатор занимается анализом/интеграционной подготовкой, не меняя файлы.
3. Reviewer проверяет зафиксированный snapshot. Автор не меняет проверяемый блок до окончания review; после изменения зависимостей review повторяется адресно.
4. Перед выдачей задания координатор фиксирует branch/HEAD, исходный dirty status и SHA256 целевых файлов, включая untracked. Перед приёмкой сравнивает изменения с этой базой; совпадения одного HEAD недостаточно.
5. При обнаружении чужих изменений остановить запись и вернуть координатору конфликт; не делать reset/clean/stash, не отменять их автоматически.
6. Отдельный worktree для writer использовать только при подготовленной воспроизводимой базе. Текущие незакоммиченные изменения сами по себе туда не попадут: нужен согласованный перенос конкретного diff/fixtures и проверка идентичности входов, без автоматического commit.
7. `PROJECT_MEMORY.md`, `docs/BETA_ILYA_UPGRADE_PLAN.md`, `AGENTS.md`, общие build/config files и агентные permissions принадлежат координатору. Сабагенты возвращают предложения, не меняют их самостоятельно.
8. Ни один сабагент не делает commit/push/tag/release, не устанавливает toolchain, не включает TUN/system proxy и не обращается к live-панели. Разрешение на делегирование не разрешает эти операции.
9. Git read-only CLI проверки отличать от действий в Fork GUI. Публикация изменений остаётся отдельным согласованным действием.

## 5. Контракт задания и отчёта

Дочерняя сессия получает свежий контекст; координатор передаёт короткий пакет, а не рассчитывает на память текущей беседы.

```text
TASK_ID / роль:
Цель: один конкретный результат.
Основание: пункт upgrade plan и критерий приёмки.
База: branch, HEAD, target-file hashes, исходные dirty/untracked файлы.
Входы: точные файлы/функции, релевантные выдержки AGENTS и memory.
Разрешено читать / менять: явный список путей.
Запрещено: shell/network/system changes, чужие файлы, секреты и иные ограничения.
Invariants: что должно сохраниться и какие отказы проверить.
Результат: карта кода / findings / diff + команды тестов.
Бюджет: steps; при остановке — частичный итог и следующий точный шаг.
Готовность: условия, по которым координатор принимает результат.
```

```text
TASK_ID / BASELINE:
STATUS: COMPLETE / PARTIAL / BLOCKED
RESULT: краткий результат, inspected/changed files с line references.
FINDINGS: severity, доказательство, последствия, предлагаемая проверка.
CHECKS: команда, cwd, окружение/версия, exit code, evidence path.
CHECK_STATUS: PASS / FAIL / NOT RUN / BLOCKED, причина.
LIMITS: непроверенные ветви, недостающий runtime, assumptions.
HANDOFF: следующий шаг и необходимые решения.
```

COMPLETE относится к поручению, не ко всему этапу проекта. Runtime PASS требует фактического запуска на указанном snapshot; результаты предыдущих SHA или другого окружения помечаются отдельно. Parsing/config-check/readiness не подтверждают VPN или полную поддержку протокола.

## 6. Первый пилот: migration acceptance

Основание: `docs/STAGE0_CONTRACTS_AND_MIGRATION.md`, разделы 2.1–3. Production `flag_reorder` до изоляции не запускать.

### Волна A — два независимых read-only задания

**MIG-01 / explorer:** проследить `ProfileManager::LoadManager()`, пути загрузки/записи и `flag_reorder`; составить карту файлов, которые затрагиваются, и точки для контролируемого отказа. Входы: contracts document, `db/Database.cpp`, связанные declarations и текущий parser runner. Результат: конкретные функции/строки, side effects и минимальная граница harness.

**MIG-02 / reviewer:** независимо вывести acceptance cases из требований сохранности: IDs, group/profile order, selection, routing, metadata, archived/skip flags, front-proxy references; определить, какие проверки существующего parser runner не подтверждают миграцию. Результат: компактная матрица `invariant → fixture → observation → failure case`, без запуска loader.

Координатор параллельно проверяет доступность нужного build environment и выбирает один узкий сценарий. Результаты A сравниваются только после завершения независимых отчётов.

### Волна B — реализация одного изолированного пакета

Координатор утверждает дизайн: synthetic disposable root с маркером владения; запрет production paths; ограниченная очистка только своего root; явные failure points и ожидаемое recovery state. Следует переиспользовать существующий runner, если это возможно; новый `test/migration/` — лишь кандидат, не заранее принятое решение.

**MIG-03 / fixture engineer:** написать согласованный fixture package. Проверить нестандартный порядок, пропущенные optional fields, повторное открытие, malformed/orphan cases и выбранный injected write failure. Не закреплять разрушительное текущее поведение как желаемый контракт. Изменения production loader/hooks выполняет координатор отдельным проходом.

### Волна C — review и исполнение

**MIG-04 / reviewer:** проверить frozen diff, границы root/cleanup, отрицательные сценарии, отсутствие доступа к обычному профилю и качество assertions. P0/P1 устранить до запуска.

Координатор запускает разрешённые проверки на disposable root, сохраняет команды и evidence. Если нужного C++ toolchain нет, результат — harness подготовлен, runtime acceptance BLOCKED; migration gate остаётся открытым. После запуска проверить сохранность исходной базы, восстановление/идемпотентность и отсутствие оставленных процессов/fixtures.

## 7. Дальнейшая очередь

| Очередь | Пакет работы | Распределение | Зависимость / результат |
|---|---|---|---|
| 1 | Migration pilot | Explorer + reviewer, затем fixture engineer | Изолированный harness и проверенное evidence либо явный BLOCKED |
| 2 | Stage 0 build reproducibility | Explorer исследует pins/scripts; координатор готовит согласованное окружение | Clean-checkout build текущего candidate; установка только по отдельному решению |
| 3 | Остальные Stage 0 contracts/manifests/стенд | Explorer — отдельные инвентари; reviewer — полнота | Выполненные критерии этапа 0; без UI polishing |
| 4 | Metadata/errors/HWID/scheduler | Координатор production; fixture engineer — один независимый набор cases; reviewer — diff | После принятия этапа 0, с явными contracts |
| 5 | Latest-wins/revocation и disk/runtime atomic apply | Координатор сначала задаёт единый контракт; затем fixtures и review | Не делить связанные state machine изменения между writers |
| 6 | Provider/geodata, routing/DNS, protocol matrix | Explorer по одному вопросу; fixture engineer по одному протоколу; reviewer по evidence | После нужных storage/runtime зависимостей, synthetic/localhost scope |
| 7 | UI/Figma, системные и release проверки | Специализированные роли обсудить позднее | После этапов 0–1 и разрешения нужных сред/операций |

## 8. Эффективность и критерии подключения

- Первые три небольших завершённых пакета — пилот. Не запускать сабагента для простой локальной правки, если подготовка задания дороже самой работы.
- Записывать длительность, steps/стоимость если доступны, полезные findings, переделки, повторное чтение и время координатора на сверку. Не обещать фиксированное ускорение.
- Оценивать по принятым результатам и подтверждённым дефектам, не по числу созданных файлов или объёму отчёта.
- При двух бесполезных/выходящих за scope отчётах подряд сузить задачу и права или убрать роль из текущего потока.
- Стартовать с той же модели, что у координатора. Более быструю модель для explorer пробовать отдельно на одинаковом задании; выбирать по точности и стоимости, не по названию. Reviewer должен сохранять способность проверять concurrency и data-loss cases.
- Не увеличивать параллельность, пока есть конфликты файлов, повторное исследование одной задачи или непроверенные результаты.

Подключение считать принятым только после: обнаружения профилей в установленном клиенте; smoke-проверки effective permissions; полезного read-only пилота; отсутствия посторонних изменений; отчётов с evidence и корректными статусами. Writer включать после проверки file ownership и изоляции.

## 9. Результат подключения и следующий шаг

- Подготовлен план ролей, прав, пилота и очереди работ.
- Прочитаны project memory, upgrade plan и migration contracts; проверены branch/HEAD, dirty status и пустой staged diff.
- Сверен описанный механизм агентов и permissions с официальными V2 docs.
- Созданы и обнаружены `.opencode/agents/mdm-explorer.md` и `mdm-reviewer.md`, без постоянного `model`; initial smoke на модели родителя. Read-only canaries и 11 effective permission cases на роль дали ожидаемые результаты. Отсутствующий tool и фактический denial учитываются раздельно.
- Удалён унаследованный `browser allow` **только у child sessions**; финальный audit повторно обнаружил его у reviewer и убрал. Проверять overrides как при создании, так и при continuation; точный момент повторного появления не установлен. Финальный evaluator 11/11 на роль PASS; глобальные/parent настройки не менялись.
- По просьбе пользователя дорогие MIG-прогоны остановлены; продолжение: `posaprosu/gpt-5.6-luna#balanced` для explorer и `posaprosu/gpt-6.1-sol#deep` для reviewer. Источник тарифов — указанная пользователем витрина ZAPRO; таблица, metadata и оговорки измерения в pilot report. Это continuation, не cold-start benchmark.
- MIG-02 принят как static review; MIG-01 и R1 полезны частично для навигации, но design handoff остался противоречивым. После исходных отчётов 608/608 baseline hashes неизменны, staged diff пуст. Temporary canaries/read exception удалены.
- **MIG-03/MIG-04, 2026-10-17:** coordinator-owned valid-root production-loader harness реализован; Sol-reviewer MIG-04 нашёл P2 no-op Save oracle, R1 подтвердил static fix без новых findings. Перед continuation 10 effective permission cases дали ожидаемые результаты, session overrides пусты; reviewer не редактировал и не запускал тесты. Затем coordinator исправил обнаруженный MSVC include-order конфликт в parser entrypoint, собрал Release target на `build@192.168.1.36` и выполнил checksum-pinned migration test дважды **PASS**. Evidence/493-file manifest/artifact hash: `test/subscription-parser/LEGACY_MIGRATION.md`.
- **MIG-05/R1:** новый read-only reviewer `ses_eb642defcffe37pUMJdCBN3HoM` проверил C++ adversarial fixture статически, P0–P2 не нашёл; P3 отдельного strict-corpus guard исправлен координатором, targeted rereview закрыл его. Два `.mjs` файла недоступны по permissions: independent JS-review **BLOCKED**, отказ не обходился. Новые permission-canary/session override проверки не выполнены; старые результаты пилота не подтверждают эту session. Координатор собрал exact R1 и выполнил два observation-прогона по 16+35 children плюс valid-root до/после PASS; manifest/logs/границы в `test/subscription-parser/LEGACY_MIGRATION_ADVERSARIAL.md`. Reviewer не запускал тесты и не правил файлы.
- **MIG-06/R1:** reviewer `ses_eb61ae3c2ffeTzi8qZf69Xc4IP` проверил checked atomic-save API и fixture статически: confirmed production P0–P2 не найдено. P2 test oracle (следующие saves скрывали failed retry) исправлен immediate readback; targeted R1 закрыл finding без новых P0–P2. После этого координатор собрал/выполнил exact R1 на Windows: valid-root до/после PASS, atomic-v1 suite дважды COMPLETE. Independent UI-callers review BLOCKED permissions, JS вне scope, runtime reviewer не запускал. Новые permission-canary/override checks не выполнялись. Детали — `test/subscription-parser/LEGACY_PERSISTENCE.md`; full migration acceptance не закрыта.
- **NOT RUN:** clean-checkout baseline, production backup/rollback и полный failure/recovery/reorder migration acceptance. Writer не активирован: по-прежнему нужны точные edit paths и writer-specific permission smoke. Этапы 0–1 сохраняют приоритет; общие acceptance-флажки не закрыты.
