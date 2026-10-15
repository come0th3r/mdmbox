# MDMBOX — technical alpha candidate

Это промежуточная Windows x64 сборка для технических испытаний, не VPN-beta
и не stable release. Новый Figma-интерфейс ещё не реализован. Если HTML assets
отсутствуют, открывается существующий native Qt-интерфейс.

## Запуск

Распакуйте ZIP в отдельную доступную для записи папку. Запускайте
`Start Alpha.cmd`: данные будут в `alpha-data` рядом с программой,
не в каталоге существующей установки. Не переносите рабочие конфиги в alpha.
Для non-admin alpha GUI собирается с `-DMDMBOX_REQUIRE_ADMIN=OFF`;
это не предоставляет прав для TUN или других privileged operations.
Не запускайте EXE напрямую, если нужна эта изоляция.
Нужен Microsoft Visual C++ Redistributable x64; если в пакете есть официальный
`vc_redist.x64.exe`, установите его при отсутствии runtime.

## Ограничения

- Legacy UI/imports доступны для исследований; поддержка всех протоколов
  и реальные VPN-соединения этой сборки ещё не подтверждены.
- Managed mihomo проверен только в ограниченном loopback-режиме. `Ready`
  означает готовность локального API, **не** VPN connected.
- Managed refresh/apply пока worker-session API, не готовая кнопка native UI.
- Providers/geodata и большинство полных реальных mikan-профилей пока
  отклоняются runtime policy. Полный исходный профиль сохраняется без flatten.
- Managed TUN/system proxy, kill switch, endpoint transition, полный routing
  и clean-VM install/upgrade/uninstall ещё не проверены.
- Не используйте для задач, требующих гарантии приватности или fail-closed.
- Автоматическое managed refresh/apply не включено.

Файл `manifest.json` содержит исходный commit и SHA256 компонентов.
Архив не содержит подписок, credentials или пользовательских данных.

**Кандидат для внутреннего тестирования:** публичное распространение
заблокировано до аудита notices/лицензий и source offers всех зависимостей.
Clean-VM и release gates остаются открытыми. Это не установщик и не релиз.
