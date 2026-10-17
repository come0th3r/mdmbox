# MDMBOX — technical alpha candidate

Этот документ описывает ограничения технического alpha-кандидата и конкретного
пакетирования, а не весь текущий source tree. Упомянутый внутренний ZIP был
собран из source commit `0a1a0c3`; его clean-VM smoke не относится к текущему
HEAD. Это не VPN-beta и не stable release. В текущей ветке новый Figma-shell
`ui/shell/` уже существует и интегрирован как Qt resource, но его полная
визуальная приёмка ещё не завершена. Для указанного старого alpha ZIP при
отсутствии optional HTML assets открывался native Qt UI.

## Запуск

Распакуйте ZIP в отдельную доступную для записи папку. Запускайте
`Start Alpha.cmd`: данные будут в `alpha-data` рядом с программой,
не в каталоге существующей установки. Не переносите рабочие конфиги в alpha.
Для non-admin alpha GUI собирается с `-DMDMBOX_REQUIRE_ADMIN=OFF`;
это не предоставляет прав для TUN или других privileged operations.
Не запускайте EXE напрямую, если нужна эта изоляция.
Пакет может содержать официальный Microsoft Visual C++ Redistributable x64;
если приложение сообщает о его отсутствии, запустите `vc_redist.x64.exe`.

## Ограничения

- Legacy UI/imports доступны для исследований; поддержка всех протоколов
  и реальные VPN-соединения этой сборки ещё не подтверждены.
- На текущей ветке отдельные synthetic loopback data paths проверены для
  REALITY Vision/TCP, SOCKS5 CONNECT/auth и одного UDP relay, HTTP CONNECT и
  endpoint A→B refresh. Это ограниченные fixtures, не полная protocol matrix,
  не внешние VPN-сеансы и не TUN. `Ready` означает готовность локального API,
  **не** VPN connected.
- Managed refresh/apply доступен через production bridge/controller API, но
  не оформлен как завершённый и принятый пользовательский workflow текущего
  shell. Сам alpha ZIP не проверяет эти возможности.
- Providers/geodata и большинство полных реальных mikan-профилей пока
  отклоняются runtime policy. Полный исходный профиль сохраняется без flatten.
- Managed TUN/system proxy, kill switch, полный routing и clean-VM
  install/upgrade/uninstall не подтверждены. Loopback endpoint A→B transition
  проверен synthetic runtime fixture, но это не внешний VPN-трафик.
- Не используйте для задач, требующих гарантии приватности или fail-closed.
- Автоматическое managed refresh/apply не включено.

Для нового пакета `tools/package-alpha.ps1` формирует `THIRD_PARTY_NOTICES.md`,
`LICENSES/` и module inventory при наличии явных licensing inputs. Аудит
применимости лицензий и source offers остаётся неполным. У старого ZIP
`0a1a0c3` есть собственный manifest; это не manifest текущего HEAD. Пакет
должен оставаться без подписок, credentials и пользовательских данных.

**Кандидат для внутреннего тестирования:** публичное распространение
заблокировано до аудита notices/лицензий и source offers всех зависимостей.
Clean-VM и release gates остаются открытыми. Это не установщик и не релиз.
