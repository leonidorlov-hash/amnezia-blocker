# Amnezia Blocker Manager

Скрипт блокировки нежелательных доменов через ipset + iptables для VPN-серверов.

**Версия:** v3.2 — IPv4 + IPv6, TCP RST (мгновенный обрыв вместо таймаута), защита от параллельного запуска (flock), параллельный DNS-резолв (xargs), живой прогресс в консоль.

## Состав

- `blocker.sh` — основной и единственный скрипт, живёт на серверах в `/etc/amnezia-blocker/blocker.sh`
- Список доменов скачивается с `https://mamkam.spb.ru/domains.txt` в `/var/cache/amnezia-blocker/domains.conf`
- Лог: `/var/log/amnezia-blocker.log`

## Команды скрипта

```bash
/etc/amnezia-blocker/blocker.sh on       # включить блокировку
/etc/amnezia-blocker/blocker.sh off      # выключить (снимает правила и ipset)
/etc/amnezia-blocker/blocker.sh status   # статус: state, кол-во IP, цепи (без аргументов = status)
/etc/amnezia-blocker/blocker.sh update   # обновить список IP (для cron)
/etc/amnezia-blocker/blocker.sh reload   # полная перезагрузка (off + on)
/etc/amnezia-blocker/blocker.sh check    # проверка зависимостей и IPv6
```

## Деплой на новый сервер

Нужен fine-grained PAT (Settings → Personal access tokens) с доступом только к этому репо, permission **Contents: Read-only**.

```bash
/etc/amnezia-blocker/blocker.sh off 2>/dev/null; curl -fsSL -H "Authorization: Bearer ТОКЕН" -H "Accept: application/vnd.github.raw" https://api.github.com/repos/leonidorlov-hash/amnezia-blocker/contents/blocker.sh -o /etc/amnezia-blocker/blocker.sh && chmod 755 /etc/amnezia-blocker/blocker.sh && /etc/amnezia-blocker/blocker.sh on && /etc/amnezia-blocker/blocker.sh status
```

Проверка в выводе status: `State: on`, `IPv4 entries > 0`, `Chain (v4): yes`.

## Автоматика (cron)

Обновление списка каждые 6 часов + включение через 30 сек после перезагрузки:

```bash
(crontab -l 2>/dev/null | grep -v blocker; echo "17 */6 * * * /etc/amnezia-blocker/blocker.sh update >> /var/log/amnezia-blocker.log 2>&1"; echo "@reboot sleep 30 && /etc/amnezia-blocker/blocker.sh on >> /var/log/amnezia-blocker.log 2>&1") | crontab - && crontab -l | grep blocker
```

Чужие задачи в crontab не затрагиваются (удаляются только строки с «blocker»). Команда идемпотентна — дублей не создаёт.

Проверка окружения перед установкой cron:

```bash
echo "--- crontab ---"; crontab -l 2>/dev/null; echo "--- cron service ---"; systemctl is-enabled cron 2>/dev/null; systemctl is-active cron 2>/dev/null; echo "--- blocker ---"; /etc/amnezia-blocker/blocker.sh status
```

## Диагностика

```bash
tail -20 /var/log/amnezia-blocker.log      # последние события (этапы, swap, ошибки)
ipset list amnezia_blocked4 | head         # содержимое IPv4-сета
iptables -L AMNEZIA_BLOCK -n               # правила цепи
```

## Важные свойства

- **Нет timeout в ipset** — список живёт бессрочно, замена только атомарным swap. Упавший cron ≠ снятая блокировка.
- **flock** — вторая копия любой команды сразу выходит, дубли процессов невозможны.
- **При нулевом резолве** (DNS не отвечает) старый список сохраняется.
- **Прогресс резолва** пишется только в консоль; в лог идут только этапы — cron не спамит.

## Серверы

Развёрнуто на: EUROBYTE, FIRSTBYTE, IHOR, NATA, RAHMET, fastvps, mrak (все — v3.2 + cron, 2026-08-20).
