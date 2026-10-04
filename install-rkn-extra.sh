#!/usr/bin/env bash
# Установка rkn-extra-block (Debian/Ubuntu, root).
# Скачивает этот репозиторий и ставит скрипт + systemd-юниты.
set -euo pipefail

REPO="https://github.com/leonidorlov-hash/amnezia-blocker"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

apt-get update -qq
apt-get install -y -qq ipset iptables curl flock >/dev/null

git clone -q --depth 1 "$REPO" "$TMP/repo" 2>/dev/null || {
    # git может быть не нужен: тянем файлы напрямую
    mkdir -p "$TMP/repo"
    for f in rkn-extra-block.sh rkn-extra-block.service rkn-extra-block.timer; do
        curl -fsSL "$REPO/raw/main/$f" -o "$TMP/repo/$f"
    done
}

install -m 0755 "$TMP/repo/rkn-extra-block.sh" /usr/local/sbin/rkn-extra-block
install -m 0644 "$TMP/repo/rkn-extra-block.service" /etc/systemd/system/rkn-extra-block.service
install -m 0644 "$TMP/repo/rkn-extra-block.timer" /etc/systemd/system/rkn-extra-block.timer

mkdir -p /etc/rkn-extra-block
[ -f /etc/rkn-extra-block/config ] || cat > /etc/rkn-extra-block/config <<'EOF'
# Источники списков C24Be/AS_Network_List (менять не обязательно)
URL_IN4="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-v4.ipset"
URL_IN6="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-v6.ipset"
URL_OUT4="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-vk-v4.ipset"
URL_OUT6="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-vk-v6.ipset"
EOF

systemctl daemon-reload
systemctl enable --now rkn-extra-block.timer
systemctl enable rkn-extra-block.service

# Первый запуск: подгрузить списки и включить
/usr/local/sbin/rkn-extra-block on

echo "Готово. Управление: rkn-extra-block {on|off|status|update}"
