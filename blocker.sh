#!/bin/bash
# Amnezia Blocker Manager v3.1.1 (IPv4 + IPv6 + TCP RST + flock + parallel DNS)
# v3.1.1 hotfix: xargs без -I (конфликт с -n), дочерние dig не валят set -e
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
set -e

BLOCKER_DIR="/etc/amnezia-blocker"
BLOCKSET4="amnezia_blocked4"
BLOCKSET6="amnezia_blocked6"
STATE_FILE="$BLOCKER_DIR/state"
DOMAINS_FILE="/var/cache/amnezia-blocker/domains.conf"
URL_LIST="https://mamkam.spb.ru/domains.txt"
LOG_FILE="/var/log/amnezia-blocker.log"
CHAIN_NAME="AMNEZIA_BLOCK"
LOCK_FILE="/run/amnezia-blocker.lock"
DNS_JOBS=10          # параллельных dig-процессов; на слабом сервере можно снизить до 5
IPV6_OK=""

log() { echo "$(date '+%F %T') $1" | tee -a "$LOG_FILE"; }
get_state() { [ -f "$STATE_FILE" ] && cat "$STATE_FILE" || echo "off"; }
set_state() { echo "$1" > "$STATE_FILE"; }

acquire_lock() {
    exec 9>"$LOCK_FILE" || { echo "ERROR: не удалось открыть $LOCK_FILE"; exit 1; }
    if ! flock -n 9; then
        echo "Другой экземпляр blocker.sh уже выполняется, выход."
        exit 0
    fi
}

check_deps() {
    if ! lsmod | grep -q ip_set; then
        log "WARNING: ip_set не загружен, загружаю..."
        modprobe ip_set 2>/dev/null || apt-get install -y ipset
    fi
    command -v ipset    &>/dev/null || apt-get install -y ipset
    command -v dig      &>/dev/null || apt-get install -y dnsutils
    command -v iptables &>/dev/null || apt-get install -y iptables
    command -v xargs    &>/dev/null || apt-get install -y findutils
    command -v ipset &>/dev/null && command -v dig &>/dev/null && command -v iptables &>/dev/null \
        || { log "ERROR: зависимости не установлены"; exit 1; }
}

check_ipv6_support() {
    [ -n "$IPV6_OK" ] && return "$IPV6_OK"
    if ipset create test_ipv6 hash:ip family inet6 2>/dev/null; then
        ipset destroy test_ipv6 2>/dev/null
        IPV6_OK=0
    else
        log "WARNING: IPv6 ipset не поддерживается ядром, только IPv4"
        IPV6_OK=1
    fi
    return "$IPV6_OK"
}

# БЕЗ timeout: актуальность контролирует только swap в update_blocks,
# иначе при падении cron блокировка молча отомрёт через сутки
create_ipsets() {
    if ! ipset list "$BLOCKSET4" &>/dev/null; then
        ipset create "$BLOCKSET4" hash:ip maxelem 100000 2>/dev/null || true
        log "ipset $BLOCKSET4 создан"
    fi
    if check_ipv6_support; then
        if ! ipset list "$BLOCKSET6" &>/dev/null; then
            ipset create "$BLOCKSET6" hash:ip family inet6 maxelem 100000 2>/dev/null || true
            log "ipset $BLOCKSET6 создан"
        fi
    fi
}

destroy_ipsets() {
    ipset destroy "$BLOCKSET4" 2>/dev/null && log "ipset $BLOCKSET4 удалён" || true
    ipset destroy "$BLOCKSET6" 2>/dev/null && log "ipset $BLOCKSET6 удалён" || true
}

create_chain() {
    iptables -N "$CHAIN_NAME" 2>/dev/null || true
    if ! iptables -L "$CHAIN_NAME" -n 2>/dev/null | grep -q "match-set"; then
        iptables -F "$CHAIN_NAME"
        iptables -A "$CHAIN_NAME" -p tcp -m set --match-set "$BLOCKSET4" dst -j REJECT --reject-with tcp-reset
        iptables -A "$CHAIN_NAME" -p tcp -m set --match-set "$BLOCKSET4" src -j REJECT --reject-with tcp-reset
        iptables -A "$CHAIN_NAME" -m set --match-set "$BLOCKSET4" dst -j REJECT
        iptables -A "$CHAIN_NAME" -m set --match-set "$BLOCKSET4" src -j REJECT
        log "Правила $CHAIN_NAME (IPv4) установлены"
    fi
    if check_ipv6_support; then
        ip6tables -N "$CHAIN_NAME" 2>/dev/null || true
        if ! ip6tables -L "$CHAIN_NAME" -n 2>/dev/null | grep -q "match-set"; then
            ip6tables -F "$CHAIN_NAME"
            ip6tables -A "$CHAIN_NAME" -p tcp -m set --match-set "$BLOCKSET6" dst -j REJECT --reject-with tcp-reset
            ip6tables -A "$CHAIN_NAME" -p tcp -m set --match-set "$BLOCKSET6" src -j REJECT --reject-with tcp-reset
            ip6tables -A "$CHAIN_NAME" -m set --match-set "$BLOCKSET6" dst -j REJECT
            ip6tables -A "$CHAIN_NAME" -m set --match-set "$BLOCKSET6" src -j REJECT
            log "Правила $CHAIN_NAME (IPv6) установлены"
        fi
    fi
}

destroy_chain() {
    for tbl in iptables ip6tables; do
        for ch in FORWARD OUTPUT; do
            $tbl -D "$ch" -j "$CHAIN_NAME" 2>/dev/null || true
        done
        $tbl -F "$CHAIN_NAME" 2>/dev/null || true
        $tbl -X "$CHAIN_NAME" 2>/dev/null || true
    done
    log "Цепи $CHAIN_NAME удалены"
}

ensure_jump() { # $1 = iptables|ip6tables, $2 = FORWARD|OUTPUT
    if ! $1 -C "$2" -j "$CHAIN_NAME" 2>/dev/null; then
        $1 -D "$2" -j "$CHAIN_NAME" 2>/dev/null || true
        $1 -I "$2" 1 -j "$CHAIN_NAME"
        log "Цепь $CHAIN_NAME установлена в $2 (позиция 1)"
    fi
}

ensure_chain_position() {
    ensure_jump iptables FORWARD
    ensure_jump iptables OUTPUT
    if check_ipv6_support; then
        ensure_jump ip6tables FORWARD
        ensure_jump ip6tables OUTPUT
    fi
}

# Параллельный резолв: xargs -P, результаты в temp-файлы, заливка через ipset restore
update_blocks() {
    mkdir -p "$(dirname "$DOMAINS_FILE")"
    if wget -q -O "${DOMAINS_FILE}.tmp" "$URL_LIST" && [ -s "${DOMAINS_FILE}.tmp" ]; then
        mv "${DOMAINS_FILE}.tmp" "$DOMAINS_FILE"
        log "Список доменов обновлён"
    else
        rm -f "${DOMAINS_FILE}.tmp"
        log "WARNING: не удалось скачать список, используем старый файл"
    fi
    [ ! -f "$DOMAINS_FILE" ] && { log "ERROR: $DOMAINS_FILE не найден"; return 1; }

    create_ipsets
    ipset create "${BLOCKSET4}_temp" hash:ip maxelem 100000 2>/dev/null || ipset flush "${BLOCKSET4}_temp"

    local has_ipv6=false
    if check_ipv6_support; then
        ipset create "${BLOCKSET6}_temp" hash:ip family inet6 maxelem 100000 2>/dev/null || ipset flush "${BLOCKSET6}_temp"
        has_ipv6=true
    fi

    local tmp4="/tmp/ab_res4.$$" tmp6="/tmp/ab_res6.$$"
    : > "$tmp4"; : > "$tmp6"
    export AB_TMP4="$tmp4" AB_TMP6="$tmp6" AB_IPV6="$has_ipv6"

    local started=$SECONDS
    # Дочерний процесс всегда завершается с кодом 0: домен без A/AAAA-записи
    # не должен валить всё обновление через set -e
    grep -vE '^\s*(#|$)' "$DOMAINS_FILE" | sed 's/^\*\.//' | sort -u | \
    xargs -P "$DNS_JOBS" -n 1 bash -c '
        d="$1"
        dig +short +timeout=2 +tries=1 A "$d" 2>/dev/null | grep -E "^[0-9.]+$" >> "$AB_TMP4" || true
        if [ "$AB_IPV6" = true ]; then
            dig +short +timeout=2 +tries=1 AAAA "$d" 2>/dev/null | grep -E "^[0-9a-fA-F:]+$" >> "$AB_TMP6" || true
        fi
        exit 0
    ' _ || true
    log "DNS-резолв завершён за $((SECONDS - started)) сек ($DNS_JOBS потоков)"

    # Заливка в temp-сеты одной транзакцией (в сотни раз быстрее, чем ipset add в цикле)
    sort -u "$tmp4" | sed "s|^|add ${BLOCKSET4}_temp |" | ipset restore -exist 2>/dev/null || true
    if [ "$has_ipv6" = true ]; then
        sort -u "$tmp6" | sed "s|^|add ${BLOCKSET6}_temp |" | ipset restore -exist 2>/dev/null || true
    fi
    rm -f "$tmp4" "$tmp6"

    local temp4_count
    temp4_count=$(ipset list "${BLOCKSET4}_temp" 2>/dev/null | grep -c '^[0-9]') || temp4_count=0
    if [ "$temp4_count" -gt 0 ]; then
        if ipset list "$BLOCKSET4" &>/dev/null; then
            ipset swap "${BLOCKSET4}_temp" "$BLOCKSET4"
        else
            ipset rename "${BLOCKSET4}_temp" "$BLOCKSET4"
        fi
        log "IPv4 swap: $temp4_count IP"
    else
        log "WARNING: Zero IPv4 IPs resolved, старый список сохранён"
    fi
    ipset destroy "${BLOCKSET4}_temp" 2>/dev/null || true

    if [ "$has_ipv6" = true ]; then
        local temp6_count
        temp6_count=$(ipset list "${BLOCKSET6}_temp" 2>/dev/null | grep -c '^[0-9]') || temp6_count=0
        if [ "$temp6_count" -gt 0 ]; then
            if ipset list "$BLOCKSET6" &>/dev/null; then
                ipset swap "${BLOCKSET6}_temp" "$BLOCKSET6"
            else
                ipset rename "${BLOCKSET6}_temp" "$BLOCKSET6"
            fi
            log "IPv6 swap: $temp6_count IP"
        fi
        ipset destroy "${BLOCKSET6}_temp" 2>/dev/null || true
    fi
}

enable() {
    check_deps
    create_ipsets
    update_blocks
    create_chain
    ensure_chain_position
    set_state "on"
    log "=== БЛОКИРОВКА ВКЛЮЧЕНА ==="
}

disable() {
    destroy_chain
    destroy_ipsets
    set_state "off"
    log "=== БЛОКИРОВКА ВЫКЛЮЧЕНА ==="
}

status() {
    local state
    state=$(get_state)
    echo -e "\n=== Amnezia Blocker Status ==="
    echo "State: $state"
    if [ "$state" = "on" ]; then
        echo "IPv4 entries: $(ipset list $BLOCKSET4 2>/dev/null | grep -c '^[0-9]' || echo 0)"
        if [ -z "$IPV6_OK" ]; then check_ipv6_support 2>/dev/null; fi
        if [ "$IPV6_OK" = "0" ]; then
            echo "IPv6 entries: $(ipset list $BLOCKSET6 2>/dev/null | grep -c '^[0-9]' || echo 0)"
        else
            echo "IPv6: not supported"
        fi
        echo "Chain (v4): $(iptables -L $CHAIN_NAME &>/dev/null && echo yes || echo no)"
        echo "Chain (v6): $(ip6tables -L $CHAIN_NAME &>/dev/null && echo yes || echo no)"
    fi
    echo "Domains: $DOMAINS_FILE"
    echo "Log: $LOG_FILE"
    echo -e "\nChain position (FORWARD):"
    iptables -L FORWARD -n --line-numbers 2>/dev/null | grep -E "(num|$CHAIN_NAME)" | head -5
    echo ""
}

case "${1:-status}" in
    on|enable|start)   acquire_lock; enable ;;
    off|disable|stop)  acquire_lock; disable ;;
    status|show)       status ;;
    update)            acquire_lock; update_blocks ;;
    reload)            acquire_lock; disable; sleep 1; enable ;;
    check)             acquire_lock; check_deps; check_ipv6_support ;;
    *)
        echo "Usage: $0 {on|off|status|update|reload|check}"
        exit 1
        ;;
esac
